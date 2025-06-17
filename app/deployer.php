<?php
class DeploymentHandler {
    private $privateKeyPath;
    private $backupDir;
    private $dbPath;
    
    /**
     * Constructor
     * 
     * @param string $privateKeyPath Path to private key for decryption
     * @param string $backupDir Directory for file backups
     * @param string $dbPath Path to SQLite database
     */
    public function __construct($privateKeyPath, $backupDir, $dbPath) {
        $this->privateKeyPath = $privateKeyPath;
        $this->backupDir = rtrim($backupDir, '/') . '/';
        $this->dbPath = $dbPath;
        
        // Create backup directory if it doesn't exist
        if (!file_exists($this->backupDir)) {
            mkdir($this->backupDir, 0755, true);
        }
        
        // Initialize database if it doesn't exist
        $this->initializeDatabase();
    }
    
    /**
     * Handle deploy request with enhanced logging
     * 
     * @param string $encryptedPayload Encrypted JSON payload
     * @param string $deploymentType Type of deployment (default: 'regular')
     * @return array Response array with status and message
     */
    public function handleDeployRequest($encryptedPayload, $deploymentType = 'regular') {
        try {
            // Start tracking deployment time
            $startTime = microtime(true);
            
            // Decrypt the payload
            $jsonPayload = $this->decryptPayload($encryptedPayload);
            $data = json_decode($jsonPayload, true);
            
            // Validate payload
            if (json_last_error() !== JSON_ERROR_NONE || 
                !isset($data['file_path']) || 
                !isset($data['file_name']) || 
                !isset($data['file_content'])) {
                throw new Exception("Invalid payload structure");
            }
            
            // Set default mode if not provided
            $fileMode = $data['file_mode'] ?? 0644;
            
            // Full file path
            $fullPath = rtrim($data['file_path'], '/') . '/' . $data['file_name'];
            
            // Backup existing file if it exists
            $backupPath = null;
            if (file_exists($fullPath)) {
                $backupPath = $this->backupFile($fullPath);
            }
            
            // Create directory if it doesn't exist
            $dir = dirname($fullPath);
            if (!file_exists($dir)) {
                if (!mkdir($dir, 0755, true)) {
                    throw new Exception("Failed to create directory: $dir");
                }
            }
            
            // Write new file
            $bytesWritten = file_put_contents($fullPath, $data['file_content']);
            if ($bytesWritten === false) {
                throw new Exception("Failed to write file");
            }
            
            // Set file permissions
            if (!chmod($fullPath, $fileMode)) {
                throw new Exception("Failed to set file permissions");
            }
            
            // Calculate deployment duration
            $duration = round(microtime(true) - $startTime, 3);
            
            // Log successful deployment to database
            $this->logDeployment([
                'file_path' => $fullPath,
                'backup_path' => $backupPath,
                'status' => 'success',
                'file_size' => $bytesWritten,
                'file_mode' => $fileMode,
                'deployment_type' => $deploymentType,
                'duration_seconds' => $duration
            ]);
            
            return [
                'status' => 'success',
                'message' => 'File deployed successfully',
                'backup_path' => $backupPath,
                'file_path' => $fullPath,
                'file_size' => $bytesWritten,
                'duration_seconds' => $duration
            ];
            
        } catch (Exception $e) {
            // Calculate duration even for failed deployments
            $duration = isset($startTime) ? round(microtime(true) - $startTime, 3) : 0;
            
            // Log failure to database
            if (isset($fullPath)) {
                $this->logDeployment([
                    'file_path' => $fullPath,
                    'status' => 'failed',
                    'error_message' => $e->getMessage(),
                    'deployment_type' => $deploymentType,
                    'duration_seconds' => $duration
                ]);
            }
            
            return [
                'status' => 'error',
                'message' => $e->getMessage(),
                'duration_seconds' => $duration
            ];
        }
    }
    
    /**
     * Decrypt the payload using asymmetric encryption
     * 
     * @param string $encryptedData Encrypted data
     * @return string Decrypted JSON string
     */
    private function decryptPayload($encryptedData) {
        // Read private key
        $privateKey = openssl_pkey_get_private(file_get_contents($this->privateKeyPath));
        if ($privateKey === false) {
            throw new Exception("Invalid private key");
        }
        
        // Decrypt the data
        $decrypted = '';
        $success = openssl_private_decrypt(
            base64_decode($encryptedData),
            $decrypted,
            $privateKey
        );
        
        if (!$success) {
            throw new Exception("Decryption failed: " . openssl_error_string());
        }
        
        return $decrypted;
    }
    
    /**
     * Backup a file to the backup directory
     * 
     * @param string $filePath Path to file to backup
     * @return string Path to backup file
     */
    private function backupFile($filePath) {
        $filename = basename($filePath);
        $backupFilename = date('Ymd_His') . '_' . $filename;
        $backupPath = $this->backupDir . $backupFilename;
        
        if (!copy($filePath, $backupPath)) {
            throw new Exception("Failed to create backup");
        }
        
        return $backupPath;
    }
    
    /**
     * Initialize SQLite database with enhanced time tracking
     */
    private function initializeDatabase() {
        $db = new SQLite3($this->dbPath);
        $db->exec("
            CREATE TABLE IF NOT EXISTS deployments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                file_path TEXT NOT NULL,
                backup_path TEXT,
                status TEXT NOT NULL,
                file_size INTEGER,
                file_mode TEXT,
                error_message TEXT,
                start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                end_time DATETIME,
                duration_seconds REAL GENERATED ALWAYS AS (
                    CASE WHEN end_time IS NOT NULL 
                    THEN (julianday(end_time) - julianday(start_time)) * 86400 
                    ELSE NULL END
                ) VIRTUAL,
                deployment_type TEXT DEFAULT 'regular'
            )
        ");
        
        // Create index for better query performance on time-based queries
        $db->exec("CREATE INDEX IF NOT EXISTS idx_deployments_time ON deployments(start_time)");
        $db->close();
    }
    
    /**
     * Log deployment to database with time tracking
     * 
     * @param array $data Deployment data to log
     */
    private function logDeployment($data) {
        $db = new SQLite3($this->dbPath);
        
        $stmt = $db->prepare("
            INSERT INTO deployments (
                file_path, 
                backup_path, 
                status, 
                file_size, 
                file_mode, 
                error_message,
                end_time,
                deployment_type
            ) VALUES (
                :file_path, 
                :backup_path, 
                :status, 
                :file_size, 
                :file_mode, 
                :error_message,
                CURRENT_TIMESTAMP,
                :deployment_type
            )
        ");
        
        $stmt->bindValue(':file_path', $data['file_path'], SQLITE3_TEXT);
        $stmt->bindValue(':backup_path', $data['backup_path'] ?? null, SQLITE3_TEXT);
        $stmt->bindValue(':status', $data['status'], SQLITE3_TEXT);
        $stmt->bindValue(':file_size', $data['file_size'] ?? null, SQLITE3_INTEGER);
        $stmt->bindValue(':file_mode', $data['file_mode'] ?? null, SQLITE3_TEXT);
        $stmt->bindValue(':error_message', $data['error_message'] ?? null, SQLITE3_TEXT);
        $stmt->bindValue(':deployment_type', $data['deployment_type'] ?? 'regular', SQLITE3_TEXT);
        
        $stmt->execute();
        $db->close();
    }
}

// Example usage:
// $handler = new DeploymentHandler('/path/to/private.key', '/backups/', '/path/to/deployments.db');
// $response = $handler->handleDeployRequest($_POST['encrypted_payload']);
// echo json_encode($response);
?>