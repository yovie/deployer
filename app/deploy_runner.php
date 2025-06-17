<?php
/**
 * Deployment Runner Application
 * A single-file PHP solution for handling code deployments with worker threads
 */
require __DIR__ . '/vendor/autoload.php';
require 'deployer.php';

$dotenv = Dotenv\Dotenv::createImmutable('/root/deployer.env');
$dotenv->load();

$sqliteDBPath = getenv('SQLITE_DB_PATH');
$backupPath = getenv('BACKUP_PATH');
$keyPath = getenv('PRIVATE_KEY_PATH');

// Check if this is a CLI environment for worker mode
$is_cli = php_sapi_name() === 'cli';

// Initialize database
initDatabase();

// Main router
if ($is_cli) {
    // Worker mode
    die;
} else {
    // API mode
    handleApiRequest($keyPath, $backupPath, $sqliteDBPath);
}

/**
 * API Request Handler
 */
function handleApiRequest($privateKeyPath, $backupDir, $dbPath) {
    // Enforce HTTPS
    enforceHttps();
    
    // Set security headers
    header('Content-Type: application/json');
    header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    
    try {
        // Verify client certificate
        verifyClientCertificate();
        
        // Check authentication
        authenticateRequest();

        // Route the request
        $method = $_SERVER['REQUEST_METHOD'];
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

        if ($method === 'POST' && $path === '/deploy') {
            $encryptedPayload = file_get_contents('php://input');
            handleDeployRequest($privateKeyPath, $backupDir, $dbPath, $encryptedPayload);
        } elseif ($method === 'GET' && $path === '/status') {
            handleStatusRequest();
        } elseif ($method === 'POST' && $path === '/keys') {
            handleKeyGeneration();
        } elseif ($method === 'DELETE' && preg_match('/^\/keys\/([a-zA-Z0-9]+)$/', $path, $matches)) {
            handleKeyRevocation($matches[1]);
        } else {
            throw new Exception('Endpoint not found', 404);
        }
    } catch (Exception $e) {
        http_response_code($e->getCode() ?: 500);
        echo json_encode(['error' => 'An error occurred']); // Generic error message
        error_log($e->getMessage()); // Log detailed error server-side
    }
}

/**
 * Enhanced key generation with expiration
 */
function handleKeyGeneration($path = $sqliteDBPath) {
    // Validate admin privileges
    if (!isset($_SERVER['HTTP_X_ADMIN_TOKEN']) || $_SERVER['HTTP_X_ADMIN_TOKEN'] !== 'your_admin_secret') {
        header('HTTP/1.1 403 Forbidden');
        throw new Exception('Admin privileges required');
    }

    // Initialize database if it doesn't exist
    $db = new SQLite3($path);
    $db->exec('CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        active BOOLEAN DEFAULT 1,
        last_used_at DATETIME NULL
    )');

    // Get input parameters
    $description = $_POST['description'] ?? 'Automatically generated key';
    $expiryDays = isset($_POST['expiry_days']) ? (int)$_POST['expiry_days'] : 30;
    $active = isset($_POST['active']) ? (int)$_POST['active'] : 1; // Default to active
    $apiKey = bin2hex(random_bytes(32));
    
    // Insert new key
    $stmt = $db->prepare('INSERT INTO api_keys 
                         (key, description, expires_at, active) 
                         VALUES 
                         (:key, :description, datetime("now", "+:expiry_days days"), :active)');
    $stmt->bindValue(':key', $apiKey, SQLITE3_TEXT);
    $stmt->bindValue(':description', $description, SQLITE3_TEXT);
    $stmt->bindValue(':expiry_days', $expiryDays, SQLITE3_INTEGER);
    $stmt->bindValue(':active', $active, SQLITE3_INTEGER);
    
    if (!$stmt->execute()) {
        $db->close();
        header('HTTP/1.1 500 Internal Server Error');
        throw new Exception('Failed to generate API key');
    }
    
    $db->close();
    
    // Return response
    header('Content-Type: application/json');
    echo json_encode([
        'api_key' => $apiKey,
        'description' => $description,
        'created_at' => date('Y-m-d H:i:s'),
        'expires_at' => date('Y-m-d H:i:s', strtotime("+$expiryDays days")),
        'active' => (bool)$active,
        'message' => 'Store this key securely. It will not be shown again.'
    ]);
}

/**
 * Key revocation with automatic cleanup
 */
function handleKeyRevocation($keyId, $path=$sqliteDBPath) {
    // Validate admin privileges
    if (!isset($_SERVER['HTTP_X_ADMIN_TOKEN']) || $_SERVER['HTTP_X_ADMIN_TOKEN'] !== 'your_admin_secret') {
        throw new Exception('Admin privileges required', 403);
    }

    $db = new SQLite3($path);
    
    // First check if key exists and is active
    $stmt = $db->prepare('SELECT is_active FROM api_keys WHERE key = :key');
    $stmt->bindValue(':key', $keyId, SQLITE3_TEXT);
    $result = $stmt->execute();
    $keyData = $result->fetchArray(SQLITE3_ASSOC);
    
    if (!$keyData) {
        $db->close();
        throw new Exception('API key not found', 404);
    }
    
    if (!$keyData['is_active']) {
        $db->close();
        throw new Exception('API key already revoked', 400);
    }
    
    // Revoke the key with reason
    $stmt = $db->prepare('UPDATE api_keys SET 
                         is_active = 0, 
                         revocation_reason = "MANUAL_REVOCATION",
                         last_used_at = datetime("now")
                         WHERE key = :key');
    $stmt->bindValue(':key', $keyId, SQLITE3_TEXT);
    
    if (!$stmt->execute()) {
        $db->close();
        throw new Exception('Failed to revoke API key', 500);
    }
    
    $db->close();
    
    echo json_encode(['message' => 'API key revoked successfully']);
}

/**
 * Initialize SQLite database with additional security features
 */
function initDatabase($path=$sqliteDBPath) {
    $db = new SQLite3($path);
    $db->exec('CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL UNIQUE,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used_at DATETIME,
        expires_at DATETIME,
        is_active INTEGER DEFAULT 1,
        usage_count INTEGER DEFAULT 0,
        last_ip TEXT,
        revocation_reason TEXT
    )');
    
    // Create indexes for better performance
    $db->exec('CREATE INDEX IF NOT EXISTS idx_active_keys ON api_keys (is_active)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_key_expiry ON api_keys (expires_at)');
    $db->close();
    
    // Perform automatic cleanup of expired keys
    cleanupExpiredKeys();
}

/**
 * Automatically revoke expired or suspicious keys
 */
function cleanupExpiredKeys($path=$sqliteDBPath) {
    $db = new SQLite3($path);
    
    // Revoke expired keys
    $db->exec('UPDATE api_keys SET is_active = 0, revocation_reason = "EXPIRED" 
              WHERE expires_at IS NOT NULL AND expires_at < datetime("now") AND is_active = 1');
    
    // Revoke keys with suspicious IP changes (example)
    $db->exec('UPDATE api_keys SET is_active = 0, revocation_reason = "SUSPICIOUS_IP_CHANGE"
              WHERE last_ip IS NOT NULL AND last_ip != "'.$_SERVER['REMOTE_ADDR'].'" 
              AND is_active = 1');
    
    $db->close();
}

/**
 * Enforce HTTPS connections
 */
function enforceHttps() {
    if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
        throw new Exception('HTTPS required', 403);
    }
}

/**
 * Verify client certificate (P12)
 */
function verifyClientCertificate() {
    if (empty($_SERVER['SSL_CLIENT_VERIFY']) || $_SERVER['SSL_CLIENT_VERIFY'] !== 'SUCCESS') {
        throw new Exception('Client certificate verification failed', 403);
    }
    
    // Additional checks can be added here:
    // - Check $_SERVER['SSL_CLIENT_S_DN'] for specific certificate attributes
    // - Verify against a certificate fingerprint
    // - Check certificate expiration
}

/**
 * Authenticate the request
 */
function authenticateRequest($dbPath=$sqliteDBPath) {
    if (empty($_SERVER['HTTP_AUTHORIZATION'])) {
        throw new Exception('Authentication required', 401);
    }

    $token = str_replace('Bearer ', '', $_SERVER['HTTP_AUTHORIZATION']);

    $db = new SQLite3($dbPath);
    $stmt = $db->prepare('SELECT * FROM api_keys WHERE key = :key AND active = 1 AND (expires_at IS NULL OR expires_at > datetime("now"))');
    $stmt->bindValue(':key', $token, SQLITE3_TEXT);
    $result = $stmt->execute();
    
    $keyData = $result->fetchArray(SQLITE3_ASSOC);

    if ($keyData) {
        // Update last used timestamp
        $update = $db->prepare('UPDATE api_keys SET last_used_at = datetime("now") WHERE id = :id');
        $update->bindValue(':id', $keyData['id'], SQLITE3_INTEGER);
        $update->execute();
        return true;
    } else {
        throw new Exception('Invalid authentication token', 403);
    }
}

/**
 * Handle deployment request
 */
function handleDeployRequest($privateKeyPath, $backupDir, $dbPath, $encryptedPayload) {
    $handler = new DeploymentHandler(
        $privateKeyPath,
        $backupDir,
        $dbPath
    );
    $response = $handler->handleDeployRequest($encryptedPayload);
    header('Content-Type: application/json');
    echo json_encode($response);
}

/**
 * Handle status request
 * Retrieves and returns the latest N deployment status records from the database
 * 
 * @param int $limit Number of recent deployments to return (default: 10)
 */
function handleStatusRequest($dbPath=$sqliteDBPath, $limit = 10) {
    try {
        // Validate and sanitize the limit parameter
        $limit = filter_var($limit, FILTER_VALIDATE_INT, [
            'options' => [
                'default' => 10,
                'min_range' => 1,
                'max_range' => 100
            ]
        ]);
        
        // Connect to SQLite database
        $db = new SQLite3($dbPath);
        
        // Prepare parameterized query
        $stmt = $db->prepare("SELECT 
                    file_path, 
                    backup_path, 
                    status, 
                    file_size, 
                    file_mode, 
                    error_message, 
                    end_time, 
                    deployment_type 
                  FROM deployments 
                  ORDER BY end_time DESC
                  LIMIT :limit");
        
        $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
        $result = $stmt->execute();
        
        $deployments = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $deployments[] = [
                'file_path' => $row['file_path'],
                'backup_path' => $row['backup_path'],
                'status' => $row['status'],
                'file_size' => (int)$row['file_size'],
                'file_mode' => $row['file_mode'],
                'error_message' => $row['error_message'],
                'end_time' => $row['end_time'],
                'deployment_type' => $row['deployment_type']
            ];
        }
        
        // Get total count of deployments for reference
        $totalCount = $db->querySingle("SELECT COUNT(*) FROM deployments");
        
        // Close database connection
        $db->close();
        
        // Return successful response with deployments data
        echo json_encode([
            'success' => true,
            'limit' => $limit,
            'total_deployments' => (int)$totalCount,
            'deployments' => $deployments
        ]);
        
    } catch (Exception $e) {
        // Handle database errors
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Failed to retrieve deployment status',
            'details' => $e->getMessage()
        ]);
    }
}


?>
