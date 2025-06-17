Deployment Runner Application
=============================

Overview
--------

A single-file PHP solution for handling secure code deployments with worker threads. This application provides an API endpoint for deployment operations and can run in both web and CLI modes.

Features
--------

*   Secure HTTPS API endpoint for deployment requests
    
*   Client certificate authentication
    
*   Encrypted payload handling
    
*   Deployment status tracking
    
*   API key management (generation/revocation)
    
*   SQLite database for storing deployment data
    
*   Environment variable configuration
    

Requirements
------------

*   PHP 7.4 or higher
    
*   Composer dependencies (see Installation)
    
*   SQLite database
    
*   SSL/TLS configuration for HTTPS
    
*   Client certificates for authentication
    

Installation
------------

1.  Clone the repository or copy the deployment script to your server
    
2.  bashCopyDownloadcomposer require vlucas/phpdotenv
    
3.  textCopyDownloadSQLITE\_DB\_PATH=/path/to/deployments.dbBACKUP\_PATH=/path/to/backupsPRIVATE\_KEY\_PATH=/path/to/private.key
    

Configuration
-------------

The application is configured through environment variables:

*   SQLITE\_DB\_PATH: Path to SQLite database file
    
*   BACKUP\_PATH: Directory for storing deployment backups
    
*   PRIVATE\_KEY\_PATH: Path to private key for decrypting payloads
    

API Endpoints
-------------

### POST /deploy

Handles deployment requests with encrypted payloads

### GET /status

Returns deployment status information

### POST /keys

Generates new API keys

### DELETE /keys/{keyId}

Revokes an existing API key

Security
--------

*   Enforces HTTPS connections
    
*   Requires client certificate authentication
    
*   Implements secure headers (HSTS, X-Content-Type-Options, X-Frame-Options)
    
*   Generic error messages to clients with detailed logging server-side
    

Usage
-----

### Web Mode (API)

The application automatically runs in API mode when accessed via web server.

    

License
-------

\[Specify your license here, e.g., MIT, GPL, etc.\]