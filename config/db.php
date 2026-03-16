<?php
// ============================================================
// DigiCustody – Database Configuration
// File: config/db.php
// ============================================================

define('DB_HOST', 'localhost');
define('DB_NAME', 'digicustody');
define('DB_USER', 'root');
define('DB_PASS', 'DigiCustody@2025');
define('DB_CHARSET', 'utf8mb4');

define('SITE_NAME', 'DigiCustody');
define('SITE_TAGLINE', 'Secure Evidence Management Platform');
define('BASE_URL', 'http://localhost/digicustody/');
define('UPLOAD_DIR', '/var/www/html/digicustody/uploads/evidence/');
define('UPLOAD_URL', BASE_URL . 'uploads/evidence/');
define('DOWNLOAD_TOKEN_EXPIRY', 24); // hours
define('SESSION_TIMEOUT', 3600);     // seconds (1 hour)

try {
    $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];
    $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
} catch (PDOException $e) {
    error_log("DB Connection Failed: " . $e->getMessage());
    die(json_encode(['error' => 'Database connection failed. Please contact the system administrator.']));
}