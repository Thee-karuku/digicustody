<?php
// ============================================================
// DigiCustody – Database Configuration (EXAMPLE)
// Copy this to db.php and fill in your credentials
// File: config/db.php
// ============================================================

define('DB_HOST', 'localhost');
define('DB_NAME', 'digicustody');
define('DB_USER', 'your_username');
define('DB_PASS', 'your_password');
define('DB_CHARSET', 'utf8mb4');

define('SITE_NAME', 'DigiCustody');
define('SITE_TAGLINE', 'Secure Evidence Management Platform');
$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
$script_path = $_SERVER['SCRIPT_NAME'] ?? '/';
$base = dirname($script_path);
if ($base === '/' || $base === '\\' || $base === '.') {
    $base = '';
} else {
    $base = rtrim($base, '/');
}
define('BASE_URL', $scheme . '://' . $host . $base . '/');
define('UPLOAD_DIR', '/var/digicustody/evidence/');
define('UPLOAD_URL', BASE_URL . 'download.php?token=');
define('DOWNLOAD_TOKEN_EXPIRY', 4);
if (!defined('SESSION_TIMEOUT')) define('SESSION_TIMEOUT', 3600);

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
