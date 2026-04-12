<?php
/**
 * DigiCustody – Health Check Endpoint
 * 
 * Returns JSON status of system components for monitoring tools.
 * Usage: health.php?token=<HEALTH_TOKEN>
 * 
 * Response:
 * - { status: "ok", components: {...} } if healthy
 * - { status: "degraded", components: {...}, errors: [...] } if any check fails
 */

header('Content-Type: application/json');

$env_file = __DIR__ . '/.env';
if (file_exists($env_file)) {
    $lines = file($env_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        if (strpos($line, '=') !== false) {
            list($key, $value) = explode('=', $line, 2);
            $_ENV[trim($key)] = trim($value);
        }
    }
}

$token = $_GET['token'] ?? '';
$expected_token = $_ENV['HEALTH_TOKEN'] ?? '';

if (empty($expected_token)) {
    http_response_code(503);
    echo json_encode(['status' => 'error', 'message' => 'Health check not configured']);
    exit;
}

if ($token !== $expected_token) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Invalid token']);
    exit;
}

$components = [];
$errors = [];

// Check database connection
try {
    $dsn = "mysql:host=localhost;dbname=digicustody;charset=utf8mb4";
    $pdo = new PDO($dsn, $_ENV['DB_USER'] ?? 'root', $_ENV['DB_PASS'] ?? '', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->query("SELECT 1");
    $components['database'] = ['status' => 'ok'];
} catch (Exception $e) {
    $components['database'] = ['status' => 'error', 'message' => $e->getMessage()];
    $errors[] = 'database: ' . $e->getMessage();
}

// Check uploads directory
$upload_dir = '/var/digicustody/evidence/';
if (is_dir($upload_dir) && is_writable($upload_dir)) {
    $components['uploads'] = ['status' => 'ok', 'path' => $upload_dir];
} else {
    $components['uploads'] = ['status' => 'error', 'message' => 'Directory not writable or does not exist'];
    $errors[] = 'uploads: not writable';
}

// Check sessions directory (using sys_get_temp_dir for session-like storage)
$session_dir = sys_get_temp_dir();
if (is_dir($session_dir) && is_writable($session_dir)) {
    $components['storage'] = ['status' => 'ok', 'path' => $session_dir];
} else {
    $components['storage'] = ['status' => 'error', 'message' => 'Temp directory not writable'];
    $errors[] = 'storage: not writable';
}

// Check cache directory for file-based caching
$cache_dir = sys_get_temp_dir() . '/digicustody_cache';
if (is_dir($cache_dir) && is_writable($cache_dir)) {
    $components['cache'] = ['status' => 'ok', 'path' => $cache_dir];
} else {
    $components['cache'] = ['status' => 'warning', 'message' => 'Cache directory not initialized yet'];
}

// Determine overall status
$status = empty($errors) ? 'ok' : 'degraded';

$response = [
    'status' => $status,
    'timestamp' => date('Y-m-d H:i:s'),
    'components' => $components,
];

if (!empty($errors)) {
    $response['errors'] = $errors;
}

http_response_code($status === 'ok' ? 200 : 503);
echo json_encode($response, JSON_PRETTY_PRINT);
