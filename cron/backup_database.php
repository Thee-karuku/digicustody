<?php
/**
 * Database Backup Script
 * Run daily at 3 AM via cron: 0 3 * * * /usr/bin/php /var/www/html/digicustody/cron/backup_database.php
 */

$env_file = __DIR__ . '/../.env';
if (!file_exists($env_file)) {
    die("ERROR: .env file not found\n");
}

$lines = file($env_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$config = [];
foreach ($lines as $line) {
    if (strpos($line, '#') === 0) continue;
    if (strpos($line, '=') !== false) {
        list($key, $value) = explode('=', $line, 2);
        $config[trim($key)] = trim($value);
    }
}

$db_host = $config['DB_HOST'] ?? 'localhost';
$db_name = $config['DB_NAME'] ?? 'digicustody';
$db_user = $config['DB_USER'] ?? 'root';
$db_pass = $config['DB_PASS'] ?? '';

$backup_dir = '/var/backups/digicustody';
if (!is_dir($backup_dir)) {
    if (!mkdir($backup_dir, 0750, true)) {
        $result = ['success' => false, 'message' => "Failed to create backup directory: $backup_dir"];
        log_error('backup_database_failed', $result);
        echo json_encode($result) . "\n";
        exit(1);
    }
}

$timestamp = date('Y-m-d_His');
$backup_file = "$backup_dir/digicustody_$timestamp.sql";

$command = sprintf(
    'mysqldump --host=%s --user=%s --password=%s %s > %s 2>&1',
    escapeshellarg($db_host),
    escapeshellarg($db_user),
    escapeshellarg($db_pass),
    escapeshellarg($db_name),
    escapeshellarg($backup_file)
);

exec($command, $output, $return_code);

if ($return_code !== 0 || !file_exists($backup_file)) {
    $result = ['success' => false, 'message' => 'mysqldump failed', 'output' => implode("\n", $output), 'return_code' => $return_code];
    log_error('backup_database_failed', $result);
    echo json_encode($result) . "\n";
    exit(1);
}

$file_size = filesize($backup_file);

$days_to_keep = 30;
$cutoff = time() - ($days_to_keep * 86400);
$deleted = 0;
foreach (glob("$backup_dir/digicustody_*.sql") as $file) {
    if (filemtime($file) < $cutoff) {
        if (unlink($file)) $deleted++;
    }
}

$result = [
    'success' => true,
    'backup_file' => $backup_file,
    'file_size' => $file_size,
    'deleted_old_backups' => $deleted
];
log_info('backup_database_completed', $result);
echo json_encode($result) . "\n";