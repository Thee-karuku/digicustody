<?php
// config/logger.php - Structured JSON logger for DigiCustody

function log_event($level, $message, $context = []) {
    $log_dir = '/var/log/digicustody';
    if (!is_dir($log_dir)) {
        @mkdir($log_dir, 0750, true);
    }
    
    $log_file = $log_dir . '/app.log';
    
    $entry = [
        'timestamp' => date('Y-m-d H:i:s.u'),
        'level' => strtoupper($level),
        'message' => $message,
        'context' => $context,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_id' => $_SESSION['user_id'] ?? null,
        'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
    ];
    
    $line = json_encode($entry) . "\n";
    @file_put_contents($log_file, $line, FILE_APPEND | LOCK_EX);
}

function log_error($message, $context = []) {
    log_event('error', $message, $context);
}

function log_warning($message, $context = []) {
    log_event('warning', $message, $context);
}

function log_info($message, $context = []) {
    log_event('info', $message, $context);
}

function log_debug($message, $context = []) {
    log_event('debug', $message, $context);
}
