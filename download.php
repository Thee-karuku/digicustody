<?php
/**
 * DigiCustody – Secure Evidence Download Controller
 * 
 * Validates download token, verifies session auth, logs download, and streams file.
 * File paths are NEVER exposed in URLs.
 * 
 * Usage: download.php?token=<download_token>
 */

require_once __DIR__ . '/config/functions.php';
require_once __DIR__ . '/config/logger.php';
require_once __DIR__ . '/config/db.php';

set_secure_session_config();

// Must have valid session
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
    http_response_code(403);
    die(json_encode(['error' => 'Authentication required.']));
}

$uid = (int)$_SESSION['user_id'];
$role = $_SESSION['role'] ?? '';

// Get token from URL
$token = $_GET['token'] ?? '';
if (empty($token)) {
    http_response_code(400);
    die('Missing download token.');
}

// Validate token with row lock to prevent race condition
$pdo->beginTransaction();
try {
    $stmt = $pdo->prepare("
        SELECT dt.*, u.full_name AS creator_name
        FROM download_tokens dt
        JOIN users u ON u.id = dt.created_by
        WHERE dt.token = ? AND dt.is_used = 0 AND dt.expires_at > NOW()
        FOR UPDATE
    ");
    $stmt->execute([$token]);
    $token_data = $stmt->fetch();

    if (!$token_data) {
        $pdo->rollBack();
        http_response_code(410);
        die('Download link has expired or is invalid.');
    }

    // Mark token as used within the same transaction
    $pdo->prepare("UPDATE download_tokens SET is_used = 1, used_at = NOW() WHERE id = ?")
        ->execute([$token_data['id']]);
    
    $pdo->commit();
} catch (Exception $e) {
    $pdo->rollBack();
    log_error("Download token redemption error", ['error' => $e->getMessage()]);
    http_response_code(500);
    die('An error occurred processing your download.');
}

// Verify user authorization (token creator or admin)
if ((int)$token_data['created_by'] !== $uid && $role !== 'admin') {
    http_response_code(403);
    die('You are not authorized to download this file.');
}

// Check analyst access to evidence (if applicable)
if ($role === 'analyst') {
    $stmt2 = $pdo->prepare("
        SELECT 1 FROM case_access ca
        JOIN evidence e ON e.case_id = ca.case_id
        WHERE e.id = ? AND ca.user_id = ?
    ");
    $stmt2->execute([$token_data['evidence_id'], $uid]);
    if (!$stmt2->fetchColumn()) {
        http_response_code(403);
        die('Access denied to this evidence.');
    }
}

// Verify file exists
$file_path = $token_data['file_path'];
if (!file_exists($file_path) || !is_readable($file_path)) {
    http_response_code(404);
    die('File not found on server.');
}

// Log download
audit_log(
    $pdo,
    $uid,
    $_SESSION['username'],
    $role,
    'evidence_downloaded',
    'evidence',
    $token_data['evidence_id'],
    $token_data['evidence_number'],
    "Downloaded: {$token_data['file_name']}",
    $_SERVER['REMOTE_ADDR'] ?? '',
    $_SERVER['HTTP_USER_AGENT'] ?? ''
);

// Stream file using helper function
stream_evidence_file($file_path, $token_data['file_name']);
