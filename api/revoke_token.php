<?php
// api/revoke_token.php - Revoke a preview token immediately after use

require_once __DIR__ . '/../config/functions.php';
set_secure_session_config();
session_start();
require_once __DIR__ . '/../config/db.php';
require_login($pdo);

$token = $_POST['token'] ?? '';

if (empty($token)) {
    echo json_encode(['success' => false, 'error' => 'No token provided']);
    exit;
}

// Mark token as used immediately
$stmt = $pdo->prepare("UPDATE download_tokens SET is_used = 1, used_at = NOW() WHERE token = ? AND created_by = ?");
$stmt->execute([$token, $_SESSION['user_id']]);

echo json_encode(['success' => true]);