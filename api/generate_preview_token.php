<?php
// api/generate_preview_token.php - Generate short-lived token for image preview

require_once __DIR__ . '/../config/functions.php';
set_secure_session_config();
session_start();
require_once __DIR__ . '/../config/db.php';
require_login($pdo);

$evidence_id = (int)($_POST['evidence_id'] ?? 0);
$uid = $_SESSION['user_id'];
$role = $_SESSION['role'];

if (!$evidence_id) {
    echo json_encode(['success' => false, 'error' => 'Invalid evidence ID']);
    exit;
}

// Verify access
$access = validate_evidence_access($pdo, $evidence_id, $uid, $role);
if (!$access['allowed']) {
    echo json_encode(['success' => false, 'error' => 'Access denied']);
    exit;
}

// Get evidence details
$stmt = $pdo->prepare("SELECT file_path, mime_type FROM evidence WHERE id = ?");
$stmt->execute([$evidence_id]);
$ev = $stmt->fetch();

if (!$ev || !file_exists($ev['file_path'])) {
    echo json_encode(['success' => false, 'error' => 'File not found']);
    exit;
}

// Only allow image types
if (!preg_match('/^image\//', $ev['mime_type'])) {
    echo json_encode(['success' => false, 'error' => 'Not an image']);
    exit;
}

// Generate short-lived token (expires in 30 seconds)
$token = bin2hex(random_bytes(16));
$expires = date('Y-m-d H:i:s', strtotime('+30 seconds'));

$stmt = $pdo->prepare("INSERT INTO download_tokens (token, evidence_id, file_path, file_name, evidence_number, sha256_hash, sha3_256_hash, created_by, intended_user_id, expires_at, download_reason) VALUES (?,?,?,?,?,?,?,?,?,?,?)");
$stmt->execute([
    $token, 
    $evidence_id, 
    $ev['file_path'], 
    basename($ev['file_path']),
    '', 
    '', 
    '', 
    $uid, 
    $uid, 
    $expires, 
    'preview'
]);

echo json_encode([
    'success' => true, 
    'token' => $token,
    'evidence_id' => $evidence_id
]);
