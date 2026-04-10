<?php
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login();

header('Content-Type: application/json');

$id = (int)($_GET['id'] ?? 0);
if (!$id) {
    echo json_encode(['success' => false, 'error' => 'Invalid ID']);
    exit;
}

$uid = $_SESSION['user_id'];
$role = $_SESSION['role'];

$sql = $role === 'admin' 
    ? "SELECT * FROM analysis_reports WHERE id=?"
    : "SELECT * FROM analysis_reports WHERE id=? AND submitted_by=? AND status='draft'";
$params = $role === 'admin' ? [$id] : [$id, $uid];

$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$draft = $stmt->fetch(PDO::FETCH_ASSOC);

if ($draft) {
    echo json_encode(['success' => true] + $draft);
} else {
    echo json_encode(['success' => false, 'error' => 'Draft not found']);
}