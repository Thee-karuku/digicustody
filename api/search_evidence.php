<?php
/**
 * DigiCustody – Search Evidence API
 * Returns evidence numbers for a given case_id
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';

header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    echo json_encode([]);
    exit;
}

$case_id = isset($_GET['case_id']) ? (int)$_GET['case_id'] : 0;
$exclude = isset($_GET['exclude']) ? (int)$_GET['exclude'] : 0;
$search = isset($_GET['q']) ? trim($_GET['q']) : '';

if ($case_id <= 0) {
    echo json_encode([]);
    exit;
}

$sql = "SELECT id, evidence_number, title FROM evidence WHERE case_id = ?";
$params = [$case_id];

if ($exclude > 0) {
    $sql .= " AND id != ?";
    $params[] = $exclude;
}

if ($search !== '') {
    $sql .= " AND (evidence_number LIKE ? OR title LIKE ?)";
    $params[] = "%$search%";
    $params[] = "%$search%";
}

$sql .= " ORDER BY uploaded_at DESC LIMIT 20";

$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$results = $stmt->fetchAll(PDO::FETCH_ASSOC);

echo json_encode($results);
