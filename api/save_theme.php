<?php
// api/save_theme.php - Save theme preference to database

session_start();
require_once __DIR__ . '/../config/db.php';
require_login();

$theme = $_POST['theme'] ?? 'dark';
$theme = in_array($theme, ['dark', 'light']) ? $theme : 'dark';
$user_id = $_SESSION['user_id'] ?? 0;

if ($user_id > 0) {
    $pdo->prepare("UPDATE users SET theme_preference = ? WHERE id = ?")->execute([$theme, $user_id]);
}

echo json_encode(['success' => true, 'theme' => $theme]);
