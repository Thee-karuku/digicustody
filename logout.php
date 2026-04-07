<?php
require_once __DIR__."/config/functions.php";
set_secure_session_config();
session_start();
require_once 'config/db.php';

if (isset($_SESSION['user_id'])) {
    audit_log($pdo, $_SESSION['user_id'], $_SESSION['username'], $_SESSION['role'],
        'logout', null, null, null, 'User logged out', $_SERVER['REMOTE_ADDR'] ?? '');
}
session_unset();
session_destroy();
header('Location: login.php?msg=logged_out');
exit;
