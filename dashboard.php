<?php
/**
 * DigiCustody – Dashboard Router
 * Save to: /var/www/html/digicustody/dashboard.php
 */
session_start();
require_once __DIR__.'/config/db.php';
require_once __DIR__.'/config/functions.php';
require_login();

// Route to correct dashboard based on role
if ($_SESSION['role'] === 'admin') {
    require_once __DIR__.'/pages/dashboard_admin.php';
} else {
    require_once __DIR__.'/pages/dashboard_user.php';
}