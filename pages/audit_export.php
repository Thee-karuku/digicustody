<?php
/**
 * DigiCustody – Audit Log Export (Printable Report)
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login();

if (!is_admin()) {
    header('Location: ../dashboard.php?error=access_denied');
    exit;
}

$uid = $_SESSION['user_id'];
$role = $_SESSION['role'];

// Get filters
$action_filter = $_GET['action'] ?? '';
$user_filter = $_GET['user'] ?? '';
$date_from = $_GET['date_from'] ?? '';
$date_to = $_GET['date_to'] ?? '';
$limit = min((int)($_GET['limit'] ?? 500), 1000);

// Build query
$where = [];
$params = [];

if ($action_filter) {
    $where[] = "al.action_type = ?";
    $params[] = $action_filter;
}
if ($user_filter) {
    $where[] = "(al.username LIKE ? OR al.user_id = ?)";
    $params[] = "%$user_filter%";
    $params[] = (int)$user_filter;
}
if ($date_from) {
    $where[] = "DATE(al.created_at) >= ?";
    $params[] = $date_from;
}
if ($date_to) {
    $where[] = "DATE(al.created_at) <= ?";
    $params[] = $date_to;
}

$where_sql = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$logs = $pdo->prepare("
    SELECT al.*, u.full_name as user_full_name
    FROM audit_logs al
    LEFT JOIN users u ON u.id = al.user_id
    $where_sql
    ORDER BY al.created_at DESC
    LIMIT $limit
");
$logs->execute($params);
$logs = $logs->fetchAll();

$total = count($logs);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Audit Log Report - DigiCustody</title>
<style>
    @media print {
        body { font-size: 10px; }
        .no-print { display: none !important; }
        .page-break { page-break-before: always; }
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 12px; line-height: 1.4; color: #333; padding: 20px; background: #fff; }
    .header { text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #333; }
    .header h1 { font-size: 24px; color: #1a1a2e; margin-bottom: 5px; }
    .header .subtitle { color: #666; font-size: 14px; }
    .meta { display: flex; justify-content: space-between; margin-bottom: 20px; font-size: 11px; color: #666; }
    .meta-left, .meta-right { }
    .filters { background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
    .filters h3 { font-size: 14px; margin-bottom: 10px; }
    .filter-row { display: flex; flex-wrap: wrap; gap: 20px; }
    .filter-item { }
    .filter-item label { font-size: 10px; color: #666; display: block; }
    .filter-item span { font-weight: bold; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background: #1a1a2e; color: white; font-size: 11px; }
    tr:nth-child(even) { background: #f9f9f9; }
    tr:hover { background: #f0f0f0; }
    .action-badge { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 10px; white-space: nowrap; }
    .action-badge.login { background: #22c55e; color: white; }
    .action-badge.logout { background: #6b7280; color: white; }
    .action-badge.upload { background: #3b82f6; color: white; }
    .action-badge.download { background: #f59e0b; color: white; }
    .action-badge.admin { background: #8b5cf6; color: white; }
    .action-badge.danger { background: #ef4444; color: white; }
    .action-badge.transfer { background: #ec4899; color: white; }
    .action-badge.warning { background: #f97316; color: white; }
    .action-badge.default { background: #6b7280; color: white; }
    .mono { font-family: 'Courier New', monospace; font-size: 10px; }
    .summary { margin-top: 30px; padding: 15px; background: #f5f5f5; border-radius: 5px; }
    .summary h3 { font-size: 14px; margin-bottom: 10px; }
    .summary-grid { display: flex; flex-wrap: wrap; gap: 30px; }
    .summary-item { }
    .summary-item label { font-size: 10px; color: #666; }
    .summary-item span { font-size: 18px; font-weight: bold; color: #1a1a2e; }
    .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; font-size: 10px; color: #999; }
    .no-print { background: #1a1a2e; color: white; padding: 15px; margin-bottom: 20px; text-align: center; }
    .no-print button { padding: 10px 20px; background: #c9a84c; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; }
    .no-print button:hover { background: #e2bc6a; }
    @page { margin: 15mm; }
</style>
</head>
<body>

<div class="no-print">
    <p style="margin-bottom:15px;">This is a printable audit report. Click the button below to print or save as PDF.</p>
    <button onclick="window.print()"><i class="fas fa-print"></i> Print / Save as PDF</button>
</div>

<div class="header">
    <h1>🔒 DigiCustody Audit Log Report</h1>
    <div class="subtitle">Chain of Custody & System Activity Log</div>
</div>

<div class="meta">
    <div class="meta-left">
        <strong>Generated:</strong> <?= date('F j, Y H:i:s') ?><br>
        <strong>Generated by:</strong> <?= e($_SESSION['full_name']) ?> (<?= e($_SESSION['username']) ?>)
    </div>
    <div class="meta-right">
        <strong>Total Records:</strong> <?= number_format($total) ?>
    </div>
</div>

<div class="filters">
    <h3>Applied Filters</h3>
    <div class="filter-row">
        <?php if ($action_filter): ?>
        <div class="filter-item">
            <label>Action Type</label>
            <span><?= e($action_filter) ?></span>
        </div>
        <?php endif; ?>
        <?php if ($user_filter): ?>
        <div class="filter-item">
            <label>User</label>
            <span><?= e($user_filter) ?></span>
        </div>
        <?php endif; ?>
        <?php if ($date_from): ?>
        <div class="filter-item">
            <label>From Date</label>
            <span><?= e($date_from) ?></span>
        </div>
        <?php endif; ?>
        <?php if ($date_to): ?>
        <div class="filter-item">
            <label>To Date</label>
            <span><?= e($date_to) ?></span>
        </div>
        <?php endif; ?>
        <?php if (!$action_filter && !$user_filter && !$date_from && !$date_to): ?>
        <span>No filters applied (showing all records)</span>
        <?php endif; ?>
    </div>
</div>

<table>
<thead>
<tr>
    <th>#</th>
    <th>Date/Time</th>
    <th>User</th>
    <th>Role</th>
    <th>Action</th>
    <th>Target</th>
    <th>Description</th>
    <th>IP Address</th>
</tr>
</thead>
<tbody>
<?php foreach ($logs as $i => $log): 
    $action_class = 'default';
    if (strpos($log['action_type'], 'login') !== false) $action_class = 'login';
    elseif (strpos($log['action_type'], 'logout') !== false) $action_class = 'logout';
    elseif (strpos($log['action_type'], 'upload') !== false) $action_class = 'upload';
    elseif (strpos($log['action_type'], 'download') !== false) $action_class = 'download';
    elseif (strpos($log['action_type'], 'transfer') !== false) $action_class = 'transfer';
    elseif (strpos($log['action_type'], 'admin') !== false || strpos($log['action_type'], 'account') !== false) $action_class = 'admin';
    elseif (strpos($log['action_type'], 'failed') !== false || strpos($log['action_type'], 'rejected') !== false) $action_class = 'danger';
    elseif (strpos($log['action_type'], 'warning') !== false) $action_class = 'warning';
    
    $action_labels = [
        'login' => 'Login', 'logout' => 'Logout', 'login_failed' => 'Failed Login',
        'evidence_uploaded' => 'Evidence Upload', 'evidence_viewed' => 'Evidence View',
        'evidence_downloaded' => 'Evidence Download', 'evidence_transferred' => 'Transfer',
        'evidence_transfer_accepted' => 'Transfer Accept', 'evidence_transfer_rejected' => 'Transfer Reject',
        'hash_verified' => 'Hash Verify', 'integrity_check' => 'Integrity Check',
        'account_created' => 'Account Create', 'account_updated' => 'Account Update',
        'account_request_submitted' => 'Account Request', 'account_request_approved' => 'Request Approved',
        'account_request_rejected' => 'Request Rejected', 'case_created' => 'Case Create',
        'case_updated' => 'Case Update', 'case_closed' => 'Case Close',
        'download_token_generated' => 'Token Create', 'download_token_used' => 'Token Used',
        'admin_action' => 'Admin Action', 'system_event' => 'System Event',
    ];
?>
<tr>
    <td><?= $i + 1 ?></td>
    <td class="mono"><?= date('Y-m-d H:i:s', strtotime($log['created_at'])) ?></td>
    <td><?= e($log['username'] ?: $log['user_full_name'] ?: 'System') ?></td>
    <td><?= e($log['user_role']) ?></td>
    <td><span class="action-badge <?= $action_class ?>"><?= $action_labels[$log['action_type']] ?? ucwords(str_replace('_', ' ', $log['action_type'])) ?></span></td>
    <td><?= e($log['target_label'] ?: '-') ?></td>
    <td style="max-width: 300px; font-size: 10px;"><?= e(substr($log['description'], 0, 200)) ?><?= strlen($log['description']) > 200 ? '...' : '' ?></td>
    <td class="mono"><?= e($log['ip_address']) ?></td>
</tr>
<?php endforeach; ?>
</tbody>
</table>

<div class="summary">
    <h3>Summary Statistics</h3>
    <div class="summary-grid">
        <div class="summary-item">
            <label>Total Events</label>
            <span><?= number_format($total) ?></span>
        </div>
        <?php
        $login_count = count(array_filter($logs, fn($l) => $l['action_type'] === 'login'));
        $upload_count = count(array_filter($logs, fn($l) => $l['action_type'] === 'evidence_uploaded'));
        $download_count = count(array_filter($logs, fn($l) => $l['action_type'] === 'evidence_downloaded'));
        $transfer_count = count(array_filter($logs, fn($l) => strpos($l['action_type'], 'transfer') !== false));
        ?>
        <div class="summary-item">
            <label>Logins</label>
            <span><?= $login_count ?></span>
        </div>
        <div class="summary-item">
            <label>Uploads</label>
            <span><?= $upload_count ?></span>
        </div>
        <div class="summary-item">
            <label>Downloads</label>
            <span><?= $download_count ?></span>
        </div>
        <div class="summary-item">
            <label>Transfers</label>
            <span><?= $transfer_count ?></span>
        </div>
    </div>
</div>

<div class="footer">
    <p>This report was generated by DigiCustody Evidence Management System</p>
    <p>Document ID: AUDIT-<?= date('Ymd') ?>-<?= substr(md5(time()), 0, 8) ?> | <?= date('F j, Y H:i:s') ?></p>
    <p style="margin-top: 10px;"><strong>CONFIDENTIAL</strong> - This document contains sensitive audit information and should be handled in accordance with applicable security policies.</p>
</div>

</body>
</html>
