<?php
/**
 * DigiCustody – Sidebar Navigation
 * Save to: /var/www/html/digicustody/includes/sidebar.php
 */
$current_page = basename($_SERVER['PHP_SELF'], '.php');
$role         = $_SESSION['role'] ?? 'analyst';
$in_pages     = strpos($_SERVER['PHP_SELF'], '/pages/') !== false;
$base         = $in_pages ? '../' : '';

$nav_items = [
    'dashboard' => ['icon'=>'fa-gauge-high',  'label'=>'Dashboard',        'roles'=>['admin','investigator','analyst'], 'href'=>$base.'dashboard.php'],
    'evidence'  => ['icon'=>'fa-database',     'label'=>'Evidence',         'roles'=>['admin','investigator','analyst'], 'href'=>$base.'pages/evidence.php'],
    'cases'     => ['icon'=>'fa-folder-open',  'label'=>'Cases',            'roles'=>['admin','investigator','analyst'],          'href'=>$base.'pages/cases.php'],
    'reports'   => ['icon'=>'fa-file-lines',   'label'=>'Analysis Reports', 'roles'=>['admin','investigator','analyst'],          'href'=>$base.'pages/reports.php'],
    'downloads' => ['icon'=>'fa-download',     'label'=>'Downloads',        'roles'=>['admin','investigator','analyst'],          'href'=>$base.'pages/downloads.php'],
    'audit'     => ['icon'=>'fa-scroll',       'label'=>'Audit Logs',       'roles'=>['admin'],                                  'href'=>$base.'pages/audit.php'],
    'users'     => ['icon'=>'fa-users',        'label'=>'Users',            'roles'=>['admin'],                                  'href'=>$base.'pages/users.php'],
    'requests'  => ['icon'=>'fa-user-clock',   'label'=>'Access Requests',  'roles'=>['admin'],                                  'href'=>$base.'pages/requests.php'],
    'settings'  => ['icon'=>'fa-gear',         'label'=>'Settings',         'roles'=>['admin'],                                  'href'=>$base.'pages/settings.php'],
];

$unread           = count_unread_notifications($pdo, $_SESSION['user_id']);
$pending_requests = 0;
if ($role === 'admin') {
    $stmt = $pdo->query("SELECT COUNT(*) FROM account_requests WHERE status='pending'");
    $pending_requests = (int)$stmt->fetchColumn();
}
?>
<aside class="sidebar" id="sidebar">
    <div class="sb-top">
        <div class="sb-logo">
            <div class="sb-logo-icon"><i class="fas fa-shield-halved"></i></div>
            <div class="sb-logo-text">
                <span class="sb-name">Digi<span>Custody</span></span>
                <span class="sb-tag">Evidence Platform</span>
            </div>
        </div>
        <button class="sb-collapse" onclick="toggleSidebar()" title="Collapse sidebar">
            <i class="fas fa-chevron-left" id="toggleIcon"></i>
        </button>
    </div>

    <div class="sb-user">
        <div class="sb-avatar"><?= strtoupper(substr($_SESSION['full_name'], 0, 2)) ?></div>
        <div class="sb-user-info">
            <span class="sb-uname"><?= e($_SESSION['full_name']) ?></span>
            <span class="sb-role role-<?= $role ?>"><?= ucfirst($role) ?></span>
        </div>
    </div>

    <nav class="sb-nav">
        <?php foreach ($nav_items as $page => $item): ?>
            <?php if (!in_array($role, $item['roles'])) continue; ?>
            <a href="<?= $item['href'] ?>" class="sb-link <?= $current_page === $page ? 'active' : '' ?>">
                <i class="fas <?= $item['icon'] ?>"></i>
                <span class="sb-link-label"><?= $item['label'] ?></span>
                <?php if ($page === 'requests' && $pending_requests > 0): ?>
                    <span class="sb-badge"><?= $pending_requests ?></span>
                <?php endif; ?>
            </a>
        <?php endforeach; ?>
    </nav>

    <div class="sb-bottom">
        <a href="<?= $base ?>pages/profile.php" class="sb-link <?= $current_page === 'profile' ? 'active' : '' ?>">
            <i class="fas fa-circle-user"></i>
            <span class="sb-link-label">My Profile</span>
        </a>
        <a href="<?= $base ?>logout.php" class="sb-link sb-logout">
            <i class="fas fa-right-from-bracket"></i>
            <span class="sb-link-label">Sign Out</span>
        </a>
    </div>
</aside>