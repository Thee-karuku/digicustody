<?php
// includes/navbar.php
$unread = count_unread_notifications($pdo, $_SESSION['user_id']);
$in_pages = strpos($_SERVER['PHP_SELF'], '/pages/') !== false;
$base     = $in_pages ? '../' : '';
?>
<header class="topbar">
    <div class="topbar-left">
        <button class="menu-btn" id="menuBtn" onclick="toggleSidebar()">
            <i class="fas fa-bars"></i>
        </button>
        <div class="topbar-title">
            <span id="pageTitle"><?= $page_title ?? 'Dashboard' ?></span>
        </div>
    </div>
    <div class="topbar-right">
        <!-- Search -->
        <div class="topbar-search" onclick="document.getElementById('globalSearch').focus()">
            <i class="fas fa-search"></i>
            <input type="text" placeholder="Search evidence, cases..." id="globalSearch"
                onkeyup="if(event.key==='Enter'&&this.value.trim())window.location='<?= $base ?>pages/search.php?q='+encodeURIComponent(this.value.trim())"
                autocomplete="off">
        </div>

        <!-- Notifications -->
        <div class="notif-wrap" id="notifWrap">
            <button class="icon-btn" onclick="toggleNotif()" id="notifBtn" title="Notifications">
                <i class="fas fa-bell"></i>
                <?php if ($unread > 0): ?>
                <span class="notif-dot"><?= $unread > 9 ? '9+' : $unread ?></span>
                <?php endif; ?>
            </button>
            <div class="notif-dropdown" id="notifDropdown">
                <div class="notif-head">
                    <span>Notifications</span>
                    <?php if ($unread > 0): ?>
                    <a href="?mark_read=1" class="notif-clear">Mark all read</a>
                    <?php endif; ?>
                </div>
                <div class="notif-list" id="notifList">
                    <?php
                    $notifs = get_unread_notifications($pdo, $_SESSION['user_id'], 6);
                    if (empty($notifs)): ?>
                        <div class="notif-empty"><i class="fas fa-bell-slash"></i> No new notifications</div>
                    <?php else:
                        foreach ($notifs as $n): ?>
                        <div class="notif-item notif-<?= e($n['type']) ?>">
                            <div class="notif-icon">
                                <?php $icons = ['info'=>'fa-circle-info','success'=>'fa-circle-check','warning'=>'fa-triangle-exclamation','danger'=>'fa-circle-exclamation'];
                                echo '<i class="fas '.($icons[$n['type']]??'fa-bell').'"></i>'; ?>
                            </div>
                            <div class="notif-body">
                                <p class="notif-title"><?= e($n['title']) ?></p>
                                <p class="notif-msg"><?= e($n['message']) ?></p>
                                <p class="notif-time"><?= time_ago($n['created_at']) ?></p>
                            </div>
                        </div>
                    <?php endforeach; endif; ?>
                </div>
                <div style="padding:10px 16px;border-top:1px solid var(--border);text-align:center;">
                    <a href="<?= $base ?>pages/notifications.php" style="font-size:12.5px;color:var(--gold);">View all notifications</a>
                </div>
            </div>
        </div>

        <!-- User menu -->
        <div class="user-menu-wrap" id="userMenuWrap">
            <button class="user-menu-btn" onclick="toggleUserMenu()">
                <div class="um-avatar"><?= strtoupper(substr($_SESSION['full_name'], 0, 2)) ?></div>
                <div class="um-info">
                    <span class="um-name"><?= e(explode(' ', $_SESSION['full_name'])[0]) ?></span>
                    <span class="um-role"><?= ucfirst($_SESSION['role']) ?></span>
                </div>
                <i class="fas fa-chevron-down um-caret"></i>
            </button>
            <div class="user-dropdown" id="userDropdown">
                <a href="<?= $base ?>pages/profile.php"><i class="fas fa-circle-user"></i> My Profile</a>
                <?php if ($_SESSION['role'] === 'admin'): ?>
                <a href="<?= $base ?>pages/settings.php"><i class="fas fa-gear"></i> Settings</a>
                <?php endif; ?>
                <div class="ud-sep"></div>
                <a href="<?= $base ?>logout.php" class="ud-logout"><i class="fas fa-right-from-bracket"></i> Sign Out</a>
            </div>
        </div>
    </div>
</header>

<?php
// Handle mark all read
if (isset($_GET['mark_read'])) {
    $pdo->prepare("UPDATE notifications SET is_read=1 WHERE user_id=?")->execute([$_SESSION['user_id']]);
    header('Location: '.$_SERVER['PHP_SELF']);
    exit;
}
?>