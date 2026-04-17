<?php
/**
 * DigiCustody – Notifications Page
 * Save to: /var/www/html/digicustody/pages/notifications.php
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login($pdo);

$page_title = 'Notifications';
$uid = $_SESSION['user_id'];

// Handle accept/reject collab invite
if (isset($_GET['accept_invite'])) {
    $invite_id = (int)$_GET['accept_invite'];
    $result = accept_collab_invite($pdo, $invite_id, $uid);
    if ($result['success']) {
        header('Location: case_view.php?id=' . $result['case_id'] . '&msg=collab_accepted');
    } else {
        header('Location: notifications.php?error=accept_failed');
    }
    exit;
}
if (isset($_GET['reject_invite'])) {
    $invite_id = (int)$_GET['reject_invite'];
    reject_collab_invite($pdo, $invite_id, $uid);
    header('Location: notifications.php?msg=invite_rejected');
    exit;
}

// Mark all read
if (isset($_GET['mark_all'])) {
    $pdo->prepare("UPDATE notifications SET is_read=1 WHERE user_id=?")->execute([$uid]);
    header('Location: notifications.php'); exit;
}
// Mark single read
if (isset($_GET['mark'])) {
    $pdo->prepare("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?")->execute([(int)$_GET['mark'],$uid]);
    header('Location: notifications.php'); exit;
}

$filter = $_GET['filter'] ?? 'all';
$where = ['user_id=?'];
$params = [$uid];
if ($filter === 'unread') { $where[] = 'is_read=0'; }
elseif ($filter === 'read') { $where[] = 'is_read=1'; }

$notifs = $pdo->prepare("SELECT * FROM notifications WHERE ".implode(' AND ',$where)." ORDER BY created_at DESC LIMIT 100");
$notifs->execute($params);
$notifs = $notifs->fetchAll(PDO::FETCH_ASSOC);
$unread_count = count_unread_notifications($pdo, $uid);

$type_icons = ['info'=>'fa-circle-info','success'=>'fa-circle-check','warning'=>'fa-triangle-exclamation','danger'=>'fa-circle-exclamation'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Notifications — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.notif-card{display:flex;align-items:flex-start;gap:14px;padding:16px 20px;border-bottom:1px solid var(--border);transition:background .15s;}
.notif-card:last-child{border-bottom:none;}
.notif-card.unread{background:rgba(201,168,76,0.03);border-left:3px solid rgba(201,168,76,0.3);}
.notif-card:hover{background:var(--surface2);}
.ni-dot{width:36px;height:36px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:14px;}
.ni-info{background:rgba(96,165,250,0.12);color:var(--info);}
.ni-success{background:rgba(74,222,128,0.12);color:var(--success);}
.ni-warning{background:rgba(251,191,36,0.12);color:var(--warning);}
.ni-danger{background:rgba(248,113,113,0.12);color:var(--danger);}
.tab-bar{display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:20px;}
.tab-link{padding:10px 20px;font-size:13.5px;color:var(--muted);border-bottom:2px solid transparent;text-decoration:none;transition:all .2s;margin-bottom:-1px;display:flex;align-items:center;gap:7px;}
.tab-link:hover{color:var(--text);}
.tab-link.active{color:var(--gold);border-bottom-color:var(--gold);}
</style>
</head>
<body>
<div class="app-shell">
<?php include __DIR__.'/../includes/sidebar.php'; ?>
<div class="main-area" id="mainArea">
<?php include __DIR__.'/../includes/navbar.php'; ?>
<div class="page-content">

<div class="page-header">
    <div>
        <button type="button" class="btn-back" onclick="goBack()"><i class="fas fa-arrow-left"></i> Back</button>
        <h1 style="margin-top:8px;">Notifications</h1>
        <p><?= $unread_count ?> unread notification<?= $unread_count!=1?'s':'' ?></p>
    </div>
    <?php if ($unread_count > 0): ?>
    <a href="notifications.php?mark_all=1" class="btn btn-outline">
        <i class="fas fa-check-double"></i> Mark All Read
    </a>
    <?php endif; ?>
</div>

<!-- Tabs -->
<div class="tab-bar">
    <a href="notifications.php?filter=all"    class="tab-link <?= $filter==='all'?'active':'' ?>"><i class="fas fa-list"></i> All (<?= count($notifs) ?>)</a>
    <a href="notifications.php?filter=unread" class="tab-link <?= $filter==='unread'?'active':'' ?>"><i class="fas fa-bell"></i> Unread <?php if($unread_count>0): ?><span class="badge badge-gold"><?= $unread_count ?></span><?php endif; ?></a>
    <a href="notifications.php?filter=read"   class="tab-link <?= $filter==='read'?'active':'' ?>"><i class="fas fa-check"></i> Read</a>
</div>

<div class="section-card">
    <?php if (empty($notifs)): ?>
    <div class="empty-state" style="padding:48px">
        <i class="fas fa-bell-slash"></i>
        <p>No <?= $filter !== 'all' ? $filter.' ' : '' ?>notifications found.</p>
    </div>
    <?php else: foreach ($notifs as $n):
        $ico = $type_icons[$n['type']] ?? 'fa-bell';
    ?>
    <div class="notif-card <?= !$n['is_read']?'unread':'' ?>">
        <div class="ni-dot ni-<?= e($n['type']) ?>"><i class="fas <?= $ico ?>"></i></div>
        <div style="flex:1;min-width:0;">
            <p style="font-size:14px;font-weight:<?= !$n['is_read']?'600':'400' ?>;color:var(--text);margin-bottom:3px;"><?= e($n['title']) ?></p>
            <p style="font-size:13px;color:var(--muted);margin-bottom:4px;"><?= e($n['message']) ?></p>
            <p style="font-size:11.5px;color:var(--dim);"><?= time_ago($n['created_at']) ?> &nbsp;·&nbsp; <?= date('M j, Y H:i',strtotime($n['created_at'])) ?></p>
        </div>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;flex-shrink:0;">
            <?php if ($n['related_type'] === 'collab_invite' && $n['related_id']):
                $invite_stmt = $pdo->prepare("SELECT id, status FROM case_collab_invites WHERE case_id = ? AND invited_user_id = ? AND status = 'pending' LIMIT 1");
                $invite_stmt->execute([$n['related_id'], $uid]);
                $invite = $invite_stmt->fetch();
                if ($invite):
            ?>
            <a href="notifications.php?accept_invite=<?= $invite['id'] ?>" class="btn btn-sm" style="font-size:11px;background:var(--success);color:#000;padding:6px 12px;">
                <i class="fas fa-check"></i> Accept
            </a>
            <a href="notifications.php?reject_invite=<?= $invite['id'] ?>" class="btn btn-outline btn-sm" style="font-size:11px;color:var(--danger);border-color:var(--danger);">
                <i class="fas fa-xmark"></i> Reject
            </a>
            <?php else: ?>
            <span style="font-size:11px;color:var(--muted);">Responded</span>
            <?php endif; ?>
            <?php else: ?>
            <?php if (!$n['is_read']): ?>
            <span style="width:8px;height:8px;border-radius:50%;background:var(--gold);display:block;"></span>
            <a href="notifications.php?mark=<?= $n['id'] ?>" class="btn btn-outline btn-sm" style="font-size:11px;">Mark read</a>
            <?php endif; ?>
            <?php if ($n['related_type'] && $n['related_id']):
                $links=['evidence'=>'evidence_view.php?id=','case'=>'case_view.php?id=','report'=>'reports.php','account_request'=>'requests.php'];
                $link = ($links[$n['related_type']] ?? null);
                if ($link): ?>
            <a href="<?= $link ?><?= in_array($n['related_type'],['evidence','case'])?$n['related_id']:'' ?>" class="btn btn-outline btn-sm" style="font-size:11px;">
                <i class="fas fa-arrow-right"></i> View
            </a>
            <?php endif; endif; ?>
            <?php endif; ?>
        </div>
    </div>
    <?php endforeach; endif; ?>
</div>

</div></div></div>
<script>
function toggleSidebar(){const sb=document.getElementById('sidebar'),ma=document.getElementById('mainArea');if(window.innerWidth<=900){sb.classList.toggle('mobile-open');}else{sb.classList.toggle('collapsed');ma.classList.toggle('collapsed');}localStorage.setItem('sb_collapsed',sb.classList.contains('collapsed')?'1':'0');}
if(localStorage.getItem('sb_collapsed')==='1'&&window.innerWidth>900){document.getElementById('sidebar').classList.add('collapsed');document.getElementById('mainArea').classList.add('collapsed');}
function toggleNotif(){document.getElementById('notifDropdown').classList.toggle('open');document.getElementById('userDropdown').classList.remove('open');}
function toggleUserMenu(){document.getElementById('userDropdown').classList.toggle('open');document.getElementById('notifDropdown').classList.remove('open');}
document.addEventListener('click',function(e){if(!e.target.closest('#notifWrap'))document.getElementById('notifDropdown').classList.remove('open');if(!e.target.closest('#userMenuWrap'))document.getElementById('userDropdown').classList.remove('open');});
function handleSearch(e){if(e.key==='Enter'){window.location='search.php?q='+encodeURIComponent(document.getElementById('globalSearch').value);}}
</script>
<script src="../assets/js/main.js"></script>
</body>
</html>
