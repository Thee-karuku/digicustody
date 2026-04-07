<?php
/**
 * DigiCustody – Admin Access Requests
 * Save to: /var/www/html/digicustody/pages/requests.php
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login();
require_role('admin');

$page_title = 'Access Requests';
$uid = $_SESSION['user_id'];
$msg = ''; $err = '';

// ── Handle approve/reject ─────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $err = 'Security token mismatch.';
    } else {
        $req_id = (int)$_POST['req_id'];
        $action = $_POST['req_action'] ?? '';
        $notes  = trim($_POST['admin_notes'] ?? '');

        if (in_array($action, ['approved','rejected'])) {
            $stmt = $pdo->prepare("SELECT * FROM account_requests WHERE id=? AND status='pending'");
            $stmt->execute([$req_id]);
            $req = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($req) {
                $pdo->prepare("UPDATE account_requests SET status=?,admin_notes=?,reviewed_by=?,reviewed_at=NOW() WHERE id=?")
                    ->execute([$action,$notes,$uid,$req_id]);

                if ($action === 'approved') {
                    // Auto-create user account
                    $base     = strtolower(preg_replace('/[^a-zA-Z0-9]/','.', explode(' ',$req['full_name'])[0]));
                    $username = $base . rand(100,999);
                    $temp_pw  = 'DC@' . rand(10000,99999);
                    $hashed   = password_hash($temp_pw, PASSWORD_BCRYPT, ['cost'=>12]);

                    $pdo->prepare("INSERT INTO users (full_name,email,username,password,role,status,phone,department,badge_number,created_by)
                        VALUES(?,?,?,?,?,?,?,?,?,?)")
                        ->execute([$req['full_name'],$req['email'],$username,$hashed,
                                   $req['requested_role'],'active',$req['phone'],
                                   $req['department'],$req['badge_number'],$uid]);
                    $new_uid = $pdo->lastInsertId();

                    send_notification($pdo,$new_uid,'Account Approved & Created',
                        "Your request was approved. Username: $username | Temp Password: $temp_pw",'success');
                    audit_log($pdo,$uid,$_SESSION['username'],'admin','account_request_approved',
                        'account_request',$req_id,$req['full_name'],
                        "Request approved. Account created: $username ({$req['requested_role']})");

                    $msg = "Request approved. Account created — Username: <code style='background:var(--surface2);padding:2px 8px;border-radius:4px;color:var(--gold)'>$username</code> &nbsp; Temp PW: <code style='background:var(--surface2);padding:2px 8px;border-radius:4px;color:var(--gold)'>$temp_pw</code>";
                } else {
                    audit_log($pdo,$uid,$_SESSION['username'],'admin','account_request_rejected',
                        'account_request',$req_id,$req['full_name'],'Request rejected by admin');
                    $msg = "Request from <strong>{$req['full_name']}</strong> rejected.";
                }
            }
        }
    }
}

// ── Fetch requests ────────────────────────────────────────
$filter_status = $_GET['status'] ?? 'pending';
$search        = trim($_GET['search'] ?? '');

$where  = ['1=1'];
$params = [];
if ($filter_status !== '') { $where[] = "status=?"; $params[] = $filter_status; }
if ($search !== '') {
    $where[] = "(full_name LIKE ? OR email LIKE ? OR department LIKE ?)";
    $s = "%$search%";
    $params = array_merge($params, [$s,$s,$s]);
}

$where_sql = implode(' AND ', $where);
$requests  = $pdo->prepare("SELECT * FROM account_requests WHERE $where_sql ORDER BY created_at DESC");
$requests->execute($params);
$requests = $requests->fetchAll(PDO::FETCH_ASSOC);

// Stats
$pending_count  = (int)$pdo->query("SELECT COUNT(*) FROM account_requests WHERE status='pending'")->fetchColumn();
$approved_count = (int)$pdo->query("SELECT COUNT(*) FROM account_requests WHERE status='approved'")->fetchColumn();
$rejected_count = (int)$pdo->query("SELECT COUNT(*) FROM account_requests WHERE status='rejected'")->fetchColumn();

$csrf = csrf_token();

$role_colors = ['investigator'=>'blue','analyst'=>'green','viewer'=>'gray'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Access Requests — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.req-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-lg);padding:20px;margin-bottom:14px;transition:border-color .2s;}
.req-card:hover{border-color:var(--border2);}
.req-card.pending{border-left:3px solid var(--warning);}
.req-card.approved{border-left:3px solid var(--success);opacity:.75;}
.req-card.rejected{border-left:3px solid var(--danger);opacity:.65;}
.req-top{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:14px;flex-wrap:wrap;}
.req-avatar{width:44px;height:44px;border-radius:50%;background:var(--gold-dim);border:1px solid rgba(201,168,76,0.2);display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:600;color:var(--gold);flex-shrink:0;}
.req-name{font-size:15px;font-weight:600;color:var(--text);}
.req-meta{font-size:12.5px;color:var(--muted);margin-top:3px;display:flex;flex-wrap:wrap;gap:8px;}
.req-meta span{display:flex;align-items:center;gap:4px;}
.req-reason{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:10px 14px;font-size:13px;color:var(--muted);font-style:italic;line-height:1.6;margin-bottom:14px;}
.req-reason::before{content:'"';color:var(--gold);font-size:18px;line-height:0;vertical-align:-4px;margin-right:3px;}
.req-reason::after{content:'"';color:var(--gold);font-size:18px;line-height:0;vertical-align:-4px;margin-left:3px;}
.req-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
.notes-input{flex:1;min-width:160px;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:8px 12px;font-size:12.5px;color:var(--text);outline:none;font-family:'Inter',sans-serif;}
.notes-input:focus{border-color:rgba(201,168,76,0.4);}
.tab-bar{display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:20px;}
.tab-link{padding:10px 20px;font-size:13.5px;color:var(--muted);border-bottom:2px solid transparent;text-decoration:none;transition:all .2s;display:flex;align-items:center;gap:7px;margin-bottom:-1px;}
.tab-link:hover{color:var(--text);}
.tab-link.active{color:var(--gold);border-bottom-color:var(--gold);}
.stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:20px;}
.sr-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:16px;text-align:center;cursor:pointer;text-decoration:none;transition:border-color .2s;}
.sr-card:hover{border-color:var(--border2);}
.sr-val{font-family:'Space Grotesk',sans-serif;font-size:28px;font-weight:700;}
.sr-lbl{font-size:12px;color:var(--muted);margin-top:4px;}
.admin-note{background:rgba(74,222,128,0.05);border:1px solid rgba(74,222,128,0.15);border-radius:7px;padding:8px 12px;font-size:12px;color:var(--muted);margin-top:8px;}
.filter-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:12px 18px;margin-bottom:20px;}
.filter-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.filter-row input{flex:1;min-width:200px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:8px 12px;font-size:13px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.filter-row input:focus{border-color:rgba(201,168,76,0.5);}
</style>
</head>
<body>
<div class="app-shell">
<?php include __DIR__.'/../includes/sidebar.php'; ?>
<div class="main-area" id="mainArea">
<?php include __DIR__.'/../includes/navbar.php'; ?>
<div class="page-content">

<!-- Header -->
<div class="page-header">
    <div>
        <button type="button" class="btn-back" onclick="goBack()"><i class="fas fa-arrow-left"></i> Back</button>
        <h1 style="margin-top:8px;">Access Requests</h1>
        <p>Review and approve or reject account access requests</p>
    </div>
</div>

<?php if ($msg): ?><div class="alert alert-success"><i class="fas fa-circle-check"></i> <?= $msg ?></div><?php endif; ?>
<?php if ($err): ?><div class="alert alert-danger"><i class="fas fa-circle-exclamation"></i> <?= e($err) ?></div><?php endif; ?>

<!-- Stats -->
<div class="stats-row">
    <a href="requests.php?status=pending" class="sr-card" style="<?= $filter_status==='pending'?'border-color:rgba(251,191,36,0.4)':'' ?>">
        <p class="sr-val" style="color:var(--warning)"><?= $pending_count ?></p>
        <p class="sr-lbl"><i class="fas fa-clock"></i> Pending</p>
    </a>
    <a href="requests.php?status=approved" class="sr-card" style="<?= $filter_status==='approved'?'border-color:rgba(74,222,128,0.4)':'' ?>">
        <p class="sr-val" style="color:var(--success)"><?= $approved_count ?></p>
        <p class="sr-lbl"><i class="fas fa-circle-check"></i> Approved</p>
    </a>
    <a href="requests.php?status=rejected" class="sr-card" style="<?= $filter_status==='rejected'?'border-color:rgba(248,113,113,0.4)':'' ?>">
        <p class="sr-val" style="color:var(--danger)"><?= $rejected_count ?></p>
        <p class="sr-lbl"><i class="fas fa-circle-xmark"></i> Rejected</p>
    </a>
</div>

<!-- Tab bar -->
<div class="tab-bar">
    <a href="requests.php?status=pending"  class="tab-link <?= $filter_status==='pending'?'active':'' ?>">
        <i class="fas fa-clock"></i> Pending
        <?php if ($pending_count>0): ?><span class="badge badge-orange"><?= $pending_count ?></span><?php endif; ?>
    </a>
    <a href="requests.php?status=approved" class="tab-link <?= $filter_status==='approved'?'active':'' ?>">
        <i class="fas fa-circle-check"></i> Approved
    </a>
    <a href="requests.php?status=rejected" class="tab-link <?= $filter_status==='rejected'?'active':'' ?>">
        <i class="fas fa-circle-xmark"></i> Rejected
    </a>
    <a href="requests.php?status=" class="tab-link <?= $filter_status===''?'active':'' ?>">
        <i class="fas fa-list"></i> All
    </a>
</div>

<!-- Search -->
<div class="filter-wrap">
    <form method="GET">
        <input type="hidden" name="status" value="<?= e($filter_status) ?>">
        <div class="filter-row">
            <input type="text" name="search" placeholder="Search by name, email, department..."
                value="<?= e($search) ?>" id="searchInput">
            <button type="submit" class="btn btn-gold btn-sm"><i class="fas fa-search"></i> Search</button>
            <?php if ($search): ?><a href="requests.php?status=<?= e($filter_status) ?>" class="btn btn-outline btn-sm"><i class="fas fa-xmark"></i> Clear</a><?php endif; ?>
        </div>
    </form>
</div>

<!-- Requests list -->
<?php if (empty($requests)): ?>
<div class="section-card">
    <div class="empty-state">
        <i class="fas fa-user-clock"></i>
        <p>No <?= $filter_status !== '' ? $filter_status : '' ?> access requests found.</p>
    </div>
</div>
<?php else: ?>
<div id="requestsList">
<?php foreach ($requests as $req): ?>
<div class="req-card <?= $req['status'] ?>">
    <div class="req-top">
        <div style="display:flex;align-items:flex-start;gap:12px;flex:1;">
            <div class="req-avatar"><?= strtoupper(substr($req['full_name'],0,2)) ?></div>
            <div style="flex:1;min-width:0;">
                <p class="req-name"><?= e($req['full_name']) ?></p>
                <div class="req-meta">
                    <span><i class="fas fa-envelope"></i> <?= e($req['email']) ?></span>
                    <?php if ($req['phone']): ?>
                    <span><i class="fas fa-phone"></i> <?= e($req['phone']) ?></span>
                    <?php endif; ?>
                    <?php if ($req['department']): ?>
                    <span><i class="fas fa-building"></i> <?= e($req['department']) ?></span>
                    <?php endif; ?>
                    <?php if ($req['badge_number']): ?>
                    <span><i class="fas fa-id-badge"></i> <?= e($req['badge_number']) ?></span>
                    <?php endif; ?>
                    <span><i class="fas fa-clock"></i> <?= time_ago($req['created_at']) ?></span>
                </div>
            </div>
        </div>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;flex-shrink:0;">
            <span class="badge badge-<?= $role_colors[$req['requested_role']]??'gray' ?>">
                <i class="fas fa-user-tag" style="font-size:9px"></i>
                <?= ucfirst($req['requested_role']) ?> requested
            </span>
            <?= status_badge($req['status']) ?>
        </div>
    </div>

    <?php if ($req['reason']): ?>
    <div class="req-reason"><?= e($req['reason']) ?></div>
    <?php endif; ?>

    <?php if ($req['status'] === 'pending'): ?>
    <!-- Approve/Reject form -->
    <form method="POST" action="requests.php">
        <input type="hidden" name="req_id"     value="<?= $req['id'] ?>">
        <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
        <div class="req-actions">
            <input type="text" name="admin_notes" class="notes-input" placeholder="Optional notes for this decision...">
            <button type="submit" name="req_action" value="approved"
                class="btn btn-success"
                onclick="return confirm('Approve this request and create user account?')">
                <i class="fas fa-check"></i> Approve &amp; Create Account
            </button>
            <button type="submit" name="req_action" value="rejected"
                class="btn btn-danger"
                onclick="return confirm('Reject this request?')">
                <i class="fas fa-xmark"></i> Reject
            </button>
        </div>
    </form>

    <?php elseif ($req['admin_notes']): ?>
    <div class="admin-note">
        <i class="fas fa-comment-dots" style="color:var(--success);margin-right:5px"></i>
        Admin note: <?= e($req['admin_notes']) ?>
        <?php if ($req['reviewed_at']): ?>
        &nbsp;·&nbsp; <?= date('M j, Y H:i', strtotime($req['reviewed_at'])) ?>
        <?php endif; ?>
    </div>
    <?php endif; ?>
</div>
<?php endforeach; ?>
</div>
<?php endif; ?>

</div></div></div>

<script>
function toggleSidebar(){const sb=document.getElementById('sidebar'),ma=document.getElementById('mainArea');if(window.innerWidth<=900){sb.classList.toggle('mobile-open');}else{sb.classList.toggle('collapsed');ma.classList.toggle('collapsed');}localStorage.setItem('sb_collapsed',sb.classList.contains('collapsed')?'1':'0');}
if(localStorage.getItem('sb_collapsed')==='1'&&window.innerWidth>900){document.getElementById('sidebar').classList.add('collapsed');document.getElementById('mainArea').classList.add('collapsed');}
function toggleNotif(){document.getElementById('notifDropdown').classList.toggle('open');document.getElementById('userDropdown').classList.remove('open');}
function toggleUserMenu(){document.getElementById('userDropdown').classList.toggle('open');document.getElementById('notifDropdown').classList.remove('open');}
document.addEventListener('click',function(e){if(!e.target.closest('#notifWrap'))document.getElementById('notifDropdown').classList.remove('open');if(!e.target.closest('#userMenuWrap'))document.getElementById('userDropdown').classList.remove('open');});
function handleSearch(e){if(e.key==='Enter'){window.location='users.php?search='+encodeURIComponent(document.getElementById('globalSearch').value);}}
var st;var si=document.getElementById('searchInput');
if(si) si.addEventListener('input',function(){clearTimeout(st);st=setTimeout(function(){si.closest('form').submit();},500);});
</script>
<script src="../assets/js/main.js"></script>
</body>
</html>
