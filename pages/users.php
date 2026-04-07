<?php
/**
 * DigiCustody – Admin User Management
 * Save to: /var/www/html/digicustody/pages/users.php
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login();
require_role('admin');

$page_title = 'User Management';
$uid = $_SESSION['user_id'];
$msg = ''; $err = '';

// ── Handle Actions ────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $err = 'Security token mismatch. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';

        // ── Create User ──
        if ($action === 'create_user') {
            $full_name  = trim($_POST['full_name'] ?? '');
            $email      = trim($_POST['email'] ?? '');
            $username   = trim($_POST['username'] ?? '');
            $password   = $_POST['password'] ?? '';
            $role       = in_array($_POST['role']??'',['admin','investigator','analyst','viewer']) ? $_POST['role'] : 'viewer';
            $department = trim($_POST['department'] ?? '');
            $badge      = trim($_POST['badge_number'] ?? '');
            $phone      = trim($_POST['phone'] ?? '');

            if (empty($full_name)||empty($email)||empty($username)||empty($password)) {
                $err = 'Full name, email, username and password are required.';
            } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $err = 'Invalid email address.';
            } elseif (strlen($password) < 8) {
                $err = 'Password must be at least 8 characters.';
            } else {
                // Check duplicates
                $chk = $pdo->prepare("SELECT id FROM users WHERE username=? OR email=?");
                $chk->execute([$username, $email]);
                if ($chk->fetch()) {
                    $err = 'Username or email already exists.';
                } else {
                    $hashed = password_hash($password, PASSWORD_BCRYPT, ['cost'=>12]);
                    $pdo->prepare("INSERT INTO users (full_name,email,username,password,role,status,department,badge_number,phone,created_by)
                        VALUES(?,?,?,?,?,'active',?,?,?,?)")
                        ->execute([$full_name,$email,$username,$hashed,$role,$department,$badge,$phone,$uid]);
                    $new_id = $pdo->lastInsertId();
                    send_notification($pdo,$new_id,'Welcome to DigiCustody',
                        "Your account has been created. Username: $username",'success');
                    audit_log($pdo,$uid,$_SESSION['username'],'admin','account_created',
                        'user',$new_id,$full_name,"Admin created account: $username ($role)");
                    $msg = "User account for <strong>$full_name</strong> created successfully.";
                }
            }
        }

        // ── Edit User ──
        elseif ($action === 'edit_user') {
            $target_id  = (int)$_POST['target_id'];
            $full_name  = trim($_POST['full_name'] ?? '');
            $email      = trim($_POST['email'] ?? '');
            $role       = in_array($_POST['role']??'',['admin','investigator','analyst','viewer']) ? $_POST['role'] : 'viewer';
            $department = trim($_POST['department'] ?? '');
            $badge      = trim($_POST['badge_number'] ?? '');
            $phone      = trim($_POST['phone'] ?? '');
            $status     = in_array($_POST['status']??'',['active','inactive','suspended']) ? $_POST['status'] : 'active';
            $new_pass   = $_POST['new_password'] ?? '';

            if (empty($full_name)||empty($email)) {
                $err = 'Full name and email are required.';
            } else {
                $pdo->prepare("UPDATE users SET full_name=?,email=?,role=?,department=?,badge_number=?,phone=?,status=?,updated_at=NOW() WHERE id=?")
                    ->execute([$full_name,$email,$role,$department,$badge,$phone,$status,$target_id]);
                if ($new_pass !== '') {
                    if (strlen($new_pass) < 8) {
                        $err = 'New password must be at least 8 characters.';
                    } else {
                        $hashed = password_hash($new_pass, PASSWORD_BCRYPT, ['cost'=>12]);
                        $pdo->prepare("UPDATE users SET password=? WHERE id=?")->execute([$hashed,$target_id]);
                    }
                }
                audit_log($pdo,$uid,$_SESSION['username'],'admin','account_updated',
                    'user',$target_id,$full_name,"Admin updated account ID $target_id");
                $msg = "User account updated successfully.";
            }
        }

        // ── Toggle Status ──
        elseif ($action === 'toggle_status') {
            $target_id = (int)$_POST['target_id'];
            if ($target_id === $uid) { $err = 'You cannot suspend your own account.'; }
            else {
                $chk = $pdo->prepare("SELECT status,full_name FROM users WHERE id=?");
                $chk->execute([$target_id]);
                $target = $chk->fetch();
                if ($target) {
                    $new_status = $target['status']==='active' ? 'suspended' : 'active';
                    $pdo->prepare("UPDATE users SET status=? WHERE id=?")->execute([$new_status,$target_id]);
                    audit_log($pdo,$uid,$_SESSION['username'],'admin',
                        $new_status==='suspended'?'account_suspended':'account_updated',
                        'user',$target_id,$target['full_name'],
                        "Account ".($new_status==='suspended'?'suspended':'reactivated').": {$target['full_name']}");
                    $msg = "Account <strong>{$target['full_name']}</strong> ".($new_status==='suspended'?'suspended':'reactivated').".";
                }
            }
        }

        // ── Reset Password ──
        elseif ($action === 'reset_password') {
            $target_id = (int)$_POST['target_id'];
            $temp_pass = 'DC@' . rand(10000,99999);
            $hashed    = password_hash($temp_pass, PASSWORD_BCRYPT, ['cost'=>12]);
            $pdo->prepare("UPDATE users SET password=? WHERE id=?")->execute([$hashed,$target_id]);
            $chk = $pdo->prepare("SELECT full_name,email FROM users WHERE id=?");
            $chk->execute([$target_id]);
            $target = $chk->fetch();
            send_notification($pdo,$target_id,'Password Reset',
                "Your password has been reset. Temporary password: $temp_pass",'warning');
            audit_log($pdo,$uid,$_SESSION['username'],'admin','account_updated',
                'user',$target_id,$target['full_name']??'','Password reset by admin');
            $msg = "Password reset. Temporary password: <code style='background:var(--surface2);padding:2px 8px;border-radius:4px;color:var(--gold)'>$temp_pass</code>";
        }

        // ── Delete User ──
        elseif ($action === 'delete_user') {
            $target_id = (int)$_POST['target_id'];
            if ($target_id === $uid) { $err = 'You cannot delete your own account.'; }
            else {
                $stmt = $pdo->prepare("SELECT full_name,username,email FROM users WHERE id=?");
                $stmt->execute([$target_id]);
                $target = $stmt->fetch();
                if ($target) {
                    $s2 = $pdo->prepare("SELECT COUNT(*) FROM evidence WHERE uploaded_by=?");
                    $s2->execute([$target_id]);
                    $ev_count = (int)$s2->fetchColumn();

                    $s3 = $pdo->prepare("SELECT COUNT(*) FROM cases WHERE created_by=?");
                    $s3->execute([$target_id]);
                    $case_count = (int)$s3->fetchColumn();

                    $pdo->prepare("DELETE FROM case_access WHERE user_id=?")->execute([$target_id]);
                    $pdo->prepare("DELETE FROM notifications WHERE user_id=?")->execute([$target_id]);
                    $pdo->prepare("DELETE FROM password_resets WHERE email=?")->execute([$target['email']]);
                    $pdo->prepare("DELETE FROM login_attempts WHERE username=?")->execute([$target['username']]);
                    $pdo->prepare("UPDATE evidence SET current_custodian=NULL WHERE current_custodian=?")->execute([$target_id]);
                    $pdo->prepare("UPDATE cases SET assigned_to=NULL WHERE assigned_to=?")->execute([$target_id]);
                    $pdo->prepare("DELETE FROM users WHERE id=?")->execute([$target_id]);
                    audit_log($pdo,$uid,$_SESSION['username'],'admin','account_deleted',
                        'user',$target_id,$target['full_name'],
                        "Account deleted: {$target['full_name']} ({$ev_count} evidence, {$case_count} cases)");
                    $msg = "User <strong>{$target['full_name']}</strong> and all associated data deleted successfully.";
                }
            }
        }

        if ($err === '') header('Location: users.php?msg='.urlencode(strip_tags($msg)));
    }
}
if (isset($_GET['msg']) && $msg === '') $msg = htmlspecialchars_decode(urldecode($_GET['msg']));

// ── Fetch Users ───────────────────────────────────────────
$search      = trim($_GET['search'] ?? '');
$filter_role = $_GET['role'] ?? '';
$filter_status = $_GET['status'] ?? '';
$sort        = in_array($_GET['sort']??'',['full_name','username','role','status','created_at','last_login']) ? $_GET['sort'] : 'created_at';
$dir         = strtoupper($_GET['dir']??'DESC')==='ASC' ? 'ASC' : 'DESC';

$where  = ['1=1'];
$params = [];
if ($search !== '') {
    $where[]  = "(full_name LIKE ? OR username LIKE ? OR email LIKE ? OR department LIKE ?)";
    $s = "%$search%";
    $params = array_merge($params, [$s,$s,$s,$s]);
}
if ($filter_role   !== '') { $where[] = "role=?";   $params[] = $filter_role; }
if ($filter_status !== '') { $where[] = "status=?"; $params[] = $filter_status; }

$where_sql = implode(' AND ', $where);
$users = $pdo->prepare("SELECT * FROM users WHERE $where_sql ORDER BY $sort $dir");
$users->execute($params);
$users = $users->fetchAll(PDO::FETCH_ASSOC);

// Stats
$total_users  = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
$active_users = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE status='active'")->fetchColumn();
$susp_users   = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE status='suspended'")->fetchColumn();
$role_counts  = $pdo->query("SELECT role,COUNT(*) as cnt FROM users GROUP BY role")->fetchAll(PDO::FETCH_ASSOC);
$rc = array_column($role_counts, 'cnt', 'role');

// Fetch single user for edit modal
$edit_user = null;
if (isset($_GET['edit'])) {
    $es = $pdo->prepare("SELECT * FROM users WHERE id=?");
    $es->execute([(int)$_GET['edit']]);
    $edit_user = $es->fetch(PDO::FETCH_ASSOC);
}

$csrf = csrf_token();

function su($col) {
    global $sort, $dir;
    $nd = ($sort===$col && $dir==='DESC') ? 'asc' : 'desc';
    return '?'.http_build_query(array_merge($_GET,['sort'=>$col,'dir'=>$nd]));
}
function si($col) {
    global $sort,$dir;
    if($sort!==$col) return '<i class="fas fa-sort" style="opacity:.3"></i>';
    return $dir==='DESC' ? '<i class="fas fa-sort-down" style="color:var(--gold)"></i>' : '<i class="fas fa-sort-up" style="color:var(--gold)"></i>';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>User Management — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.filter-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:14px 18px;margin-bottom:20px;}
.filter-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.filter-row input,.filter-row select{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:8px 12px;font-size:13px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.filter-row input{flex:1;min-width:200px;}
.filter-row input:focus,.filter-row select:focus{border-color:rgba(201,168,76,0.5);}
.filter-row select option{background:var(--surface2);}
.user-avatar{width:36px;height:36px;border-radius:50%;background:var(--gold-dim);border:1px solid rgba(201,168,76,0.2);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;color:var(--gold);flex-shrink:0;}
.user-avatar.suspended{background:rgba(248,113,113,0.1);border-color:rgba(248,113,113,0.2);color:var(--danger);}
.stats-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-bottom:20px;}
.sr-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:14px 16px;text-align:center;}
.sr-val{font-family:'Space Grotesk',sans-serif;font-size:24px;font-weight:700;color:var(--text);}
.sr-lbl{font-size:11.5px;color:var(--muted);margin-top:3px;}
/* modal */
.overlay{position:fixed;inset:0;z-index:300;background:rgba(4,8,18,.9);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;padding:20px;animation:fi .2s ease;}
@keyframes fi{from{opacity:0}to{opacity:1}}
.modal{background:var(--surface);border:1px solid var(--border2);border-radius:var(--radius-lg);width:100%;max-width:540px;max-height:92vh;overflow-y:auto;animation:up .3s cubic-bezier(.22,.68,0,1.15);}
@keyframes up{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
.modal-head{padding:22px 26px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;}
.modal-head h3{font-family:'Space Grotesk',sans-serif;font-size:17px;font-weight:600;color:var(--text);}
.modal-head h3 span{color:var(--gold);}
.modal-body{padding:22px 26px;}
.modal-foot{padding:14px 26px 22px;display:flex;gap:10px;justify-content:flex-end;}
.xbtn{background:none;border:none;color:var(--muted);font-size:15px;cursor:pointer;padding:3px 5px;border-radius:5px;transition:all .2s;}
.xbtn:hover{color:var(--danger);}
.field{margin-bottom:14px;}
.field label{display:block;font-size:11px;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px;}
.field input,.field select{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:9px;padding:10px 13px;font-size:13.5px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.field input:focus,.field select:focus{border-color:rgba(201,168,76,0.5);box-shadow:0 0 0 3px rgba(201,168,76,0.06);}
.field select option{background:var(--surface2);}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
.pass-wrap{position:relative;}
.pass-wrap input{padding-right:38px;}
.pass-eye{position:absolute;right:11px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--dim);cursor:pointer;font-size:13px;transition:color .2s;}
.pass-eye:hover{color:var(--gold);}
.sort-th{cursor:pointer;display:flex;align-items:center;gap:5px;color:var(--muted);text-decoration:none;}
.sort-th:hover{color:var(--text);}
.dc-table th:nth-child(1){width:220px}
.dc-table th:nth-child(2){width:130px}
.dc-table th:nth-child(3){width:110px}
.dc-table th:nth-child(4){width:140px}
.dc-table th:nth-child(5){width:100px}
.dc-table th:nth-child(6){width:120px}
.dc-table th:nth-child(7){width:180px}
/* toast */
.toast-container{position:fixed;top:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:10px;pointer-events:none;}
.toast{pointer-events:auto;background:var(--surface);border:1px solid var(--border2);border-radius:var(--radius-lg);padding:16px 20px;min-width:320px;max-width:420px;box-shadow:0 20px 50px rgba(0,0,0,0.6);display:flex;align-items:flex-start;gap:12px;animation:toastIn .4s cubic-bezier(.22,.68,0,1.15) both;}
.toast.removing{animation:toastOut .3s ease both;}
@keyframes toastIn{from{opacity:0;transform:translateX(60px)}to{opacity:1;transform:translateX(0)}}
@keyframes toastOut{to{opacity:0;transform:translateX(60px)}}
.toast-icon{width:36px;height:36px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:15px;}
.toast.success .toast-icon{background:rgba(74,222,128,0.12);color:var(--success);}
.toast.error .toast-icon{background:rgba(248,113,113,0.12);color:var(--danger);}
.toast.warning .toast-icon{background:rgba(251,191,36,0.12);color:var(--warning);}
.toast.info .toast-icon{background:rgba(96,165,250,0.12);color:var(--info);}
.toast-body{flex:1;min-width:0;}
.toast-title{font-size:14px;font-weight:600;color:var(--text);margin-bottom:2px;}
.toast-msg{font-size:12.5px;color:var(--muted);line-height:1.5;}
.toast-close{background:none;border:none;color:var(--dim);cursor:pointer;font-size:13px;padding:2px;flex-shrink:0;transition:color .2s;}
.toast-close:hover{color:var(--text);}
.toast-bar{position:absolute;bottom:0;left:0;height:3px;border-radius:0 0 var(--radius-lg) var(--radius-lg);animation:toastBar 4s linear forwards;}
.toast.success .toast-bar{background:var(--success);}
.toast.error .toast-bar{background:var(--danger);}
.toast.warning .toast-bar{background:var(--warning);}
.toast.info .toast-bar{background:var(--info);}
@keyframes toastBar{from{width:100%}to{width:0%}}
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
        <h1 style="margin-top:8px;">User Management</h1>
        <p><?= $total_users ?> registered users &nbsp;·&nbsp; <?= $active_users ?> active</p>
    </div>
    <button class="btn btn-gold" onclick="openCreateModal()">
        <i class="fas fa-user-plus"></i> Create User
    </button>
</div>

<?php if ($msg): ?><div class="alert alert-success"><i class="fas fa-circle-check"></i> <?= $msg ?></div><?php endif; ?>
<?php if ($err): ?><div class="alert alert-danger"><i class="fas fa-circle-exclamation"></i> <?= e($err) ?></div><?php endif; ?>

<!-- Stats -->
<div class="stats-row">
    <div class="sr-card">
        <p class="sr-val"><?= $total_users ?></p>
        <p class="sr-lbl">Total Users</p>
    </div>
    <div class="sr-card">
        <p class="sr-val" style="color:var(--success)"><?= $active_users ?></p>
        <p class="sr-lbl">Active</p>
    </div>
    <div class="sr-card">
        <p class="sr-val" style="color:var(--danger)"><?= $susp_users ?></p>
        <p class="sr-lbl">Suspended</p>
    </div>
    <div class="sr-card">
        <p class="sr-val" style="color:var(--gold)"><?= $rc['admin'] ?? 0 ?></p>
        <p class="sr-lbl">Admins</p>
    </div>
    <div class="sr-card">
        <p class="sr-val" style="color:var(--info)"><?= $rc['investigator'] ?? 0 ?></p>
        <p class="sr-lbl">Investigators</p>
    </div>
    <div class="sr-card">
        <p class="sr-val" style="color:var(--success)"><?= $rc['analyst'] ?? 0 ?></p>
        <p class="sr-lbl">Analysts</p>
    </div>
    <div class="sr-card">
        <p class="sr-val" style="color:var(--muted)"><?= $rc['viewer'] ?? 0 ?></p>
        <p class="sr-lbl">Viewers</p>
    </div>
</div>

<!-- Filters -->
<div class="filter-wrap">
    <form method="GET" id="filterForm">
        <div class="filter-row">
            <input type="text" name="search" id="searchInput"
                placeholder="Search name, username, email, department..."
                value="<?= e($search) ?>">
            <select name="role" onchange="this.form.submit()">
                <option value="">All Roles</option>
                <?php foreach (['admin','investigator','analyst','viewer'] as $r): ?>
                <option value="<?= $r ?>" <?= $filter_role===$r?'selected':'' ?>><?= ucfirst($r) ?></option>
                <?php endforeach; ?>
            </select>
            <select name="status" onchange="this.form.submit()">
                <option value="">All Statuses</option>
                <option value="active"    <?= $filter_status==='active'?'selected':'' ?>>Active</option>
                <option value="suspended" <?= $filter_status==='suspended'?'selected':'' ?>>Suspended</option>
                <option value="inactive"  <?= $filter_status==='inactive'?'selected':'' ?>>Inactive</option>
            </select>
            <input type="hidden" name="sort" value="<?= e($sort) ?>">
            <input type="hidden" name="dir"  value="<?= strtolower($dir) ?>">
            <button type="submit" class="btn btn-gold btn-sm"><i class="fas fa-search"></i> Search</button>
            <?php if ($search||$filter_role||$filter_status): ?>
            <a href="users.php" class="btn btn-outline btn-sm"><i class="fas fa-xmark"></i> Clear</a>
            <?php endif; ?>
        </div>
    </form>
</div>

<!-- Users Table -->
<div class="section-card">
    <div class="section-head">
        <h2><i class="fas fa-users"></i> Users
            <span class="badge badge-gray" style="margin-left:6px"><?= count($users) ?></span>
        </h2>
        <span style="font-size:12px;color:var(--muted)">Click a row to view details</span>
    </div>
    <?php if (empty($users)): ?>
    <div class="empty-state"><i class="fas fa-users"></i><p>No users found.</p></div>
    <?php else: ?>
    <div style="overflow-x:auto;">
    <div class="table-responsive"><table class="dc-table" style="table-layout:fixed;width:100%">
        <thead><tr>
            <th><a href="<?= su('full_name') ?>" class="sort-th">User <?= si('full_name') ?></a></th>
            <th><a href="<?= su('role') ?>" class="sort-th">Role <?= si('role') ?></a></th>
            <th><a href="<?= su('status') ?>" class="sort-th">Status <?= si('status') ?></a></th>
            <th>Department</th>
            <th>Evidence</th>
            <th><a href="<?= su('last_login') ?>" class="sort-th">Last Login <?= si('last_login') ?></a></th>
            <th>Actions</th>
        </tr></thead>
        <tbody>
        <?php foreach ($users as $u):
            // Count evidence for this user
            $ev_count = $pdo->prepare("SELECT COUNT(*) FROM evidence WHERE uploaded_by=?");
            $ev_count->execute([$u['id']]);
            $ev_count = (int)$ev_count->fetchColumn();
        ?>
        <tr>
            <td data-label="User">
                <div style="display:flex;align-items:center;gap:10px;">
                    <div class="user-avatar <?= $u['status']==='suspended'?'suspended':'' ?>">
                        <?= strtoupper(substr($u['full_name'],0,2)) ?>
                    </div>
                    <div style="min-width:0;">
                        <p style="font-weight:500;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                            <?= e($u['full_name']) ?>
                            <?php if ($u['id']===$uid): ?>
                            <span class="badge badge-gold" style="font-size:9px;margin-left:4px">You</span>
                            <?php endif; ?>
                        </p>
                        <p style="font-size:11.5px;color:var(--muted)">@<?= e($u['username']) ?></p>
                        <p style="font-size:11px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><?= e($u['email']) ?></p>
                    </div>
                </div>
            </td>
            <td data-label="Role"><?= role_badge($u['role']) ?></td>
            <td data-label="Status"><?= status_badge($u['status']) ?></td>
            <td data-label="Department">
                <p style="font-size:12.5px;color:var(--text)"><?= e($u['department'] ?: '—') ?></p>
                <?php if ($u['badge_number']): ?>
                <p style="font-size:11px;color:var(--dim)"><?= e($u['badge_number']) ?></p>
                <?php endif; ?>
            </td>
            <td data-label="Evidence">
                <span class="badge <?= $ev_count>0?'badge-blue':'badge-gray' ?>">
                    <i class="fas fa-database" style="font-size:9px"></i> <?= $ev_count ?>
                </span>
            </td>
            <td data-label="Last Login">
                <?php if ($u['last_login']): ?>
                <span style="font-size:12px;color:var(--muted)"><?= date('M j, Y', strtotime($u['last_login'])) ?></span><br>
                <span style="font-size:11px;color:var(--dim)"><?= date('H:i', strtotime($u['last_login'])) ?></span>
                <?php else: ?>
                <span style="font-size:12px;color:var(--dim)">Never logged in</span>
                <?php endif; ?>
            </td>
            <td data-label="Actions">
                <div style="display:flex;gap:6px;flex-wrap:wrap;">
                    <button class="btn btn-outline btn-sm"
                        onclick="openEditModal(<?= htmlspecialchars(json_encode($u), ENT_QUOTES) ?>)">
                        <i class="fas fa-pen"></i> Edit
                    </button>
                    <?php if ($u['id'] !== $uid): ?>
                    <button class="btn <?= $u['status']==='active'?'btn-danger':'btn-success' ?> btn-sm" onclick="openConfirmModal('toggle_status',<?= $u['id'] ?>,'<?= $u['status']==='active'?'Suspend':'Activate' ?>','<?= e(addslashes($u['full_name'])) ?>','<?= $u['status']==='active'?'Suspend':'Reactivate' ?> this user?')">
                        <i class="fas <?= $u['status']==='active'?'fa-ban':'fa-circle-check' ?>"></i>
                        <?= $u['status']==='active'?'Suspend':'Activate' ?>
                    </button>
                    <button class="btn btn-outline btn-sm" onclick="openConfirmModal('reset_password',<?= $u['id'] ?>,'Reset Password','<?= e(addslashes($u['full_name'])) ?>','Reset password for this user? A temporary password will be generated.')">
                        <i class="fas fa-key"></i> Reset PW
                    </button>
                    <button class="btn btn-danger btn-sm" onclick="openDeleteModal(<?= $u['id'] ?>,'<?= e(addslashes($u['full_name'])) ?>')">
                        <i class="fas fa-trash"></i> Delete
                    </button>
                    <?php endif; ?>
                </div>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table></div>
    </div>
    <?php endif; ?>
</div>

</div></div></div>

<!-- ══ CREATE USER MODAL ══ -->
<div class="overlay" id="createModal" style="display:none" onclick="ovClose('createModal',event)">
    <div class="modal">
        <div class="modal-head">
            <h3>Create <span>New User</span></h3>
            <button class="xbtn" onclick="closeModal('createModal')"><i class="fas fa-xmark"></i></button>
        </div>
        <form method="POST" action="users.php">
            <input type="hidden" name="action"     value="create_user">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <div class="modal-body">
                <div class="grid-2">
                    <div class="field">
                        <label>Full Name *</label>
                        <input type="text" name="full_name" placeholder="e.g. John Doe" required>
                    </div>
                    <div class="field">
                        <label>Email *</label>
                        <input type="email" name="email" placeholder="user@example.com" required>
                    </div>
                </div>
                <div class="grid-2">
                    <div class="field">
                        <label>Username *</label>
                        <input type="text" name="username" placeholder="e.g. jdoe" required>
                    </div>
                    <div class="field">
                        <label>Role *</label>
                        <select name="role">
                            <option value="investigator">Investigator</option>
                            <option value="analyst">Analyst</option>
                            <option value="viewer">Viewer</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                </div>
                <div class="grid-2">
                    <div class="field">
                        <label>Department</label>
                        <input type="text" name="department" placeholder="e.g. Cyber Crime Unit">
                    </div>
                    <div class="field">
                        <label>Badge / Staff No.</label>
                        <input type="text" name="badge_number" placeholder="e.g. DCI-00123">
                    </div>
                </div>
                <div class="grid-2">
                    <div class="field">
                        <label>Phone</label>
                        <input type="text" name="phone" placeholder="+254 7XX XXX XXX">
                    </div>
                    <div class="field">
                        <label>Password * (min 8 chars)</label>
                        <div class="pass-wrap">
                            <input type="password" name="password" id="createPw" placeholder="Set a strong password" required>
                            <button type="button" class="pass-eye" onclick="togglePw('createPw','createPwEye')">
                                <i class="fas fa-eye" id="createPwEye"></i>
                            </button>
                        </div>
                    </div>
                </div>
                <div style="background:rgba(201,168,76,0.05);border:1px solid rgba(201,168,76,0.15);border-radius:8px;padding:10px 14px;font-size:12.5px;color:var(--muted);">
                    <i class="fas fa-info-circle" style="color:var(--gold);margin-right:6px"></i>
                    The user will be notified via the system. They should change their password after first login.
                </div>
            </div>
            <div class="modal-foot">
                <button type="button" class="btn btn-outline" onclick="closeModal('createModal')">Cancel</button>
                <button type="submit" class="btn btn-gold"><i class="fas fa-user-plus"></i> Create Account</button>
            </div>
        </form>
    </div>
</div>

<!-- ══ EDIT USER MODAL ══ -->
<div class="overlay" id="editModal" style="display:none" onclick="ovClose('editModal',event)">
    <div class="modal">
        <div class="modal-head">
            <h3>Edit <span>User Account</span></h3>
            <button class="xbtn" onclick="closeModal('editModal')"><i class="fas fa-xmark"></i></button>
        </div>
        <form method="POST" action="users.php">
            <input type="hidden" name="action"     value="edit_user">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <input type="hidden" name="target_id"  id="editTargetId">
            <div class="modal-body">
                <div class="grid-2">
                    <div class="field">
                        <label>Full Name *</label>
                        <input type="text" name="full_name" id="editFullName" required>
                    </div>
                    <div class="field">
                        <label>Email *</label>
                        <input type="email" name="email" id="editEmail" required>
                    </div>
                </div>
                <div class="grid-2">
                    <div class="field">
                        <label>Role</label>
                        <select name="role" id="editRole">
                            <option value="investigator">Investigator</option>
                            <option value="analyst">Analyst</option>
                            <option value="viewer">Viewer</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                    <div class="field">
                        <label>Status</label>
                        <select name="status" id="editStatus">
                            <option value="active">Active</option>
                            <option value="suspended">Suspended</option>
                            <option value="inactive">Inactive</option>
                        </select>
                    </div>
                </div>
                <div class="grid-2">
                    <div class="field">
                        <label>Department</label>
                        <input type="text" name="department" id="editDept">
                    </div>
                    <div class="field">
                        <label>Badge / Staff No.</label>
                        <input type="text" name="badge_number" id="editBadge">
                    </div>
                </div>
                <div class="grid-2">
                    <div class="field">
                        <label>Phone</label>
                        <input type="text" name="phone" id="editPhone">
                    </div>
                    <div class="field">
                        <label>New Password (leave blank to keep)</label>
                        <div class="pass-wrap">
                            <input type="password" name="new_password" id="editPw" placeholder="Leave blank to keep current">
                            <button type="button" class="pass-eye" onclick="togglePw('editPw','editPwEye')">
                                <i class="fas fa-eye" id="editPwEye"></i>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-foot">
                <button type="button" class="btn btn-outline" onclick="closeModal('editModal')">Cancel</button>
                <button type="submit" class="btn btn-gold"><i class="fas fa-save"></i> Save Changes</button>
            </div>
        </form>
    </div>
</div>

<!-- ══ DELETE USER MODAL ══ -->
<div class="overlay" id="deleteModal" style="display:none" onclick="ovClose('deleteModal',event)">
    <div class="modal" style="max-width:460px">
        <div class="modal-head">
            <h3 style="color:var(--danger)"><i class="fas fa-triangle-exclamation"></i> Delete <span style="color:var(--danger)">User</span></h3>
            <button class="xbtn" onclick="closeModal('deleteModal')"><i class="fas fa-xmark"></i></button>
        </div>
        <form method="POST" action="users.php">
            <input type="hidden" name="action"     value="delete_user">
            <input type="hidden" name="target_id"  id="deleteTargetId">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <div class="modal-body" style="text-align:center;">
                <div style="width:64px;height:64px;border-radius:50%;background:rgba(248,113,113,0.1);display:flex;align-items:center;justify-content:center;margin:0 auto 16px;">
                    <i class="fas fa-trash" style="font-size:28px;color:var(--danger)"></i>
                </div>
                <p style="font-size:15px;font-weight:600;color:var(--text);margin-bottom:8px;">
                    Are you sure you want to delete <span id="deleteUserName" style="color:var(--danger)"></span>?
                </p>
                <p style="font-size:13px;color:var(--muted);line-height:1.6;">
                    This action is <strong style="color:var(--danger)">permanent</strong> and cannot be undone.<br>
                    All associated data (case access, notifications, login history) will be removed.
                    Evidence and cases created by this user will be <strong>preserved</strong>.
                </p>
                <div style="margin-top:16px;padding:10px 14px;background:rgba(248,113,113,0.06);border:1px solid rgba(248,113,113,0.15);border-radius:8px;font-size:12px;color:var(--muted);text-align:left;">
                    <i class="fas fa-info-circle" style="color:var(--danger);margin-right:6px"></i>
                    Evidence uploaded by this user will have their custodian set to NULL.<br>
                    Cases created by this user will have their assignment cleared.
                </div>
            </div>
            <div class="modal-foot">
                <button type="button" class="btn btn-outline" onclick="closeModal('deleteModal')">Cancel</button>
                <button type="submit" class="btn btn-danger"><i class="fas fa-trash"></i> Delete Permanently</button>
            </div>
        </form>
    </div>
</div>

<!-- ══ GENERIC CONFIRM MODAL ══ -->
<div class="overlay" id="confirmModal" style="display:none" onclick="ovClose('confirmModal',event)">
    <div class="modal" style="max-width:440px">
        <div class="modal-head">
            <h3 id="confirmTitle" style="color:var(--warning)"><i class="fas fa-shield-halved"></i> <span id="confirmTitleText"></span></h3>
            <button class="xbtn" onclick="closeModal('confirmModal')"><i class="fas fa-xmark"></i></button>
        </div>
        <form method="POST" action="users.php" id="confirmForm">
            <input type="hidden" name="action"     id="confirmAction">
            <input type="hidden" name="target_id"  id="confirmTargetId">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <div class="modal-body" style="text-align:center;">
                <div id="confirmIconWrap" style="width:64px;height:64px;border-radius:50%;background:rgba(251,191,36,0.1);display:flex;align-items:center;justify-content:center;margin:0 auto 16px;">
                    <i class="fas fa-question" style="font-size:28px;color:var(--warning)"></i>
                </div>
                <p style="font-size:15px;font-weight:600;color:var(--text);margin-bottom:8px;">
                    <span id="confirmName"></span>
                </p>
                <p id="confirmMsg" style="font-size:13px;color:var(--muted);line-height:1.6;"></p>
            </div>
            <div class="modal-foot">
                <button type="button" class="btn btn-outline" onclick="closeModal('confirmModal')">Cancel</button>
                <button type="submit" class="btn btn-warning" id="confirmSubmitBtn"><i class="fas fa-check" id="confirmBtnIcon"></i> <span id="confirmBtnText"></span></button>
            </div>
        </form>
    </div>
</div>

<!-- ══ TOAST CONTAINER ══ -->
<div class="toast-container" id="toastContainer"></div>

<script>
// Sidebar
function toggleSidebar(){const sb=document.getElementById('sidebar'),ma=document.getElementById('mainArea');if(window.innerWidth<=900){sb.classList.toggle('mobile-open');}else{sb.classList.toggle('collapsed');ma.classList.toggle('collapsed');}localStorage.setItem('sb_collapsed',sb.classList.contains('collapsed')?'1':'0');}
if(localStorage.getItem('sb_collapsed')==='1'&&window.innerWidth>900){document.getElementById('sidebar').classList.add('collapsed');document.getElementById('mainArea').classList.add('collapsed');}
function toggleNotif(){document.getElementById('notifDropdown').classList.toggle('open');document.getElementById('userDropdown').classList.remove('open');}
function toggleUserMenu(){document.getElementById('userDropdown').classList.toggle('open');document.getElementById('notifDropdown').classList.remove('open');}
document.addEventListener('click',function(e){if(!e.target.closest('#notifWrap'))document.getElementById('notifDropdown').classList.remove('open');if(!e.target.closest('#userMenuWrap'))document.getElementById('userDropdown').classList.remove('open');});
function handleSearch(e){if(e.key==='Enter'){window.location='users.php?search='+encodeURIComponent(document.getElementById('globalSearch').value);}}

// Modals
function openCreateModal(){document.getElementById('createModal').style.display='flex';}
function closeModal(id){document.getElementById(id).style.display='none';}
function ovClose(id,e){if(e.target===document.getElementById(id))closeModal(id);}

function openEditModal(u){
    document.getElementById('editTargetId').value = u.id;
    document.getElementById('editFullName').value  = u.full_name;
    document.getElementById('editEmail').value     = u.email;
    document.getElementById('editRole').value      = u.role;
    document.getElementById('editStatus').value    = u.status;
    document.getElementById('editDept').value      = u.department || '';
    document.getElementById('editBadge').value     = u.badge_number || '';
    document.getElementById('editPhone').value     = u.phone || '';
    document.getElementById('editPw').value        = '';
    document.getElementById('editModal').style.display = 'flex';
}

function openDeleteModal(id,name){
    document.getElementById('deleteTargetId').value = id;
    document.getElementById('deleteUserName').textContent = name;
    document.getElementById('deleteModal').style.display = 'flex';
}

function openConfirmModal(action,id,title,name,msg){
    document.getElementById('confirmAction').value = action;
    document.getElementById('confirmTargetId').value = id;
    document.getElementById('confirmTitleText').textContent = title;
    document.getElementById('confirmName').textContent = name;
    document.getElementById('confirmMsg').textContent = msg;
    document.getElementById('confirmBtnText').textContent = title;
    if(action==='delete_user'){
        document.getElementById('confirmIconWrap').style.background='rgba(248,113,113,0.1)';
        document.getElementById('confirmIconWrap').innerHTML='<i class="fas fa-trash" style="font-size:28px;color:var(--danger)"></i>';
        document.getElementById('confirmTitle').style.color='var(--danger)';
        document.getElementById('confirmSubmitBtn').className='btn btn-danger';
        document.getElementById('confirmBtnIcon').className='fas fa-trash';
    } else if(action==='toggle_status'){
        document.getElementById('confirmIconWrap').style.background='rgba(96,165,250,0.1)';
        document.getElementById('confirmIconWrap').innerHTML='<i class="fas fa-user-shield" style="font-size:28px;color:var(--info)"></i>';
        document.getElementById('confirmTitle').style.color='var(--info)';
        document.getElementById('confirmSubmitBtn').className='btn btn-outline';
        document.getElementById('confirmBtnIcon').className='fas fa-check';
    } else {
        document.getElementById('confirmIconWrap').style.background='rgba(251,191,36,0.1)';
        document.getElementById('confirmIconWrap').innerHTML='<i class="fas fa-key" style="font-size:28px;color:var(--warning)"></i>';
        document.getElementById('confirmTitle').style.color='var(--warning)';
        document.getElementById('confirmSubmitBtn').className='btn btn-warning';
        document.getElementById('confirmBtnIcon').className='fas fa-key';
    }
    document.getElementById('confirmModal').style.display = 'flex';
}

function togglePw(inputId, iconId){
    const i=document.getElementById(inputId), ic=document.getElementById(iconId);
    i.type=i.type==='password'?'text':'password';
    ic.classList.toggle('fa-eye'); ic.classList.toggle('fa-eye-slash');
}

// Toast notifications
function showToast(type,title,msg,duration){
    duration=duration||4000;
    var icons={success:'fa-circle-check',error:'fa-circle-xmark',warning:'fa-triangle-exclamation',info:'fa-circle-info'};
    var t=document.createElement('div');
    t.className='toast '+type;
    t.innerHTML='<div class="toast-icon"><i class="fas '+(icons[type]||icons.info)+'"></i></div><div class="toast-body"><div class="toast-title">'+title+'</div><div class="toast-msg">'+msg+'</div></div><button class="toast-close" onclick="removeToast(this.parentElement)"><i class="fas fa-xmark"></i></button><div class="toast-bar" style="animation-duration:'+(duration/1000)+'s"></div>';
    document.getElementById('toastContainer').appendChild(t);
    setTimeout(function(){removeToast(t);},duration);
}
function removeToast(t){
    if(!t||t.classList.contains('removing'))return;
    t.classList.add('removing');
    setTimeout(function(){if(t.parentElement)t.parentElement.removeChild(t);},300);
}

// Live search
var st;
var si=document.getElementById('searchInput');
if(si) si.addEventListener('input',function(){clearTimeout(st);st=setTimeout(function(){document.getElementById('filterForm').submit();},500);});

<?php if ($edit_user): ?>
openEditModal(<?= json_encode($edit_user) ?>);
<?php endif; ?>

<?php if ($msg): ?>
showToast('success','Success','<?= addslashes($msg) ?>');
<?php endif; ?>
<?php if ($err): ?>
showToast('error','Error','<?= addslashes($err) ?>');
<?php endif; ?>
</script>
<script src="../assets/js/main.js"></script>
</body>
</html>
