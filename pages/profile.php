<?php
/**
 * DigiCustody – User Profile Page
 * Save to: /var/www/html/digicustody/pages/profile.php
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login($pdo);

$page_title = 'My Profile';
$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];
$msg  = ''; $err = '';

// Fetch fresh user data
$stmt = $pdo->prepare("SELECT * FROM users WHERE id=?");

$stmt->execute([$uid]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

$two_factor_enabled = !empty($user['two_factor_enabled']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $err = 'Security token mismatch.';
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'update_profile') {
            $full_name  = trim($_POST['full_name'] ?? '');
            $email      = trim($_POST['email'] ?? '');
            $department = trim($_POST['department'] ?? '');
            $phone      = trim($_POST['phone'] ?? '');

            if (empty($full_name) || empty($email)) {
                $err = 'Name and email are required.';
            } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $err = 'Invalid email address.';
            } elseif ($two_factor_enabled && $email !== $user['email']) {
                $err = 'Email cannot be changed while 2FA is enabled. Disable 2FA first to change your email.';
            } else {
                $pdo->prepare("UPDATE users SET full_name=?,email=?,department=?,phone=?,updated_at=NOW() WHERE id=?")
                    ->execute([$full_name,$email,$department,$phone,$uid]);
                $_SESSION['full_name'] = $full_name;
                $_SESSION['email']     = $email;
                audit_log($pdo,$uid,$_SESSION['username'],$role,'account_updated','user',$uid,$full_name,'User updated own profile');
                $msg = 'Profile updated successfully.';
                $user['full_name'] = $full_name;
                $user['email']     = $email;
                $user['department']= $department;
                $user['phone']     = $phone;
            }
        }

        elseif ($action === 'change_password') {
            $current = $_POST['current_password'] ?? '';
            $new_pw  = $_POST['new_password'] ?? '';
            $confirm = $_POST['confirm_password'] ?? '';

            if (!password_verify($current, $user['password'])) {
                $err = 'Current password is incorrect.';
            } elseif (strlen($new_pw) < 8) {
                $err = 'New password must be at least 8 characters.';
            } elseif ($new_pw !== $confirm) {
                $err = 'New passwords do not match.';
            } else {
                $hashed = password_hash($new_pw, PASSWORD_BCRYPT, ['cost'=>12]);
                $pdo->prepare("UPDATE users SET password=? WHERE id=?")->execute([$hashed,$uid]);
                audit_log($pdo,$uid,$_SESSION['username'],$role,'account_updated','user',$uid,$user['full_name'],'User changed own password');
                $msg = 'Password changed successfully.';
            }
        }
    }
}

// Stats for this user
$s = $pdo->prepare("SELECT COUNT(*) FROM evidence WHERE uploaded_by=?"); $s->execute([$uid]);
$ev_uploaded = (int)$s->fetchColumn();

$s = $pdo->prepare("SELECT COUNT(*) FROM download_history WHERE user_id=?"); $s->execute([$uid]);
$downloads = (int)$s->fetchColumn();

$s = $pdo->prepare("SELECT COUNT(*) FROM analysis_reports WHERE submitted_by=?"); $s->execute([$uid]);
$reports = (int)$s->fetchColumn();

$s = $pdo->prepare("SELECT COUNT(*) FROM audit_logs WHERE user_id=?"); $s->execute([$uid]);
$total_actions = (int)$s->fetchColumn();

// Recent activity
$recent = $pdo->prepare("SELECT * FROM audit_logs WHERE user_id=? ORDER BY created_at DESC LIMIT 8");
$recent->execute([$uid]);
$recent = $recent->fetchAll(PDO::FETCH_ASSOC);

$csrf = csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>My Profile — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.profile-hero{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:28px;margin-bottom:24px;display:flex;align-items:center;gap:22px;flex-wrap:wrap;}
.profile-avatar{width:72px;height:72px;border-radius:50%;background:var(--gold-dim);border:2px solid rgba(201,168,76,0.3);display:flex;align-items:center;justify-content:center;font-size:26px;font-weight:700;color:var(--gold);flex-shrink:0;}
.profile-info h2{font-family:'Space Grotesk',sans-serif;font-size:20px;font-weight:700;color:var(--text);}
.profile-info p{font-size:13.5px;color:var(--muted);margin-top:4px;}
.field{margin-bottom:16px;}
.field label{display:block;font-size:11.5px;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:7px;}
.field input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:11px 14px;font-size:14px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.field input:focus{border-color:rgba(201,168,76,0.5);box-shadow:0 0 0 3px rgba(201,168,76,0.06);}
.field input:disabled{opacity:.5;cursor:not-allowed;}
.pw-wrap{position:relative;}
.pw-wrap input{padding-right:40px;}
.pw-eye{position:absolute;right:12px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--dim);cursor:pointer;font-size:13px;transition:color .2s;}
.pw-eye:hover{color:var(--gold);}
.stats-mini{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px;}
.sm-stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:16px;text-align:center;}
.sm-val{font-family:'Space Grotesk',sans-serif;font-size:22px;font-weight:700;color:var(--text);}
.sm-lbl{font-size:11.5px;color:var(--muted);margin-top:3px;}
.log-item{display:flex;gap:11px;padding:10px 0;border-bottom:1px solid var(--border);}
.log-item:last-child{border-bottom:none;}
</style>
</head>
<body>
<div class="app-shell">
<?php include __DIR__.'/../includes/sidebar.php'; ?>
<div class="main-area" id="mainArea">
<?php include __DIR__.'/../includes/navbar.php'; ?>
<div class="page-content">

<div class="page-header">
    <div style="display:flex;align-items:center;gap:12px;">
        <button type="button" class="btn-back" onclick="goBack()"><i class="fas fa-arrow-left"></i> Back</button>
        <h1 style="margin:0;">My Profile</h1>
    </div>
</div>

<!-- ══ TOAST CONTAINER ══ -->
<div class="toast-container" id="toastContainer"></div>

<!-- Profile Hero -->
<div class="profile-hero">
    <div class="profile-avatar"><?= strtoupper(substr($user['full_name'],0,2)) ?></div>
    <div class="profile-info" style="flex:1;">
        <h2><?= e($user['full_name']) ?></h2>
        <p>
            @<?= e($user['username']) ?> &nbsp;·&nbsp;
            <?= role_badge($user['role']) ?> &nbsp;·&nbsp;
            <?= status_badge($user['status']) ?>
        </p>
        <p style="margin-top:6px">
            <i class="fas fa-envelope" style="color:var(--muted);margin-right:5px"></i><?= e($user['email']) ?>
            <?php if ($user['department']): ?>
            &nbsp;·&nbsp; <i class="fas fa-building" style="color:var(--muted);margin-right:5px"></i><?= e($user['department']) ?>
            <?php endif; ?>
            <?php if ($user['badge_number']): ?>
            &nbsp;·&nbsp; <i class="fas fa-id-badge" style="color:var(--muted);margin-right:5px"></i><?= e($user['badge_number']) ?>
            <?php endif; ?>
        </p>
        <p style="font-size:12px;color:var(--dim);margin-top:6px">
            Member since <?= date('F Y', strtotime($user['created_at'])) ?>
            <?php if ($user['last_login']): ?>
            &nbsp;·&nbsp; Last login: <?= date('M j, Y H:i', strtotime($user['last_login'])) ?>
            <?php endif; ?>
        </p>
    </div>
</div>

<!-- Stats -->
<div class="stats-mini">
    <div class="sm-stat">
        <p class="sm-val" style="color:var(--gold)"><?= $ev_uploaded ?></p>
        <p class="sm-lbl">Evidence Uploaded</p>
    </div>
    <div class="sm-stat">
        <p class="sm-val" style="color:var(--info)"><?= $downloads ?></p>
        <p class="sm-lbl">Downloads</p>
    </div>
    <div class="sm-stat">
        <p class="sm-val" style="color:var(--success)"><?= $reports ?></p>
        <p class="sm-lbl">Reports</p>
    </div>
    <div class="sm-stat">
        <p class="sm-val" style="color:var(--muted)"><?= $total_actions ?></p>
        <p class="sm-lbl">Total Actions</p>
    </div>
</div>

<div class="grid-2" style="gap:24px;">

    <!-- Edit Profile -->
    <div>
        <div class="section-card" style="margin-bottom:20px;">
            <div class="section-head"><h2><i class="fas fa-pen"></i> Edit Profile</h2></div>
            <div class="section-body padded">
                <form method="POST">
                    <input type="hidden" name="action"     value="update_profile">
                    <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
                    <div class="field">
                        <label>Username</label>
                        <input type="text" value="<?= e($user['username']) ?>" disabled>
                    </div>
                    <div class="field">
                        <label>Full Name *</label>
                        <input type="text" name="full_name" value="<?= e($user['full_name']) ?>" required>
                    </div>
                    <div class="field">
                        <label>Email *</label>
                        <?php if ($two_factor_enabled): ?>
                        <input type="email" name="email" value="<?= e($user['email']) ?>" readonly style="background:var(--surface);cursor:not-allowed;">
                        <input type="hidden" name="email" value="<?= e($user['email']) ?>">
                        <small style="color:var(--warning);font-size:11px;"><i class="fas fa-lock"></i> Email locked - 2FA is enabled</small>
                        <?php else: ?>
                        <input type="email" name="email" value="<?= e($user['email']) ?>" required>
                        <?php endif; ?>
                    </div>
                    <div class="field">
                        <label>Department</label>
                        <input type="text" name="department" value="<?= e($user['department'] ?? '') ?>" placeholder="e.g. Cyber Crime Unit">
                    </div>
                    <div class="field">
                        <label>Phone</label>
                        <input type="text" name="phone" value="<?= e($user['phone'] ?? '') ?>" placeholder="+254 7XX XXX XXX">
                    </div>
                    <button type="submit" class="btn btn-gold" style="width:100%;padding:12px;">
                        <i class="fas fa-save"></i> Save Changes
                    </button>
                </form>
            </div>
        </div>

        <!-- Change Password -->
        <div class="section-card">
            <div class="section-head"><h2><i class="fas fa-lock"></i> Change Password</h2></div>
            <div class="section-body padded">
                <form method="POST">
                    <input type="hidden" name="action"     value="change_password">
                    <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
                    <div class="field">
                        <label>Current Password</label>
                        <div class="pw-wrap">
                            <input type="password" name="current_password" id="cp" placeholder="Enter current password" required>
                            <button type="button" class="pw-eye" onclick="tp('cp','ce')"><i class="fas fa-eye" id="ce"></i></button>
                        </div>
                    </div>
                    <div class="field">
                        <label>New Password (min 8 characters)</label>
                        <div class="pw-wrap">
                            <input type="password" name="new_password" id="np" placeholder="Enter new password" required>
                            <button type="button" class="pw-eye" onclick="tp('np','ne')"><i class="fas fa-eye" id="ne"></i></button>
                        </div>
                    </div>
                    <div class="field">
                        <label>Confirm New Password</label>
                        <div class="pw-wrap">
                            <input type="password" name="confirm_password" id="cnp" placeholder="Repeat new password" required>
                            <button type="button" class="pw-eye" onclick="tp('cnp','cne')"><i class="fas fa-eye" id="cne"></i></button>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-outline" style="width:100%;padding:12px;">
                        <i class="fas fa-key"></i> Change Password
                    </button>
                </form>
            </div>
        </div>
    </div>

    <!-- Recent Activity -->
    <div class="section-card">
        <div class="section-head"><h2><i class="fas fa-clock-rotate-left"></i> Recent Activity</h2></div>
        <div class="section-body padded">
            <?php if (empty($recent)): ?>
            <div class="empty-state" style="padding:20px 0"><i class="fas fa-scroll"></i><p>No activity yet.</p></div>
            <?php else:
            $icons=['login'=>['blue','fa-right-to-bracket'],'logout'=>['muted','fa-right-from-bracket'],'evidence_uploaded'=>['green','fa-upload'],'evidence_viewed'=>['blue','fa-eye'],'evidence_downloaded'=>['warning','fa-download'],'evidence_transferred'=>['purple','fa-right-left'],'hash_verified'=>['gold','fa-fingerprint'],'account_updated'=>['info','fa-pen']];
            foreach ($recent as $log):
                [$c,$i] = $icons[$log['action_type']] ?? ['gray','fa-circle-dot'];
            ?>
            <div class="log-item">
                <div class="stat-icon <?= $c ?>" style="width:30px;height:30px;border-radius:50%;flex-shrink:0;font-size:11px;">
                    <i class="fas <?= $i ?>"></i>
                </div>
                <div style="flex:1;min-width:0;">
                    <p style="font-size:13px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><?= e($log['description']) ?></p>
                    <p style="font-size:11.5px;color:var(--dim);margin-top:2px"><?= date('M j, Y H:i', strtotime($log['created_at'])) ?></p>
                </div>
            </div>
            <?php endforeach; endif; ?>
            <div style="margin-top:14px;text-align:center;">
                <a href="audit.php" style="font-size:13px;color:var(--gold)">View full activity log →</a>
            </div>
        </div>
    </div>
</div>

</div></div></div>
<script>
function toggleSidebar(){const sb=document.getElementById('sidebar'),ma=document.getElementById('mainArea');if(window.innerWidth<=900){sb.classList.toggle('mobile-open');}else{sb.classList.toggle('collapsed');ma.classList.toggle('collapsed');}localStorage.setItem('sb_collapsed',sb.classList.contains('collapsed')?'1':'0');}
if(localStorage.getItem('sb_collapsed')==='1'&&window.innerWidth>900){document.getElementById('sidebar').classList.add('collapsed');document.getElementById('mainArea').classList.add('collapsed');}
function toggleNotif(){document.getElementById('notifDropdown').classList.toggle('open');document.getElementById('userDropdown').classList.remove('open');}
function toggleUserMenu(){document.getElementById('userDropdown').classList.toggle('open');document.getElementById('notifDropdown').classList.remove('open');}
document.addEventListener('click',function(e){if(!e.target.closest('#notifWrap'))document.getElementById('notifDropdown').classList.remove('open');if(!e.target.closest('#userMenuWrap'))document.getElementById('userDropdown').classList.remove('open');});
function handleSearch(e){if(e.key==='Enter'){window.location='evidence.php?search='+encodeURIComponent(document.getElementById('globalSearch').value);}}
function tp(inp,ico){const i=document.getElementById(inp),ic=document.getElementById(ico);i.type=i.type==='password'?'text':'password';ic.classList.toggle('fa-eye');ic.classList.toggle('fa-eye-slash');}

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
