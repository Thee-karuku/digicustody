<?php
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../config/functions.php';
require_login($pdo);
set_security_headers();
set_secure_session_config();

$uid = $_SESSION['user_id'];
$error = '';
$success = '';
$show_qr = false;
$secret = '';
$qr_url = '';

// Handle enabling 2FA
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'enable_2fa') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request.';
    } else {
        $code = trim($_POST['verification_code'] ?? '');
        $temp_secret = $_SESSION['temp_2fa_secret'] ?? '';

        if (empty($code) || empty($temp_secret)) {
            $error = 'Please enter the verification code.';
        } elseif (!verify_2fa_code($temp_secret, $code)) {
            $error = 'Invalid verification code. Please try again.';
        } else {
            $backup_codes = generate_backup_codes();
            $stmt = $pdo->prepare("UPDATE users SET two_factor_enabled = 1, two_factor_secret = ?, two_factor_verified = 1, backup_codes = ? WHERE id = ?");
            $stmt->execute([$temp_secret, json_encode($backup_codes), $uid]);
            
            unset($_SESSION['temp_2fa_secret']);
            $success = 'Two-factor authentication has been enabled!';
            
            audit_log($pdo, $uid, get_user_email($pdo, $uid), $_SESSION['role'], '2fa_enabled', 'user', $uid, get_user_email($pdo, $uid), '2FA enabled', $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
        }
    }
}

// Handle disabling 2FA
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'disable_2fa') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request.';
    } else {
        $password = $_POST['confirm_password'] ?? '';
        $stmt = $pdo->prepare("SELECT password FROM users WHERE id = ?");
        $stmt->execute([$uid]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($password, $user['password'])) {
            $error = 'Incorrect password.';
        } else {
            disable_2fa($pdo, $uid);
            $success = 'Two-factor authentication has been disabled.';
            
            audit_log($pdo, $uid, get_user_email($pdo, $uid), $_SESSION['role'], '2fa_disabled', 'user', $uid, get_user_email($pdo, $uid), '2FA disabled', $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
        }
    }
}

// Check current 2FA status
$stmt = $pdo->prepare("SELECT two_factor_enabled, backup_codes FROM users WHERE id = ?");
$stmt->execute([$uid]);
$user_2fa = $stmt->fetch();
$two_factor_enabled = $user_2fa && $user_2fa['two_factor_enabled'] == 1;
$backup_codes = $two_factor_enabled ? json_decode($user_2fa['backup_codes'] ?? '[]', true) : [];

// Generate new secret if needed
if (!$two_factor_enabled && !isset($_SESSION['temp_2fa_secret'])) {
    $secret = generate_2fa_secret();
    $_SESSION['temp_2fa_secret'] = $secret;
    $qr_url = get_2fa_qrcode_url(get_user_email($pdo, $uid), $secret);
    $show_qr = true;
} elseif (isset($_SESSION['temp_2fa_secret'])) {
    $secret = $_SESSION['temp_2fa_secret'];
    $qr_url = get_2fa_qrcode_url(get_user_email($pdo, $uid), $secret);
    $show_qr = true;
}

$csrf = csrf_token();
$page_title = 'Two-Factor Authentication';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>DigiCustody — 2FA Settings</title>
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#060d1a;--surface:#0c1526;--surface2:#111d30;--border:rgba(255,255,255,0.08);--border-focus:rgba(201,168,76,0.55);--gold:#c9a84c;--gold2:#e2bc6a;--text:#f0f4fa;--muted:#6b82a0;--dim:#2e4060;--danger:#f87171;--success:#4ade80;}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;margin:0;}
.main{display:flex;min-height:100vh;}
.sidebar{width:250px;background:var(--surface);border-right:1px solid var(--border);padding:20px;position:fixed;height:100vh;overflow-y:auto;}
.sidebar h2{font-family:'Space Grotesk',sans-serif;font-size:18px;color:var(--gold);margin-bottom:30px;display:flex;align-items:center;gap:8px;}
.nav-item{display:flex;align-items:center;gap:10px;padding:12px 14px;border-radius:8px;color:var(--muted);text-decoration:none;font-size:14px;transition:all .2s;margin-bottom:4px;}
.nav-item:hover,.nav-item.active{background:rgba(201,168,76,0.1);color:var(--gold);}
.nav-item i{width:20px;text-align:center;}
.content{flex:1;margin-left:250px;padding:30px 40px;}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:30px;}
.header h1{font-family:'Space Grotesk',sans-serif;font-size:24px;font-weight:600;}
.alert{padding:12px 16px;border-radius:10px;font-size:14px;margin-bottom:20px;display:flex;align-items:flex-start;gap:10px;}
.alert.error{background:rgba(248,113,113,0.1);border:1px solid rgba(248,113,113,0.3);color:var(--danger);}
.alert.success{background:rgba(74,222,128,0.1);border:1px solid rgba(74,222,128,0.3);color:var(--success);}
.alert.info{background:rgba(74,158,255,0.1);border:1px solid rgba(74,158,255,0.3);color:#4a9eff;}
.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:30px;margin-bottom:20px;}
.card h3{font-family:'Space Grotesk',sans-serif;font-size:16px;margin-bottom:15px;color:var(--text);}
.card p{color:var(--muted);font-size:14px;line-height:1.6;margin-bottom:15px;}
.twofa-grid{display:grid;grid-template-columns:1fr 1fr;gap:30px;align-items:start;}
.qr-box{text-align:center;padding:20px;background:var(--surface2);border-radius:12px;border:1px solid var(--border);}
.qr-box img{max-width:200px;border-radius:8px;}
.secret-code{font-family:monospace;font-size:16px;letter-spacing:2px;padding:12px 20px;background:var(--surface2);border-radius:8px;color:var(--gold);margin:15px 0;word-break:break-all;}
.form-group{margin-bottom:18px;}
.form-group label{display:block;font-size:12px;font-weight:500;color:var(--muted);letter-spacing:.5px;text-transform:uppercase;margin-bottom:8px;}
.form-group input{width:100%;padding:12px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:14px;outline:none;transition:border-color .2s;}
.form-group input:focus{border-color:var(--border-focus);}
.btn{display:inline-flex;align-items:center;gap:8px;padding:12px 24px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;border:none;transition:all .2s;}
.btn-primary{background:var(--gold);color:#060d1a;}
.btn-primary:hover{background:var(--gold2);transform:translateY(-1px);}
.btn-danger{background:rgba(248,113,113,0.1);color:var(--danger);border:1px solid rgba(248,113,113,0.3);}
.btn-danger:hover{background:rgba(248,113,113,0.2);}
.backup-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:15px;}
.backup-code{padding:10px 15px;background:var(--surface2);border-radius:6px;font-family:monospace;font-size:13px;color:var(--gold);text-align:center;}
.status-badge{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:20px;font-size:12px;font-weight:600;}
.status-enabled{background:rgba(74,222,128,0.15);color:var(--success);}
.status-disabled{background:rgba(248,113,113,0.15);color:var(--danger);}
.verify-box{max-width:400px;}
.verify-input{font-size:24px !important;text-align:center;letter-spacing:8px;padding:15px !important;}
@media(max-width:768px){.twofa-grid{grid-template-columns:1fr;}.sidebar{display:none;}.content{margin-left:0;padding:20px;}}
</style>
</head>
<body>
<div class="main">
<?php include __DIR__ . '/../includes/sidebar.php'; ?>
<div class="content">
  <div class="header">
    <h1><i class="fas fa-shield-halved"></i> Two-Factor Authentication</h1>
    <span class="status-badge <?= $two_factor_enabled ? 'status-enabled' : 'status-disabled' ?>">
      <i class="fas fa-<?= $two_factor_enabled ? 'check-circle' : 'times-circle' ?>"></i>
      <?= $two_factor_enabled ? 'Enabled' : 'Disabled' ?>
    </span>
  </div>

  <?php if($error): ?>
    <div class="alert error"><i class="fas fa-circle-exclamation"></i><?= e($error) ?></div>
  <?php endif; ?>
  
  <?php if($success): ?>
    <div class="alert success"><i class="fas fa-check-circle"></i><?= e($success) ?></div>
  <?php endif; ?>

  <?php if($two_factor_enabled): ?>
    <div class="card">
      <h3><i class="fas fa-lock"></i> 2FA is Active</h3>
      <p>Your account is protected with two-factor authentication. You'll need your authenticator app to sign in.</p>
      
      <?php if(!empty($backup_codes)): ?>
      <h4 style="margin-top:20px;margin-bottom:10px;font-size:14px;">Backup Codes</h4>
      <p style="margin-bottom:5px;font-size:13px;color:var(--muted);">Save these codes in a safe place. Each code can only be used once.</p>
      <div class="backup-grid">
        <?php foreach($backup_codes as $code): ?>
          <div class="backup-code"><?= e($code) ?></div>
        <?php endforeach; ?>
      </div>
      <?php endif; ?>
    </div>

    <div class="card">
      <h3><i class="fas fa-ban"></i> Disable 2FA</h3>
      <p>To disable two-factor authentication, please enter your password below.</p>
      <form method="POST">
        <input type="hidden" name="action" value="disable_2fa">
        <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
        <div class="form-group">
          <label>Confirm Password</label>
          <input type="password" name="confirm_password" placeholder="Enter your password" required>
        </div>
        <button type="submit" class="btn btn-danger"><i class="fas fa-times"></i> Disable 2FA</button>
      </form>
    </div>

  <?php elseif($show_qr): ?>
    <div class="twofa-grid">
      <div class="card">
        <h3><i class="fas fa-mobile-alt"></i> Set Up Authenticator App</h3>
        <p>Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)</p>
        
        <div class="qr-box">
          <img src="<?= e($qr_url) ?>" alt="QR Code">
        </div>
        
        <p style="margin-top:15px;font-size:12px;color:var(--muted);">Manual entry code:</p>
        <div class="secret-code"><?= chunk_split($secret, 4, ' ') ?></div>
      </div>

      <div class="card verify-box">
        <h3><i class="fas fa-key"></i> Verify Code</h3>
        <p>Enter the 6-digit code from your authenticator app to complete setup.</p>
        
        <form method="POST">
          <input type="hidden" name="action" value="enable_2fa">
          <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
          <div class="form-group">
            <label>Verification Code</label>
            <input type="text" name="verification_code" class="verify-input" placeholder="000000" maxlength="6" pattern="[0-9]{6}" autocomplete="one-time-code" required>
          </div>
          <button type="submit" class="btn btn-primary"><i class="fas fa-check"></i> Enable 2FA</button>
        </form>
      </div>
    </div>
  <?php endif; ?>
</div>
</div>
</body>
</html>
