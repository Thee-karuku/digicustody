<?php
require_once 'config/db.php';
require_once 'config/functions.php';

set_secure_session_config();
session_start();
set_security_headers();
if (!isset($_SESSION['pending_2fa_setup'])) {
    header('Location: login.php');
    exit;
}
$user_id = $_SESSION['pending_2fa_setup'];
// Get user info
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$user_id]);
$user = $stmt->fetch();
if (!$user) {
    header('Location: login.php');
    exit;
}
$error = '';
$success = false;
// Generate new secret if not set
if (!isset($_SESSION['temp_2fa_secret'])) {
    $_SESSION['temp_2fa_secret'] = generate_2fa_secret();
}
$secret = $_SESSION['temp_2fa_secret'];
$qr_url = get_2fa_qrcode_url($user['email'], $secret);
// Handle verification
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request.';
    } else {
        $code = trim($_POST['verification_code'] ?? '');
        
        if (empty($code)) {
            $error = 'Please enter the verification code.';
        } elseif (!verify_2fa_code($secret, $code)) {
            $error = 'Invalid verification code. Please try again.';
        } else {
            // Enable 2FA
            $backup_codes = generate_backup_codes();
            $stmt = $pdo->prepare("UPDATE users SET two_factor_enabled = 1, two_factor_secret = ?, two_factor_verified = 1, backup_codes = ? WHERE id = ?");
            $stmt->execute([$secret, json_encode($backup_codes), $user_id]);
            
            // Check if user wants to remember device
            $remember_device = isset($_POST['remember_device']);
            if ($remember_device) {
                $token = create_trusted_device($pdo, $user_id, 30);
                set_trusted_device_cookie($token, 30);
            }
            
            // Complete login
            secure_session_regenerate();
            unset($_SESSION['pending_2fa_setup']);
            unset($_SESSION['temp_2fa_secret']);
            
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['full_name'] = $user['full_name'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['last_activity'] = time();
            $_SESSION['2fa_verified'] = true;
            $_SESSION['require_2fa'] = true;
            
            audit_log($pdo, $user['id'], $user['username'], $user['role'], '2fa_enabled', 'user', $user_id, $user['username'], 'Mandatory 2FA enabled on first login', $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
            audit_log($pdo, $user['id'], $user['username'], $user['role'], 'login', null, null, null, 'User logged in after mandatory 2FA setup', $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
            
            header('Location: dashboard.php');
            exit;
        }
    }
}
$csrf = csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>DigiCustody — Setup Two-Factor Authentication</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#060d1a;--surface:#0c1526;--surface2:#111d30;--border:rgba(255,255,255,0.08);--border-focus:rgba(201,168,76,0.55);--gold:#c9a84c;--gold2:#e2bc6a;--text:#f0f4fa;--muted:#6b82a0;--dim:#2e4060;--danger:#f87171;--success:#4ade80;}
html,body{height:100%;font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);}
#cv{position:fixed;inset:0;z-index:0;}
.page{position:relative;z-index:1;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
.card{width:100%;max-width:500px;background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:40px 36px 32px;animation:up .5s cubic-bezier(.22,.68,0,1.15) both;}
@keyframes up{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
.logo-row{display:flex;align-items:center;gap:10px;margin-bottom:30px;}
.lmark{width:40px;height:40px;border-radius:10px;background:linear-gradient(135deg,var(--gold),#7a5010);display:flex;align-items:center;justify-content:center;font-size:18px;color:#060d1a;flex-shrink:0;}
.lname{font-family:'Space Grotesk',sans-serif;font-size:18px;font-weight:700;color:var(--text);}
.lname span{color:var(--gold);}
.ttl{font-family:'Space Grotesk',sans-serif;font-size:21px;font-weight:600;color:var(--text);margin-bottom:4px;}
.sub{font-size:13px;color:var(--muted);margin-bottom:26px;line-height:1.6;}
.alert{display:flex;align-items:center;gap:8px;padding:10px 13px;border-radius:9px;font-size:13px;margin-bottom:18px;animation:fi .25s ease;}
@keyframes fi{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
.ae{background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.22);color:var(--danger);}
.ao{background:rgba(74,222,128,0.08);border:1px solid rgba(74,222,128,0.22);color:var(--success);}
.warning{background:rgba(251,191,36,0.08);border:1px solid rgba(251,191,36,0.22);color:#fbbf24;}
.twofa-grid{display:grid;grid-template-columns:1fr 1fr;gap:25px;align-items:start;}
@media(max-width:500px){.twofa-grid{grid-template-columns:1fr;}}
.qr-box{text-align:center;padding:20px;background:var(--surface2);border-radius:12px;border:1px solid var(--border);}
.qr-box img{max-width:180px;border-radius:8px;}
.secret-code{font-family:monospace;font-size:14px;letter-spacing:2px;padding:12px 16px;background:var(--surface2);border-radius:8px;color:var(--gold);margin-top:12px;word-break:break-all;font-size:13px;}
.verify-box{padding:15px 0;}
.form-group{margin-bottom:18px;}
.form-group label{display:block;font-size:11px;font-weight:500;color:var(--muted);letter-spacing:.7px;text-transform:uppercase;margin-bottom:8px;}
.form-group input{width:100%;padding:14px;background:var(--surface2);border:1px solid var(--border);border-radius:9px;color:var(--text);font-size:18px;text-align:center;letter-spacing:8px;outline:none;transition:border-color .2s;}
.form-group input:focus{border-color:var(--border-focus);}
.form-group input::placeholder{color:var(--dim);letter-spacing:4px;}
.btn{width:100%;padding:14px;background:var(--gold);border:none;border-radius:9px;font-family:'Space Grotesk',sans-serif;font-size:14.5px;font-weight:600;color:#060d1a;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px;transition:background .2s,transform .15s;}
.btn:hover{background:var(--gold2);transform:translateY(-1px);}
.remember-me{display:flex;align-items:center;gap:8px;margin-bottom:15px;cursor:pointer;}
.remember-me input{width:auto;accent-color:var(--gold);}
.remember-me span{font-size:13px;color:var(--muted);}
.user-info{text-align:center;margin-bottom:20px;}
.user-info .avatar{width:50px;height:50px;border-radius:50%;background:linear-gradient(135deg,var(--gold),#7a5010);display:flex;align-items:center;justify-content:center;margin:0 auto 8px;font-size:20px;color:#060d1a;}
.user-info .name{font-weight:600;color:var(--text);font-size:14px;}
.user-info .email{font-size:12px;color:var(--muted);}
@media(max-width:440px){.card{padding:30px 22px 26px;}}
</style>
</head>
<body>
<canvas id="cv"></canvas>
<div class="page">
  <div class="card">
    <div class="logo-row" style="justify-content:center;">
      <div class="lmark"><i class="fas fa-shield-halved"></i></div>
    </div>
    <div class="ttl" style="text-align:center;">Setup Two-Factor Authentication</div>
    <p class="sub" style="text-align:center;">This is required for your account. Set up your authenticator app to continue.</p>
    <div class="alert warning" style="margin-bottom:20px;">
      <i class="fas fa-exclamation-triangle"></i>
      <span>You must set up 2FA to access the system. This cannot be skipped.</span>
    </div>
    <?php if($error): ?>
      <div class="alert ae"><i class="fas fa-circle-exclamation"></i><?= e($error) ?></div>
    <?php endif; ?>
    <div class="user-info">
      <div class="avatar"><i class="fas fa-user"></i></div>
      <div class="name"><?= e($user['full_name']) ?></div>
      <div class="email"><?= e($user['email']) ?></div>
    </div>
    <div class="twofa-grid">
      <div>
        <h4 style="margin-bottom:10px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;">Step 1: Scan QR Code</h4>
        <div class="qr-box">
          <img src="<?= e($qr_url) ?>" alt="QR Code">
          <div class="secret-code"><?= chunk_split($secret, 4, ' ') ?></div>
        </div>
        <p style="margin-top:12px;font-size:12px;color:var(--muted);">Scan with Google Authenticator, Authy, or any TOTP app.</p>
      </div>
      
      <div class="verify-box">
        <h4 style="margin-bottom:10px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;">Step 2: Verify Code</h4>
        <form method="POST">
          <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
          <div class="form-group">
            <input type="text" name="verification_code" placeholder="000000" maxlength="6" pattern="[0-9]{6}" inputmode="numeric" autocomplete="off" required autofocus>
          </div>
          <label class="remember-me">
            <input type="checkbox" name="remember_device" value="1">
            <span>Remember this account for 30 days</span>
          </label>
          <button type="submit" class="btn"><i class="fas fa-check"></i> Enable 2FA & Continue</button>
        </form>
      </div>
    </div>
  </div>
</div>
<script>
(function(){
  const c=document.getElementById('cv'),ctx=c.getContext('2d');
  let W,H,pts=[];
  function resize(){W=c.width=innerWidth;H=c.height=innerHeight;}
  resize();window.addEventListener('resize',resize);
  for(let i=0;i<40;i++)pts.push({x:Math.random()*2000,y:Math.random()*2000,vx:(Math.random()-.5)*.2,vy:(Math.random()-.5)*.2,r:Math.random()*1.2+.4});
  function draw(){
    ctx.clearRect(0,0,W,H);
    pts.forEach(p=>{
      p.x+=p.vx;p.y+=p.vy;
      if(p.x<0||p.x>W)p.vx*=-1;
      if(p.y<0||p.y>H)p.vy*=-1;
      ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
      ctx.fillStyle='rgba(201,168,76,0.5)';ctx.fill();
    });
    pts.forEach((a,i)=>pts.slice(i+1).forEach(b=>{
      const dx=a.x-b.x,dy=a.y-b.y,d=Math.sqrt(dx*dx+dy*dy);
      if(d<120){ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.strokeStyle=`rgba(201,168,76,${.1*(1-d/120)})`;ctx.lineWidth=.4;ctx.stroke();}
    }));
    requestAnimationFrame(draw);
  }
  draw();
})();
document.querySelector('input[name="verification_code"]').addEventListener('input',function(){
  this.value=this.value.replace(/\D/g,'').slice(0,6);
});
</script>
</body>
</html>
