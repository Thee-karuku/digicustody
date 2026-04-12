<?php
require_once 'config/db.php';
require_once 'config/functions.php';

set_secure_session_config();
session_start();
set_security_headers();
if (!isset($_SESSION['pending_2fa_user'])) {
    header('Location: login.php');
    exit;
}
$error = '';
$user_id = $_SESSION['pending_2fa_user'];
$is_backup = false;
// Get user info
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$user_id]);
$user = $stmt->fetch();
if (!$user) {
    header('Location: login.php');
    exit;
}
// Handle verification
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $attempts = $_SESSION['2fa_attempts'] ?? 0;
    if ($attempts >= 5) {
        unset($_SESSION['pending_2fa_user'], $_SESSION['2fa_attempts']);
        header('Location: login.php?error=locked');
        exit;
    }
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request.';
    } else {
        $code = trim($_POST['code'] ?? '');
        $remember_device = isset($_POST['remember_device']);
        
        if (!empty($user['two_factor_secret'])) {
            if (verify_2fa_code($user['two_factor_secret'], $code)) {
                unset($_SESSION['2fa_attempts']);
                // 2FA successful
                secure_session_regenerate();
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['full_name'] = $user['full_name'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['last_activity'] = time();
                $_SESSION['2fa_verified'] = true;
                $_SESSION['require_2fa'] = true;
                
                // Remember device for 30 days if checkbox was checked
                if ($remember_device) {
                    $token = bin2hex(random_bytes(32));
                    $token_hash = hash('sha256', $token);
                    $expires_at = date('Y-m-d H:i:s', strtotime('+30 days'));
                    $device_name = parse_user_agent($_SERVER['HTTP_USER_AGENT'] ?? '');
                    $ip = $_SERVER['REMOTE_ADDR'] ?? null;
                    $user_agent = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500);
                    
                    $pdo->prepare("INSERT INTO trusted_devices (user_id, token_hash, device_name, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
                        ->execute([$user['id'], $token_hash, $device_name, $ip, $user_agent, $expires_at]);
                    
                    setcookie('trusted_device', $token, [
                        'expires' => time() + (30 * 86400),
                        'path' => '/',
                        'domain' => '',
                        'secure' => false,
                        'httponly' => true,
                        'samesite' => 'Lax'
                    ]);
                }
                
                unset($_SESSION['pending_2fa_user']);
                
                audit_log($pdo, $user['id'], $user['username'], $user['role'], 'login_2fa', null, null, null, '2FA verification successful' . ($remember_device ? ' (device remembered for 30 days)' : ''), $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                
                header('Location: dashboard.php');
                exit;
            }
        }
        
        // Check backup codes
        if (!empty($user['backup_codes'])) {
            $result = verify_backup_code($user['backup_codes'], $code);
            if ($result['valid']) {
                // Update backup codes
                $pdo->prepare("UPDATE users SET backup_codes = ? WHERE id = ?")
                    ->execute([json_encode($result['remaining_codes']), $user_id]);
                
                secure_session_regenerate();
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['full_name'] = $user['full_name'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['last_activity'] = time();
                $_SESSION['2fa_verified'] = true;
                $_SESSION['require_2fa'] = true;
                
                // Remember device for 30 days if checkbox was checked
                if ($remember_device) {
                    $token = bin2hex(random_bytes(32));
                    $token_hash = hash('sha256', $token);
                    $expires_at = date('Y-m-d H:i:s', strtotime('+30 days'));
                    $device_name = parse_user_agent($_SERVER['HTTP_USER_AGENT'] ?? '');
                    $ip = $_SERVER['REMOTE_ADDR'] ?? null;
                    $user_agent = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500);
                    
                    $pdo->prepare("INSERT INTO trusted_devices (user_id, token_hash, device_name, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
                        ->execute([$user['id'], $token_hash, $device_name, $ip, $user_agent, $expires_at]);
                    
                    setcookie('trusted_device', $token, [
                        'expires' => time() + (30 * 86400),
                        'path' => '/',
                        'domain' => '',
                        'secure' => false,
                        'httponly' => true,
                        'samesite' => 'Lax'
                    ]);
                }
                
                unset($_SESSION['pending_2fa_user']);
                
                audit_log($pdo, $user['id'], $user['username'], $user['role'], 'login_2fa_backup', null, null, null, '2FA backup code used' . ($remember_device ? ' (device remembered for 30 days)' : ''), $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                
                header('Location: dashboard.php');
                exit;
            }
        }
        
        $error = 'Invalid verification code.';
    }
}
$csrf = csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>DigiCustody — Two-Factor Authentication</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#060d1a;--surface:#0c1526;--surface2:#111d30;--border:rgba(255,255,255,0.08);--border-focus:rgba(201,168,76,0.55);--gold:#c9a84c;--gold2:#e2bc6a;--text:#f0f4fa;--muted:#6b82a0;--dim:#2e4060;--danger:#f87171;--success:#4ade80;}
html,body{height:100%;font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);}
#cv{position:fixed;inset:0;z-index:0;}
.page{position:relative;z-index:1;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
.card{width:100%;max-width:420px;background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:40px 36px 32px;animation:up .5s cubic-bezier(.22,.68,0,1.15) both;}
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
.fld{margin-bottom:18px;}
.fld label{display:block;font-size:11px;font-weight:500;color:var(--muted);letter-spacing:.7px;text-transform:uppercase;margin-bottom:6px;}
.code-input{width:100%;padding:16px;background:var(--surface2);border:1px solid var(--border);border-radius:9px;font-size:28px;text-align:center;letter-spacing:12px;color:var(--text);outline:none;font-family:'Space Grotesk',sans-serif;transition:border-color .2s,box-shadow .2s;}
.code-input::placeholder{letter-spacing:12px;color:var(--dim);}
.code-input:focus{border-color:var(--border-focus);box-shadow:0 0 0 3px rgba(201,168,76,0.07);}
.btn{width:100%;padding:14px;background:var(--gold);border:none;border-radius:9px;font-family:'Space Grotesk',sans-serif;font-size:14.5px;font-weight:600;color:#060d1a;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px;transition:background .2s,transform .15s;}
.btn:hover{background:var(--gold2);transform:translateY(-1px);}
.brow{text-align:center;margin-top:20px;padding-top:18px;border-top:1px solid var(--border);}
.brow a{font-size:13px;color:var(--muted);text-decoration:none;transition:color .2s;}
.brow a:hover{color:var(--gold);}
.user-info{text-align:center;margin-bottom:20px;}
.user-info .avatar{width:60px;height:60px;border-radius:50%;background:linear-gradient(135deg,var(--gold),#7a5010);display:flex;align-items:center;justify-content:center;margin:0 auto 10px;font-size:24px;color:#060d1a;}
.user-info .name{font-weight:600;color:var(--text);}
.user-info .email{font-size:13px;color:var(--muted);}
.hint{font-size:12px;color:var(--muted);text-align:center;margin-bottom:15px;}
.hint a{color:var(--gold);}
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
    <div class="ttl" style="text-align:center;">Two-Factor Authentication</div>
    <p class="sub" style="text-align:center;">Enter the 6-digit code from your authenticator app.</p>
    <?php if($error): ?>
      <div class="alert ae"><i class="fas fa-circle-exclamation"></i><?= e($error) ?></div>
    <?php endif; ?>
    <div class="user-info">
      <div class="avatar"><i class="fas fa-user"></i></div>
      <div class="name"><?= e($user['full_name']) ?></div>
      <div class="email"><?= e($user['email']) ?></div>
    </div>
    <form method="POST">
      <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
      <div class="fld">
        <label style="text-align:center;display:block;">Verification Code</label>
        <input type="text" name="code" class="code-input" placeholder="000000" maxlength="6" pattern="[0-9]{6}" autocomplete="off" inputmode="numeric" required autofocus>
      </div>
      <label class="remember-me" style="display:flex;align-items:center;gap:8px;margin-bottom:18px;cursor:pointer;">
        <input type="checkbox" name="remember_device" value="1" style="width:auto;accent-color:var(--gold);">
        <span style="font-size:13px;color:var(--muted);">Remember this account for 30 days</span>
      </label>
      <button type="submit" class="btn"><i class="fas fa-check"></i> Verify</button>
    </form>
    <p class="hint">Use a <a href="2fa_backup.php">backup code</a> if you can't access your authenticator app.</p>
    <div class="brow">
      <a href="login.php"><i class="fas fa-arrow-left"></i> Back to Sign In</a>
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
document.querySelector('.code-input').addEventListener('input',function(){
  this.value=this.value.replace(/\D/g,'').slice(0,6);
});
</script>
</body>
</html>
