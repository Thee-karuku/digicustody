<?php
session_start();
require_once 'config/db.php';
require_once 'config/functions.php';

set_security_headers();
set_secure_session_config();

if (isset($_SESSION['user_id'])) { header('Location: dashboard.php'); exit; }

$error = '';
$success = '';
$token = trim($_GET['token'] ?? '');

if (empty($token)) {
    header('Location: login.php');
    exit;
}

$result = verify_password_reset_token($pdo, $token);
if (!$result['success']) {
    $error = $result['message'] ?? 'Invalid or expired reset token.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($error)) {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request. Please try again.';
    } else {
        $password = $_POST['password'] ?? '';
        $confirm = $_POST['confirm_password'] ?? '';

        if (empty($password) || empty($confirm)) {
            $error = 'Both fields are required.';
        } elseif (strlen($password) < 8) {
            $error = 'Password must be at least 8 characters.';
        } elseif ($password !== $confirm) {
            $error = 'Passwords do not match.';
        } else {
            $reset_result = reset_password($pdo, $token, $password);
            if ($reset_result['success']) {
                $success = 'Password has been reset successfully. You can now sign in with your new password.';
            } else {
                $error = $reset_result['message'] ?? 'Failed to reset password.';
            }
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
<title>DigiCustody — New Password</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#060d1a;--surface:#0c1526;--surface2:#111d30;
  --border:rgba(255,255,255,0.08);--border-focus:rgba(201,168,76,0.55);
  --gold:#c9a84c;--gold2:#e2bc6a;
  --text:#f0f4fa;--muted:#6b82a0;--dim:#2e4060;
  --danger:#f87171;--success:#4ade80;
}
html,body{height:100%;font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);}
#cv{position:fixed;inset:0;z-index:0;}
.page{position:relative;z-index:1;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
.card{width:100%;max-width:420px;background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:40px 36px 32px;animation:up .5s cubic-bezier(.22,.68,0,1.15) both;}
@keyframes up{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
.logo-row{display:flex;align-items:center;gap:10px;margin-bottom:30px;}
.lmark{width:36px;height:36px;border-radius:9px;background:linear-gradient(135deg,var(--gold),#7a5010);display:flex;align-items:center;justify-content:center;font-size:15px;color:#060d1a;flex-shrink:0;}
.lname{font-family:'Space Grotesk',sans-serif;font-size:18px;font-weight:700;color:var(--text);}
.lname span{color:var(--gold);}
.lsep{width:1px;height:18px;background:var(--border);margin:0 2px;}
.ltag{font-size:10.5px;color:var(--muted);letter-spacing:.3px;}
.ttl{font-family:'Space Grotesk',sans-serif;font-size:21px;font-weight:600;color:var(--text);margin-bottom:4px;}
.sub{font-size:13px;color:var(--muted);margin-bottom:26px;line-height:1.6;}
.alert{display:flex;align-items:center;gap:8px;padding:10px 13px;border-radius:9px;font-size:13px;margin-bottom:18px;animation:fi .25s ease;}
@keyframes fi{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
.ae{background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.22);color:var(--danger);}
.ao{background:rgba(74,222,128,0.08);border:1px solid rgba(74,222,128,0.22);color:var(--success);}
.fld{margin-bottom:18px;}
.fld label{display:block;font-size:11px;font-weight:500;color:var(--muted);letter-spacing:.7px;text-transform:uppercase;margin-bottom:6px;}
.iw{position:relative;}
.iw .ic{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--dim);font-size:12px;pointer-events:none;transition:color .2s;}
.iw input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:9px;padding:11px 40px 11px 36px;font-size:14px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s,box-shadow .2s;}
.iw input::placeholder{color:var(--dim);}
.iw input:focus{border-color:var(--border-focus);box-shadow:0 0 0 3px rgba(201,168,76,0.07);}
.iw:focus-within .ic{color:var(--gold);}
.eye{position:absolute;right:11px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--dim);cursor:pointer;font-size:12px;padding:2px;transition:color .2s;}
.eye:hover{color:var(--gold);}
.strength{margin-top:6px;height:4px;background:rgba(255,255,255,0.1);border-radius:4px;overflow:hidden;}
.strength-fill{height:100%;transition:width .3s,background .3s;}
.bsign{width:100%;padding:12px;background:var(--gold);border:none;border-radius:9px;font-family:'Space Grotesk',sans-serif;font-size:14.5px;font-weight:600;color:#060d1a;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:7px;transition:background .2s,transform .15s,box-shadow .2s;margin-top:8px;}
.bsign:hover:not(:disabled){background:var(--gold2);transform:translateY(-1px);box-shadow:0 5px 18px rgba(201,168,76,0.22);}
.bsign:disabled{opacity:0.5;cursor:not-allowed;}
.brow{text-align:center;margin-top:20px;padding-top:18px;border-top:1px solid var(--border);}
.brow a{font-size:13px;color:var(--muted);text-decoration:none;transition:color .2s;}
.brow a:hover{color:var(--gold);}
.hint{font-size:12px;color:var(--muted);margin-bottom:18px;line-height:1.5;}
@media(max-width:440px){.card{padding:30px 22px 26px;}}
</style>
</head>
<body>
<canvas id="cv"></canvas>
<div class="page">
  <div class="card">
    <div class="logo-row">
      <div class="lmark"><i class="fas fa-shield-halved"></i></div>
      <span class="lname">Digi<span>Custody</span></span>
      <div class="lsep"></div>
      <span class="ltag">Evidence Platform</span>
    </div>
    <div class="ttl">Set New Password</div>
    <p class="sub">Enter your new password below.</p>

    <?php if($error): ?><div class="alert ae"><i class="fas fa-circle-exclamation"></i><?= e($error) ?></div><?php endif; ?>
    <?php if($success): ?><div class="alert ao"><i class="fas fa-circle-check"></i><?= e($success) ?></div><?php endif; ?>

    <?php if(empty($error) && empty($success)): ?>
    <form method="POST" action="reset_password.php?token=<?= urlencode($token) ?>">
      <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
      <div class="fld">
        <label>New Password</label>
        <div class="iw">
          <i class="fas fa-lock ic"></i>
          <input type="password" name="password" id="pw" placeholder="Minimum 8 characters" minlength="8" required>
          <button type="button" class="eye" onclick="togglePw()"><i class="fas fa-eye" id="ei"></i></button>
        </div>
        <div class="strength"><div class="strength-fill" id="strength-fill" style="width:0%"></div></div>
        <small id="strength-text" style="color:var(--muted);font-size:11px;margin-top:4px;display:block;"></small>
      </div>
      <div class="fld">
        <label>Confirm Password</label>
        <div class="iw">
          <i class="fas fa-lock ic"></i>
          <input type="password" name="confirm_password" id="cpw" placeholder="Re-enter password" required>
          <button type="button" class="eye" onclick="toggleCp()"><i class="fas fa-eye" id="cei"></i></button>
        </div>
      </div>
      <button type="submit" class="bsign" id="submit-btn"><i class="fas fa-key"></i> Reset Password</button>
    </form>
    <?php endif; ?>

    <div class="brow">
      <a href="login.php"><i class="fas fa-arrow-left"></i> Back to Sign In</a>
    </div>
  </div>
</div>
<script>
function togglePw(){
  const f=document.getElementById('pw'),i=document.getElementById('ei');
  f.type=f.type==='password'?'text':'password';
  i.classList.toggle('fa-eye');
  i.classList.toggle('fa-eye-slash');
}
function toggleCp(){
  const f=document.getElementById('cpw'),i=document.getElementById('cei');
  f.type=f.type==='password'?'text':'password';
  i.classList.toggle('fa-eye');
  i.classList.toggle('fa-eye-slash');
}
document.getElementById('pw').addEventListener('input',function(){
  const p=this.value;
  const fill=document.getElementById('strength-fill');
  const text=document.getElementById('strength-text');
  let score=0,msg='',color='#f87171';
  if(p.length>=8)score++;
  if(p.length>=12)score++;
  if(/[A-Z]/.test(p))score++;
  if(/[a-z]/.test(p))score++;
  if(/[0-9]/.test(p))score++;
  if(/[^A-Za-z0-9]/.test(p))score++;
  const pct=Math.min(100,(score/6)*100);
  fill.style.width=pct+'%';
  if(score<=2){msg='Weak';color='#f87171';}
  else if(score<=4){msg='Medium';color='#f59e0b';}
  else{msg='Strong';color='#4ade80';}
  fill.style.background=color;
  text.textContent=msg;
});
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
</script>
</body>
</html>
