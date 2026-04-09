<?php
require_once 'config/db.php';
require_once 'config/functions.php';

set_secure_session_config();
session_start();
set_security_headers();

if (isset($_SESSION['user_id'])) { header('Location: dashboard.php'); exit; }

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Rate limiting: max 3 requests per 15 minutes per IP
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM rate_limits WHERE ip_address = ? AND action = 'forgot_password' AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)");
    $stmt->execute([$ip]);
    $count = (int)$stmt->fetchColumn();
    if ($count >= 3) {
        $error = 'Too many requests. Please wait before trying again.';
    } elseif (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request. Please try again.';
    } else {
        $email = trim($_POST['email'] ?? '');
        if (empty($email)) {
            $error = 'Please enter your email address.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Please enter a valid email address.';
        } else {
            $result = generate_password_reset_token($pdo, $email);
            if ($result['success'] && isset($result['token'])) {
                $pdo->prepare("INSERT INTO rate_limits (ip_address, action) VALUES (?, 'forgot_password')")->execute([$ip]);
                send_password_reset_email($result['email'], $result['token']);
            }
            $success = 'If an account exists with this email, a password reset link has been sent.';
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
<title>DigiCustody — Forgot Password</title>
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
.iw input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:9px;padding:11px 12px 11px 36px;font-size:14px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s,box-shadow .2s;}
.iw input::placeholder{color:var(--dim);}
.iw input:focus{border-color:var(--border-focus);box-shadow:0 0 0 3px rgba(201,168,76,0.07);}
.iw:focus-within .ic{color:var(--gold);}
.bsign{width:100%;padding:12px;background:var(--gold);border:none;border-radius:9px;font-family:'Space Grotesk',sans-serif;font-size:14.5px;font-weight:600;color:#060d1a;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:7px;transition:background .2s,transform .15s,box-shadow .2s;}
.bsign:hover{background:var(--gold2);transform:translateY(-1px);box-shadow:0 5px 18px rgba(201,168,76,0.22);}
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
    <div class="ttl">Reset Password</div>
    <p class="sub">Enter your email address and we'll send you a link to reset your password.</p>

    <?php if($error): ?><div class="alert ae"><i class="fas fa-circle-exclamation"></i><?= e($error) ?></div><?php endif; ?>
    <?php if($success): ?><div class="alert ao"><i class="fas fa-circle-check"></i><?= e($success) ?></div><?php endif; ?>

    <form method="POST" action="forgot_password.php">
      <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
      <p class="hint">Check your email for the reset link. The link expires in 1 hour.</p>
      <div class="fld">
        <label>Email Address</label>
        <div class="iw">
          <i class="fas fa-envelope ic"></i>
          <input type="email" name="email" placeholder="you@example.com" required>
        </div>
      </div>
      <button type="submit" class="bsign"><i class="fas fa-paper-plane"></i> Send Reset Link</button>
    </form>

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
</script>
</body>
</html>
