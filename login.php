<?php
require_once 'config/db.php';
require_once 'config/functions.php';

set_secure_session_config();
session_start();
set_security_headers();

cleanup_old_login_attempts($pdo);
if (isset($_SESSION['user_id'])) { header('Location: dashboard.php'); exit; }

$error = $req_error = $req_success = '';
$show_modal = false;
$locked_until = 0;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Security token mismatch. Please refresh and try again.';
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

        if (empty($username) || empty($password)) {
            $error = 'Both fields are required.';
        } else {
            if (is_locked_out($pdo, $username, $ip)) {
                $locked_until = get_lockout_remaining($pdo, $username, $ip);
                $mins = floor($locked_until / 60);
                $secs = $locked_until % 60;
                $time_str = $mins > 0 ? "{$mins}m {$secs}s" : "{$secs}s";
                $error = "Too many failed attempts. Try again in {$time_str}.";
            } else {
                $stmt = $pdo->prepare("SELECT * FROM users WHERE (username=? OR email=?) AND status='active' LIMIT 1");
                $stmt->execute([$username, $username]);
                $user = $stmt->fetch();
                if ($user && password_verify($password, $user['password'])) {
                    record_login_attempt($pdo, $username, $ip, true);
                    
                    // Check if mandatory 2FA is enabled system-wide
                    $mandatory_2fa = is_mandatory_2fa_enabled($pdo);
                    
                    // Check if 2FA is enabled
                    if ($user['two_factor_enabled'] == 1) {
                        // Check if user has a valid trusted device cookie
                        $trusted_token = $_COOKIE['trusted_device'] ?? null;
                        $device_valid = false;
                        if ($trusted_token) {
                            $device_valid = validate_trusted_device($pdo, $user['id'], $trusted_token);
                        }
                        if ($device_valid) {
                            // Skip 2FA for trusted device
                            secure_session_regenerate();
                            $_SESSION['user_id']       = $user['id'];
                            $_SESSION['username']      = $user['username'];
                            $_SESSION['full_name']     = $user['full_name'];
                            $_SESSION['role']          = $user['role'];
                            $_SESSION['email']         = $user['email'];
                            $_SESSION['last_activity'] = time();
                            $_SESSION['2fa_verified']  = true;
                            $_SESSION['require_2fa']   = true;
                            $pdo->prepare("UPDATE users SET last_login=NOW() WHERE id=?")->execute([$user['id']]);
                            audit_log($pdo,$user['id'],$user['username'],$user['role'],'login',null,null,null,'Login via trusted device (2FA skipped)',$ip,$_SERVER['HTTP_USER_AGENT']??'');
                            header('Location: dashboard.php'); exit;
                        }
                        $_SESSION['pending_2fa_user'] = $user['id'];
                        header('Location: verify_2fa.php'); exit;
                    }
                    
                    // If mandatory 2FA is enabled and user hasn't set it up, force setup
                    if ($mandatory_2fa && $user['two_factor_enabled'] != 1) {
                        $_SESSION['pending_2fa_setup'] = $user['id'];
                        header('Location: setup_2fa_required.php'); exit;
                    }
                    
                    secure_session_regenerate();
                    $_SESSION['user_id']       = $user['id'];
                    $_SESSION['username']      = $user['username'];
                    $_SESSION['full_name']     = $user['full_name'];
                    $_SESSION['role']          = $user['role'];
                    $_SESSION['email']         = $user['email'];
                    $_SESSION['last_activity'] = time();
                    $_SESSION['require_2fa']   = ($user['two_factor_enabled'] == 1);
                    $pdo->prepare("UPDATE users SET last_login=NOW() WHERE id=?")->execute([$user['id']]);
                    audit_log($pdo,$user['id'],$user['username'],$user['role'],'login',null,null,null,'User logged in',$ip,$_SERVER['HTTP_USER_AGENT']??'');
                    header('Location: dashboard.php'); exit;
                } else {
                    record_login_attempt($pdo, $username, $ip, false);
                    $attempts_left = LOGIN_MAX_ATTEMPTS - get_failed_attempts($pdo, $username, $ip);
                    if ($attempts_left <= 0) {
                        $locked_until = get_lockout_remaining($pdo, $username, $ip);
                        $mins = floor($locked_until / 60);
                        $secs = $locked_until % 60;
                        $time_str = $mins > 0 ? "{$mins}m {$secs}s" : "{$secs}s";
                        $error = "Account locked. Try again in {$time_str}.";
                    } elseif ($attempts_left <= 2) {
                        $error = "Incorrect username or password. {$attempts_left} attempt" . ($attempts_left !== 1 ? 's' : '') . " remaining.";
                    } else {
                        $error = 'Incorrect username or password.';
                    }
                    audit_log($pdo,null,$username,null,'login_failed',null,null,null,"Failed login: $username",$ip,$_SERVER['HTTP_USER_AGENT']??'');
                }
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'request_account') {
    $show_modal = true;
    $full_name  = trim($_POST['req_full_name'] ?? '');
    $email      = trim($_POST['req_email'] ?? '');
    $phone      = trim($_POST['req_phone'] ?? '');
    $department = trim($_POST['req_department'] ?? '');
    $badge      = trim($_POST['req_badge'] ?? '');
    $role       = in_array($_POST['req_role']??'',['investigator','analyst']) ? $_POST['req_role'] : 'analyst';
    $reason     = trim($_POST['req_reason'] ?? '');
    if (empty($full_name)||empty($email)||empty($reason)) {
        $req_error = 'Full name, email, and reason are required.';
    } elseif (!filter_var($email,FILTER_VALIDATE_EMAIL)) {
        $req_error = 'Please enter a valid email address.';
    } else {
        $chk2 = $pdo->prepare("SELECT id FROM users WHERE email=? LIMIT 1");
        $chk2->execute([$email]);
        if ($chk2->fetch()) {
            $req_error = 'An account with this email address already exists. Contact your administrator if you need help logging in.';
        } else {
            $chk = $pdo->prepare("SELECT id FROM account_requests WHERE email=? AND status='pending' LIMIT 1");
            $chk->execute([$email]);
            if ($chk->fetch()) {
                $req_error = 'A pending request already exists for this email.';
            } else {
                $pdo->prepare("INSERT INTO account_requests (full_name,email,phone,department,badge_number,requested_role,reason) VALUES(?,?,?,?,?,?,?)")
                    ->execute([$full_name,$email,$phone,$department,$badge,$role,$reason]);
                $rid = $pdo->lastInsertId();
                foreach ($pdo->query("SELECT id FROM users WHERE role='admin' AND status='active'")->fetchAll() as $adm)
                    send_notification($pdo,$adm['id'],'New Account Request',"Request from $full_name for role: $role",'info','account_request',$rid);
                audit_log($pdo,null,$email,null,'account_request_submitted','account_request',$rid,$full_name,"Request by $full_name");
                $req_success = 'Request submitted successfully. An administrator will contact you.';
                $show_modal  = false;
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
<title>DigiCustody — Sign In</title>
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
html,body{height:100%;font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);overflow:hidden;}
#cv{position:fixed;inset:0;z-index:0;}
.page{position:relative;z-index:1;height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}

/* card */
.card{width:100%;max-width:400px;background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:40px 36px 32px;animation:up .5s cubic-bezier(.22,.68,0,1.15) both;}
@keyframes up{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}

/* logo */
.logo-row{display:flex;align-items:center;gap:10px;margin-bottom:30px;}
.lmark{width:36px;height:36px;border-radius:9px;background:linear-gradient(135deg,var(--gold),#7a5010);display:flex;align-items:center;justify-content:center;font-size:15px;color:#060d1a;flex-shrink:0;}
.lname{font-family:'Space Grotesk',sans-serif;font-size:18px;font-weight:700;color:var(--text);}
.lname span{color:var(--gold);}
.lsep{width:1px;height:18px;background:var(--border);margin:0 2px;}
.ltag{font-size:10.5px;color:var(--muted);letter-spacing:.3px;}

.ttl{font-family:'Space Grotesk',sans-serif;font-size:21px;font-weight:600;color:var(--text);margin-bottom:4px;}
.sub{font-size:13px;color:var(--muted);margin-bottom:26px;}

/* alert */
.alert{display:flex;align-items:center;gap:8px;padding:10px 13px;border-radius:9px;font-size:13px;margin-bottom:18px;animation:fi .25s ease;}
@keyframes fi{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
.ae{background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.22);color:var(--danger);}
.ao{background:rgba(74,222,128,0.08);border:1px solid rgba(74,222,128,0.22);color:var(--success);}

/* fields */
.fld{margin-bottom:15px;}
.fld label{display:block;font-size:11px;font-weight:500;color:var(--muted);letter-spacing:.7px;text-transform:uppercase;margin-bottom:6px;}
.iw{position:relative;}
.iw .ic{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--dim);font-size:12px;pointer-events:none;transition:color .2s;}
.iw input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:9px;padding:11px 12px 11px 36px;font-size:14px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s,box-shadow .2s;}
.iw input::placeholder{color:var(--dim);}
.iw input:focus{border-color:var(--border-focus);box-shadow:0 0 0 3px rgba(201,168,76,0.07);}
.iw input:focus~.ic,.iw:focus-within .ic{color:var(--gold);}
.eye{position:absolute;right:11px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--dim);cursor:pointer;font-size:12px;padding:2px;transition:color .2s;}
.eye:hover{color:var(--gold);}

/* submit */
.bsign{width:100%;margin-top:6px;padding:12px;background:var(--gold);border:none;border-radius:9px;font-family:'Space Grotesk',sans-serif;font-size:14.5px;font-weight:600;color:#060d1a;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:7px;transition:background .2s,transform .15s,box-shadow .2s;}
.bsign:hover{background:var(--gold2);transform:translateY(-1px);box-shadow:0 5px 18px rgba(201,168,76,0.22);}
.bsign:active{transform:translateY(0);}
.spin{display:none;width:15px;height:15px;border:2px solid rgba(6,13,26,.25);border-top-color:#060d1a;border-radius:50%;animation:sp .7s linear infinite;}
@keyframes sp{to{transform:rotate(360deg)}}

/* request */
.rrow{text-align:center;margin-top:20px;padding-top:18px;border-top:1px solid var(--border);}
.rrow p{font-size:12px;color:var(--muted);margin-bottom:8px;}
.breq{background:none;border:1px solid var(--border);border-radius:8px;padding:8px 18px;font-size:13px;font-weight:500;color:var(--muted);cursor:pointer;display:inline-flex;align-items:center;gap:6px;transition:all .2s;font-family:'Inter',sans-serif;}
.breq:hover{border-color:var(--gold);color:var(--gold);background:rgba(201,168,76,0.05);}

/* modal */
.ov{position:fixed;inset:0;z-index:50;background:rgba(4,8,18,.9);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;padding:20px;animation:fi .2s ease;}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:16px;width:100%;max-width:480px;max-height:90vh;overflow-y:auto;animation:up .3s cubic-bezier(.22,.68,0,1.15) both;}
.mh{padding:22px 26px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;}
.mh h3{font-family:'Space Grotesk',sans-serif;font-size:17px;font-weight:600;color:var(--text);}
.mh h3 span{color:var(--gold);}
.xbtn{background:none;border:none;color:var(--muted);font-size:15px;cursor:pointer;padding:3px 5px;border-radius:5px;transition:all .2s;}
.xbtn:hover{color:var(--danger);background:rgba(248,113,113,0.08);}
.mb{padding:20px 26px;}
.mb .hint{font-size:12.5px;color:var(--muted);line-height:1.65;margin-bottom:18px;}
.mf{padding:12px 26px 22px;display:flex;gap:10px;}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.fld.pl input,.fld.pl select,.fld.pl textarea{padding-left:12px;}
.fld select{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:9px;padding:11px 12px;font-size:14px;color:var(--text);outline:none;font-family:'Inter',sans-serif;cursor:pointer;transition:border-color .2s;}
.fld select:focus{border-color:var(--border-focus);}
.fld select option{background:var(--surface);}
.fld textarea{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:9px;padding:11px 12px;font-size:14px;color:var(--text);outline:none;font-family:'Inter',sans-serif;resize:vertical;min-height:75px;transition:border-color .2s;}
.fld textarea:focus{border-color:var(--border-focus);}
.fld textarea::placeholder{color:var(--dim);}
.bsub{flex:1;padding:11px;background:var(--gold);border:none;border-radius:8px;font-family:'Space Grotesk',sans-serif;font-size:14px;font-weight:600;color:#060d1a;cursor:pointer;transition:all .2s;}
.bsub:hover{background:var(--gold2);transform:translateY(-1px);}
.bcan{padding:11px 16px;background:none;border:1px solid var(--border);border-radius:8px;font-size:13px;color:var(--muted);cursor:pointer;transition:all .2s;font-family:'Inter',sans-serif;}
.bcan:hover{border-color:var(--danger);color:var(--danger);}
.rh{margin-top:8px;padding:8px 11px;background:rgba(201,168,76,0.05);border:1px solid rgba(201,168,76,0.12);border-radius:7px;font-size:12px;color:var(--muted);line-height:1.6;}
.rh strong{color:var(--gold);}
@media(max-width:440px){.card{padding:30px 22px 26px;}.g2{grid-template-columns:1fr;}.mb,.mh,.mf{padding-left:18px;padding-right:18px;}}
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

    <div class="ttl">Sign in</div>
    <p class="sub">Access the secure evidence management system</p>

    <?php if($error): ?><div class="alert ae"><i class="fas fa-circle-exclamation"></i><?= e($error) ?></div><?php endif; ?>
    <?php if($req_success): ?><div class="alert ao"><i class="fas fa-circle-check"></i><?= e($req_success) ?></div><?php endif; ?>
    <?php if(($_GET['msg']??'')==='timeout'): ?><div class="alert ae"><i class="fas fa-clock"></i>Session expired. Please sign in again.</div><?php endif; ?>

    <form method="POST" action="login.php" id="lf">
      <input type="hidden" name="action" value="login">
      <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
      <div class="fld">
        <label>Username or Email</label>
        <div class="iw">
          <i class="fas fa-user ic"></i>
          <input type="text" name="username" placeholder="Enter your username" value="<?= e($_POST['username']??'') ?>" autocomplete="off" required>
        </div>
      </div>
      <div class="fld">
        <label>Password</label>
        <div class="iw">
          <i class="fas fa-lock ic"></i>
          <input type="password" name="password" id="pw" placeholder="Enter your password" autocomplete="off" required>
          <button type="button" class="eye" onclick="togglePw()" tabindex="-1"><i class="fas fa-eye" id="ei"></i></button>
        </div>
      </div>
      <button type="submit" class="bsign">
        <span id="bl"><i class="fas fa-arrow-right-to-bracket"></i> Sign In</span>
        <div class="spin" id="sp"></div>
      </button>
    </form>

    <div class="rrow" style="padding-top:12px;border-top:1px solid var(--border);margin-top:15px;">
      <a href="forgot_password.php" style="font-size:12px;color:var(--muted);text-decoration:none;"><i class="fas fa-key"></i> Forgot password?</a>
    </div>

    <div class="rrow" style="margin-top:15px;padding-top:15px;">
      <p>Don't have an account?</p>
      <button class="breq" onclick="openM()"><i class="fas fa-user-plus" style="font-size:11px"></i> Request access</button>
    </div>
  </div>
</div>

<!-- modal -->
<div class="ov" id="ov" style="display:none" onclick="ovClose(event)">
  <div class="modal" id="mb">
    <div class="mh">
      <h3>Request <span>Access</span></h3>
      <button class="xbtn" onclick="closeM()"><i class="fas fa-xmark"></i></button>
    </div>
    <form method="POST" action="login.php">
      <input type="hidden" name="action" value="request_account">
      <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
      <div class="mb">
        <?php if($req_error): ?><div class="alert ae" style="margin-bottom:14px"><i class="fas fa-circle-exclamation"></i><?= e($req_error) ?></div><?php endif; ?>
        <p class="hint">Fill in your details. The administrator will review your request and create your account.</p>
        <div class="g2">
          <div class="fld pl"><label>Full Name *</label><input type="text" name="req_full_name" placeholder="John Doe" value="<?= e($_POST['req_full_name']??'') ?>" required></div>
          <div class="fld pl"><label>Email *</label><input type="email" name="req_email" placeholder="you@example.com" value="<?= e($_POST['req_email']??'') ?>" required></div>
        </div>
        <div class="g2">
          <div class="fld pl"><label>Phone</label><input type="text" name="req_phone" placeholder="+254 7XX XXX XXX" value="<?= e($_POST['req_phone']??'') ?>"></div>
          <div class="fld pl"><label>Department</label><input type="text" name="req_department" placeholder="e.g. Forensics Unit" value="<?= e($_POST['req_department']??'') ?>"></div>
        </div>
        <div class="g2">
          <div class="fld pl"><label>Badge / Staff No.</label><input type="text" name="req_badge" placeholder="e.g. DCI-00123" value="<?= e($_POST['req_badge']??'') ?>"></div>
          <div class="fld pl">
            <label>Requested Role *</label>
            <select name="req_role" onchange="upRole(this.value)">
              <option value="investigator" <?= ($_POST['req_role']??'')==='investigator'?'selected':'' ?>>Investigator</option>
              <option value="analyst"      <?= ($_POST['req_role']??'')==='analyst'?'selected':'' ?>>Analyst</option>
            </select>
          </div>
        </div>
        <div class="rh" id="rh"><strong>Investigator:</strong> Upload evidence, download files, verify integrity, submit analysis reports, manage cases.</div>
        <div class="fld pl" style="margin-top:13px">
          <label>Reason for Access *</label>
          <textarea name="req_reason" placeholder="Briefly explain your role and why you need access..."><?= e($_POST['req_reason']??'') ?></textarea>
        </div>
      </div>
      <div class="mf">
        <button type="button" class="bcan" onclick="closeM()">Cancel</button>
        <button type="submit" class="bsub"><i class="fas fa-paper-plane" style="margin-right:5px"></i>Submit Request</button>
      </div>
    </form>
  </div>
</div>

<script>
function togglePw(){const f=document.getElementById('pw'),i=document.getElementById('ei');f.type=f.type==='password'?'text':'password';i.classList.toggle('fa-eye');i.classList.toggle('fa-eye-slash');}
function openM(){document.getElementById('ov').style.display='flex';}
function closeM(){document.getElementById('ov').style.display='none';}
function ovClose(e){if(e.target===document.getElementById('ov'))closeM();}
const rh={investigator:'<strong>Investigator:</strong> Upload evidence, download files, verify file integrity, submit analysis reports, manage cases.',analyst:'<strong>Analyst:</strong> Same as Investigator — upload evidence, download files, verify integrity, submit analysis reports and manage cases.'};
function upRole(v){document.getElementById('rh').innerHTML=rh[v]||'';}
// Form submit handled normally
<?php if($show_modal):?>openM();<?php endif;?>
(function(){
  const c=document.getElementById('cv'),ctx=c.getContext('2d');
  let W,H,pts=[];
  function resize(){W=c.width=innerWidth;H=c.height=innerHeight;}
  resize();window.addEventListener('resize',resize);
  for(let i=0;i<50;i++)pts.push({x:Math.random()*2000,y:Math.random()*2000,vx:(Math.random()-.5)*.2,vy:(Math.random()-.5)*.2,r:Math.random()*1.2+.4});
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