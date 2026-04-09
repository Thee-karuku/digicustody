<?php
/**
 * DigiCustody – Evidence Download Page
 * Save to: /var/www/html/digicustody/pages/evidence_download.php
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login();

$page_title = 'Download Evidence';
$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];

// Analysts can only download evidence assigned to them (via case_access)
if (!is_admin() && isset($_GET['id'])) {
    $ev_id = (int)$_GET['id'];
    $check = $pdo->prepare("
        SELECT e.id FROM evidence e
        WHERE e.id=? AND (e.case_id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id=?)
            OR e.uploaded_by=? OR e.current_custodian=?)
    ");
    $check->execute([$ev_id, $uid, $uid, $uid]);
    if (!$check->fetch()) {
        header('Location: ../dashboard.php?error=access_denied');
        exit;
    }
}

// ── Handle actual file download via token ─────────────────
if (isset($_GET['token'])) {
    $token = trim($_GET['token']);
    
    // Rate limit download attempts
    if (!rate_limit_check($pdo, 'download', $_SERVER['REMOTE_ADDR'] ?? 'unknown', 20, 60)) {
        die('<div style="font-family:sans-serif;padding:40px;text-align:center;background:#060d1a;color:#f87171;min-height:100vh"><h2>⚠ Too Many Requests</h2><p style="color:#6b82a0;margin-top:10px">Please wait before downloading more files.</p></div>');
    }
    
    $td    = validate_download_token($pdo, $token);

    if (!$td) {
        die('<div style="font-family:sans-serif;padding:40px;text-align:center;background:#060d1a;color:#f87171;min-height:100vh"><h2>⚠ Invalid or Expired Token</h2><p style="color:#6b82a0;margin-top:10px">This download link has expired or already been used.</p><a href="evidence.php" style="color:#c9a84c;margin-top:20px;display:inline-block">← Back to Evidence</a></div>');
    }

    $file_path = $td['file_path'];
    if (!file_exists($file_path)) {
        die('<div style="font-family:sans-serif;padding:40px;text-align:center;background:#060d1a;color:#f87171;min-height:100vh"><h2>⚠ File Not Found</h2><p style="color:#6b82a0;margin-top:10px">The evidence file could not be located on the server.</p></div>');
    }

    // ── SHA-256 Verification on Download ────────────────────────
    // Re-hash file at download time and compare against stored hash
    $stored_sha256 = $td['sha256_hash'] ?? '';
    $stored_md5 = $td['md5_hash'] ?? '';
    
    if ($stored_sha256 || $stored_md5) {
        $integrity = verify_file_integrity($file_path, $stored_sha256, $stored_md5);
        
        if ($integrity === 'file_missing') {
            die('<div style="font-family:sans-serif;padding:40px;text-align:center;background:#060d1a;color:#f87171;min-height:100vh"><h2>⚠ File Missing</h2><p style="color:#6b82a0;margin-top:10px">The evidence file no longer exists on the server.</p></div>');
        }
        
        if ($integrity === 'tampered') {
            // Log integrity failure but still allow download (with warning header)
            $current_sha256 = hash_file('sha256', $file_path);
            $current_md5 = hash_file('md5', $file_path);
            
            audit_log($pdo, $uid, $_SESSION['username'], $role,
                'integrity_check_failed', 'evidence', $td['evidence_id'], $td['evidence_number'],
                "INTEGRITY MISMATCH! Stored SHA256: {$stored_sha256}, Current SHA256: {$current_sha256}",
                $_SERVER['REMOTE_ADDR'] ?? '');
            
            // Notify admins
            $admins = $pdo->query("SELECT id FROM users WHERE role='admin' AND status='active'")->fetchAll();
            foreach ($admins as $admin) {
                send_notification($pdo, $admin['id'], '🔴 INTEGRITY ALERT', 
                    "Evidence {$td['evidence_number']} hash mismatch detected during download! File may be corrupted or tampered.", 
                    'danger', 'evidence', $td['evidence_id']);
            }
            
            // Update evidence record with integrity flag
            $pdo->prepare("UPDATE evidence SET is_verified=0 WHERE id=?")->execute([$td['evidence_id']]);
            
            // Add warning header but allow download
            header('X-Integrity-Warning: SHA256 mismatch detected - file may be corrupted');
        }
    }

    // Mark token as used
    $pdo->prepare("UPDATE download_tokens SET is_used=1, used_at=NOW() WHERE token=?")
        ->execute([$token]);

    // Audit log
    audit_log($pdo, $uid, $_SESSION['username'], $role,
        'evidence_downloaded', 'evidence', $td['evidence_id'], '',
        "Evidence downloaded via token. File: {$td['file_name']}",
        $_SERVER['REMOTE_ADDR'] ?? '');

    // Log to download_history
    log_download($pdo, $td['evidence_id'], $uid, $td['id'], $td['download_reason'] ?? '');

    // Serve file
    $finfo    = new finfo(FILEINFO_MIME_TYPE);
    $mime     = $finfo->file($file_path);
    $filename = basename($td['file_name']);

    header('Content-Type: '.$mime);
    header('Content-Disposition: attachment; filename="'.addslashes($filename).'"');
    header('Content-Length: '.filesize($file_path));
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    readfile($file_path);
    exit;
}

// ── Generate download token ───────────────────────────────
$id = (int)($_GET['id'] ?? 0);
if (!$id) { header('Location: evidence.php'); exit; }

$stmt = $pdo->prepare("
    SELECT e.*, c.case_number, c.case_title
    FROM evidence e
    JOIN cases c ON c.id = e.case_id
    WHERE e.id = ?
");
$stmt->execute([$id]);
$ev = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$ev) { header('Location: evidence.php?error=not_found'); exit; }

$error = '';
$token_data = null;

// Handle token generation
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Security token mismatch.';
    } else {
        $reason = trim($_POST['download_reason'] ?? '');
        $hours  = max(1, min(72, (int)($_POST['expiry_hours'] ?? 24)));

        if (empty($reason)) {
            $error = 'Please provide a reason for downloading this evidence.';
        } else {
            $token = create_download_token($pdo, $id, $uid, $reason, $hours);

            audit_log($pdo, $uid, $_SESSION['username'], $role,
                'download_token_generated', 'evidence', $id, $ev['evidence_number'],
                "Download token generated for {$ev['evidence_number']}. Expires in {$hours}h. Reason: $reason",
                $_SERVER['REMOTE_ADDR'] ?? '');

            $token_data = [
                'token'      => $token,
                'expires_in' => $hours,
                'url'        => BASE_URL . 'pages/evidence_download.php?token=' . $token,
                'reason'     => $reason,
            ];
        }
    }
}

// Existing active tokens for this evidence
$existing_tokens = $pdo->prepare("
    SELECT dt.*, u.full_name AS creator_name
    FROM download_tokens dt
    JOIN users u ON u.id = dt.created_by
    WHERE dt.evidence_id = ? AND dt.is_used = 0 AND dt.expires_at > NOW()
    ORDER BY dt.created_at DESC
");
$existing_tokens->execute([$id]);
$existing_tokens = $existing_tokens->fetchAll(PDO::FETCH_ASSOC);

$csrf = csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Download Evidence — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.field{margin-bottom:18px;}
.field label{display:block;font-size:11.5px;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:7px;}
.field input,.field select,.field textarea{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:11px 14px;font-size:14px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.field input:focus,.field select:focus,.field textarea:focus{border-color:rgba(201,168,76,0.5);}
.field select option{background:var(--surface2);}
.field textarea{resize:vertical;min-height:80px;}
.token-box{background:rgba(74,222,128,0.05);border:1px solid rgba(74,222,128,0.25);border-radius:var(--radius-lg);padding:24px;}
.token-url{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px;font-family:'Courier New',monospace;font-size:12px;color:var(--text);word-break:break-all;margin:12px 0;}
.expiry-option{display:flex;gap:8px;flex-wrap:wrap;}
.exp-btn{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:8px 16px;font-size:13px;color:var(--muted);cursor:pointer;transition:all .2s;font-family:'Inter',sans-serif;}
.exp-btn.active,.exp-btn:hover{border-color:var(--gold);color:var(--gold);background:var(--gold-dim);}
.token-row{display:flex;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid var(--border);}
.token-row:last-child{border-bottom:none;}
.countdown{font-family:'Space Grotesk',sans-serif;font-size:13px;font-weight:600;color:var(--warning);}
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
        <h1>Download Evidence</h1>
        <p>Generate a secure time-limited download link</p>
    </div>
    <div style="display:flex;gap:10px;align-items:center;">
        <button type="button" class="btn-back" onclick="goBack()"><i class="fas fa-arrow-left"></i> Back</button>
        <a href="evidence_view.php?id=<?= $id ?>" class="btn btn-outline">
            <i class="fas fa-arrow-left"></i> Back to Evidence
        </a>
    </div>
</div>

<?php if ($error): ?>
<div class="alert alert-danger"><i class="fas fa-circle-exclamation"></i> <?= e($error) ?></div>
<?php endif; ?>

<!-- Evidence info -->
<div style="background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-lg);padding:18px 20px;margin-bottom:24px;display:flex;align-items:center;gap:16px;flex-wrap:wrap;">
    <div class="stat-icon gold" style="width:44px;height:44px;border-radius:11px;flex-shrink:0;"><i class="fas fa-database"></i></div>
    <div style="flex:1;">
        <p style="font-family:'Space Grotesk',sans-serif;font-size:15px;font-weight:700;color:var(--gold)"><?= e($ev['evidence_number']) ?></p>
        <p style="font-size:13.5px;font-weight:500;color:var(--text);margin-top:2px"><?= e($ev['title']) ?></p>
        <p style="font-size:12px;color:var(--muted);margin-top:3px"><?= e($ev['case_number']) ?> — <?= e($ev['case_title']) ?> &nbsp;·&nbsp; <?= format_filesize($ev['file_size']) ?></p>
    </div>
    <?= status_badge($ev['status']) ?>
</div>

<?php if ($token_data): ?>
<!-- Token generated successfully -->
<div class="token-box" style="margin-bottom:24px;">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
        <i class="fas fa-circle-check" style="color:var(--success);font-size:20px"></i>
        <div>
            <p style="font-size:15px;font-weight:600;color:var(--text)">Download Link Generated</p>
            <p style="font-size:12.5px;color:var(--muted);margin-top:2px">This link expires in <strong style="color:var(--warning)"><?= $token_data['expires_in'] ?> hour<?= $token_data['expires_in']!=1?'s':'' ?></strong> and can only be used once.</p>
        </div>
    </div>
    <p style="font-size:11.5px;color:var(--muted);margin-bottom:6px">Download URL:</p>
    <div class="token-url" id="tokenUrl"><?= e($token_data['url']) ?></div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <button class="btn btn-gold" onclick="copyToken()">
            <i class="fas fa-copy" id="copyIcon"></i> Copy Link
        </button>
        <a href="<?= e($token_data['url']) ?>" class="btn btn-download" download>
            <i class="fas fa-download"></i> Download Now
        </a>
    </div>
    <div style="margin-top:14px;padding-top:14px;border-top:1px solid rgba(74,222,128,0.2);">
        <p style="font-size:12px;color:var(--muted)">
            <i class="fas fa-shield-check" style="color:var(--success);margin-right:5px"></i>
            This download has been logged to the audit trail and chain of custody.
        </p>
    </div>
</div>
<?php endif; ?>

<div class="grid-2" style="gap:24px;">

    <!-- Generate Token Form -->
    <div class="section-card">
        <div class="section-head">
            <h2><i class="fas fa-key"></i> Generate Download Token</h2>
        </div>
        <div class="section-body padded">
            <div style="background:rgba(251,191,36,0.06);border:1px solid rgba(251,191,36,0.15);border-radius:var(--radius);padding:12px 14px;margin-bottom:18px;font-size:13px;color:var(--muted);">
                <i class="fas fa-clock" style="color:var(--warning);margin-right:6px"></i>
                For security, all downloads require a time-limited token. The token is single-use and expires automatically.
            </div>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
                <div class="field">
                    <label>Reason for Download *</label>
                    <textarea name="download_reason" placeholder="Why are you downloading this evidence? e.g. For forensic analysis, court presentation, review..." required></textarea>
                </div>
                <div class="field">
                    <label>Link Expiry</label>
                    <div class="expiry-option">
                        <?php foreach ([1=>'1 Hour',6=>'6 Hours',12=>'12 Hours',24=>'24 Hours',48=>'48 Hours',72=>'72 Hours'] as $h=>$label): ?>
                        <button type="button" class="exp-btn <?= $h===24?'active':'' ?>"
                            onclick="setExpiry(<?= $h ?>,this)">
                            <?= $label ?>
                        </button>
                        <?php endforeach; ?>
                    </div>
                    <input type="hidden" name="expiry_hours" id="expiryInput" value="24">
                </div>
                <button type="submit" class="btn btn-gold" style="width:100%;padding:12px;font-size:15px;">
                    <i class="fas fa-key"></i> Generate Secure Download Link
                </button>
            </form>
        </div>
    </div>

    <!-- Active tokens -->
    <div class="section-card">
        <div class="section-head">
            <h2><i class="fas fa-clock"></i> Active Download Tokens</h2>
        </div>
        <div class="section-body padded">
            <?php if (empty($existing_tokens)): ?>
            <div class="empty-state" style="padding:20px 0">
                <i class="fas fa-key"></i>
                <p>No active download tokens for this evidence.</p>
            </div>
            <?php else: foreach ($existing_tokens as $tk): ?>
            <div class="token-row">
                <div class="stat-icon warning" style="width:32px;height:32px;border-radius:8px;flex-shrink:0;font-size:12px;"><i class="fas fa-key"></i></div>
                <div style="flex:1;min-width:0;">
                    <p style="font-size:13px;font-weight:500;color:var(--text)">Generated by <?= e($tk['creator_name']) ?></p>
                    <p style="font-size:12px;color:var(--muted);margin-top:2px"><?= e(substr($tk['download_reason']??'',0,50)) ?></p>
                    <p class="countdown" id="cd_<?= $tk['id'] ?>" style="margin-top:4px;font-size:11.5px;">
                        Expires: <?= date('M j, Y H:i', strtotime($tk['expires_at'])) ?>
                    </p>
                </div>
                <a href="?token=<?= e($tk['token']) ?>" class="btn btn-outline btn-sm">
                    <i class="fas fa-download"></i> Download
                </a>
            </div>
            <?php endforeach; endif; ?>
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
function setExpiry(h,btn){
    document.getElementById('expiryInput').value=h;
    document.querySelectorAll('.exp-btn').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
}
function copyToken(){
    const url=document.getElementById('tokenUrl')?.textContent;
    if(url){navigator.clipboard.writeText(url).then(()=>{const ic=document.getElementById('copyIcon');ic.className='fas fa-check';setTimeout(()=>ic.className='fas fa-copy',1500);});}
}
</script>
<script src="../assets/js/main.js"></script>
</body>
</html>
