<?php
/**
 * DigiCustody – Evidence Integrity Verification
 * Save to: /var/www/html/digicustody/pages/evidence_verify.php
 */
session_start();
require_once __DIR__.'/../config/db.php';
require_once __DIR__.'/../config/functions.php';
require_login();
if (is_viewer()) { header('Location: ../dashboard.php?error=access_denied'); exit; }

$page_title = 'Verify Integrity';
$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];
$id   = (int)($_GET['id'] ?? 0);
if (!$id) { header('Location: evidence.php'); exit; }

$stmt = $pdo->prepare("
    SELECT e.*, c.case_number, c.case_title
    FROM evidence e JOIN cases c ON c.id=e.case_id WHERE e.id=?
");
$stmt->execute([$id]);
$ev = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$ev) { header('Location: evidence.php?error=not_found'); exit; }

$result = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && verify_csrf($_POST['csrf_token']??'')) {
    $notes = trim($_POST['notes'] ?? '');
    if (file_exists($ev['file_path'])) {
        $cur_sha256 = hash_file('sha256', $ev['file_path']);
        $cur_md5    = hash_file('md5',    $ev['file_path']);
        $status     = ($cur_sha256 === $ev['sha256_hash'] && $cur_md5 === $ev['md5_hash'])
                      ? 'intact' : 'tampered';

        $pdo->prepare("INSERT INTO hash_verifications
            (evidence_id,verified_by,sha256_at_verification,md5_at_verification,
             original_sha256,original_md5,integrity_status,notes)
            VALUES(?,?,?,?,?,?,?,?)")
            ->execute([$id,$uid,$cur_sha256,$cur_md5,
                       $ev['sha256_hash'],$ev['md5_hash'],$status,$notes]);

        if ($status === 'tampered') {
            $pdo->prepare("UPDATE evidence SET status='flagged' WHERE id=?")->execute([$id]);
            foreach ($pdo->query("SELECT id FROM users WHERE role='admin' AND status='active'")->fetchAll() as $adm)
                send_notification($pdo,$adm['id'],'⚠ Integrity Alert',
                    "Evidence {$ev['evidence_number']} FAILED integrity check — possible tampering!",'danger','evidence',$id);
        }

        audit_log($pdo,$uid,$_SESSION['username'],$role,'hash_verified','evidence',$id,
            $ev['evidence_number'],
            "Integrity check: $status for {$ev['evidence_number']}",
            $_SERVER['REMOTE_ADDR']??'','',
            ['status'=>$status,'sha256_match'=>$cur_sha256===$ev['sha256_hash'],
             'md5_match'=>$cur_md5===$ev['md5_hash'],'current_sha256'=>$cur_sha256,'current_md5'=>$cur_md5]);

        $result = [
            'status'       => $status,
            'cur_sha256'   => $cur_sha256,
            'cur_md5'      => $cur_md5,
            'sha256_match' => $cur_sha256 === $ev['sha256_hash'],
            'md5_match'    => $cur_md5    === $ev['md5_hash'],
            'file_size'    => filesize($ev['file_path']),
        ];
    } else {
        $result = ['status' => 'file_missing'];
    }
}

// Previous verifications
$history = $pdo->prepare("
    SELECT hv.*, u.full_name AS verifier_name
    FROM hash_verifications hv JOIN users u ON u.id=hv.verified_by
    WHERE hv.evidence_id=? ORDER BY hv.verified_at DESC LIMIT 10
");
$history->execute([$id]);
$history = $history->fetchAll(PDO::FETCH_ASSOC);
$csrf = csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Verify Integrity — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.hash-compare{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px;}
.hc-box{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:14px;}
.hc-label{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px;}
.hc-val{font-family:'Courier New',monospace;font-size:11.5px;color:var(--text);word-break:break-all;line-height:1.5;}
.hc-box.match{border-color:rgba(74,222,128,0.35);background:rgba(74,222,128,0.04);}
.hc-box.mismatch{border-color:rgba(248,113,113,0.35);background:rgba(248,113,113,0.04);}
.result-banner{border-radius:var(--radius-lg);padding:22px 24px;margin-bottom:20px;display:flex;align-items:center;gap:18px;}
.result-banner.intact{background:rgba(74,222,128,0.08);border:2px solid rgba(74,222,128,0.3);}
.result-banner.tampered{background:rgba(248,113,113,0.08);border:2px solid rgba(248,113,113,0.3);}
.result-icon{font-size:36px;flex-shrink:0;}
.result-banner.intact .result-icon{color:var(--success);}
.result-banner.tampered .result-icon{color:var(--danger);}
.field{margin-bottom:16px;}
.field label{display:block;font-size:11.5px;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:7px;}
.field textarea{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:11px 14px;font-size:14px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;resize:vertical;min-height:80px;}
.field textarea:focus{border-color:rgba(201,168,76,0.5);}
</style>
</head>
<body>
<div class="app-shell">
<?php include __DIR__.'/../includes/sidebar.php'; ?>
<div class="main-area" id="mainArea">
<?php include __DIR__.'/../includes/navbar.php'; ?>
<div class="page-content">

<div class="page-header">
    <div><h1>Integrity Verification</h1><p><?= e($ev['evidence_number']) ?> — <?= e($ev['title']) ?></p></div>
    <div style="display:flex;gap:10px;">
        <a href="evidence_view.php?id=<?= $id ?>" class="btn btn-outline"><i class="fas fa-arrow-left"></i> Back</a>
        <a href="coc_report.php?id=<?= $id ?>" class="btn btn-outline"><i class="fas fa-file-pdf"></i> COC Report</a>
    </div>
</div>

<!-- Result banner -->
<?php if ($result): ?>
<?php if ($result['status'] === 'file_missing'): ?>
<div class="alert alert-danger"><i class="fas fa-circle-exclamation"></i> <strong>File not found.</strong> The evidence file could not be located on the server.</div>
<?php elseif ($result['status'] === 'intact'): ?>
<div class="result-banner intact">
    <div class="result-icon"><i class="fas fa-shield-check"></i></div>
    <div>
        <p style="font-family:'Space Grotesk',sans-serif;font-size:18px;font-weight:700;color:var(--success)">✓ Integrity Verified — File Intact</p>
        <p style="font-size:13.5px;color:var(--muted);margin-top:4px">Both SHA-256 and MD5 hashes match the originals recorded at upload. This evidence has not been modified.</p>
    </div>
</div>
<?php else: ?>
<div class="result-banner tampered">
    <div class="result-icon"><i class="fas fa-triangle-exclamation"></i></div>
    <div>
        <p style="font-family:'Space Grotesk',sans-serif;font-size:18px;font-weight:700;color:var(--danger)">⚠ INTEGRITY FAILURE — File May Be Tampered</p>
        <p style="font-size:13.5px;color:var(--muted);margin-top:4px">Hash mismatch detected. The current file hashes do not match the originals. This evidence has been flagged and administrators notified.</p>
    </div>
</div>
<?php endif; ?>

<!-- Hash comparison -->
<?php if (isset($result['cur_sha256'])): ?>
<div class="section-card" style="margin-bottom:20px;">
    <div class="section-head"><h2><i class="fas fa-fingerprint"></i> Hash Comparison</h2></div>
    <div class="section-body padded">
        <div class="hash-compare">
            <div class="hc-box <?= $result['sha256_match']?'match':'mismatch' ?>">
                <p class="hc-label">Original SHA-256 (at upload)</p>
                <p class="hc-val"><?= e($ev['sha256_hash']) ?></p>
            </div>
            <div class="hc-box <?= $result['sha256_match']?'match':'mismatch' ?>">
                <p class="hc-label">Current SHA-256 <?= $result['sha256_match']?'<span style="color:var(--success)">✓ Match</span>':'<span style="color:var(--danger)">✗ MISMATCH</span>' ?></p>
                <p class="hc-val"><?= e($result['cur_sha256']) ?></p>
            </div>
        </div>
        <div class="hash-compare">
            <div class="hc-box <?= $result['md5_match']?'match':'mismatch' ?>">
                <p class="hc-label">Original MD5 (at upload)</p>
                <p class="hc-val"><?= e($ev['md5_hash']) ?></p>
            </div>
            <div class="hc-box <?= $result['md5_match']?'match':'mismatch' ?>">
                <p class="hc-label">Current MD5 <?= $result['md5_match']?'<span style="color:var(--success)">✓ Match</span>':'<span style="color:var(--danger)">✗ MISMATCH</span>' ?></p>
                <p class="hc-val"><?= e($result['cur_md5']) ?></p>
            </div>
        </div>
        <div style="display:flex;gap:14px;flex-wrap:wrap;margin-top:6px;">
            <span style="font-size:13px;color:var(--muted)"><i class="fas fa-hard-drive" style="margin-right:5px"></i>Current size: <strong style="color:var(--text)"><?= format_filesize($result['file_size']) ?></strong></span>
            <span style="font-size:13px;color:var(--muted)"><i class="fas fa-clock" style="margin-right:5px"></i>Verified: <strong style="color:var(--text)"><?= date('M j, Y H:i:s') ?></strong></span>
            <span style="font-size:13px;color:var(--muted)"><i class="fas fa-user" style="margin-right:5px"></i>By: <strong style="color:var(--text)"><?= e($_SESSION['full_name']) ?></strong></span>
        </div>
    </div>
</div>
<?php endif; ?>
<?php endif; ?>

<div class="grid-2" style="gap:20px;">
    <!-- Run verification form -->
    <div class="section-card">
        <div class="section-head"><h2><i class="fas fa-fingerprint"></i> Run Integrity Check</h2></div>
        <div class="section-body padded">
            <div style="background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:14px;margin-bottom:18px;">
                <p style="font-size:13px;font-weight:500;color:var(--text);margin-bottom:8px">Evidence: <span style="color:var(--gold)"><?= e($ev['evidence_number']) ?></span></p>
                <p style="font-size:12px;color:var(--muted);margin-bottom:4px">Original SHA-256:</p>
                <p style="font-family:'Courier New',monospace;font-size:11px;color:var(--text);word-break:break-all;margin-bottom:8px"><?= e($ev['sha256_hash']) ?></p>
                <p style="font-size:12px;color:var(--muted);margin-bottom:4px">Original MD5:</p>
                <p style="font-family:'Courier New',monospace;font-size:11px;color:var(--text);word-break:break-all"><?= e($ev['md5_hash']) ?></p>
            </div>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
                <div class="field">
                    <label>Verification Notes (optional)</label>
                    <textarea name="notes" placeholder="Reason for running this check, observations, or any relevant notes..."></textarea>
                </div>
                <button type="submit" class="btn btn-gold" style="width:100%;padding:13px;font-size:15px;" id="verifyBtn" onclick="startVerify()">
                    <i class="fas fa-fingerprint"></i> Run Integrity Verification
                </button>
            </form>
            <div style="margin-top:14px;padding:12px 14px;background:rgba(201,168,76,0.05);border:1px solid rgba(201,168,76,0.15);border-radius:var(--radius);font-size:12.5px;color:var(--muted);">
                <i class="fas fa-info-circle" style="color:var(--gold);margin-right:5px"></i>
                This will re-calculate the SHA-256 and MD5 hashes of the current file and compare them with the originals recorded at upload. The result is permanently logged to the audit trail.
            </div>
        </div>
    </div>

    <!-- Verification history -->
    <div class="section-card">
        <div class="section-head">
            <h2><i class="fas fa-clock-rotate-left"></i> Verification History</h2>
            <span style="font-size:12px;color:var(--muted)"><?= count($history) ?> check<?= count($history)!=1?'s':'' ?></span>
        </div>
        <div class="section-body">
            <?php if (empty($history)): ?>
            <div class="empty-state" style="padding:28px 0"><i class="fas fa-fingerprint"></i><p>No checks performed yet.</p></div>
            <?php else: foreach ($history as $v): ?>
            <div style="display:flex;gap:12px;padding:12px 16px;border-bottom:1px solid var(--border);">
                <div class="stat-icon <?= $v['integrity_status']==='intact'?'green':'red' ?>" style="width:34px;height:34px;border-radius:9px;flex-shrink:0;font-size:12px;">
                    <i class="fas <?= $v['integrity_status']==='intact'?'fa-check':'fa-triangle-exclamation' ?>"></i>
                </div>
                <div style="flex:1;">
                    <p style="font-size:13.5px;font-weight:600;color:<?= $v['integrity_status']==='intact'?'var(--success)':'var(--danger)' ?>">
                        <?= $v['integrity_status']==='intact' ? 'Intact' : 'TAMPERED' ?>
                    </p>
                    <p style="font-size:12px;color:var(--muted);margin-top:2px">
                        <?= e($v['verifier_name']) ?> &nbsp;·&nbsp; <?= date('M j, Y H:i',strtotime($v['verified_at'])) ?>
                    </p>
                    <?php if ($v['notes']): ?>
                    <p style="font-size:12px;color:var(--dim);margin-top:3px;font-style:italic">"<?= e($v['notes']) ?>"</p>
                    <?php endif; ?>
                </div>
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
function startVerify(){const b=document.getElementById('verifyBtn');b.innerHTML='<i class="fas fa-spinner fa-spin"></i> Calculating hashes...';b.disabled=true;}
</script>
</body>
</html>
