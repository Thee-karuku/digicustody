<?php
/**
 * DigiCustody – Evidence Integrity Verification
 * Save to: /var/www/html/digicustody/pages/evidence_verify.php
 */
require_once __DIR__."/../config/functions.php";
require_once __DIR__."/../config/logger.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login($pdo);
if (!is_admin() && !is_investigator() && !is_analyst()) { header('Location: ../dashboard.php?error=access_denied'); exit; }

$page_title = 'Verify Integrity';
$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];
$id   = (int)($_GET['id'] ?? 0);
if (!$id) { header('Location: evidence.php'); exit; }

if (!user_can_access_evidence($pdo, $uid, $role, $id)) {
    http_response_code(403);
    die('You are not authorized to access this evidence.');
}

$stmt = $pdo->prepare("
    SELECT e.*, c.case_number, c.case_title
    FROM evidence e JOIN cases c ON c.id=e.case_id WHERE e.id=?
");
$stmt->execute([$id]);
$ev = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$ev) { header('Location: evidence.php?error=not_found'); exit; }

if ($role === 'analyst') {
    $stmt = $pdo->prepare("SELECT 1 FROM case_access WHERE case_id = ? AND user_id = ?");
    $stmt->execute([$ev['case_id'], $uid]);
    if (!$stmt->fetchColumn()) {
        header('Location: evidence.php?error=access_denied'); exit;
    }
}

$result = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && verify_csrf($_POST['csrf_token']??'')) {
    ob_start();
    
    if ($_POST['ajax'] === '1') {
        set_exception_handler(null);
        ini_set('display_errors', 0);
        register_shutdown_function(function() {
            $err = error_get_last();
            if ($err && ($err['type'] & (E_ERROR | E_PARSE | E_COMPILE_ERROR))) {
                if (!headers_sent()) header('Content-Type: application/json');
                echo json_encode(['status' => 'error', 'message' => $err['message']]);
            }
        });
        set_time_limit(300);
        ignore_user_abort(true);
        ob_end_clean();
        header('Content-Type: application/json');

        try {
            $notes = trim($_POST['notes'] ?? '');
            $file_path = $ev['file_path'];
            if (!file_exists($file_path)) {
                $fallback_path = UPLOAD_DIR . basename($ev['file_name']);
                if (file_exists($fallback_path)) {
                    $file_path = $fallback_path;
                }
            }
            if (file_exists($file_path)) {
                if ($file_path !== $ev['file_path']) {
                    log_warning("evidence_verify: Using fallback path", ['evidence_id' => $id, 'path' => $file_path]);
                }
                $cur_sha256 = hash_file('sha256', $file_path);
                $cur_sha3_256 = hash_file('sha3-256', $file_path);
                $sha256_match = ($cur_sha256 === $ev['sha256_hash']);
                $sha3_match = (empty($ev['sha3_256_hash'])) || ($cur_sha3_256 === $ev['sha3_256_hash']);
                $status = ($sha256_match && $sha3_match) ? 'intact' : 'tampered';

                $pdo->prepare("INSERT INTO hash_verifications
                    (evidence_id,verified_by,sha256_at_verification,sha3_256_at_verification,
                     original_sha256,original_sha3_256,integrity_status,notes)
                    VALUES(?,?,?,?,?,?,?,?)")
                    ->execute([$id,$uid,$cur_sha256,$cur_sha3_256,
                               $ev['sha256_hash'],$ev['sha3_256_hash'],$status,$notes]);

                if ($status === 'tampered') {
                    $pdo->prepare("UPDATE evidence SET status='flagged', pre_flag_status=COALESCE(pre_flag_status, status) WHERE id=?")->execute([$id]);
                    foreach ($pdo->query("SELECT id FROM users WHERE role='admin' AND status='active'")->fetchAll() as $adm)
                        send_notification($pdo,$adm['id'],'⚠ Integrity Alert',
                            "Evidence {$ev['evidence_number']} FAILED integrity check — possible tampering!",'danger','evidence',$id);
                }

                audit_log($pdo,$uid,$_SESSION['username'],$role,'hash_verified','evidence',$id,
                    $ev['evidence_number'],
                    "Integrity check: $status for {$ev['evidence_number']}",
                    $_SERVER['REMOTE_ADDR']??'','',
                    ['status'=>$status,'sha256_match'=>$cur_sha256===$ev['sha256_hash'],
                     'sha3_256_match'=>$cur_sha3_256===$ev['sha3_256_hash'],'current_sha256'=>$cur_sha256,'current_sha3_256'=>$cur_sha3_256]);

                $result = [
                    'status'         => $status,
                    'cur_sha256'     => $cur_sha256,
                    'cur_sha3_256'   => $cur_sha3_256,
                    'sha256_match'   => $cur_sha256   === $ev['sha256_hash'],
                    'sha3_256_match' => $cur_sha3_256 === $ev['sha3_256_hash'],
                    'file_size'      => filesize($file_path),
                ];
            } else {
                $result = ['status' => 'file_missing', 'cur_sha256' => '', 'cur_sha3_256' => '', 'sha256_match' => false, 'sha3_256_match' => false];
                $pdo->prepare("UPDATE evidence SET status='flagged', pre_flag_status=COALESCE(pre_flag_status, status) WHERE id=?")->execute([$id]);
                $pdo->prepare("INSERT INTO hash_verifications (evidence_id,verified_by,sha256_at_verification,sha3_256_at_verification,original_sha256,original_sha3_256,integrity_status,notes) VALUES(?,?,?,?,?,?,?,?)")
                    ->execute([$id,$uid,'','',$ev['sha256_hash'],$ev['sha3_256_hash'],'file_missing',$notes]);
                foreach ($pdo->query("SELECT id FROM users WHERE role='admin' AND status='active'")->fetchAll() as $adm)
                    send_notification($pdo,$adm['id'],'⚠ Integrity Alert',"Evidence {$ev['evidence_number']} integrity check FAILED — file cannot be located on the server!",'danger','evidence',$id);
                audit_log($pdo,$uid,$_SESSION['username'],$role,'hash_verified','evidence',$id,$ev['evidence_number'],"Integrity check: file_missing for {$ev['evidence_number']}",$_SERVER['REMOTE_ADDR']??'','');
            }

            echo json_encode($result);
            exit;
        } catch (Throwable $e) {
            echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
            exit;
        }
    }
    
    // Standard non-AJAX POST behavior
    $notes = trim($_POST['notes'] ?? '');
    $file_path = $ev['file_path'];
    if (!file_exists($file_path)) {
        $fallback_path = UPLOAD_DIR . basename($ev['file_name']);
        if (file_exists($fallback_path)) {
            $file_path = $fallback_path;
        }
    }
    if (file_exists($file_path)) {
        if ($file_path !== $ev['file_path']) {
            error_log("evidence_verify: Using fallback path for id $id: $file_path");
        }
        $cur_sha256 = hash_file('sha256', $file_path);
        $cur_sha3_256 = hash_file('sha3-256', $file_path);
        $sha256_match = ($cur_sha256 === $ev['sha256_hash']);
        $sha3_match = ($ev['sha3_256_hash'] === null) || ($cur_sha3_256 === $ev['sha3_256_hash']);
        $status = ($sha256_match && $sha3_match) ? 'intact' : 'tampered';

        $pdo->prepare("INSERT INTO hash_verifications
            (evidence_id,verified_by,sha256_at_verification,sha3_256_at_verification,
             original_sha256,original_sha3_256,integrity_status,notes)
            VALUES(?,?,?,?,?,?,?,?)")
            ->execute([$id,$uid,$cur_sha256,$cur_sha3_256,
                       $ev['sha256_hash'],$ev['sha3_256_hash'],$status,$notes]);

        if ($status === 'tampered') {
            $pdo->prepare("UPDATE evidence SET status='flagged', pre_flag_status=COALESCE(pre_flag_status, status) WHERE id=?")->execute([$id]);
            foreach ($pdo->query("SELECT id FROM users WHERE role='admin' AND status='active'")->fetchAll() as $adm)
                send_notification($pdo,$adm['id'],'⚠ Integrity Alert',
                    "Evidence {$ev['evidence_number']} FAILED integrity check — possible tampering!",'danger','evidence',$id);
        }

        audit_log($pdo,$uid,$_SESSION['username'],$role,'hash_verified','evidence',$id,
            $ev['evidence_number'],
            "Integrity check: $status for {$ev['evidence_number']}",
            $_SERVER['REMOTE_ADDR']??'','',
            ['status'=>$status,'sha256_match'=>$cur_sha256===$ev['sha256_hash'],
             'sha3_256_match'=>$cur_sha3_256===$ev['sha3_256_hash'],'current_sha256'=>$cur_sha256,'current_sha3_256'=>$cur_sha3_256]);

        $result = [
            'status'       => $status,
            'cur_sha256'   => $cur_sha256,
            'cur_sha3_256' => $cur_sha3_256,
            'sha256_match' => $cur_sha256 === $ev['sha256_hash'],
            'sha3_256_match' => $cur_sha3_256 === $ev['sha3_256_hash'],
            'file_size'    => filesize($file_path),
        ];
    } else {
        $result = ['status' => 'file_missing', 'cur_sha256' => '', 'cur_sha3_256' => '', 'sha256_match' => false, 'sha3_256_match' => false];
        $pdo->prepare("UPDATE evidence SET status='flagged', pre_flag_status=COALESCE(pre_flag_status, status) WHERE id=?")->execute([$id]);
        $pdo->prepare("INSERT INTO hash_verifications (evidence_id,verified_by,sha256_at_verification,sha3_256_at_verification,original_sha256,original_sha3_256,integrity_status,notes) VALUES(?,?,?,?,?,?,?,?)")
            ->execute([$id,$uid,'','',$ev['sha256_hash'],$ev['sha3_256_hash'],'file_missing',$notes]);
        foreach ($pdo->query("SELECT id FROM users WHERE role='admin' AND status='active'")->fetchAll() as $adm)
            send_notification($pdo,$adm['id'],'⚠ Integrity Alert',"Evidence {$ev['evidence_number']} integrity check FAILED — file cannot be located on the server!",'danger','evidence',$id);
        audit_log($pdo,$uid,$_SESSION['username'],$role,'hash_verified','evidence',$id,$ev['evidence_number'],"Integrity check: file_missing for {$ev['evidence_number']}",$_SERVER['REMOTE_ADDR']??'','');
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'clear_flag' && is_admin() && verify_csrf($_POST['csrf_token'] ?? '')) {
        $admin_note = trim($_POST['admin_note'] ?? '');
        if (!$admin_note) {
            if (($_POST['ajax'] ?? '') === '1') {
                header('Content-Type: application/json');
                echo json_encode(['success' => false, 'error' => 'Admin note is required']);
                exit;
            }
            header('Location: evidence_verify.php?id=' . $id . '&error=admin_note_required');
            exit;
        }
        
        $pre_status = $ev['pre_flag_status'] ?? 'collected';
        $pdo->prepare("UPDATE evidence SET status = ?, pre_flag_status = NULL WHERE id = ?")->execute([$pre_status, $id]);
        $pdo->prepare("INSERT INTO hash_verifications (evidence_id, verified_by, sha256_at_verification, sha3_256_at_verification, original_sha256, original_sha3_256, integrity_status, notes) VALUES(?, ?, ?, ?, ?, ?, ?, ?)")->execute([$id, $uid, $ev['sha256_hash'], $ev['sha3_256_hash'], $ev['sha256_hash'], $ev['sha3_256_hash'], 'flag_cleared', $admin_note]);
        
        audit_log($pdo, $uid, $_SESSION['username'], $role, 'flag_cleared', 'evidence', $id, $ev['evidence_number'], "Flag cleared by admin. Restored to: $pre_status. Note: $admin_note", $_SERVER['REMOTE_ADDR'] ?? '', '');
        
        $stmt = $pdo->prepare("SELECT u.id FROM users u JOIN evidence e ON e.submitted_by = u.id WHERE e.id = ? AND u.status = 'active'");
        $stmt->execute([$id]);
        $u = $stmt->fetch();
        if ($u) {
            send_notification($pdo, $u['id'], 'Flag Cleared', "Evidence {$ev['evidence_number']} flag has been cleared by an admin and status restored to $pre_status.", 'info', 'evidence', $id);
        }
        
        if (($_POST['ajax'] ?? '') === '1') {
            header('Content-Type: application/json');
            echo json_encode(['success' => true, 'status' => $pre_status]);
            exit;
        }
        
        header('Location: evidence_verify.php?id=' . $id . '&flag_cleared=1');
        exit;
    }
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'confirm_tamper' && is_admin() && verify_csrf($_POST['csrf_token'] ?? '')) {
        $admin_note = trim($_POST['admin_note'] ?? '');
        if (!$admin_note) {
            if (($_POST['ajax'] ?? '') === '1') {
                header('Content-Type: application/json');
                echo json_encode(['success' => false, 'error' => 'Admin note is required']);
                exit;
            }
            header('Location: evidence_verify.php?id=' . $id . '&error=admin_note_required');
            exit;
        }
        
        $pdo->prepare("INSERT INTO hash_verifications (evidence_id, verified_by, sha256_at_verification, sha3_256_at_verification, original_sha256, original_sha3_256, integrity_status, notes) VALUES(?, ?, ?, ?, ?, ?, ?, ?)")->execute([$id, $uid, $ev['sha256_hash'], $ev['sha3_256_hash'], $ev['sha256_hash'], $ev['sha3_256_hash'], 'tamper_confirmed', $admin_note]);
        
        audit_log($pdo, $uid, $_SESSION['username'], $role, 'tamper_confirmed', 'evidence', $id, $ev['evidence_number'], "Tampering investigation closed. Admin confirmed: $admin_note", $_SERVER['REMOTE_ADDR'] ?? '', '');
        
        if (($_POST['ajax'] ?? '') === '1') {
            header('Content-Type: application/json');
            echo json_encode(['success' => true]);
            exit;
        }
        
        header('Location: evidence_verify.php?id=' . $id . '&tamper_confirmed=1');
        exit;
    }

// Previous verifications
$history = $pdo->prepare("
    SELECT hv.*, u.full_name AS verifier_name
    FROM hash_verifications hv JOIN users u ON u.id=hv.verified_by
    WHERE hv.evidence_id=? ORDER BY hv.verified_at DESC LIMIT 10
");
$history->execute([$id]);
$history = $history->fetchAll(PDO::FETCH_ASSOC);

// Get flag reason from latest tampered/file_missing verification
$flag_reason_stmt = $pdo->prepare("SELECT hv.*, u.full_name FROM hash_verifications hv JOIN users u ON u.id=hv.verified_by WHERE hv.evidence_id=? AND hv.integrity_status IN ('tampered','file_missing') ORDER BY hv.verified_at DESC LIMIT 1");
$flag_reason_stmt->execute([$id]);
$flag_reason = $flag_reason_stmt->fetch();

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
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
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
        <button type="button" class="btn-back" onclick="goBack()"><i class="fas fa-arrow-left"></i> Back</button>
        <a href="evidence_view.php?id=<?= $id ?>" class="btn btn-outline"><i class="fas fa-arrow-left"></i> Back to Evidence</a>
        <a href="coc_report.php?id=<?= $id ?>" class="btn btn-coc"><i class="fas fa-file-pdf"></i> COC Report</a>
    </div>
</div>

<!-- Result banner -->
<div id="verifyResult"></div>
<?php if ($result): ?>
<?php if ($result['status'] === 'file_missing'): ?>
<div class="alert alert-danger"><i class="fas fa-circle-exclamation"></i> <strong>File not found.</strong> The evidence file could not be located on the server.</div>
<?php elseif ($result['status'] === 'intact'): ?>
<div class="result-banner intact">
    <div class="result-icon"><i class="fas fa-shield-check"></i></div>
    <div>
        <p style="font-family:'Space Grotesk',sans-serif;font-size:18px;font-weight:700;color:var(--success)">✓ Integrity Verified — File Intact</p>
        <p style="font-size:13.5px;color:var(--muted);margin-top:4px">Both SHA-256 and SHA3-256 hashes match the originals recorded at upload. This evidence has not been modified.</p>
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
            <div class="hc-box <?= $result['sha3_256_match']?'match':'mismatch' ?>">
                <p class="hc-label">Original SHA3-256 (at upload)</p>
                <p class="hc-val"><?= e($ev['sha3_256_hash']) ?></p>
            </div>
            <div class="hc-box <?= $result['sha3_256_match']?'match':'mismatch' ?>">
                <p class="hc-label">Current SHA3-256 <?= $result['sha3_256_match']?'<span style="color:var(--success)">✓ Match</span>':'<span style="color:var(--danger)">✗ MISMATCH</span>' ?></p>
                <p class="hc-val"><?= e($result['cur_sha3_256']) ?></p>
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
                <p style="font-size:12px;color:var(--muted);margin-bottom:4px">Original SHA3-256:</p>
                <p style="font-family:'Courier New',monospace;font-size:11px;color:var(--text);word-break:break-all"><?= e($ev['sha3_256_hash']) ?></p>
            </div>
            <form method="POST" action="?id=<?= $id ?>" id="verifyForm">
                <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
                <input type="hidden" name="ajax" value="1">
                <div class="field">
                    <label>Verification Notes (optional)</label>
                    <textarea name="notes" placeholder="Reason for running this check, observations, or any relevant notes..."></textarea>
                </div>
                <button type="submit" class="btn btn-gold" style="width:100%;padding:13px;font-size:15px;" id="verifyBtn">
                    <i class="fas fa-fingerprint"></i> Run Integrity Verification
                </button>
            </form>
            <div style="margin-top:14px;padding:12px 14px;background:rgba(201,168,76,0.05);border:1px solid rgba(201,168,76,0.15);border-radius:var(--radius);font-size:12.5px;color:var(--muted);">
                <i class="fas fa-info-circle" style="color:var(--gold);margin-right:5px"></i>
                This will re-calculate the SHA-256 and SHA3-256 hashes of the current file and compare them with the originals recorded at upload. The result is permanently logged to the audit trail.
            </div>
        </div>
    </div>

    <?php if (is_admin() && $ev['status'] === 'flagged'): ?>
    <div class="section-card">
        <div class="section-head"><h2><i class="fas fa-clipboard-check"></i> Flag Review</h2></div>
        <div class="section-body padded">
            <div style="background:var(--surface2);border:1px solid rgba(248,113,113,0.3);border-radius:var(--radius);padding:14px;margin-bottom:18px;">
                <p style="font-size:11px;font-weight:600;color:var(--danger);text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px">Current Flag Reason</p>
                <p style="font-size:13px;color:var(--text);margin-bottom:6px"><strong><?= e($flag_reason['integrity_status'] ?? 'N/A') ?></strong></p>
                <p style="font-size:12px;color:var(--muted);margin-bottom:4px"><?= e($flag_reason['notes'] ?? '') ?></p>
                <p style="font-size:11px;color:var(--muted);margin-top:8px">Verified by <?= e($flag_reason['full_name'] ?? 'Unknown') ?> on <?= $flag_reason ? date('M j, Y H:i', strtotime($flag_reason['verified_at'])) : 'N/A' ?></p>
            </div>
            <div style="display:flex;gap:10px;">
                <button type="button" class="btn btn-green" style="flex:1;padding:12px;font-size:14px;" onclick="document.getElementById('clearFlagModal').style.display='flex'">
                    <i class="fas fa-check-circle"></i> Clear Flag
                </button>
                <button type="button" class="btn btn-danger" style="flex:1;padding:12px;font-size:14px;" onclick="document.getElementById('confirmTamperModal').style.display='flex'">
                    <i class="fas fa-gavel"></i> Confirm Tampering
                </button>
            </div>
        </div>
    </div>

    <!-- Clear Flag Modal -->
    <div id="clearFlagModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999;align-items:center;justify-content:center;">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:24px;width:90%;max-width:450px;">
            <h3 style="font-size:18px;font-weight:600;margin-bottom:16px;color:var(--text);"><i class="fas fa-check-circle"></i> Clear Flag</h3>
            <form method="POST" action="?id=<?= $id ?>" id="clearFlagForm">
                <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
                <input type="hidden" name="action" value="clear_flag">
                <input type="hidden" name="ajax" value="1">
                <div class="field">
                    <label>Admin Note (required)</label>
                    <textarea name="admin_note" id="clearFlagNote" placeholder="Reason for clearing the flag..." required style="min-height:100px;"></textarea>
                </div>
                <div style="display:flex;gap:10px;margin-top:16px;">
                    <button type="button" class="btn btn-outline" style="flex:1;padding:12px;" onclick="document.getElementById('clearFlagModal').style.display='none'">Cancel</button>
                    <button type="submit" class="btn btn-green" style="flex:1;padding:12px;" id="clearFlagBtn">Confirm Clear</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Confirm Tamper Modal -->
    <div id="confirmTamperModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999;align-items:center;justify-content:center;">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:24px;width:90%;max-width:450px;">
            <h3 style="font-size:18px;font-weight:600;margin-bottom:16px;color:var(--danger);"><i class="fas fa-gavel"></i> Confirm Tampering</h3>
            <form method="POST" action="?id=<?= $id ?>" id="confirmTamperForm">
                <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
                <input type="hidden" name="action" value="confirm_tamper">
                <input type="hidden" name="ajax" value="1">
                <div class="field">
                    <label>Investigation Conclusion (required)</label>
                    <textarea name="admin_note" id="confirmTamperNote" placeholder="Document findings and conclusion..." required style="min-height:100px;"></textarea>
                </div>
                <div style="display:flex;gap:10px;margin-top:16px;">
                    <button type="button" class="btn btn-outline" style="flex:1;padding:12px;" onclick="document.getElementById('confirmTamperModal').style.display='none'">Cancel</button>
                    <button type="submit" class="btn btn-danger" style="flex:1;padding:12px;" id="confirmTamperBtn">Confirm Tampering</button>
                </div>
            </form>
        </div>
    </div>
    <?php endif; ?>

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
document.getElementById('verifyForm').addEventListener('submit',async function(e){
    e.preventDefault();
    const b=document.getElementById('verifyBtn'),f=this;
    const c=new FormData(f);
    c.append('ajax','1');
    b.innerHTML='<i class="fas fa-spinner fa-spin"></i> Calculating hashes, please wait...';
    b.disabled=true;
    let raw;
    try{
        const res=await fetch(f.action,{method:'POST',body:c});
        raw=await res.text();
        var r=JSON.parse(raw);
    }catch(err){
        b.innerHTML='<i class="fas fa-times"></i> Error';
        b.disabled=false;
        alert('Verification failed: '+err.message+'\n\nRaw response:\n'+raw);
        return;
    }
    if(r.status==='file_missing'){
        b.innerHTML='<i class="fas fa-times"></i> File Missing';
        b.disabled=false;
        document.getElementById('verifyResult').innerHTML='<div class="result-banner tampered"><div class="result-icon"><i class="fas fa-file-excel"></i></div><div><p style="font-family:Space Grotesk,sans-serif;font-size:18px;font-weight:700;color:var(--danger)">File Not Found</p><p style="font-size:13.5px;color:var(--muted);margin-top:4px">The evidence file could not be located on the server.</p></div></div>';
        return;
    }
    const intact=r.status==='intact';
    b.innerHTML=intact?'<i class="fas fa-check"></i> Verified':'<i class="fas fa-times"></i> Tampered';
    b.disabled=false;
    document.getElementById('verifyResult').innerHTML='<div class="result-banner '+r.status+'"><div class="result-icon"><i class="fas '+(intact?'fa-shield-check':'fa-triangle-exclamation')+'"></i></div><div><p style="font-family:Space Grotesk,sans-serif;font-size:18px;font-weight:700;color:var('+(intact?'success':'danger')+')">'+(intact?'Integrity Verified - File Intact':'INTEGRITY FAILURE - File May Be Tampered')+'</p><p style="font-size:13.5px;color:var(--muted);margin-top:4px">'+(intact?'Both SHA-256 and SHA3-256 hashes match the originals.':'Hash mismatch detected.')+'</p></div></div>';
});
document.querySelectorAll('form[action*="clear_flag"]').forEach(f=>f.addEventListener('submit',async function(e){e.preventDefault();const b=document.getElementById('clearFlagBtn'),c=new FormData(this);if(!c.get('admin_note')){alert('Admin note is required');return;}b.innerHTML='<i class="fas fa-spinner fa-spin"></i> Clearing flag...';b.disabled=true;let r;try{const res=await fetch(this.action,{method:'POST',body:c});r=await res.json();}catch(err){b.innerHTML='<i class="fas fa-times"></i> Error';b.disabled=false;alert('Error: '+err.message);return;}if(r.success){b.innerHTML='<i class="fas fa-check"></i> Flag Cleared';b.disabled=false;alert('Flag cleared! Status restored to: '+r.status);window.location.reload();}else{b.innerHTML='<i class="fas fa-times"></i> Failed';b.disabled=false;alert(r.error||'Failed to clear flag');}}));
document.getElementById('confirmTamperForm')?.addEventListener('submit',async function(e){e.preventDefault();const b=document.getElementById('confirmTamperBtn'),c=new FormData(this);if(!c.get('admin_note')){alert('Investigation conclusion is required');return;}b.innerHTML='<i class="fas fa-spinner fa-spin"></i> Closing investigation...';b.disabled=true;let r;try{const res=await fetch(this.action,{method:'POST',body:c});r=await res.json();}catch(err){b.innerHTML='<i class="fas fa-times"></i> Error';b.disabled=false;alert('Error: '+err.message);return;}if(r.success){b.innerHTML='<i class="fas fa-check"></i> Investigation Closed';b.disabled=false;alert('Tampering confirmed! Investigation closed.');window.location.reload();}else{b.innerHTML='<i class="fas fa-times"></i> Failed';b.disabled=false;alert(r.error||'Failed to confirm tampering');}});
</script>
<script src="../assets/js/main.js"></script>
</body>
</html>
