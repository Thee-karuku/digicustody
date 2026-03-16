<?php
/**
 * DigiCustody – Evidence Detail / View Page
 * Save to: /var/www/html/digicustody/pages/evidence_view.php
 */
session_start();
require_once __DIR__.'/../config/db.php';
require_once __DIR__.'/../config/functions.php';
require_login();

$page_title = 'Evidence Details';
$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];
$id   = (int)($_GET['id'] ?? 0);

if (!$id) { header('Location: evidence.php'); exit; }

// Fetch evidence with full details
$stmt = $pdo->prepare("
    SELECT e.*,
           u_up.full_name  AS uploader_name,  u_up.username   AS uploader_username,  u_up.role AS uploader_role,
           u_cur.full_name AS custodian_name,  u_cur.username  AS custodian_username, u_cur.role AS custodian_role,
           c.case_number, c.case_title, c.case_type, c.status AS case_status, c.priority AS case_priority
    FROM evidence e
    JOIN users u_up  ON u_up.id  = e.uploaded_by
    JOIN users u_cur ON u_cur.id = e.current_custodian
    JOIN cases c     ON c.id     = e.case_id
    WHERE e.id = ?
");
$stmt->execute([$id]);
$ev = $stmt->fetch();
if (!$ev) { header('Location: evidence.php?error=not_found'); exit; }

// Log view action
audit_log($pdo,$uid,$_SESSION['username'],$role,'evidence_viewed','evidence',$id,$ev['evidence_number'],
    "Evidence viewed: {$ev['evidence_number']} — {$ev['title']}", $_SERVER['REMOTE_ADDR']??'');

// Full transfer/custody history
$transfers = $pdo->prepare("
    SELECT et.*,
           u_from.full_name AS from_name, u_from.role AS from_role,
           u_to.full_name   AS to_name,   u_to.role   AS to_role
    FROM evidence_transfers et
    JOIN users u_from ON u_from.id = et.from_user
    JOIN users u_to   ON u_to.id   = et.to_user
    WHERE et.evidence_id = ?
    ORDER BY et.transferred_at ASC
");
$transfers->execute([$id]);
$transfers = $transfers->fetchAll();

// Hash verifications
$verifications = $pdo->prepare("
    SELECT hv.*, u.full_name AS verifier_name
    FROM hash_verifications hv
    JOIN users u ON u.id = hv.verified_by
    WHERE hv.evidence_id = ?
    ORDER BY hv.verified_at DESC
");
$verifications->execute([$id]);
$verifications = $verifications->fetchAll();

// Audit logs for this evidence
$logs = $pdo->prepare("
    SELECT al.* FROM audit_logs al
    WHERE al.target_type='evidence' AND al.target_id=?
    ORDER BY al.created_at DESC LIMIT 20
");
$logs->execute([$id]);
$logs = $logs->fetchAll();

// Reports for this evidence
$reports = $pdo->prepare("
    SELECT ar.*, u.full_name AS analyst_name
    FROM analysis_reports ar
    JOIN users u ON u.id = ar.submitted_by
    WHERE ar.evidence_id = ?
    ORDER BY ar.created_at DESC
");
$reports->execute([$id]);
$reports = $reports->fetchAll();

// Handle integrity verification
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action']??'')==='verify_integrity') {
    $file_path = $ev['file_path'];
    if (file_exists($file_path)) {
        $current_sha256 = hash_file('sha256', $file_path);
        $current_md5    = hash_file('md5',    $file_path);
        $status = ($current_sha256===$ev['sha256_hash'] && $current_md5===$ev['md5_hash']) ? 'intact' : 'tampered';

        $pdo->prepare("INSERT INTO hash_verifications
            (evidence_id,verified_by,sha256_at_verification,md5_at_verification,original_sha256,original_md5,integrity_status,notes)
            VALUES(?,?,?,?,?,?,?,?)")
            ->execute([$id,$uid,$current_sha256,$current_md5,$ev['sha256_hash'],$ev['md5_hash'],$status,$_POST['notes']??'']);

        if ($status==='tampered') {
            $pdo->prepare("UPDATE evidence SET status='flagged' WHERE id=?")->execute([$id]);
            send_notification($pdo,$uid,'Integrity Alert',"Evidence {$ev['evidence_number']} integrity check FAILED — file may be tampered!",'danger','evidence',$id);
        }

        audit_log($pdo,$uid,$_SESSION['username'],$role,'hash_verified','evidence',$id,$ev['evidence_number'],
            "Integrity check: $status for {$ev['evidence_number']}",
            $_SERVER['REMOTE_ADDR']??'','',[
                'status'=>$status,'sha256_match'=>$current_sha256===$ev['sha256_hash'],'md5_match'=>$current_md5===$ev['md5_hash']
            ]);
        header("Location: evidence_view.php?id=$id&verified=$status"); exit;
    }
}

$verified_msg = $_GET['verified'] ?? '';

// Type icon map
$type_icons = [
    'image'           => ['fa-file-image',   'blue'],
    'video'           => ['fa-file-video',    'purple'],
    'document'        => ['fa-file-lines',    'green'],
    'log_file'        => ['fa-file-code',     'orange'],
    'email'           => ['fa-envelope',      'info'],
    'database'        => ['fa-database',      'gold'],
    'network_capture' => ['fa-network-wired', 'muted'],
    'mobile_data'     => ['fa-mobile',        'warning'],
    'other'           => ['fa-file',          'gray'],
];
[$ico, $col] = $type_icons[$ev['evidence_type']] ?? ['fa-file', 'gray'];
$last_integrity = $verifications[0]['integrity_status'] ?? 'unchecked';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title><?= e($ev['evidence_number']) ?> — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px 20px;}
.detail-row{padding:9px 0;border-bottom:1px solid var(--border);}
.detail-row:last-child{border-bottom:none;}
.detail-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:3px;}
.detail-value{font-size:13.5px;color:var(--text);font-weight:500;}
.hash-block{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;margin-bottom:10px;}
.hash-block .hb-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px;display:flex;align-items:center;justify-content:space-between;}
.hash-block .hb-val{font-family:'Courier New',monospace;font-size:12px;color:var(--text);word-break:break-all;line-height:1.6;}
.copy-btn{background:none;border:none;color:var(--dim);cursor:pointer;font-size:12px;padding:2px 6px;border-radius:4px;transition:all .2s;}
.copy-btn:hover{color:var(--gold);background:var(--gold-dim);}
/* chain of custody timeline */
.coc-timeline{padding:20px;}
.coc-item{display:flex;gap:16px;position:relative;padding-bottom:24px;}
.coc-item:last-child{padding-bottom:0;}
.coc-item::before{content:'';position:absolute;left:19px;top:40px;bottom:0;width:2px;background:var(--border);}
.coc-item:last-child::before{display:none;}
.coc-dot{width:40px;height:40px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:14px;border:2px solid var(--border);position:relative;z-index:1;}
.coc-dot.upload{background:rgba(74,222,128,0.1);border-color:rgba(74,222,128,0.3);color:var(--success);}
.coc-dot.transfer{background:rgba(167,139,250,0.1);border-color:rgba(167,139,250,0.3);color:#a78bfa;}
.coc-dot.accepted{background:rgba(96,165,250,0.1);border-color:rgba(96,165,250,0.3);color:var(--info);}
.coc-dot.rejected{background:rgba(248,113,113,0.1);border-color:rgba(248,113,113,0.3);color:var(--danger);}
.coc-dot.current{background:rgba(201,168,76,0.1);border-color:rgba(201,168,76,0.3);color:var(--gold);}
.coc-body{flex:1;padding-top:8px;}
.coc-title{font-size:13.5px;font-weight:500;color:var(--text);margin-bottom:4px;}
.coc-meta{font-size:12px;color:var(--muted);}
.coc-reason{font-size:12px;color:var(--dim);font-style:italic;margin-top:4px;}
/* integrity history */
.integ-item{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);}
.integ-item:last-child{border-bottom:none;}
.tabs{display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:0;}
.tab-btn{background:none;border:none;border-bottom:2px solid transparent;padding:12px 18px;font-size:13.5px;color:var(--muted);cursor:pointer;transition:all .2s;font-family:'Inter',sans-serif;margin-bottom:-1px;}
.tab-btn.active{color:var(--gold);border-bottom-color:var(--gold);}
.tab-btn:hover{color:var(--text);}
.tab-panel{display:none;padding:20px;}
.tab-panel.active{display:block;}
.ev-hero{display:flex;align-items:flex-start;gap:20px;margin-bottom:24px;}
.ev-hero-icon{width:64px;height:64px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:26px;flex-shrink:0;}
</style>
</head>
<body>
<div class="app-shell">
<?php include __DIR__.'/../includes/sidebar.php'; ?>
<div class="main-area" id="mainArea">
<?php include __DIR__.'/../includes/navbar.php'; ?>
<div class="page-content">

<!-- Header -->
<div class="page-header">
    <div>
        <h1><?= e($ev['evidence_number']) ?></h1>
        <p><?= e($ev['title']) ?> &nbsp;·&nbsp; <?= e($ev['case_number']) ?></p>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <a href="evidence.php" class="btn btn-outline"><i class="fas fa-arrow-left"></i> Back</a>
        <?php if(!is_viewer()): ?>
        <a href="evidence_download.php?id=<?= $id ?>" class="btn btn-outline"><i class="fas fa-download"></i> Download</a>
        <?php endif; ?>
        <?php if(can_write()): ?>
        <a href="evidence_transfer.php?id=<?= $id ?>" class="btn btn-outline"><i class="fas fa-right-left"></i> Transfer</a>
        <?php endif; ?>
        <?php if(!is_viewer()): ?>
        <a href="evidence_verify.php?id=<?= $id ?>" class="btn btn-outline">
            <i class="fas fa-fingerprint"></i> Verify Integrity
        </a>
        <a href="coc_report.php?id=<?= $id ?>" class="btn btn-outline">
            <i class="fas fa-file-lines"></i> COC Report
        </a>
        <?php endif; ?>
    </div>
</div>

<?php if($verified_msg==='intact'): ?>
<div class="alert alert-success"><i class="fas fa-circle-check"></i> Integrity check passed — file is intact. SHA-256 and MD5 hashes match.</div>
<?php elseif($verified_msg==='tampered'): ?>
<div class="alert alert-danger"><i class="fas fa-triangle-exclamation"></i> <strong>INTEGRITY ALERT:</strong> Hash mismatch detected — this file may have been tampered with. Evidence has been flagged.</div>
<?php endif; ?>

<!-- Hero bar -->
<div class="section-card" style="margin-bottom:20px;">
    <div class="section-body padded">
        <div class="ev-hero">
            <div class="ev-hero-icon stat-icon <?= $col ?>"><i class="fas <?= $ico ?>"></i></div>
            <div style="flex:1;">
                <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px;">
                    <h2 style="font-family:'Space Grotesk',sans-serif;font-size:18px;font-weight:700;color:var(--text)"><?= e($ev['title']) ?></h2>
                    <?= status_badge($ev['status']) ?>
                    <?php if($last_integrity==='intact'): ?><span class="badge badge-green"><i class="fas fa-check"></i> Verified Intact</span>
                    <?php elseif($last_integrity==='tampered'): ?><span class="badge badge-red"><i class="fas fa-triangle-exclamation"></i> TAMPERED</span>
                    <?php else: ?><span class="badge badge-gray">Not Verified</span><?php endif; ?>
                </div>
                <?php if($ev['description']): ?>
                <p style="font-size:13.5px;color:var(--muted);margin-bottom:10px;line-height:1.65"><?= e($ev['description']) ?></p>
                <?php endif; ?>
                <div style="display:flex;gap:20px;flex-wrap:wrap;">
                    <span style="font-size:12.5px;color:var(--muted)"><i class="fas fa-folder-open" style="color:var(--gold);margin-right:5px"></i><?= e($ev['case_number']) ?> — <?= e($ev['case_title']) ?></span>
                    <span style="font-size:12.5px;color:var(--muted)"><i class="fas fa-hard-drive" style="color:var(--muted);margin-right:5px"></i><?= format_filesize($ev['file_size']) ?></span>
                    <span style="font-size:12.5px;color:var(--muted)"><i class="fas fa-calendar" style="color:var(--muted);margin-right:5px"></i><?= date('M j, Y H:i',strtotime($ev['uploaded_at'])) ?></span>
                    <span style="font-size:12.5px;color:var(--muted)"><i class="fas fa-user" style="color:var(--muted);margin-right:5px"></i><?= e($ev['uploader_name']) ?></span>
                </div>
            </div>
        </div>

        <!-- Hash blocks -->
        <div class="grid-2" style="margin-top:16px;">
            <div class="hash-block">
                <div class="hb-label">
                    <span><i class="fas fa-fingerprint" style="color:var(--gold);margin-right:6px"></i>SHA-256 Hash</span>
                    <button class="copy-btn" onclick="copyText('sha256val','Copy SHA-256')"><i class="fas fa-copy"></i></button>
                </div>
                <div class="hb-val" id="sha256val"><?= e($ev['sha256_hash']) ?></div>
            </div>
            <div class="hash-block">
                <div class="hb-label">
                    <span><i class="fas fa-fingerprint" style="color:var(--info);margin-right:6px"></i>MD5 Hash</span>
                    <button class="copy-btn" onclick="copyText('md5val','Copy MD5')"><i class="fas fa-copy"></i></button>
                </div>
                <div class="hb-val" id="md5val"><?= e($ev['md5_hash']) ?></div>
            </div>
        </div>
    </div>
</div>

<!-- Tabs -->
<div class="section-card">
    <div class="tabs">
        <button class="tab-btn active" onclick="showTab('details',this)">Details</button>
        <button class="tab-btn" onclick="showTab('custody',this)">Chain of Custody <span class="badge badge-purple" style="margin-left:4px"><?= count($transfers)+1 ?></span></button>
        <button class="tab-btn" onclick="showTab('integrity',this)">Integrity History <span class="badge badge-<?= $last_integrity==='tampered'?'red':($last_integrity==='intact'?'green':'gray') ?>" style="margin-left:4px"><?= count($verifications) ?></span></button>
        <button class="tab-btn" onclick="showTab('reports',this)"><i class="fas fa-file-lines" style="margin-right:5px"></i>Reports <span class="badge badge-<?= count($reports)>0?'green':'gray' ?>" style="margin-left:4px"><?= count($reports) ?></span></button>
        <button class="tab-btn" onclick="showTab('auditlog',this)">Audit Log <span class="badge badge-gray" style="margin-left:4px"><?= count($logs) ?></span></button>
    </div>

    <!-- Details -->
    <div class="tab-panel active" id="tab-details">
        <div class="detail-grid">
            <div class="detail-row"><p class="detail-label">Evidence Number</p><p class="detail-value" style="color:var(--gold);font-family:'Space Grotesk',sans-serif"><?= e($ev['evidence_number']) ?></p></div>
            <div class="detail-row"><p class="detail-label">Evidence Type</p><p class="detail-value"><?= ucwords(str_replace('_',' ',$ev['evidence_type'])) ?></p></div>
            <div class="detail-row"><p class="detail-label">File Name</p><p class="detail-value" style="font-family:'Courier New',monospace;font-size:12.5px"><?= e($ev['file_name']) ?></p></div>
            <div class="detail-row"><p class="detail-label">MIME Type</p><p class="detail-value" style="font-family:'Courier New',monospace;font-size:12.5px"><?= e($ev['mime_type'] ?? 'Unknown') ?></p></div>
            <div class="detail-row"><p class="detail-label">File Size</p><p class="detail-value"><?= format_filesize($ev['file_size']) ?></p></div>
            <div class="detail-row"><p class="detail-label">Status</p><p class="detail-value"><?= status_badge($ev['status']) ?></p></div>
            <div class="detail-row"><p class="detail-label">Collection Date</p><p class="detail-value"><?= $ev['collection_date'] ? date('M j, Y H:i',strtotime($ev['collection_date'])) : 'Not specified' ?></p></div>
            <div class="detail-row"><p class="detail-label">Collection Location</p><p class="detail-value"><?= e($ev['collection_location'] ?: 'Not specified') ?></p></div>
            <div class="detail-row"><p class="detail-label">Uploaded By</p><p class="detail-value"><?= e($ev['uploader_name']) ?> <?= role_badge($ev['uploader_role']) ?></p></div>
            <div class="detail-row"><p class="detail-label">Upload Date</p><p class="detail-value"><?= date('M j, Y H:i:s',strtotime($ev['uploaded_at'])) ?></p></div>
            <div class="detail-row"><p class="detail-label">Current Custodian</p><p class="detail-value"><?= e($ev['custodian_name']) ?> <?= role_badge($ev['custodian_role']) ?></p></div>
            <div class="detail-row"><p class="detail-label">Number of Transfers</p><p class="detail-value"><?= count($transfers) ?></p></div>
        </div>
        <?php if($ev['collection_notes']): ?>
        <div style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border);">
            <p class="detail-label" style="margin-bottom:8px">Chain of Custody Notes</p>
            <p style="font-size:13.5px;color:var(--text);line-height:1.7;background:var(--surface2);border-radius:var(--radius);padding:12px 16px;"><?= nl2br(e($ev['collection_notes'])) ?></p>
        </div>
        <?php endif; ?>

        <!-- Case info -->
        <div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border);">
            <p class="detail-label" style="margin-bottom:10px">Associated Case</p>
            <div style="background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;display:flex;align-items:center;gap:16px;flex-wrap:wrap;">
                <div class="stat-icon gold" style="width:38px;height:38px;border-radius:9px;"><i class="fas fa-folder-open"></i></div>
                <div>
                    <p style="font-size:14px;font-weight:600;color:var(--gold)"><?= e($ev['case_number']) ?></p>
                    <p style="font-size:13px;color:var(--text);margin-top:2px"><?= e($ev['case_title']) ?></p>
                    <div style="display:flex;gap:8px;margin-top:6px;">
                        <?= status_badge($ev['case_status']) ?>
                        <span class="badge badge-<?= ['low'=>'gray','medium'=>'blue','high'=>'orange','critical'=>'red'][$ev['case_priority']]??'gray' ?>"><?= ucfirst($ev['case_priority']) ?> priority</span>
                        <?php if($ev['case_type']): ?><span class="badge badge-gray"><?= e($ev['case_type']) ?></span><?php endif; ?>
                    </div>
                </div>
                <a href="case_view.php?id=<?= $ev['case_id'] ?>" class="btn btn-gold btn-sm" style="margin-left:auto"><i class="fas fa-eye"></i> View Case Details</a>
            </div>
        </div>
    </div>

    <!-- Chain of Custody -->
    <div class="tab-panel" id="tab-custody">
        <div class="coc-timeline">
            <!-- Initial collection -->
            <div class="coc-item">
                <div class="coc-dot upload"><i class="fas fa-upload"></i></div>
                <div class="coc-body">
                    <p class="coc-title">Evidence Collected & Uploaded</p>
                    <p class="coc-meta">
                        By: <strong style="color:var(--text)"><?= e($ev['uploader_name']) ?></strong> <?= role_badge($ev['uploader_role']) ?>
                        &nbsp;·&nbsp; <?= date('M j, Y H:i:s',strtotime($ev['uploaded_at'])) ?>
                    </p>
                    <?php if($ev['collection_location']): ?>
                    <p class="coc-reason"><i class="fas fa-location-dot"></i> <?= e($ev['collection_location']) ?></p>
                    <?php endif; ?>
                    <div style="margin-top:8px;background:var(--surface2);border-radius:7px;padding:8px 12px;">
                        <p style="font-size:11px;color:var(--muted);margin-bottom:4px">SHA-256 at upload:</p>
                        <p style="font-family:'Courier New',monospace;font-size:11px;color:var(--text)"><?= e($ev['sha256_hash']) ?></p>
                    </div>
                </div>
            </div>

            <!-- Transfers -->
            <?php foreach($transfers as $t): ?>
            <div class="coc-item">
                <div class="coc-dot <?= $t['status'] ?>"><i class="fas <?= $t['status']==='accepted'?'fa-circle-check':($t['status']==='rejected'?'fa-circle-xmark':'fa-right-left') ?>"></i></div>
                <div class="coc-body">
                    <p class="coc-title">
                        Custody Transfer — <span class="badge badge-<?= $t['status']==='accepted'?'green':($t['status']==='rejected'?'red':'orange') ?>"><?= ucfirst($t['status']) ?></span>
                    </p>
                    <p class="coc-meta">
                        From: <strong style="color:var(--text)"><?= e($t['from_name']) ?></strong> <?= role_badge($t['from_role']) ?>
                        &nbsp;<i class="fas fa-arrow-right" style="font-size:10px"></i>&nbsp;
                        To: <strong style="color:var(--text)"><?= e($t['to_name']) ?></strong> <?= role_badge($t['to_role']) ?>
                    </p>
                    <p class="coc-meta" style="margin-top:3px">Initiated: <?= date('M j, Y H:i',strtotime($t['transferred_at'])) ?>
                        <?= $t['accepted_at']?' &nbsp;·&nbsp; Responded: '.date('M j, Y H:i',strtotime($t['accepted_at'])):'' ?></p>
                    <?php if($t['transfer_reason']): ?>
                    <p class="coc-reason">"<?= e($t['transfer_reason']) ?>"</p>
                    <?php endif; ?>
                    <?php if($t['hash_at_transfer']): ?>
                    <div style="margin-top:6px;background:var(--surface2);border-radius:6px;padding:6px 10px;">
                        <p style="font-size:10.5px;color:var(--muted)">SHA-256 at transfer: <span style="font-family:'Courier New',monospace;color:var(--text)"><?= e($t['hash_at_transfer']) ?></span></p>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
            <?php endforeach; ?>

            <!-- Current holder -->
            <div class="coc-item">
                <div class="coc-dot current"><i class="fas fa-shield-halved"></i></div>
                <div class="coc-body">
                    <p class="coc-title">Current Custodian <span class="badge badge-gold" style="margin-left:4px">Now</span></p>
                    <p class="coc-meta"><strong style="color:var(--text)"><?= e($ev['custodian_name']) ?></strong> <?= role_badge($ev['custodian_role']) ?></p>
                </div>
            </div>
        </div>
    </div>

    <!-- Integrity History -->
    <div class="tab-panel" id="tab-integrity">
        <?php if(empty($verifications)): ?>
        <div class="empty-state"><i class="fas fa-fingerprint"></i><p>No integrity checks performed yet.</p>
        <?php if(!is_viewer()): ?><form method="POST" style="margin-top:14px"><input type="hidden" name="action" value="verify_integrity"><button type="submit" class="btn btn-gold"><i class="fas fa-fingerprint"></i> Run First Check</button></form><?php endif ?>
        </div>
        <?php else: ?>
        <div style="padding:10px 0;">
        <?php foreach($verifications as $v): ?>
        <div class="integ-item">
            <div class="stat-icon <?= $v['integrity_status']==='intact'?'green':'red' ?>" style="width:36px;height:36px;border-radius:9px;flex-shrink:0;">
                <i class="fas <?= $v['integrity_status']==='intact'?'fa-check':'fa-triangle-exclamation' ?>"></i>
            </div>
            <div style="flex:1;">
                <p style="font-size:13.5px;font-weight:500;color:var(--text)">
                    <?= $v['integrity_status']==='intact'?'Integrity Verified — File Intact':'<span style=\"color:var(--danger)\">INTEGRITY FAILED — File May Be Tampered</span>' ?>
                </p>
                <p style="font-size:12px;color:var(--muted);margin-top:2px">
                    By: <?= e($v['verifier_name']) ?> &nbsp;·&nbsp; <?= date('M j, Y H:i:s',strtotime($v['verified_at'])) ?>
                </p>
                <?php if($v['notes']): ?><p style="font-size:12px;color:var(--dim);font-style:italic;margin-top:3px">"<?= e($v['notes']) ?>"</p><?php endif; ?>
                <div style="margin-top:8px;background:var(--surface2);border-radius:6px;padding:8px 12px;font-size:11px;">
                    <p style="color:var(--muted);margin-bottom:3px">SHA-256 at check: <span style="font-family:'Courier New',monospace;color:<?= $v['sha256_at_verification']===$v['original_sha256']?'var(--success)':'var(--danger)' ?>"><?= e($v['sha256_at_verification']) ?></span></p>
                    <p style="color:var(--muted)">MD5 at check: <span style="font-family:'Courier New',monospace;color:<?= $v['md5_at_verification']===$v['original_md5']?'var(--success)':'var(--danger)' ?>"><?= e($v['md5_at_verification']) ?></span></p>
                </div>
            </div>
        </div>
        <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>

    <!-- Reports -->
    <div class="tab-panel" id="tab-reports">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
            <p style="font-size:13px;color:var(--muted)"><?= count($reports) ?> report<?= count($reports)!=1?'s':'' ?> submitted for this evidence</p>
            <?php if(can_report()): ?>
            <a href="reports.php?evidence_id=<?= $id ?>" class="btn btn-gold btn-sm">
                <i class="fas fa-file-plus"></i> Submit New Report
            </a>
            <?php endif; ?>
        </div>
        <?php if(empty($reports)): ?>
        <div class="empty-state"><i class="fas fa-file-lines"></i>
            <p>No analysis reports submitted for this evidence yet.</p>
            <?php if(can_report()): ?><a href="reports.php?evidence_id=<?= $id ?>" class="btn btn-gold" style="margin-top:14px"><i class="fas fa-file-plus"></i> Submit First Report</a><?php endif; ?>
        </div>
        <?php else: foreach($reports as $r):
            $sc=['draft'=>'gray','submitted'=>'warning','reviewed'=>'blue','approved'=>'green','rejected'=>'red'][$r['status']]??'gray';
        ?>
        <?php
        $border_colors=['gray'=>'#344560','warning'=>'#fbbf24','blue'=>'#60a5fa','green'=>'#4ade80','red'=>'#f87171'];
        $bl_color = $border_colors[$sc] ?? '#344560';
        ?>
        <div style="background:var(--surface2);border:1px solid var(--border);border-left:3px solid <?= $bl_color ?>;border-radius:var(--radius);padding:18px;margin-bottom:14px;">
            <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:12px;flex-wrap:wrap;">
                <div>
                    <p style="font-family:'Space Grotesk',sans-serif;font-size:12.5px;font-weight:700;color:var(--gold)"><?= e($r['report_number']) ?></p>
                    <p style="font-size:14.5px;font-weight:600;color:var(--text);margin-top:3px"><?= e($r['title']) ?></p>
                    <p style="font-size:12px;color:var(--muted);margin-top:4px">
                        By: <strong style="color:var(--text)"><?= e($r['analyst_name']) ?></strong>
                        &nbsp;·&nbsp; <?= date('M j, Y H:i',strtotime($r['created_at'])) ?>
                    </p>
                </div>
                <?= status_badge($r['status']) ?>
            </div>
            <!-- Summary -->
            <div style="margin-bottom:12px;">
                <p style="font-size:11px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin-bottom:5px">Summary</p>
                <p style="font-size:13.5px;color:var(--muted);line-height:1.7"><?= nl2br(e($r['summary'])) ?></p>
            </div>
            <!-- Findings -->
            <div style="margin-bottom:12px;">
                <p style="font-size:11px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin-bottom:5px">Findings</p>
                <p style="font-size:13.5px;color:var(--muted);line-height:1.7"><?= nl2br(e($r['findings'])) ?></p>
            </div>
            <?php if($r['conclusions']): ?>
            <div style="margin-bottom:12px;">
                <p style="font-size:11px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin-bottom:5px">Conclusions</p>
                <p style="font-size:13.5px;color:var(--muted);line-height:1.7"><?= nl2br(e($r['conclusions'])) ?></p>
            </div>
            <?php endif; ?>
            <?php if($r['recommendations']): ?>
            <div style="margin-bottom:12px;">
                <p style="font-size:11px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin-bottom:5px">Recommendations</p>
                <p style="font-size:13.5px;color:var(--muted);line-height:1.7"><?= nl2br(e($r['recommendations'])) ?></p>
            </div>
            <?php endif; ?>
            <?php if($r['tools_used']): ?>
            <p style="font-size:12.5px;color:var(--dim);margin-bottom:8px"><i class="fas fa-wrench" style="margin-right:5px;color:var(--muted)"></i><strong style="color:var(--muted)">Tools used:</strong> <?= e($r['tools_used']) ?></p>
            <?php endif; ?>
            <?php if($r['reviewer_notes']): ?>
            <div style="background:rgba(96,165,250,0.06);border:1px solid rgba(96,165,250,0.15);border-radius:8px;padding:10px 14px;margin-top:8px;">
                <p style="font-size:12px;color:var(--muted)"><i class="fas fa-comment-dots" style="color:var(--info);margin-right:5px"></i><strong style="color:var(--text)">Reviewer notes:</strong> <?= nl2br(e($r['reviewer_notes'])) ?></p>
                <?php if($r['reviewed_at']): ?><p style="font-size:11px;color:var(--dim);margin-top:4px">Reviewed: <?= date('M j, Y H:i',strtotime($r['reviewed_at'])) ?></p><?php endif; ?>
            </div>
            <?php endif; ?>
        </div>
        <?php endforeach; endif; ?>
    </div>

    <!-- Audit Log -->
    <div class="tab-panel" id="tab-auditlog">
        <?php if(empty($logs)): ?>
        <div class="empty-state"><i class="fas fa-scroll"></i><p>No audit entries found.</p></div>
        <?php else:
        $log_icons=['evidence_uploaded'=>['upload','fa-upload'],'evidence_viewed'=>['login','fa-eye'],'evidence_downloaded'=>['download','fa-download'],'evidence_transferred'=>['transfer','fa-right-left'],'hash_verified'=>['verify','fa-fingerprint'],'integrity_check'=>['verify','fa-shield-check']];
        foreach($logs as $log):[$cls,$ico]=$log_icons[$log['action_type']]??['default','fa-circle-dot']; ?>
        <div style="display:flex;gap:11px;padding:10px 0;border-bottom:1px solid var(--border);">
            <div class="log-icon <?= $cls ?>" style="width:28px;height:28px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:11px;"><i class="fas <?= $ico ?>"></i></div>
            <div style="flex:1;">
                <p style="font-size:13px;color:var(--text)"><?= e($log['description']) ?></p>
                <p style="font-size:11.5px;color:var(--dim);margin-top:2px"><?= e($log['username']??'System') ?> &nbsp;·&nbsp; <?= date('M j, Y H:i:s',strtotime($log['created_at'])) ?> &nbsp;·&nbsp; <?= e($log['ip_address']??'') ?></p>
            </div>
            <span class="badge badge-gray" style="font-size:10px;flex-shrink:0"><?= str_replace('_',' ',e($log['action_type'])) ?></span>
        </div>
        <?php endforeach; endif; ?>
    </div>
</div>

</div></div></div>
<script>
function toggleSidebar(){const sb=document.getElementById('sidebar'),ma=document.getElementById('mainArea');if(window.innerWidth<=900){sb.classList.toggle('mobile-open');}else{sb.classList.toggle('collapsed');ma.classList.toggle('collapsed');}localStorage.setItem('sb_collapsed',sb.classList.contains('collapsed')?'1':'0');}
if(localStorage.getItem('sb_collapsed')==='1'&&window.innerWidth>900){document.getElementById('sidebar').classList.add('collapsed');document.getElementById('mainArea').classList.add('collapsed');}
function toggleNotif(){document.getElementById('notifDropdown').classList.toggle('open');document.getElementById('userDropdown').classList.remove('open');}
function toggleUserMenu(){document.getElementById('userDropdown').classList.toggle('open');document.getElementById('notifDropdown').classList.remove('open');}
document.addEventListener('click',e=>{if(!e.target.closest('#notifWrap'))document.getElementById('notifDropdown').classList.remove('open');if(!e.target.closest('#userMenuWrap'))document.getElementById('userDropdown').classList.remove('open');});
function handleSearch(e){if(e.key==='Enter'){window.location='evidence.php?search='+encodeURIComponent(document.getElementById('globalSearch').value);}}
function showTab(id,btn){
    document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
    document.getElementById('tab-'+id).classList.add('active');
    btn.classList.add('active');
}
function copyText(id,label){
    const val=document.getElementById(id)?.textContent;
    if(val){navigator.clipboard.writeText(val).then(()=>{const btn=event.target.closest('button');if(btn){const orig=btn.innerHTML;btn.innerHTML='<i class="fas fa-check"></i> Copied!';btn.style.color='var(--success)';setTimeout(()=>{btn.innerHTML=orig;btn.style.color='';},1500);}});}
}
</script>
</body>
</html>