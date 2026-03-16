<?php
/**
 * DigiCustody – Chain of Custody Report
 * Save to: /var/www/html/digicustody/pages/coc_report.php
 */
session_start();
require_once __DIR__.'/../config/db.php';
require_once __DIR__.'/../config/functions.php';
require_login();

$id = (int)($_GET['id'] ?? 0);
if (!$id) { header('Location: evidence.php'); exit; }

// Fetch evidence with full details
$stmt = $pdo->prepare("
    SELECT e.*,
           u_up.full_name  AS uploader_name,
           u_up.username   AS uploader_username,
           u_up.role       AS uploader_role,
           u_up.badge_number AS uploader_badge,
           u_up.department AS uploader_dept,
           u_cur.full_name AS custodian_name,
           u_cur.role      AS custodian_role,
           c.case_number, c.case_title, c.case_type,
           c.status AS case_status, c.priority AS case_priority,
           c.description AS case_description
    FROM evidence e
    JOIN users u_up  ON u_up.id  = e.uploaded_by
    JOIN users u_cur ON u_cur.id = e.current_custodian
    JOIN cases c     ON c.id     = e.case_id
    WHERE e.id = ?
");
$stmt->execute([$id]);
$ev = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$ev) { header('Location: evidence.php?error=not_found'); exit; }

// All audit logs for this evidence
$logs = $pdo->prepare("
    SELECT al.*, u.full_name, u.badge_number, u.department
    FROM audit_logs al
    LEFT JOIN users u ON u.id = al.user_id
    WHERE al.target_type='evidence' AND al.target_id=?
    ORDER BY al.created_at ASC
");
$logs->execute([$id]);
$logs = $logs->fetchAll(PDO::FETCH_ASSOC);

// Hash verifications
$verifications = $pdo->prepare("
    SELECT hv.*, u.full_name AS verifier_name, u.badge_number AS verifier_badge
    FROM hash_verifications hv
    JOIN users u ON u.id = hv.verified_by
    WHERE hv.evidence_id = ?
    ORDER BY hv.verified_at ASC
");
$verifications->execute([$id]);
$verifications = $verifications->fetchAll(PDO::FETCH_ASSOC);

// Analysis reports
$reports = $pdo->prepare("
    SELECT ar.*, u.full_name AS analyst_name, u.badge_number AS analyst_badge,
           r.full_name AS reviewer_name
    FROM analysis_reports ar
    JOIN users u ON u.id = ar.submitted_by
    LEFT JOIN users r ON r.id = ar.reviewed_by
    WHERE ar.evidence_id = ?
    ORDER BY ar.created_at ASC
");
$reports->execute([$id]);
$reports = $reports->fetchAll(PDO::FETCH_ASSOC);

// Log this report generation
audit_log($pdo,$_SESSION['user_id'],$_SESSION['username'],$_SESSION['role'],
    'evidence_viewed','evidence',$id,$ev['evidence_number'],
    "Chain of Custody Report generated for {$ev['evidence_number']}",
    $_SERVER['REMOTE_ADDR']??'');

$generated_by = $_SESSION['full_name'];
$generated_at = date('F j, Y \a\t H:i:s');
$print_mode   = isset($_GET['print']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Chain of Custody Report — <?= e($ev['evidence_number']) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<?php if (!$print_mode): ?>
<link rel="stylesheet" href="../assets/css/global.css">
<?php endif; ?>
<style>
<?php if ($print_mode): ?>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Inter', sans-serif; background: white; color: #111; font-size: 12px; line-height: 1.5; }
@page { size: A4; margin: 20mm 18mm; }
@media print { .no-print { display: none !important; } .page-break { page-break-before: always; } }
<?php else: ?>
.report-wrap { max-width: 820px; margin: 0 auto; background: white; color: #111; padding: 40px; border-radius: 12px; }
<?php endif; ?>

/* ── shared report styles ── */
.rpt-header { border-bottom: 3px solid #0a1628; padding-bottom: 16px; margin-bottom: 24px; display: flex; align-items: flex-start; justify-content: space-between; }
.rpt-logo { font-family: 'Space Grotesk', sans-serif; font-size: 22px; font-weight: 700; color: #0a1628; }
.rpt-logo span { color: #c9a84c; }
.rpt-logo-sub { font-size: 10px; color: #666; letter-spacing: 1px; text-transform: uppercase; margin-top: 2px; }
.rpt-title { text-align: right; }
.rpt-title h1 { font-family: 'Space Grotesk', sans-serif; font-size: 16px; font-weight: 700; color: #0a1628; text-transform: uppercase; letter-spacing: 1px; }
.rpt-title p { font-size: 11px; color: #666; margin-top: 3px; }
.rpt-ev-num { font-size: 24px; font-weight: 700; color: #c9a84c; font-family: 'Space Grotesk', sans-serif; margin-bottom: 4px; }
.section { margin-bottom: 22px; }
.section-title { font-family: 'Space Grotesk', sans-serif; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.2px; color: #0a1628; border-bottom: 1.5px solid #c9a84c; padding-bottom: 5px; margin-bottom: 12px; display: flex; align-items: center; gap: 7px; }
.section-title i { color: #c9a84c; font-size: 12px; }
.info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 20px; }
.info-row { display: flex; gap: 8px; padding: 4px 0; border-bottom: 1px solid #f0f0f0; }
.info-row:last-child { border-bottom: none; }
.info-label { font-size: 11px; font-weight: 600; color: #555; min-width: 130px; flex-shrink: 0; }
.info-value { font-size: 11.5px; color: #111; }
.info-value.mono { font-family: 'Courier New', monospace; font-size: 10.5px; word-break: break-all; }
.hash-box { background: #f8f9fa; border: 1px solid #e0e0e0; border-radius: 6px; padding: 10px 14px; margin-bottom: 8px; }
.hash-box .hl { font-size: 10px; font-weight: 700; color: #555; text-transform: uppercase; letter-spacing: .8px; margin-bottom: 4px; }
.hash-box .hv { font-family: 'Courier New', monospace; font-size: 10.5px; color: #111; word-break: break-all; }
/* timeline */
.timeline { margin: 0; padding: 0; list-style: none; }
.tl-item { display: flex; gap: 12px; padding-bottom: 14px; position: relative; }
.tl-item::before { content: ''; position: absolute; left: 14px; top: 30px; bottom: 0; width: 1.5px; background: #e0e0e0; }
.tl-item:last-child::before { display: none; }
.tl-dot { width: 28px; height: 28px; border-radius: 50%; flex-shrink: 0; display: flex; align-items: center; justify-content: center; font-size: 10px; position: relative; z-index: 1; border: 1.5px solid; }
.tl-dot.upload   { background: #e8f8f0; border-color: #22aa66; color: #22aa66; }
.tl-dot.view     { background: #e8f0fa; border-color: #3377cc; color: #3377cc; }
.tl-dot.download { background: #fff8e0; border-color: #cc8800; color: #cc8800; }
.tl-dot.verify   { background: #fef9ec; border-color: #c9a84c; color: #c9a84c; }
.tl-dot.report   { background: #f0f8ff; border-color: #5599dd; color: #5599dd; }
.tl-dot.default  { background: #f5f5f5; border-color: #aaa; color: #aaa; }
.tl-body { flex: 1; padding-top: 4px; }
.tl-action { font-size: 12px; font-weight: 600; color: #111; margin-bottom: 2px; }
.tl-meta { font-size: 11px; color: #555; }
.tl-extra { font-size: 10.5px; color: #777; margin-top: 2px; font-style: italic; }
/* integrity */
.integ-intact   { color: #22aa66; font-weight: 600; }
.integ-tampered { color: #cc2222; font-weight: 700; }
/* report section */
.report-block { background: #f8f9fa; border: 1px solid #e0e0e0; border-left: 3px solid #c9a84c; border-radius: 4px; padding: 12px 14px; margin-bottom: 10px; }
.rb-num { font-size: 10px; font-weight: 700; color: #c9a84c; text-transform: uppercase; letter-spacing: .8px; }
.rb-title { font-size: 13px; font-weight: 700; color: #0a1628; margin: 3px 0 6px; }
.rb-label { font-size: 10px; font-weight: 700; color: #555; text-transform: uppercase; letter-spacing: .6px; margin: 8px 0 3px; }
.rb-text { font-size: 11.5px; color: #333; line-height: 1.6; }
/* signature */
.sig-box { border: 1px solid #ccc; border-radius: 6px; padding: 16px; margin-top: 8px; }
.sig-line { border-bottom: 1.5px solid #333; margin-bottom: 4px; height: 36px; }
.sig-label { font-size: 10px; color: #555; }
.sig-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }
/* alert box */
.alert-tampered { background: #fff0f0; border: 1.5px solid #cc2222; border-radius: 6px; padding: 10px 14px; margin-bottom: 16px; color: #cc2222; font-size: 12px; font-weight: 600; }
.alert-intact   { background: #f0fff8; border: 1.5px solid #22aa66; border-radius: 6px; padding: 10px 14px; margin-bottom: 16px; color: #22aa66; font-size: 12px; font-weight: 600; }
/* footer */
.rpt-footer { border-top: 1.5px solid #ccc; margin-top: 24px; padding-top: 10px; display: flex; justify-content: space-between; font-size: 10px; color: #888; }
/* badge */
.badge-status { display: inline-block; padding: 2px 8px; border-radius: 20px; font-size: 10px; font-weight: 600; }
.bs-green  { background: #e8f8f0; color: #22aa66; }
.bs-blue   { background: #e8f0fa; color: #3377cc; }
.bs-orange { background: #fff4e0; color: #cc7700; }
.bs-red    { background: #fff0f0; color: #cc2222; }
.bs-gray   { background: #f5f5f5; color: #666; }
/* watermark */
.watermark { position: fixed; top: 50%; left: 50%; transform: translate(-50%,-50%) rotate(-35deg); font-size: 80px; font-weight: 900; color: rgba(201,168,76,0.04); font-family: 'Space Grotesk',sans-serif; pointer-events: none; white-space: nowrap; z-index: 0; }
</style>
</head>
<body>

<?php if (!$print_mode): ?>
<!-- Screen toolbar -->
<div class="no-print" style="background:#0a1628;padding:14px 24px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;position:sticky;top:0;z-index:100;">
    <div style="display:flex;align-items:center;gap:14px;">
        <a href="evidence_view.php?id=<?= $id ?>" style="color:#c9a84c;font-size:13px;text-decoration:none;display:flex;align-items:center;gap:6px;">
            <i class="fas fa-arrow-left"></i> Back to Evidence
        </a>
        <span style="color:#344560">|</span>
        <span style="color:#f0f4fa;font-size:13px;font-weight:500"><?= e($ev['evidence_number']) ?> — Chain of Custody Report</span>
    </div>
    <div style="display:flex;gap:10px;">
        <a href="coc_report.php?id=<?= $id ?>&print=1" target="_blank"
           style="background:none;border:1px solid rgba(255,255,255,0.2);color:#c9a84c;padding:7px 16px;border-radius:8px;font-size:13px;text-decoration:none;display:flex;align-items:center;gap:6px;">
            <i class="fas fa-external-link-alt"></i> Open Printable Version
        </a>
        <button onclick="window.print()"
            style="background:#c9a84c;border:none;color:#0a1628;padding:7px 16px;border-radius:8px;font-size:13px;cursor:pointer;font-weight:600;display:flex;align-items:center;gap:6px;">
            <i class="fas fa-print"></i> Print / Save as PDF
        </button>
    </div>
</div>
<div style="padding:24px;">
<div class="report-wrap">
<?php endif; ?>

<div class="watermark">DIGICUSTODY</div>

<!-- ══ REPORT HEADER ══ -->
<div class="rpt-header">
    <div>
        <div class="rpt-logo">Digi<span>Custody</span></div>
        <div class="rpt-logo-sub">Secure Evidence Management Platform</div>
        <?php
        $inst = $pdo->query("SELECT setting_value FROM system_settings WHERE setting_key='institution_name'")->fetchColumn();
        if ($inst): ?><div style="font-size:11px;color:#333;margin-top:4px;font-weight:500"><?= e($inst) ?></div><?php endif; ?>
    </div>
    <div class="rpt-title">
        <h1>Chain of Custody Report</h1>
        <p>Generated: <?= $generated_at ?></p>
        <p>Generated by: <?= e($generated_by) ?></p>
        <p>CONFIDENTIAL — For Official Use Only</p>
    </div>
</div>

<!-- Evidence number banner -->
<div style="background:#0a1628;color:white;padding:14px 18px;border-radius:8px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;">
    <div>
        <div class="rpt-ev-num"><?= e($ev['evidence_number']) ?></div>
        <div style="font-size:14px;font-weight:500;color:#e0e0e0"><?= e($ev['title']) ?></div>
    </div>
    <div style="text-align:right;">
        <?php
        $last_integ = $verifications ? end($verifications)['integrity_status'] : null;
        if ($last_integ === 'tampered'): ?>
        <div style="background:#cc2222;color:white;padding:6px 14px;border-radius:20px;font-size:12px;font-weight:700;">
            ⚠ INTEGRITY COMPROMISED
        </div>
        <?php elseif ($last_integ === 'intact'): ?>
        <div style="background:#22aa66;color:white;padding:6px 14px;border-radius:20px;font-size:12px;font-weight:700;">
            ✓ INTEGRITY VERIFIED
        </div>
        <?php else: ?>
        <div style="background:#888;color:white;padding:6px 14px;border-radius:20px;font-size:12px;font-weight:600;">
            NOT YET VERIFIED
        </div>
        <?php endif; ?>
    </div>
</div>

<?php if ($last_integ === 'tampered'): ?>
<div class="alert-tampered">⚠ WARNING: This evidence has FAILED integrity verification. The SHA-256 or MD5 hash does not match the original recorded at time of upload. This evidence may be inadmissible in court.</div>
<?php elseif ($last_integ === 'intact'): ?>
<div class="alert-intact">✓ This evidence has been verified intact. Current SHA-256 and MD5 hashes match the originals recorded at time of upload.</div>
<?php endif; ?>

<!-- ══ 1. CASE INFORMATION ══ -->
<div class="section">
    <div class="section-title"><i class="fas fa-folder-open"></i> 1. Case Information</div>
    <div class="info-grid">
        <div>
            <div class="info-row"><span class="info-label">Case Number</span><span class="info-value"><?= e($ev['case_number']) ?></span></div>
            <div class="info-row"><span class="info-label">Case Title</span><span class="info-value"><?= e($ev['case_title']) ?></span></div>
            <div class="info-row"><span class="info-label">Case Type</span><span class="info-value"><?= e($ev['case_type'] ?: 'Not specified') ?></span></div>
        </div>
        <div>
            <div class="info-row"><span class="info-label">Case Status</span><span class="info-value"><?= ucwords(str_replace('_',' ',$ev['case_status'])) ?></span></div>
            <div class="info-row"><span class="info-label">Priority</span><span class="info-value"><?= ucfirst($ev['case_priority'] ?? 'Medium') ?></span></div>
        </div>
    </div>
</div>

<!-- ══ 2. EVIDENCE DETAILS ══ -->
<div class="section">
    <div class="section-title"><i class="fas fa-database"></i> 2. Evidence Details</div>
    <div class="info-grid">
        <div>
            <div class="info-row"><span class="info-label">Evidence Number</span><span class="info-value" style="font-weight:700;color:#c9a84c"><?= e($ev['evidence_number']) ?></span></div>
            <div class="info-row"><span class="info-label">Title</span><span class="info-value"><?= e($ev['title']) ?></span></div>
            <div class="info-row"><span class="info-label">Evidence Type</span><span class="info-value"><?= ucwords(str_replace('_',' ',$ev['evidence_type'])) ?></span></div>
            <div class="info-row"><span class="info-label">File Name</span><span class="info-value mono"><?= e($ev['file_name']) ?></span></div>
            <div class="info-row"><span class="info-label">File Size</span><span class="info-value"><?= format_filesize($ev['file_size']) ?></span></div>
            <div class="info-row"><span class="info-label">MIME Type</span><span class="info-value mono"><?= e($ev['mime_type'] ?? 'Unknown') ?></span></div>
        </div>
        <div>
            <div class="info-row"><span class="info-label">Status</span><span class="info-value"><?= ucwords(str_replace('_',' ',$ev['status'])) ?></span></div>
            <div class="info-row"><span class="info-label">Collection Date</span><span class="info-value"><?= $ev['collection_date'] ? date('F j, Y H:i:s',strtotime($ev['collection_date'])) : 'Not recorded' ?></span></div>
            <div class="info-row"><span class="info-label">Collection Location</span><span class="info-value"><?= e($ev['collection_location'] ?: 'Not recorded') ?></span></div>
            <div class="info-row"><span class="info-label">Upload Date</span><span class="info-value"><?= date('F j, Y H:i:s',strtotime($ev['uploaded_at'])) ?></span></div>
            <div class="info-row"><span class="info-label">Uploaded By</span><span class="info-value"><?= e($ev['uploader_name']) ?> (<?= ucfirst($ev['uploader_role']) ?>)</span></div>
            <div class="info-row"><span class="info-label">Current Custodian</span><span class="info-value"><?= e($ev['custodian_name']) ?> (<?= ucfirst($ev['custodian_role']) ?>)</span></div>
        </div>
    </div>
    <?php if ($ev['description']): ?>
    <div style="margin-top:10px;">
        <div class="info-row"><span class="info-label">Description</span><span class="info-value"><?= nl2br(e($ev['description'])) ?></span></div>
    </div>
    <?php endif; ?>
</div>

<!-- ══ 3. COLLECTION & COC NOTES ══ -->
<?php if ($ev['collection_notes']): ?>
<div class="section">
    <div class="section-title"><i class="fas fa-shield-halved"></i> 3. Collection &amp; Chain of Custody Details</div>
    <div style="background:#f8f9fa;border:1px solid #e0e0e0;border-radius:6px;padding:12px 14px;">
        <?php
        $lines = explode("\n", trim($ev['collection_notes']));
        foreach ($lines as $line):
            $line = trim($line);
            if (!$line) continue;
            $parts = explode(': ', $line, 2);
        ?>
        <div class="info-row">
            <span class="info-label"><?= e($parts[0]) ?></span>
            <span class="info-value"><?= e($parts[1] ?? '') ?></span>
        </div>
        <?php endforeach; ?>
    </div>
</div>
<?php endif; ?>

<!-- ══ 4. INTEGRITY HASHES ══ -->
<div class="section">
    <div class="section-title"><i class="fas fa-fingerprint"></i> <?= $ev['collection_notes']?'4':'3' ?>. Cryptographic Integrity Hashes</div>
    <p style="font-size:11px;color:#555;margin-bottom:10px;">Hashes recorded at time of upload. Any modification to the file will produce different hash values.</p>
    <div class="hash-box">
        <div class="hl">SHA-256 (Primary — Forensic Standard)</div>
        <div class="hv"><?= e($ev['sha256_hash']) ?></div>
    </div>
    <div class="hash-box">
        <div class="hl">MD5</div>
        <div class="hv"><?= e($ev['md5_hash']) ?></div>
    </div>
    <div class="hash-box">
        <div class="hl">File Size</div>
        <div class="hv"><?= format_filesize($ev['file_size']) ?> (<?= number_format($ev['file_size']) ?> bytes)</div>
    </div>
</div>

<!-- ══ 5. INTEGRITY VERIFICATION HISTORY ══ -->
<div class="section">
    <div class="section-title"><i class="fas fa-check-double"></i> Integrity Verification History</div>
    <?php if (empty($verifications)): ?>
    <p style="font-size:11.5px;color:#888;font-style:italic;">No integrity checks have been performed on this evidence yet.</p>
    <?php else: ?>
    <table style="width:100%;border-collapse:collapse;font-size:11px;">
        <thead>
            <tr style="background:#f0f0f0;">
                <th style="padding:6px 10px;text-align:left;border:1px solid #ddd;">Date &amp; Time</th>
                <th style="padding:6px 10px;text-align:left;border:1px solid #ddd;">Verified By</th>
                <th style="padding:6px 10px;text-align:left;border:1px solid #ddd;">Result</th>
                <th style="padding:6px 10px;text-align:left;border:1px solid #ddd;">SHA-256 Match</th>
                <th style="padding:6px 10px;text-align:left;border:1px solid #ddd;">MD5 Match</th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($verifications as $v): ?>
        <tr>
            <td style="padding:6px 10px;border:1px solid #eee;"><?= date('M j, Y H:i:s',strtotime($v['verified_at'])) ?></td>
            <td style="padding:6px 10px;border:1px solid #eee;"><?= e($v['verifier_name']) ?><?= $v['verifier_badge']?' ('.e($v['verifier_badge']).')':'' ?></td>
            <td style="padding:6px 10px;border:1px solid #eee;">
                <span class="<?= $v['integrity_status']==='intact'?'integ-intact':'integ-tampered' ?>">
                    <?= strtoupper($v['integrity_status']) ?>
                </span>
            </td>
            <td style="padding:6px 10px;border:1px solid #eee;">
                <?= $v['sha256_at_verification']===$v['original_sha256']
                    ?'<span style="color:#22aa66">✓ Match</span>'
                    :'<span style="color:#cc2222">✗ MISMATCH</span>' ?>
            </td>
            <td style="padding:6px 10px;border:1px solid #eee;">
                <?= $v['md5_at_verification']===$v['original_md5']
                    ?'<span style="color:#22aa66">✓ Match</span>'
                    :'<span style="color:#cc2222">✗ MISMATCH</span>' ?>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>
</div>

<!-- ══ 6. AUDIT TRAIL / CHAIN OF CUSTODY TIMELINE ══ -->
<div class="section <?= $print_mode?'page-break':'' ?>">
    <div class="section-title"><i class="fas fa-scroll"></i> Complete Audit Trail — Chain of Custody Timeline</div>
    <p style="font-size:11px;color:#555;margin-bottom:12px;">Every action performed on this evidence, recorded automatically and immutably.</p>
    <?php if (empty($logs)): ?>
    <p style="font-size:11.5px;color:#888;font-style:italic;">No audit entries found.</p>
    <?php else: ?>
    <ul class="timeline">
    <?php
    $dot_map = [
        'evidence_uploaded'   => ['upload','fa-upload'],
        'evidence_viewed'     => ['view','fa-eye'],
        'evidence_downloaded' => ['download','fa-download'],
        'hash_verified'       => ['verify','fa-fingerprint'],
        'integrity_check'     => ['verify','fa-shield-check'],
        'report_submitted'    => ['report','fa-file-lines'],
        'report_approved'     => ['report','fa-file-circle-check'],
        'download_token_generated' => ['download','fa-key'],
    ];
    foreach ($logs as $log):
        [$cls,$ico] = $dot_map[$log['action_type']] ?? ['default','fa-circle-dot'];
        $extra = $log['extra_data'] ? json_decode($log['extra_data'],true) : [];
    ?>
    <li class="tl-item">
        <div class="tl-dot <?= $cls ?>"><i class="fas <?= $ico ?>"></i></div>
        <div class="tl-body">
            <div class="tl-action"><?= e($log['description']) ?></div>
            <div class="tl-meta">
                <?= e($log['full_name'] ?? $log['username'] ?? 'System') ?>
                <?= $log['badge_number']?' · Badge: '.e($log['badge_number']):'' ?>
                <?= $log['department']?' · '.e($log['department']):'' ?>
                &nbsp;·&nbsp; <?= date('M j, Y H:i:s',strtotime($log['created_at'])) ?>
                &nbsp;·&nbsp; IP: <?= e($log['ip_address']??'—') ?>
            </div>
            <?php if (!empty($extra) && isset($extra['sha256'])): ?>
            <div class="tl-extra">SHA-256 at event: <?= e(substr($extra['sha256'],0,32)) ?>...</div>
            <?php endif; ?>
        </div>
    </li>
    <?php endforeach; ?>
    </ul>
    <?php endif; ?>
</div>

<!-- ══ 7. ANALYSIS REPORTS ══ -->
<?php if (!empty($reports)): ?>
<div class="section">
    <div class="section-title"><i class="fas fa-file-lines"></i> Analysis Reports (<?= count($reports) ?>)</div>
    <?php foreach ($reports as $r): ?>
    <div class="report-block">
        <div class="rb-num"><?= e($r['report_number']) ?> &nbsp;·&nbsp; <?= date('M j, Y',strtotime($r['created_at'])) ?> &nbsp;·&nbsp; <?= e($r['analyst_name']) ?><?= $r['analyst_badge']?' ('.e($r['analyst_badge']).')':'' ?></div>
        <div class="rb-title"><?= e($r['title']) ?></div>
        <div class="rb-label">Summary</div>
        <div class="rb-text"><?= nl2br(e($r['summary'])) ?></div>
        <div class="rb-label">Findings</div>
        <div class="rb-text"><?= nl2br(e($r['findings'])) ?></div>
        <?php if ($r['conclusions']): ?>
        <div class="rb-label">Conclusions</div>
        <div class="rb-text"><?= nl2br(e($r['conclusions'])) ?></div>
        <?php endif; ?>
        <?php if ($r['recommendations']): ?>
        <div class="rb-label">Recommendations</div>
        <div class="rb-text"><?= nl2br(e($r['recommendations'])) ?></div>
        <?php endif; ?>
        <?php if ($r['tools_used']): ?>
        <div class="rb-label">Tools Used</div>
        <div class="rb-text"><?= e($r['tools_used']) ?></div>
        <?php endif; ?>
        <div style="margin-top:8px;font-size:10.5px;color:#555;">
            Status: <strong><?= ucfirst($r['status']) ?></strong>
            <?php if ($r['reviewer_name']): ?> &nbsp;·&nbsp; Reviewed by: <?= e($r['reviewer_name']) ?> on <?= date('M j, Y',strtotime($r['reviewed_at'])) ?><?php endif; ?>
        </div>
    </div>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<!-- ══ 8. SIGNATURE BLOCK ══ -->
<div class="section">
    <div class="section-title"><i class="fas fa-pen"></i> Certification &amp; Signatures</div>
    <p style="font-size:11px;color:#333;margin-bottom:14px;line-height:1.6;">
        I hereby certify that the information contained in this Chain of Custody Report is accurate and complete to the best of my knowledge. This evidence has been collected, handled, stored and maintained in accordance with accepted digital forensic standards and procedures.
    </p>
    <div class="sig-grid">
        <div class="sig-box">
            <div class="sig-line"></div>
            <div class="sig-label">Collecting Officer Signature</div>
            <div class="sig-label" style="margin-top:4px">Name: <?= e($ev['uploader_name']) ?></div>
            <div class="sig-label">Date: ____________________</div>
        </div>
        <div class="sig-box">
            <div class="sig-line"></div>
            <div class="sig-label">Supervisor / Reviewing Officer</div>
            <div class="sig-label" style="margin-top:4px">Name: ____________________</div>
            <div class="sig-label">Date: ____________________</div>
        </div>
        <div class="sig-box">
            <div class="sig-line"></div>
            <div class="sig-label">Court / Legal Officer (if applicable)</div>
            <div class="sig-label" style="margin-top:4px">Name: ____________________</div>
            <div class="sig-label">Date: ____________________</div>
        </div>
    </div>
</div>

<!-- Report footer -->
<div class="rpt-footer">
    <span>DigiCustody — Secure Evidence Management Platform</span>
    <span>Evidence: <?= e($ev['evidence_number']) ?> &nbsp;|&nbsp; Case: <?= e($ev['case_number']) ?></span>
    <span>Generated: <?= $generated_at ?> by <?= e($generated_by) ?></span>
</div>

<?php if (!$print_mode): ?>
</div><!-- /report-wrap -->
</div><!-- /padding -->
<?php endif; ?>

<?php if ($print_mode): ?>
<script>window.onload=function(){window.print();}</script>
<?php endif; ?>
</body>
</html>
