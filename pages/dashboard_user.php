<?php
/**
 * DigiCustody – User Dashboard (Investigator / Analyst / Viewer)
 * Save to: /var/www/html/digicustody/pages/dashboard_user.php
 */
$page_title = 'Dashboard';
$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];

// ── Stats ─────────────────────────────────────────────────
$s = $pdo->prepare("SELECT COUNT(*) FROM evidence WHERE uploaded_by=?");
$s->execute([$uid]); $my_evidence = (int)$s->fetchColumn();

// ── All evidence with chain of custody info ───────────────
if ($role === 'analyst') {
    $all_evidence = $pdo->prepare("
        SELECT e.*,
               u_up.full_name  AS uploader_name,
               c.case_number,
               c.case_title,
               (SELECT COUNT(*) FROM audit_logs al
                WHERE al.target_type='evidence' AND al.target_id=e.id) AS action_count,
               (SELECT hv.integrity_status
                FROM hash_verifications hv
                WHERE hv.evidence_id=e.id
                ORDER BY hv.verified_at DESC LIMIT 1) AS last_integrity,
               (SELECT COUNT(*) FROM analysis_reports ar
                WHERE ar.evidence_id=e.id) AS report_count
        FROM evidence e
        JOIN users u_up ON u_up.id = e.uploaded_by
        JOIN cases c    ON c.id    = e.case_id
        WHERE e.case_id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id=?)
        ORDER BY e.uploaded_at DESC
        LIMIT 50
    ");
    $all_evidence->execute([$uid]);
    $all_evidence = $all_evidence->fetchAll(PDO::FETCH_ASSOC);
    
    $total_evidence = count($all_evidence);
    $total_cases = (int)$pdo->query("SELECT COUNT(DISTINCT case_id) FROM evidence WHERE case_id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id=$uid)")->fetchColumn();
} elseif ($role === 'investigator') {
    $all_evidence = $pdo->prepare("
        SELECT e.*,
               u_up.full_name  AS uploader_name,
               c.case_number,
               c.case_title,
               (SELECT COUNT(*) FROM audit_logs al
                WHERE al.target_type='evidence' AND al.target_id=e.id) AS action_count,
               (SELECT hv.integrity_status
                FROM hash_verifications hv
                WHERE hv.evidence_id=e.id
                ORDER BY hv.verified_at DESC LIMIT 1) AS last_integrity,
               (SELECT COUNT(*) FROM analysis_reports ar
                WHERE ar.evidence_id=e.id) AS report_count
        FROM evidence e
        JOIN users u_up ON u_up.id = e.uploaded_by
        JOIN cases c    ON c.id    = e.case_id
        WHERE e.uploaded_by=? OR e.current_custodian=? OR e.case_id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id=?)
        ORDER BY e.uploaded_at DESC
        LIMIT 50
    ");
    $all_evidence->execute([$uid, $uid, $uid]);
    $all_evidence = $all_evidence->fetchAll(PDO::FETCH_ASSOC);
    
    $total_evidence = count($all_evidence);
    $total_cases = (int)$pdo->query("SELECT COUNT(*) FROM cases WHERE status IN ('open','under_investigation')")->fetchColumn();
} else {
    $all_evidence = $pdo->query("
        SELECT e.*,
               u_up.full_name  AS uploader_name,
               c.case_number,
               c.case_title,
               (SELECT COUNT(*) FROM audit_logs al
                WHERE al.target_type='evidence' AND al.target_id=e.id) AS action_count,
               (SELECT hv.integrity_status
                FROM hash_verifications hv
                WHERE hv.evidence_id=e.id
                ORDER BY hv.verified_at DESC LIMIT 1) AS last_integrity,
               (SELECT COUNT(*) FROM analysis_reports ar
                WHERE ar.evidence_id=e.id) AS report_count
        FROM evidence e
        JOIN users u_up ON u_up.id = e.uploaded_by
        JOIN cases c    ON c.id    = e.case_id
        ORDER BY e.uploaded_at DESC
        LIMIT 50
    ")->fetchAll(PDO::FETCH_ASSOC);
    
    $total_evidence = (int)$pdo->query("SELECT COUNT(*) FROM evidence")->fetchColumn();
    $total_cases = (int)$pdo->query("SELECT COUNT(*) FROM cases WHERE status IN ('open','under_investigation')")->fetchColumn();
}

$s = $pdo->prepare("SELECT COUNT(*) FROM analysis_reports WHERE submitted_by=?");
$s->execute([$uid]); $my_reports = (int)$s->fetchColumn();

$s = $pdo->prepare("SELECT COUNT(*) FROM hash_verifications WHERE verified_by=? AND integrity_status='tampered'");
$s->execute([$uid]); $tampered = (int)$s->fetchColumn();

// ── My recent uploads ─────────────────────────────────────
$my_recent = $pdo->prepare("
    SELECT e.*, c.case_number
    FROM evidence e
    JOIN cases c ON c.id = e.case_id
    WHERE e.uploaded_by = ?
    ORDER BY e.uploaded_at DESC LIMIT 6
");
$my_recent->execute([$uid]);
$my_recent = $my_recent->fetchAll(PDO::FETCH_ASSOC);

// ── My recent activity ────────────────────────────────────
$my_logs = $pdo->prepare("
    SELECT * FROM audit_logs
    WHERE user_id = ?
    ORDER BY created_at DESC LIMIT 8
");
$my_logs->execute([$uid]);
$my_logs = $my_logs->fetchAll(PDO::FETCH_ASSOC);

// ── My assigned cases (for analysts) ───────────────────────
$my_cases = [];
$my_cases_count = 0;
if ($role === 'analyst') {
    $stmt = $pdo->prepare("
        SELECT c.*, 
               (SELECT COUNT(*) FROM evidence e WHERE e.case_id = c.id) AS evidence_count,
               u.full_name AS creator_name
        FROM cases c
        JOIN users u ON u.id = c.created_by
        WHERE c.assigned_analyst = ? OR c.id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id = ?)
        ORDER BY c.updated_at DESC
        LIMIT 10
    ");
    $stmt->execute([$uid, $uid]);
    $my_cases = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $my_cases_count = count($my_cases);
}

// ── Integrity alerts ──────────────────────────────────────
if ($role === 'investigator') {
    $integrity_alerts = $pdo->prepare("
        SELECT e.evidence_number, e.title, e.id,
               hv.integrity_status, hv.verified_at, u.full_name AS verifier
        FROM hash_verifications hv
        JOIN evidence e ON e.id = hv.evidence_id
        JOIN users u    ON u.id = hv.verified_by
        WHERE hv.integrity_status = 'tampered'
          AND (e.uploaded_by=? OR e.current_custodian=? OR e.case_id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id=?))
        ORDER BY hv.verified_at DESC LIMIT 5
    ");
    $integrity_alerts->execute([$uid, $uid, $uid]);
    $integrity_alerts = $integrity_alerts->fetchAll(PDO::FETCH_ASSOC);
} else {
    $integrity_alerts = $pdo->query("
        SELECT e.evidence_number, e.title, e.id,
               hv.integrity_status, hv.verified_at, u.full_name AS verifier
        FROM hash_verifications hv
        JOIN evidence e ON e.id = hv.evidence_id
        JOIN users u    ON u.id = hv.verified_by
        WHERE hv.integrity_status = 'tampered'
        ORDER BY hv.verified_at DESC LIMIT 5
    ")->fetchAll(PDO::FETCH_ASSOC);
}

$type_icons = [
    'image'=>['fa-file-image','blue'],'video'=>['fa-file-video','purple'],
    'document'=>['fa-file-lines','green'],'log_file'=>['fa-file-code','orange'],
    'email'=>['fa-envelope','info'],'database'=>['fa-database','gold'],
    'network_capture'=>['fa-network-wired','muted'],'mobile_data'=>['fa-mobile','warning'],
    'other'=>['fa-file','gray'],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Dashboard — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/global.css">
<style>
.hash-chip{font-family:'Courier New',monospace;font-size:10.5px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;max-width:130px;}
.filter-bar{display:flex;gap:8px;padding:12px 16px;border-bottom:1px solid var(--border);flex-wrap:wrap;align-items:center;}
.filter-btn{background:none;border:1px solid var(--border);border-radius:7px;padding:5px 13px;font-size:12.5px;color:var(--muted);cursor:pointer;transition:all .2s;font-family:'Inter',sans-serif;}
.filter-btn.active,.filter-btn:hover{border-color:var(--gold);color:var(--gold);background:var(--gold-dim);}
.search-ev{display:flex;align-items:center;gap:8px;background:var(--surface2);border:1px solid var(--border);border-radius:7px;padding:5px 12px;margin-left:auto;}
.search-ev input{background:none;border:none;outline:none;color:var(--text);font-size:12.5px;width:160px;font-family:'Inter',sans-serif;}
.search-ev input::placeholder{color:var(--dim);}
.search-ev i{color:var(--dim);font-size:11px;}
.log-icon{width:28px;height:28px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:11px;}
.log-icon.login{background:rgba(96,165,250,0.1);color:var(--info);}
.log-icon.upload{background:rgba(74,222,128,0.1);color:var(--success);}
.log-icon.download{background:rgba(251,191,36,0.1);color:var(--warning);}
.log-icon.verify{background:rgba(201,168,76,0.1);color:var(--gold);}
.log-icon.default{background:rgba(107,130,160,0.1);color:var(--muted);}
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
        <h1>Dashboard</h1>
        <p>Welcome back, <?= e($_SESSION['full_name']) ?> &nbsp;·&nbsp; <?= ucfirst($role) ?> &nbsp;·&nbsp; <?= date('l, F j, Y') ?></p>
    </div>
    <div style="display:flex;gap:10px;">
        <?php if (can_upload()): ?>
        <a href="pages/evidence_upload.php" class="btn btn-gold">
            <i class="fas fa-upload"></i> Upload Evidence
        </a>
        <?php endif; ?>
        <?php if (can_analyse()): ?>
        <a href="pages/reports.php" class="btn btn-outline">
            <i class="fas fa-file-lines"></i> New Report
        </a>
        <?php endif; ?>
    </div>
</div>

<!-- Integrity Alert Banner -->
<?php if (!empty($integrity_alerts)): ?>
<div class="alert alert-danger" style="margin-bottom:20px;">
    <i class="fas fa-triangle-exclamation"></i>
    <div>
        <strong>Integrity Alert:</strong> <?= count($integrity_alerts) ?> evidence file<?= count($integrity_alerts)>1?'s':'' ?> failed integrity verification.
        <?php foreach($integrity_alerts as $a): ?>
        <a href="pages/evidence_view.php?id=<?= $a['id'] ?>" style="color:var(--danger);margin-left:8px;font-weight:600"><?= e($a['evidence_number']) ?></a>
        <?php endforeach; ?>
    </div>
</div>
<?php endif; ?>

<!-- My Assigned Cases (Analysts Only) -->
<?php if ($role === 'analyst' && !empty($my_cases)): ?>
<div class="section-card" style="margin-bottom:20px;">
    <div class="section-head">
        <h2><i class="fas fa-folder-open"></i> My Assigned Cases</h2>
        <a href="pages/cases.php" class="see-all">View all</a>
    </div>
    <div style="overflow-x:auto;">
    <div class="table-responsive"><table class="dc-table">
        <thead><tr>
            <th>Case</th>
            <th>Type</th>
            <th>Priority</th>
            <th>Status</th>
            <th>Evidence</th>
            <th>Updated</th>
            <th>Action</th>
        </tr></thead>
        <tbody>
        <?php foreach ($my_cases as $c):
            $priority_colors = ['low'=>'gray','medium'=>'blue','high'=>'orange','critical'=>'red'];
        ?>
        <tr>
            <td>
                <a href="pages/case_view.php?id=<?= $c['id'] ?>" style="font-weight:600;font-size:12.5px;color:var(--gold);text-decoration:none">
                    <?= e($c['case_number']) ?>
                </a>
                <p style="font-size:11px;color:var(--muted)"><?= e(substr($c['case_title'],0,30)) ?>...</p>
            </td>
            <td><span style="font-size:12px;color:var(--muted)"><?= e($c['case_type'] ?: '—') ?></span></td>
            <td>
                <span class="badge badge-<?= $priority_colors[$c['priority']] ?? 'gray' ?>">
                    <?= ucfirst($c['priority']) ?>
                </span>
            </td>
            <td><?= status_badge($c['status']) ?></td>
            <td>
                <span class="badge badge-blue">
                    <i class="fas fa-database" style="font-size:9px"></i> <?= $c['evidence_count'] ?>
                </span>
            </td>
            <td><span style="font-size:11.5px;color:var(--muted)"><?= time_ago($c['updated_at']) ?></span></td>
            <td>
                <a href="pages/case_view.php?id=<?= $c['id'] ?>" class="btn btn-outline btn-sm">
                    <i class="fas fa-eye"></i> View
                </a>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table></div>
    </div>
</div>
<?php elseif ($role === 'analyst'): ?>
<div class="section-card" style="margin-bottom:20px;">
    <div class="section-head">
        <h2><i class="fas fa-folder-open"></i> My Assigned Cases</h2>
    </div>
    <div class="empty-state">
        <i class="fas fa-folder-open"></i>
        <p>No cases assigned to you yet.</p>
    </div>
</div>
<?php endif; ?>

<!-- Stats -->
<div class="stats-grid">
    <div class="stat-card gold">
        <div class="stat-icon gold"><i class="fas fa-database"></i></div>
        <div class="stat-body">
            <p class="stat-label">Total Evidence</p>
            <p class="stat-value"><?= number_format($total_evidence) ?></p>
            <p class="stat-sub"><?= $my_evidence ?> uploaded by me</p>
        </div>
    </div>
    <div class="stat-card blue">
        <div class="stat-icon blue"><i class="fas fa-folder-open"></i></div>
        <div class="stat-body">
            <p class="stat-label"><?= $role === 'analyst' ? 'My Cases' : 'Active Cases' ?></p>
            <p class="stat-value"><?= $role === 'analyst' ? $my_cases_count : number_format($total_cases) ?></p>
            <p class="stat-sub"><?= $role === 'analyst' ? 'Assigned to you' : 'Open &amp; under investigation' ?></p>
        </div>
    </div>
    <div class="stat-card green">
        <div class="stat-icon green"><i class="fas fa-file-lines"></i></div>
        <div class="stat-body">
            <p class="stat-label">My Reports</p>
            <p class="stat-value"><?= $my_reports ?></p>
            <p class="stat-sub">Analysis reports submitted</p>
        </div>
    </div>
    <div class="stat-card <?= $tampered > 0 ? 'red' : 'green' ?>">
        <div class="stat-icon <?= $tampered > 0 ? 'red' : 'green' ?>"><i class="fas fa-fingerprint"></i></div>
        <div class="stat-body">
            <p class="stat-label">Integrity Alerts</p>
            <p class="stat-value"><?= $tampered ?></p>
            <p class="stat-sub"><?= $tampered > 0 ? '<span class="down">Tampered files found</span>' : '<span class="up">All verified intact</span>' ?></p>
        </div>
    </div>
</div>

<!-- All Evidence Table with Chain of Custody -->
<div class="section-card" style="margin-bottom:20px;">
    <div class="section-head">
        <h2><i class="fas fa-database"></i> All Evidence &amp; Chain of Custody</h2>
        <a href="pages/evidence.php" class="see-all">Full view</a>
    </div>

    <div class="filter-bar">
        <button class="filter-btn active" onclick="filterEv('all',this)">All</button>
        <button class="filter-btn" onclick="filterEv('collected',this)">Collected</button>
        <button class="filter-btn" onclick="filterEv('in_analysis',this)">In Analysis</button>
        <button class="filter-btn" onclick="filterEv('archived',this)">Archived</button>
        <button class="filter-btn" onclick="filterEv('flagged',this)" style="color:var(--danger);border-color:rgba(248,113,113,0.3)">Flagged</button>
        <div class="search-ev">
            <i class="fas fa-search"></i>
            <input type="text" placeholder="Search evidence..." oninput="searchEv(this.value)">
        </div>
    </div>

    <div style="overflow-x:auto;">
    <div class="table-responsive"><table class="dc-table" style="table-layout:fixed;width:100%">
        <thead><tr>
            <th style="width:85px">Evidence</th>
            <th style="width:220px">Title &amp; Case</th>
            <th style="width:90px">Type</th>
            <th style="width:95px">Uploader</th>
            <th style="width:60px">Size</th>
            <th style="width:95px">Status</th>
            <th style="width:65px">Date</th>
            <th style="width:130px">Actions</th>
        </tr></thead>
        <tbody id="evBody">
        <?php foreach ($all_evidence as $ev):
            $tampered_row = ($ev['last_integrity'] === 'tampered');
            [$ico, $col]  = $type_icons[$ev['evidence_type']] ?? ['fa-file','gray'];
        ?>
        <tr data-status="<?= e($ev['status']) ?>" <?= $tampered_row ? 'style="background:rgba(248,113,113,0.04)"' : '' ?> onclick="window.location='pages/evidence_view.php?id=<?= $ev['id'] ?>'" style="cursor:pointer;<?= $tampered_row ? 'background:rgba(248,113,113,0.04)' : '' ?>">
            <td data-label="Evidence No.">
                <span style="font-weight:700;font-size:11px;color:var(--gold);font-family:'Space Grotesk',sans-serif;display:block"><?= e($ev['evidence_number']) ?></span>
                <span class="badge <?= (int)$ev['report_count']>0?'badge-green':'badge-gray' ?>" style="margin-top:3px;font-size:9px">
                    <i class="fas fa-file-lines" style="font-size:8px"></i> <?= (int)$ev['report_count'] ?>
                </span>
            </td>
            <td data-label="Title & Case" style="min-width:0">
                <span style="font-weight:500;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;max-width:180px;" title="<?= e($ev['title']) ?>"><?= e(substr($ev['title'],0,25)) ?></span>
                <a href="pages/case_view.php?id=<?= $ev['case_id'] ?>" style="font-size:10px;color:var(--info);text-decoration:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block;max-width:150px;" title="<?= e($ev['case_title']) ?>" onclick="event.stopPropagation()">
                    <?= e($ev['case_number']) ?>
                </a>
            </td>
            <td data-label="Type">
                <span class="badge badge-<?= $col ?>" style="font-size:9px;padding:2px 5px;white-space:nowrap;">
                    <i class="fas <?= $ico ?>" style="font-size:8px"></i> <?= ucfirst(str_replace(['_capture','log_file','_data','_'],['',' log',' data',' '],$ev['evidence_type'])) ?>
                </span>
            </td>
            <td data-label="Uploaded By"><span style="font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block;" title="<?= e($ev['uploader_name']) ?>"><?= e($ev['uploader_name']) ?></span></td>
            <td data-label="Size"><span style="font-size:11px;color:var(--muted);white-space:nowrap"><?= format_filesize($ev['file_size']) ?></span></td>
            <td data-label="Status">
                <?= status_badge($ev['status']) ?>
                <?php if ($tampered_row): ?>
                <span class="badge badge-red" style="font-size:9px;margin-top:3px"><i class="fas fa-triangle-exclamation"></i> Tampered</span>
                <?php elseif ($ev['last_integrity'] === 'intact'): ?>
                <span class="badge badge-green" style="font-size:9px;margin-top:3px"><i class="fas fa-check"></i> Intact</span>
                <?php else: ?>
                <span class="badge badge-gray" style="font-size:9px;margin-top:3px">Unchecked</span>
                <?php endif; ?>
            </td>
            <td data-label="Date"><span style="font-size:10.5px;color:var(--muted);white-space:nowrap"><?= date('M j',strtotime($ev['uploaded_at'])) ?></span></td>
            <td data-label="Actions">
                <div style="display:flex;flex-direction:column;gap:3px;">
                    <a href="pages/evidence_download.php?id=<?= $ev['id'] ?>" class="btn btn-download btn-sm" style="width:100%;justify-content:center;" title="Download" onclick="event.stopPropagation()"><i class="fas fa-download"></i> Download</a>
                    <?php if (can_analyse()): ?>
                    <div style="display:flex;gap:3px;">
                        <a href="pages/reports.php?evidence_id=<?= $ev['id'] ?>" class="btn btn-gold btn-sm" style="flex:1;justify-content:center;" title="Report" onclick="event.stopPropagation()"><i class="fas fa-file-lines"></i> Report</a>
                        <a href="pages/coc_report.php?id=<?= $ev['id'] ?>" class="btn btn-coc btn-sm" style="flex:1;justify-content:center;" title="COC Report" onclick="event.stopPropagation()"><i class="fas fa-file-shield"></i> COC</a>
                    </div>
                    <?php endif; ?>
                </div>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table></div>
    </div>
</div>

<!-- Bottom: My Uploads + My Activity -->
<div class="grid-2">
    <div class="section-card">
        <div class="section-head">
            <h2><i class="fas fa-upload"></i> My Recent Uploads</h2>
            <a href="pages/evidence.php?my=1" class="see-all">View all</a>
        </div>
        <div class="section-body">
            <?php if (empty($my_recent)): ?>
            <div class="empty-state" style="padding:24px 0">
                <i class="fas fa-upload"></i>
                <p>No uploads yet.<?= can_upload() ? ' <a href="pages/evidence_upload.php" style="color:var(--gold)">Upload now</a>' : '' ?></p>
            </div>
            <?php else: ?>
            <div class="table-responsive"><table class="dc-table">
                <thead><tr><th>Evidence</th><th>Case</th><th>Status</th><th>When</th></tr></thead>
                <tbody>
                <?php foreach ($my_recent as $ev): ?>
                <tr>
                    <td>
                        <a href="pages/evidence_view.php?id=<?= $ev['id'] ?>" style="font-weight:600;font-size:12.5px;color:var(--gold);text-decoration:none"><?= e($ev['evidence_number']) ?></a>
                        <p style="font-size:11px;color:var(--muted)"><?= e(substr($ev['title'],0,22)) ?>...</p>
                    </td>
                    <td><span style="font-size:12px;color:var(--muted)"><?= e($ev['case_number']) ?></span></td>
                    <td><?= status_badge($ev['status']) ?></td>
                    <td><span style="font-size:11.5px;color:var(--muted)"><?= time_ago($ev['uploaded_at']) ?></span></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table></div>
            <?php endif; ?>
        </div>
    </div>

    <div class="section-card">
        <div class="section-head">
            <h2><i class="fas fa-clock-rotate-left"></i> My Recent Activity</h2>
            <a href="pages/audit.php" class="see-all">Full log</a>
        </div>
        <div class="section-body padded">
            <?php if (empty($my_logs)): ?>
            <div class="empty-state" style="padding:24px 0"><i class="fas fa-scroll"></i><p>No activity yet.</p></div>
            <?php else:
            $imap=['login'=>['login','fa-right-to-bracket'],'logout'=>['login','fa-right-from-bracket'],'evidence_uploaded'=>['upload','fa-upload'],'evidence_viewed'=>['login','fa-eye'],'evidence_downloaded'=>['download','fa-download'],'hash_verified'=>['verify','fa-fingerprint'],'report_submitted'=>['upload','fa-file-lines'],'account_updated'=>['login','fa-pen']];
            foreach ($my_logs as $log):[$cls,$ico]=$imap[$log['action_type']]??['default','fa-circle-dot'];?>
            <div style="display:flex;gap:10px;padding:9px 0;border-bottom:1px solid var(--border);">
                <div class="log-icon <?= $cls ?>"><i class="fas <?= $ico ?>"></i></div>
                <div style="flex:1;min-width:0;">
                    <p style="font-size:13px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><?= e($log['description']) ?></p>
                    <p style="font-size:11px;color:var(--dim);margin-top:2px"><?= date('M j, Y H:i',strtotime($log['created_at'])) ?></p>
                </div>
            </div>
            <?php endforeach; endif; ?>
        </div>
    </div>
</div>

</div></div></div>

<script>
function toggleSidebar(){
    const sb=document.getElementById('sidebar'),ma=document.getElementById('mainArea');
    if(window.innerWidth<=900){sb.classList.toggle('mobile-open');}
    else{sb.classList.toggle('collapsed');ma.classList.toggle('collapsed');}
    localStorage.setItem('sb_collapsed',sb.classList.contains('collapsed')?'1':'0');
}
if(localStorage.getItem('sb_collapsed')==='1'&&window.innerWidth>900){
    document.getElementById('sidebar').classList.add('collapsed');
    document.getElementById('mainArea').classList.add('collapsed');
}
function toggleNotif(){document.getElementById('notifDropdown').classList.toggle('open');document.getElementById('userDropdown').classList.remove('open');}
function toggleUserMenu(){document.getElementById('userDropdown').classList.toggle('open');document.getElementById('notifDropdown').classList.remove('open');}
document.addEventListener('click',function(e){
    if(!e.target.closest('#notifWrap'))document.getElementById('notifDropdown').classList.remove('open');
    if(!e.target.closest('#userMenuWrap'))document.getElementById('userDropdown').classList.remove('open');
});
function handleSearch(e){if(e.key==='Enter'){window.location='pages/evidence.php?search='+encodeURIComponent(document.getElementById('globalSearch').value);}}
function filterEv(status,btn){
    document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('#evBody tr').forEach(row=>{
        row.style.display=status==='all'||row.dataset.status===status?'':'none';
    });
}
function searchEv(val){
    val=val.toLowerCase();
    document.querySelectorAll('#evBody tr').forEach(row=>{
        row.style.display=row.textContent.toLowerCase().includes(val)?'':'none';
    });
}
</script>
</body>
</html>
