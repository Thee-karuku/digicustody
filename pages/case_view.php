<?php
/**
 * DigiCustody – Case Detail View
 * Save to: /var/www/html/digicustody/pages/case_view.php
 */
session_start();
require_once __DIR__.'/../config/db.php';
require_once __DIR__.'/../config/functions.php';
require_login();

$page_title = 'Case Details';
$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];
$id   = (int)($_GET['id'] ?? 0);

if (!$id) { header('Location: cases.php'); exit; }

// Fetch case
$stmt = $pdo->prepare("
    SELECT c.*, u.full_name AS creator_name, u.role AS creator_role
    FROM cases c
    JOIN users u ON u.id = c.created_by
    WHERE c.id = ?
");
$stmt->execute([$id]);
$case = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$case) { header('Location: cases.php?error=not_found'); exit; }

// Log view
audit_log($pdo,$uid,$_SESSION['username'],$role,'case_updated','case',$id,
    $case['case_number'],"Case viewed: {$case['case_number']}",$_SERVER['REMOTE_ADDR']??'');

// Handle status update
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['update_status']) && $role==='admin') {
    if (verify_csrf($_POST['csrf_token']??'')) {
        $new_status = in_array($_POST['status']??'',['open','under_investigation','closed','archived'])
            ? $_POST['status'] : $case['status'];
        $pdo->prepare("UPDATE cases SET status=?,updated_at=NOW() WHERE id=?")->execute([$new_status,$id]);
        $case['status'] = $new_status;
        audit_log($pdo,$uid,$_SESSION['username'],$role,'case_updated','case',$id,
            $case['case_number'],"Case status updated to: $new_status");
    }
}

// All evidence for this case
$evidence = $pdo->prepare("
    SELECT e.*,
           u.full_name AS uploader_name,
           (SELECT hv.integrity_status FROM hash_verifications hv
            WHERE hv.evidence_id=e.id ORDER BY hv.verified_at DESC LIMIT 1) AS last_integrity,
           (SELECT COUNT(*) FROM analysis_reports ar WHERE ar.evidence_id=e.id) AS report_count,
           (SELECT COUNT(*) FROM audit_logs al
            WHERE al.target_type='evidence' AND al.target_id=e.id) AS action_count
    FROM evidence e
    JOIN users u ON u.id = e.uploaded_by
    WHERE e.case_id = ?
    ORDER BY e.uploaded_at DESC
");
$evidence->execute([$id]);
$evidence = $evidence->fetchAll(PDO::FETCH_ASSOC);

// All reports for this case
$reports = $pdo->prepare("
    SELECT ar.*, e.evidence_number, e.title AS ev_title,
           u.full_name AS analyst_name
    FROM analysis_reports ar
    JOIN evidence e ON e.id = ar.evidence_id
    JOIN users u    ON u.id = ar.submitted_by
    WHERE ar.case_id = ?
    ORDER BY ar.created_at DESC
");
$reports->execute([$id]);
$reports = $reports->fetchAll(PDO::FETCH_ASSOC);

// Case activity from audit log
$logs = $pdo->prepare("
    SELECT al.* FROM audit_logs al
    WHERE (al.target_type='case' AND al.target_id=?)
       OR (al.target_type='evidence' AND al.target_id IN
           (SELECT id FROM evidence WHERE case_id=?))
    ORDER BY al.created_at DESC LIMIT 15
");
$logs->execute([$id,$id]);
$logs = $logs->fetchAll(PDO::FETCH_ASSOC);

// Stats
$total_ev      = count($evidence);
$intact_ev     = count(array_filter($evidence, fn($e) => $e['last_integrity']==='intact'));
$tampered_ev   = count(array_filter($evidence, fn($e) => $e['last_integrity']==='tampered'));
$total_reports = count($reports);
$storage       = array_sum(array_column($evidence,'file_size'));

$type_icons=['image'=>['fa-file-image','blue'],'video'=>['fa-file-video','purple'],
    'document'=>['fa-file-lines','green'],'log_file'=>['fa-file-code','orange'],
    'email'=>['fa-envelope','info'],'database'=>['fa-database','gold'],
    'network_capture'=>['fa-network-wired','muted'],'mobile_data'=>['fa-mobile','warning'],
    'other'=>['fa-file','gray']];

$priority_colors=['low'=>'gray','medium'=>'blue','high'=>'orange','critical'=>'red'];
$csrf = csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title><?= e($case['case_number']) ?> — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.case-hero{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:26px;margin-bottom:24px;}
.case-hero h2{font-family:'Space Grotesk',sans-serif;font-size:20px;font-weight:700;color:var(--text);margin-bottom:6px;}
.meta-row{display:flex;flex-wrap:wrap;gap:16px;margin-top:10px;}
.meta-item{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--muted);}
.meta-item i{font-size:12px;color:var(--dim);}
.ev-row-tampered{background:rgba(248,113,113,0.04)!important;}
.hash-chip{font-family:'Courier New',monospace;font-size:10.5px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;max-width:120px;}
.tabs{display:flex;gap:0;border-bottom:1px solid var(--border);}
.tab-btn{background:none;border:none;border-bottom:2px solid transparent;padding:13px 20px;font-size:13.5px;color:var(--muted);cursor:pointer;transition:all .2s;font-family:'Inter',sans-serif;margin-bottom:-1px;}
.tab-btn.active{color:var(--gold);border-bottom-color:var(--gold);}
.tab-btn:hover{color:var(--text);}
.tab-panel{display:none;padding:20px;}
.tab-panel.active{display:block;}
.report-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:16px;margin-bottom:12px;transition:border-color .2s;}
.report-card:hover{border-color:var(--border2);}
.report-card.approved{border-left:3px solid var(--success);}
.report-card.submitted{border-left:3px solid var(--warning);}
.report-card.rejected{border-left:3px solid var(--danger);}
.log-item{display:flex;gap:11px;padding:10px 0;border-bottom:1px solid var(--border);}
.log-item:last-child{border-bottom:none;}
.status-select{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:7px 12px;font-size:13px;color:var(--text);outline:none;font-family:'Inter',sans-serif;cursor:pointer;}
.status-select:focus{border-color:rgba(201,168,76,0.5);}
.status-select option{background:var(--surface2);}
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
        <h1><?= e($case['case_number']) ?></h1>
        <p><?= e($case['case_title']) ?></p>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <a href="cases.php" class="btn btn-outline"><i class="fas fa-arrow-left"></i> All Cases</a>
        <?php if (can_write()): ?>
        <a href="evidence_upload.php?case_id=<?= $id ?>" class="btn btn-gold">
            <i class="fas fa-upload"></i> Upload Evidence
        </a>
        <?php endif; ?>
    </div>
</div>

<!-- Case Hero -->
<div class="case-hero">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:14px;flex-wrap:wrap;">
        <div style="flex:1;">
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px;">
                <h2><?= e($case['case_title']) ?></h2>
                <?= status_badge($case['status']) ?>
                <span class="badge badge-<?= $priority_colors[$case['priority']]??'gray' ?>">
                    <?= ucfirst($case['priority']) ?> priority
                </span>
                <?php if ($case['case_type']): ?>
                <span class="badge badge-gray"><?= e($case['case_type']) ?></span>
                <?php endif; ?>
            </div>
            <?php if ($case['description']): ?>
            <p style="font-size:13.5px;color:var(--muted);line-height:1.7;margin-bottom:10px;"><?= nl2br(e($case['description'])) ?></p>
            <?php endif; ?>
            <div class="meta-row">
                <span class="meta-item"><i class="fas fa-hashtag"></i><?= e($case['case_number']) ?></span>
                <span class="meta-item"><i class="fas fa-user"></i>Created by <?= e($case['creator_name']) ?></span>
                <span class="meta-item"><i class="fas fa-calendar"></i><?= date('M j, Y', strtotime($case['created_at'])) ?></span>
                <?php if ($case['updated_at'] !== $case['created_at']): ?>
                <span class="meta-item"><i class="fas fa-clock"></i>Updated <?= time_ago($case['updated_at']) ?></span>
                <?php endif; ?>
            </div>
        </div>

        <!-- Admin: quick status update -->
        <?php if ($role === 'admin'): ?>
        <form method="POST" style="display:flex;align-items:center;gap:8px;">
            <input type="hidden" name="csrf_token"    value="<?= $csrf ?>">
            <input type="hidden" name="update_status" value="1">
            <select name="status" class="status-select" onchange="this.form.submit()">
                <?php foreach(['open','under_investigation','closed','archived'] as $s): ?>
                <option value="<?= $s ?>" <?= $case['status']===$s?'selected':'' ?>>
                    <?= ucwords(str_replace('_',' ',$s)) ?>
                </option>
                <?php endforeach; ?>
            </select>
            <span style="font-size:12px;color:var(--dim)">Change status</span>
        </form>
        <?php endif; ?>
    </div>

    <!-- Case quick stats -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-top:20px;padding-top:18px;border-top:1px solid var(--border);">
        <div style="text-align:center;padding:12px;background:var(--surface2);border-radius:var(--radius);">
            <p style="font-family:'Space Grotesk',sans-serif;font-size:22px;font-weight:700;color:var(--gold)"><?= $total_ev ?></p>
            <p style="font-size:12px;color:var(--muted);margin-top:2px">Evidence Files</p>
        </div>
        <div style="text-align:center;padding:12px;background:var(--surface2);border-radius:var(--radius);">
            <p style="font-family:'Space Grotesk',sans-serif;font-size:22px;font-weight:700;color:var(--success)"><?= $intact_ev ?></p>
            <p style="font-size:12px;color:var(--muted);margin-top:2px">Verified Intact</p>
        </div>
        <div style="text-align:center;padding:12px;background:var(--surface2);border-radius:var(--radius);" style="<?= $tampered_ev>0?'border-color:rgba(248,113,113,0.3)':'' ?>">
            <p style="font-family:'Space Grotesk',sans-serif;font-size:22px;font-weight:700;color:<?= $tampered_ev>0?'var(--danger)':'var(--muted)' ?>"><?= $tampered_ev ?></p>
            <p style="font-size:12px;color:var(--muted);margin-top:2px">Tampered</p>
        </div>
        <div style="text-align:center;padding:12px;background:var(--surface2);border-radius:var(--radius);">
            <p style="font-family:'Space Grotesk',sans-serif;font-size:22px;font-weight:700;color:var(--info)"><?= $total_reports ?></p>
            <p style="font-size:12px;color:var(--muted);margin-top:2px">Reports</p>
        </div>
        <div style="text-align:center;padding:12px;background:var(--surface2);border-radius:var(--radius);">
            <p style="font-family:'Space Grotesk',sans-serif;font-size:22px;font-weight:700;color:var(--text)"><?= format_filesize($storage) ?></p>
            <p style="font-size:12px;color:var(--muted);margin-top:2px">Total Size</p>
        </div>
    </div>
</div>

<!-- Tabs -->
<div class="section-card">
    <div class="tabs">
        <button class="tab-btn active" onclick="showTab('evidence',this)">
            <i class="fas fa-database" style="margin-right:6px"></i>Evidence
            <span class="badge badge-gold" style="margin-left:6px"><?= $total_ev ?></span>
        </button>
        <button class="tab-btn" onclick="showTab('reports',this)">
            <i class="fas fa-file-lines" style="margin-right:6px"></i>Reports
            <span class="badge badge-blue" style="margin-left:6px"><?= $total_reports ?></span>
        </button>
        <button class="tab-btn" onclick="showTab('activity',this)">
            <i class="fas fa-scroll" style="margin-right:6px"></i>Activity Log
            <span class="badge badge-gray" style="margin-left:6px"><?= count($logs) ?></span>
        </button>
    </div>

    <!-- Evidence Tab -->
    <div class="tab-panel active" id="tab-evidence">
        <?php if (empty($evidence)): ?>
        <div class="empty-state">
            <i class="fas fa-database"></i>
            <p>No evidence uploaded for this case yet.</p>
            <?php if (can_write()): ?>
            <a href="evidence_upload.php?case_id=<?= $id ?>" class="btn btn-gold" style="margin-top:14px">
                <i class="fas fa-upload"></i> Upload First Evidence
            </a>
            <?php endif; ?>
        </div>
        <?php else: ?>
        <div style="overflow-x:auto;">
        <table class="dc-table" style="table-layout:fixed;width:100%">
            <thead><tr>
                <th style="width:110px">Evidence No.</th>
                <th style="width:auto">Title</th>
                <th style="width:90px">Type</th>
                <th style="width:120px">Uploaded By</th>
                <th style="width:150px">Hashes</th>
                <th style="width:75px">Size</th>
                <th style="width:90px">Status</th>
                <th style="width:90px">Integrity</th>
                <th style="width:70px">Reports</th>
                <th style="width:90px">Date</th>
                <th style="width:160px">Actions</th>
            </tr></thead>
            <tbody>
            <?php foreach ($evidence as $ev):
                $tampered = $ev['last_integrity']==='tampered';
                [$ico,$col] = $type_icons[$ev['evidence_type']] ?? ['fa-file','gray'];
            ?>
            <tr class="<?= $tampered?'ev-row-tampered':'' ?>">
                <td><span style="font-weight:700;font-size:12.5px;color:var(--gold);font-family:'Space Grotesk',sans-serif"><?= e($ev['evidence_number']) ?></span></td>
                <td>
                    <p style="font-weight:500;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="<?= e($ev['title']) ?>"><?= e($ev['title']) ?></p>
                    <?php if ($ev['description']): ?>
                    <p style="font-size:11px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><?= e(substr($ev['description'],0,40)) ?></p>
                    <?php endif; ?>
                </td>
                <td><span class="badge badge-blue"><i class="fas <?= $ico ?>" style="font-size:9px"></i> <?= ucfirst(str_replace('_',' ',$ev['evidence_type'])) ?></span></td>
                <td><span style="font-size:12.5px"><?= e($ev['uploader_name']) ?></span></td>
                <td>
                    <span class="hash-chip" title="SHA-256: <?= e($ev['sha256_hash']) ?>">SHA: <?= e(substr($ev['sha256_hash'],0,14)) ?>...</span>
                    <span class="hash-chip" title="MD5: <?= e($ev['md5_hash']) ?>">MD5: <?= e(substr($ev['md5_hash'],0,14)) ?>...</span>
                </td>
                <td><span style="font-size:12px;color:var(--muted)"><?= format_filesize($ev['file_size']) ?></span></td>
                <td><?= status_badge($ev['status']) ?></td>
                <td>
                    <?php if ($tampered): ?>
                        <span class="badge badge-red"><i class="fas fa-triangle-exclamation"></i> Tampered</span>
                    <?php elseif ($ev['last_integrity']==='intact'): ?>
                        <span class="badge badge-green"><i class="fas fa-check"></i> Intact</span>
                    <?php else: ?>
                        <span class="badge badge-gray">Unchecked</span>
                    <?php endif; ?>
                </td>
                <td>
                    <span class="badge <?= (int)$ev['report_count']>0?'badge-green':'badge-gray' ?>">
                        <i class="fas fa-file-lines" style="font-size:9px"></i> <?= (int)$ev['report_count'] ?>
                    </span>
                </td>
                <td><span style="font-size:11.5px;color:var(--muted)"><?= date('M j, Y',strtotime($ev['uploaded_at'])) ?></span></td>
                <td>
                    <div style="display:flex;gap:5px;flex-wrap:wrap;">
                        <a href="evidence_view.php?id=<?= $ev['id'] ?>" class="btn btn-outline btn-sm">
                            <i class="fas fa-eye"></i> View
                        </a>
                        <?php if (can_write()): ?>
                        <a href="evidence_download.php?id=<?= $ev['id'] ?>" class="btn btn-outline btn-sm">
                            <i class="fas fa-download"></i>
                        </a>
                        <?php endif; ?>
                        <?php if (can_report()): ?>
                        <a href="reports.php?evidence_id=<?= $ev['id'] ?>" class="btn btn-gold btn-sm">
                            <i class="fas fa-file-plus"></i>
                        </a>
                        <?php endif; ?>
                    </div>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
        <?php endif; ?>
    </div>

    <!-- Reports Tab -->
    <div class="tab-panel" id="tab-reports">
        <?php if (empty($reports)): ?>
        <div class="empty-state">
            <i class="fas fa-file-lines"></i>
            <p>No analysis reports submitted for this case yet.</p>
            <?php if (can_report()): ?>
            <a href="reports.php" class="btn btn-gold" style="margin-top:14px">
                <i class="fas fa-file-plus"></i> Submit Report
            </a>
            <?php endif; ?>
        </div>
        <?php else: foreach ($reports as $r):
            $sc = ['draft'=>'gray','submitted'=>'warning','reviewed'=>'blue','approved'=>'green','rejected'=>'red'][$r['status']]??'gray';
        ?>
        <div class="report-card <?= $r['status'] ?>">
            <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px;flex-wrap:wrap;">
                <div style="flex:1;">
                    <p style="font-family:'Space Grotesk',sans-serif;font-size:12.5px;font-weight:700;color:var(--gold)"><?= e($r['report_number']) ?></p>
                    <p style="font-size:14.5px;font-weight:600;color:var(--text);margin-top:3px"><?= e($r['title']) ?></p>
                    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:5px;font-size:12px;color:var(--muted);">
                        <span><i class="fas fa-database" style="color:var(--gold);margin-right:4px"></i><?= e($r['evidence_number']) ?> — <?= e(substr($r['ev_title'],0,30)) ?></span>
                        <span><i class="fas fa-user" style="margin-right:4px"></i><?= e($r['analyst_name']) ?></span>
                        <span><i class="fas fa-calendar" style="margin-right:4px"></i><?= date('M j, Y',strtotime($r['created_at'])) ?></span>
                    </div>
                </div>
                <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;">
                    <?= status_badge($r['status']) ?>
                    <button class="btn btn-outline btn-sm" onclick="toggleRep(<?= $r['id'] ?>)">
                        <i class="fas fa-chevron-down" id="ri_<?= $r['id'] ?>"></i> Details
                    </button>
                </div>
            </div>
            <div id="rc_<?= $r['id'] ?>" style="display:none;margin-top:14px;padding-top:14px;border-top:1px solid var(--border);">
                <div class="grid-2" style="gap:16px;margin-bottom:12px;">
                    <div>
                        <p style="font-size:11px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin-bottom:5px">Summary</p>
                        <p style="font-size:13.5px;color:var(--muted);line-height:1.65"><?= nl2br(e($r['summary'])) ?></p>
                    </div>
                    <div>
                        <p style="font-size:11px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin-bottom:5px">Findings</p>
                        <p style="font-size:13.5px;color:var(--muted);line-height:1.65"><?= nl2br(e($r['findings'])) ?></p>
                    </div>
                </div>
                <?php if ($r['conclusions']): ?>
                <div style="margin-bottom:10px;">
                    <p style="font-size:11px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin-bottom:5px">Conclusions</p>
                    <p style="font-size:13.5px;color:var(--muted);line-height:1.65"><?= nl2br(e($r['conclusions'])) ?></p>
                </div>
                <?php endif; ?>
                <?php if ($r['recommendations']): ?>
                <div style="margin-bottom:10px;">
                    <p style="font-size:11px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin-bottom:5px">Recommendations</p>
                    <p style="font-size:13.5px;color:var(--muted);line-height:1.65"><?= nl2br(e($r['recommendations'])) ?></p>
                </div>
                <?php endif; ?>
                <?php if ($r['tools_used']): ?>
                <p style="font-size:12.5px;color:var(--dim)"><strong style="color:var(--muted)">Tools:</strong> <?= e($r['tools_used']) ?></p>
                <?php endif; ?>
                <?php if ($r['reviewer_notes']): ?>
                <div style="margin-top:10px;background:rgba(96,165,250,0.06);border:1px solid rgba(96,165,250,0.15);border-radius:var(--radius);padding:10px 14px;">
                    <p style="font-size:12px;color:var(--muted)"><strong style="color:var(--text)">Reviewer notes:</strong> <?= nl2br(e($r['reviewer_notes'])) ?></p>
                </div>
                <?php endif; ?>
            </div>
        </div>
        <?php endforeach; endif; ?>
    </div>

    <!-- Activity Log Tab -->
    <div class="tab-panel" id="tab-activity">
        <?php if (empty($logs)): ?>
        <div class="empty-state"><i class="fas fa-scroll"></i><p>No activity recorded yet.</p></div>
        <?php else:
        $imap=['evidence_uploaded'=>['upload','fa-upload'],'evidence_viewed'=>['login','fa-eye'],
               'evidence_downloaded'=>['download','fa-download'],'hash_verified'=>['verify','fa-fingerprint'],
               'report_submitted'=>['upload','fa-file-lines'],'case_updated'=>['login','fa-folder'],
               'case_created'=>['upload','fa-folder-plus']];
        foreach ($logs as $log): [$cls,$ico]=$imap[$log['action_type']]??['default','fa-circle-dot'];?>
        <div class="log-item">
            <div class="log-icon <?= $cls ?>" style="width:30px;height:30px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:11px;">
                <i class="fas <?= $ico ?>"></i>
            </div>
            <div style="flex:1;min-width:0;">
                <p style="font-size:13px;color:var(--text)"><?= e($log['description']) ?></p>
                <p style="font-size:11.5px;color:var(--dim);margin-top:2px">
                    <?= e($log['username']??'System') ?> &nbsp;·&nbsp; <?= date('M j, Y H:i',strtotime($log['created_at'])) ?>
                </p>
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
document.addEventListener('click',function(e){if(!e.target.closest('#notifWrap'))document.getElementById('notifDropdown').classList.remove('open');if(!e.target.closest('#userMenuWrap'))document.getElementById('userDropdown').classList.remove('open');});
function handleSearch(e){if(e.key==='Enter'){window.location='evidence.php?search='+encodeURIComponent(document.getElementById('globalSearch').value);}}
function showTab(id,btn){
    document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
    document.getElementById('tab-'+id).classList.add('active');
    btn.classList.add('active');
}
function toggleRep(id){
    const c=document.getElementById('rc_'+id),i=document.getElementById('ri_'+id);
    if(c.style.display==='none'){c.style.display='block';i.className='fas fa-chevron-up';}
    else{c.style.display='none';i.className='fas fa-chevron-down';}
}
</script>
</body>
</html>
