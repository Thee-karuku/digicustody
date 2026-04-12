<?php
/**
 * DigiCustody – Analysis Reports Page
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login();

$page_title = 'Analysis Reports';
$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];
$msg  = ''; $err = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $err = 'Security token mismatch.';
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'save_draft') {
            $evidence_id = (int)($_POST['evidence_id'] ?? 0);
            
            if (!$evidence_id) {
                $err = 'Evidence ID is required.';
            } elseif (!user_can_access_evidence($pdo, $uid, $role, $evidence_id)) {
                $err = 'You are not authorized to access this evidence.';
            } else {
                $title = trim($_POST['title'] ?? '');
                $summary = trim($_POST['summary'] ?? '');
                $findings = trim($_POST['findings'] ?? '');
                $conclusions = trim($_POST['conclusions'] ?? '');
                $recommendations = trim($_POST['recommendations'] ?? '');
                $tools_used = trim($_POST['tools_used'] ?? '');
                $report_type = trim($_POST['report_type'] ?? 'general');
                $severity = trim($_POST['severity'] ?? 'medium');

                if (empty($title)) {
                    $err = 'Title is required to save a draft.';
                } else {
                    $ev = $pdo->prepare("SELECT case_id FROM evidence WHERE id=?");
                    $ev->execute([$evidence_id]);
                    $ev = $ev->fetch(PDO::FETCH_ASSOC);

                    if (!$ev) {
                        $err = 'Evidence not found.';
                    } else {
                        $draft_id = (int)($_POST['draft_id'] ?? 0);
                        if ($draft_id > 0) {
                            $pdo->prepare("UPDATE analysis_reports SET title=?,summary=?,findings=?,conclusions=?,recommendations=?,tools_used=?,report_type=?,severity=?,updated_at=NOW() WHERE id=? AND status='draft' AND submitted_by=?")
                                ->execute([$title, $summary, $findings, $conclusions, $recommendations, $tools_used, $report_type, $severity, $draft_id, $uid]);
                            $msg = "Draft updated successfully.";
                        } else {
                            $rnum = generate_report_number($pdo);
                            $pdo->prepare("INSERT INTO analysis_reports (report_number,evidence_id,case_id,title,summary,findings,conclusions,recommendations,tools_used,report_type,severity,submitted_by,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
                                ->execute([$rnum, $evidence_id, $ev['case_id'], $title, $summary, $findings, $conclusions, $recommendations, $tools_used, $report_type, $severity, $uid, 'draft']);
                            $msg = "Draft saved successfully.";
                        }
                        $_SESSION['draft_msg'] = $msg;
                        header('Location: reports.php');
                        exit;
                    }
                }
            }
        }

        elseif ($action === 'submit_report') {
            $evidence_id     = (int)($_POST['evidence_id'] ?? 0);
            $title           = trim($_POST['title'] ?? '');
            $summary         = trim($_POST['summary'] ?? '');
            $findings        = trim($_POST['findings'] ?? '');
            $conclusions     = trim($_POST['conclusions'] ?? '');
            $recommendations = trim($_POST['recommendations'] ?? '');
            $tools_used      = trim($_POST['tools_used'] ?? '');
            $report_type     = trim($_POST['report_type'] ?? 'general');
            $severity        = trim($_POST['severity'] ?? 'medium');
            $draft_id        = (int)($_POST['draft_id'] ?? 0);

            if (!$evidence_id || empty($title) || empty($summary) || empty($findings)) {
                $err = 'Evidence, title, summary and findings are required.';
            } else {
                $ev = $pdo->prepare("SELECT case_id FROM evidence WHERE id=?");
                $ev->execute([$evidence_id]);
                $ev = $ev->fetch(PDO::FETCH_ASSOC);

                if (!$ev) { $err = 'Evidence not found.'; }
                else {
                    $rnum = generate_report_number($pdo);
                    if ($draft_id > 0) {
                        $pdo->prepare("UPDATE analysis_reports SET report_number=?,evidence_id=?,case_id=?,title=?,summary=?,findings=?,conclusions=?,recommendations=?,tools_used=?,report_type=?,severity=?,status='submitted',submitted_by=?,updated_at=NOW() WHERE id=? AND status='draft'")
                            ->execute([$rnum,$evidence_id,$ev['case_id'],$title,$summary,$findings,$conclusions,$recommendations,$tools_used,$report_type,$severity,$uid,$draft_id]);
                        $rid = $draft_id;
                    } else {
                        $pdo->prepare("INSERT INTO analysis_reports (report_number,evidence_id,case_id,title,summary,findings,conclusions,recommendations,tools_used,report_type,severity,submitted_by,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
                            ->execute([$rnum,$evidence_id,$ev['case_id'],$title,$summary,$findings,$conclusions,$recommendations,$tools_used,$report_type,$severity,$uid,'submitted']);
                        $rid = $pdo->lastInsertId();
                    }

                    foreach ($pdo->query("SELECT id FROM users WHERE role='admin' AND status='active'")->fetchAll() as $adm) {
                        send_notification($pdo,$adm['id'],'New Analysis Report',"Report $rnum submitted by {$_SESSION['full_name']}",'info','report',$rid);
                    }
                    audit_log($pdo,$uid,$_SESSION['username'],$role,'report_submitted','report',$rid,$rnum,"Analysis report submitted: $rnum — $title");
                    $msg = "Report <strong>$rnum</strong> submitted successfully.";
                }
            }
        }

        elseif ($action === 'delete_draft') {
            $draft_id = (int)($_POST['draft_id'] ?? 0);
            if ($draft_id > 0) {
                $pdo->prepare("DELETE FROM analysis_reports WHERE id=? AND submitted_by=? AND status='draft'")->execute([$draft_id,$uid]);
                $msg = "Draft deleted successfully.";
            }
        }

        elseif ($action === 'review_report' && $role === 'admin') {
            $rid         = (int)($_POST['report_id'] ?? 0);
            $new_status  = in_array($_POST['review_status']??'',['approved','rejected','reviewed']) ? $_POST['review_status'] : 'reviewed';
            $notes       = trim($_POST['reviewer_notes'] ?? '');
            $pdo->prepare("UPDATE analysis_reports SET status=?,reviewed_by=?,reviewed_at=NOW(),reviewer_notes=? WHERE id=?")
                ->execute([$new_status,$uid,$notes,$rid]);
            audit_log($pdo,$uid,$_SESSION['username'],$role,'report_'.$new_status,'report',$rid,'',"Report ID $rid marked as $new_status");
            $msg = "Report marked as <strong>$new_status</strong>.";
        }
    }
}

if (isset($_SESSION['draft_msg'])) { $msg = $_SESSION['draft_msg']; unset($_SESSION['draft_msg']); }

$filter_status = $_GET['status'] ?? '';
$search        = trim($_GET['search'] ?? '');
$ev_filter     = (int)($_GET['evidence_id'] ?? 0);

$where = ['1=1']; $params = [];
if ($role !== 'admin') { $where[] = "ar.submitted_by=?"; $params[] = $uid; }
if ($filter_status !== '') { $where[] = "ar.status=?"; $params[] = $filter_status; }
if ($search !== '') {
    $where[] = "(ar.title LIKE ? OR ar.report_number LIKE ? OR ar.summary LIKE ?)";
    $s = "%$search%"; $params = array_merge($params,[$s,$s,$s]);
}
if ($ev_filter) { $where[] = "ar.evidence_id=?"; $params[] = $ev_filter; }

$where_sql = implode(' AND ', $where);
$reports_stmt = $pdo->prepare("
    SELECT ar.*,
           e.evidence_number, e.title AS evidence_title,
           c.case_number, c.case_title,
           u.full_name AS analyst_name,
           r.full_name AS reviewer_name
    FROM analysis_reports ar
    JOIN evidence e ON e.id = ar.evidence_id
    JOIN cases c    ON c.id = ar.case_id
    JOIN users u    ON u.id = ar.submitted_by
    LEFT JOIN users r ON r.id = ar.reviewed_by
    WHERE $where_sql
    ORDER BY ar.created_at DESC
");
$reports_stmt->execute($params);
$reports = $reports_stmt->fetchAll(PDO::FETCH_ASSOC);

$evidence_list = $pdo->query("SELECT id, evidence_number, title, case_id FROM evidence ORDER BY uploaded_at DESC")->fetchAll(PDO::FETCH_ASSOC);

$total_reports    = (int)$pdo->query("SELECT COUNT(*) FROM analysis_reports")->fetchColumn();
$pending_reports  = (int)$pdo->query("SELECT COUNT(*) FROM analysis_reports WHERE status='submitted'")->fetchColumn();
$approved_reports = (int)$pdo->query("SELECT COUNT(*) FROM analysis_reports WHERE status='approved'")->fetchColumn();
$draft_reports    = $role !== 'admin' ? (int)$pdo->query("SELECT COUNT(*) FROM analysis_reports WHERE status='draft' AND submitted_by=$uid")->fetchColumn() : 0;

$csrf = csrf_token();
$status_colors = ['draft'=>'gray','submitted'=>'warning','reviewed'=>'blue','approved'=>'green','rejected'=>'red'];
$report_types = [
    'general' => 'General Analysis',
    'malware' => 'Malware Analysis',
    'network' => 'Network Forensics',
    'memory' => 'Memory Forensics',
    'disk' => 'Disk Forensics',
    'mobile' => 'Mobile Forensics',
    'web' => 'Web Application Analysis',
    'crypto' => 'Cryptographic Analysis'
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Analysis Reports — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.field{margin-bottom:16px;}
.field label{display:block;font-size:11.5px;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:7px;}
.field input,.field select,.field textarea{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:11px 14px;font-size:14px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.field input:focus,.field select:focus,.field textarea:focus{border-color:rgba(201,168,76,0.5);box-shadow:0 0 0 3px rgba(201,168,76,0.06);}
.field select option{background:var(--surface2);}
.field textarea{resize:vertical;min-height:100px;}
.char-count{font-size:10px;color:var(--dim);text-align:right;margin-top:2px;}
.field-hint{font-size:11px;color:var(--dim);margin-top:4px;}

.report-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-lg);padding:20px;margin-bottom:14px;transition:border-color .2s;}
.report-card:hover{border-color:var(--border2);}
.report-card.submitted{border-left:3px solid var(--warning);}
.report-card.approved{border-left:3px solid var(--success);}
.report-card.rejected{border-left:3px solid var(--danger);}
.report-card.reviewed{border-left:3px solid var(--info);}
.report-card.draft{border-left:3px solid var(--dim);opacity:0.85;}
.report-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:12px;flex-wrap:wrap;}
.report-num{font-family:'Space Grotesk',sans-serif;font-size:13px;font-weight:700;color:var(--gold);}
.report-title{font-size:15px;font-weight:600;color:var(--text);margin-top:2px;}
.report-meta{font-size:12px;color:var(--muted);margin-top:4px;display:flex;flex-wrap:wrap;gap:10px;}
.report-meta .badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;font-size:10.5px;font-weight:500;}
.report-meta .badge.critical{background:rgba(239,68,68,0.15);color:#ef4444;}
.report-meta .badge.high{background:rgba(249,115,22,0.15);color:#f97316;}
.report-meta .badge.medium{background:rgba(234,179,8,0.15);color:#eab308;}
.report-meta .badge.low{background:rgba(34,197,94,0.15);color:#22c55e;}
.report-meta .badge.general{background:rgba(148,163,184,0.15);color:#94a3b8;}
.report-meta .badge.malware{background:rgba(239,68,68,0.15);color:#ef4444;}
.report-meta .badge.network{background:rgba(59,130,246,0.15);color:#3b82f6;}
.report-meta .badge.memory{background:rgba(139,92,246,0.15);color:#8b5cf6;}
.report-meta .badge.disk{background:rgba(20,184,166,0.15);color:#14b8a6;}
.report-meta .badge.mobile{background:rgba(6,182,212,0.15);color:#06b6d4;}
.report-meta .badge.web{background:rgba(132,204,22,0.15);color:#84cc16;}
.report-meta .badge.crypto{background:rgba(251,191,36,0.15);color:#fbbf24;}
.report-body{font-size:13.5px;color:var(--muted);line-height:1.7;margin:10px 0;}
.section-label{font-size:11px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.7px;margin-bottom:4px;}
.review-form{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;margin-top:12px;}
.stats-mini{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-bottom:20px;}
.sm-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:14px 16px;text-align:center;text-decoration:none;transition:border-color .2s;}
.sm-card:hover{border-color:var(--border2);}
.sm-val{font-family:'Space Grotesk',sans-serif;font-size:22px;font-weight:700;color:var(--text);}
.sm-lbl{font-size:11.5px;color:var(--muted);margin-top:3px;}
.filter-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:14px 18px;margin-bottom:20px;}
.filter-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.filter-row input,.filter-row select{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:8px 12px;font-size:13px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.filter-row input{flex:1;min-width:180px;}
.filter-row select option{background:var(--surface2);}

.overlay{position:fixed;inset:0;z-index:300;background:rgba(4,8,18,.9);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;padding:20px;animation:fi .2s ease;}
@keyframes fi{from{opacity:0}to{opacity:1}}
.modal{background:var(--surface);border:1px solid var(--border2);border-radius:var(--radius-lg);width:100%;max-width:720px;max-height:92vh;overflow-y:auto;animation:up .3s cubic-bezier(.22,.68,0,1.15);}
@keyframes up{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
.modal-head{padding:22px 26px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;}
.modal-head h3{font-family:'Space Grotesk',sans-serif;font-size:17px;font-weight:600;color:var(--text);}
.modal-head h3 span{color:var(--gold);}
.modal-body{padding:22px 26px;}
.modal-body .form-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;}
.modal-foot{padding:14px 26px 22px;display:flex;gap:10px;justify-content:space-between;}
.modal-foot-left,.modal-foot-right{display:flex;gap:10px;}
.xbtn{background:none;border:none;color:var(--muted);font-size:15px;cursor:pointer;padding:3px 5px;border-radius:5px;}
.xbtn:hover{color:var(--danger);}

.severity-selector{display:flex;gap:8px;margin-bottom:16px;}
.sev-btn{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:8px 16px;font-size:12px;font-weight:500;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:6px;}
.sev-btn:hover{border-color:var(--gold);}
.sev-btn input{display:none;}
.sev-btn.critical{color:#ef4444;}
.sev-btn.critical.active{border-color:#ef4444;background:rgba(239,68,68,0.15);}
.sev-btn.high{color:#f97316;}
.sev-btn.high.active{border-color:#f97316;background:rgba(249,115,22,0.15);}
.sev-btn.medium{color:#eab308;}
.sev-btn.medium.active{border-color:#eab308;background:rgba(234,179,8,0.15);}
.sev-btn.low{color:#22c55e;}
.sev-btn.low.active{border-color:#22c55e;background:rgba(34,197,94,0.15);}

.draft-indicator{background:rgba(148,163,184,0.1);border:1px dashed var(--dim);border-radius:6px;padding:10px 14px;margin-bottom:16px;display:flex;align-items:center;gap:8px;font-size:12px;color:var(--muted);}

.draft-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;margin-bottom:20px;}
.draft-card{background:var(--surface);border:1px dashed var(--dim);border-radius:var(--radius);padding:14px;transition:border-color .2s;}
.draft-card:hover{border-color:var(--gold);}
.draft-card-title{font-weight:600;font-size:13.5px;color:var(--text);margin-bottom:6px;}
.draft-card-meta{font-size:11.5px;color:var(--muted);display:flex;gap:12px;flex-wrap:wrap;}
.draft-card-actions{display:flex;gap:8px;margin-top:10px;}
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
        <button type="button" class="btn-back" onclick="goBack()"><i class="fas fa-arrow-left"></i> Back</button>
        <h1 style="margin-top:8px;">Analysis Reports</h1>
        <p><?= $role==='admin' ? 'All forensic analysis reports' : 'Your submitted analysis reports' ?></p>
    </div>
    <?php if (can_analyse()): ?>
    <button class="btn btn-gold" onclick="openReportModal()">
        <i class="fas fa-file-plus"></i> New Report
    </button>
    <?php endif; ?>
</div>

<?php if ($msg): ?><div class="alert alert-success"><i class="fas fa-circle-check"></i> <?= $msg ?></div><?php endif; ?>
<?php if ($err): ?><div class="alert alert-danger"><i class="fas fa-circle-exclamation"></i> <?= $err ?></div><?php endif; ?>

<div class="stats-mini">
    <a href="reports.php" class="sm-card"><p class="sm-val"><?= $total_reports ?></p><p class="sm-lbl">Total Reports</p></a>
    <a href="reports.php?status=submitted" class="sm-card"><p class="sm-val" style="color:var(--warning)"><?= $pending_reports ?></p><p class="sm-lbl">Awaiting Review</p></a>
    <a href="reports.php?status=approved" class="sm-card"><p class="sm-val" style="color:var(--success)"><?= $approved_reports ?></p><p class="sm-lbl">Approved</p></a>
    <?php if ($role !== 'admin' && $draft_reports > 0): ?>
    <a href="reports.php?status=draft" class="sm-card"><p class="sm-val" style="color:var(--dim)"><?= $draft_reports ?></p><p class="sm-lbl">Drafts</p></a>
    <?php endif; ?>
</div>

<div class="filter-wrap">
    <form method="GET" id="filterForm">
        <div class="filter-row">
            <input type="text" name="search" id="searchInput" placeholder="Search report number, title, summary..." value="<?= e($search) ?>">
            <select name="status" onchange="this.form.submit()">
                <option value="">All Statuses</option>
                <?php foreach(['draft','submitted','reviewed','approved','rejected'] as $s): ?>
                <option value="<?= $s ?>" <?= $filter_status===$s?'selected':'' ?>><?= ucfirst($s) ?></option>
                <?php endforeach; ?>
            </select>
            <button type="submit" class="btn btn-gold btn-sm"><i class="fas fa-search"></i> Search</button>
            <?php if ($search||$filter_status): ?><a href="reports.php" class="btn btn-outline btn-sm"><i class="fas fa-xmark"></i> Clear</a><?php endif; ?>
        </div>
    </form>
</div>

<?php if ($role !== 'admin'): ?>
<?php $drafts = $pdo->prepare("SELECT ar.*, e.evidence_number, e.title as evidence_title FROM analysis_reports ar JOIN evidence e ON e.id=ar.evidence_id WHERE ar.submitted_by=? AND ar.status='draft' ORDER BY ar.updated_at DESC"); $drafts->execute([$uid]); $drafts = $drafts->fetchAll(); ?>
<?php if (!empty($drafts)): ?>
<h3 style="font-size:13px;color:var(--muted);margin-bottom:12px;text-transform:uppercase;letter-spacing:.5px;"><i class="fas fa-file-circle-xmark" style="color:var(--dim);margin-right:6px"></i> Your Drafts</h3>
<div class="draft-list">
<?php foreach($drafts as $d): ?>
<div class="draft-card">
    <p class="draft-card-title"><?= e($d['title']) ?: 'Untitled Draft' ?></p>
    <div class="draft-card-meta">
        <span><i class="fas fa-database"></i> <?= e($d['evidence_number']) ?></span>
        <span><i class="fas fa-clock"></i> <?= date('M j, Y g:i A', strtotime($d['updated_at'])) ?></span>
    </div>
    <div class="draft-card-actions">
        <button class="btn btn-outline btn-sm" onclick="editDraft(<?= $d['id'] ?>)"><i class="fas fa-edit"></i> Edit</button>
        <form method="POST" style="display:inline;" onsubmit="return confirm('Delete this draft?')">
            <input type="hidden" name="action" value="delete_draft">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <input type="hidden" name="draft_id" value="<?= $d['id'] ?>">
            <button type="submit" class="btn btn-danger btn-sm"><i class="fas fa-trash"></i></button>
        </form>
    </div>
</div>
<?php endforeach; ?>
</div>
<?php endif; endif; ?>

<?php if (empty($reports)): ?>
<div class="section-card">
    <div class="empty-state">
        <i class="fas fa-file-lines"></i>
        <p>No reports found.</p>
        <?php if (can_analyse()): ?>
        <button class="btn btn-gold" style="margin-top:14px" onclick="openReportModal()">
            <i class="fas fa-file-plus"></i> Submit First Report
        </button>
        <?php endif; ?>
    </div>
</div>
<?php else: foreach ($reports as $r):
    $sc = $status_colors[$r['status']] ?? 'gray';
?>
<div class="report-card <?= $r['status'] ?>">
    <div class="report-head">
        <div style="flex:1;min-width:0;">
            <p class="report-num"><?= e($r['report_number']) ?></p>
            <p class="report-title"><?= e($r['title']) ?></p>
            <div class="report-meta">
                <span><i class="fas fa-database" style="color:var(--gold)"></i> <?= e($r['evidence_number']) ?></span>
                <span><i class="fas fa-folder-open" style="color:var(--muted)"></i> <?= e($r['case_number']) ?></span>
                <span class="badge <?= e($r['report_type'] ?? 'general') ?>"><?= $report_types[$r['report_type']] ?? 'General' ?></span>
                <?php if(!empty($r['severity'])): ?>
                <span class="badge <?= e($r['severity']) ?>"><?= ucfirst(e($r['severity'])) ?></span>
                <?php endif; ?>
                <span><i class="fas fa-user" style="color:var(--muted)"></i> <?= e($r['analyst_name']) ?></span>
                <span><i class="fas fa-calendar" style="color:var(--muted)"></i> <?= date('M j, Y', strtotime($r['created_at'])) ?></span>
            </div>
        </div>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;flex-shrink:0;">
            <?= status_badge($r['status']) ?>
            <button class="btn btn-outline btn-sm" onclick="toggleReport(<?= $r['id'] ?>)">
                <i class="fas fa-chevron-down" id="ri_<?= $r['id'] ?>"></i> View
            </button>
        </div>
    </div>

    <div id="rc_<?= $r['id'] ?>" style="display:none;">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:14px;">
            <div>
                <p class="section-label">Summary</p>
                <p class="report-body"><?= nl2br(e($r['summary'])) ?></p>
            </div>
            <div>
                <p class="section-label">Findings</p>
                <p class="report-body"><?= nl2br(e($r['findings'])) ?></p>
            </div>
        </div>
        <?php if ($r['conclusions']): ?>
        <div style="margin-bottom:12px;">
            <p class="section-label">Conclusions</p>
            <p class="report-body"><?= nl2br(e($r['conclusions'])) ?></p>
        </div>
        <?php endif; ?>
        <?php if ($r['recommendations']): ?>
        <div style="margin-bottom:12px;">
            <p class="section-label">Recommendations</p>
            <p class="report-body"><?= nl2br(e($r['recommendations'])) ?></p>
        </div>
        <?php endif; ?>
        <?php if ($r['tools_used']): ?>
        <div style="margin-bottom:12px;">
            <p class="section-label">Tools Used</p>
            <p style="font-size:13px;color:var(--muted)"><?= e($r['tools_used']) ?></p>
        </div>
        <?php endif; ?>
        <?php if ($r['reviewer_notes']): ?>
        <div style="background:rgba(96,165,250,0.06);border:1px solid rgba(96,165,250,0.15);border-radius:var(--radius);padding:10px 14px;margin-bottom:12px;">
            <p class="section-label">Reviewer Notes</p>
            <p style="font-size:13px;color:var(--muted)"><?= nl2br(e($r['reviewer_notes'])) ?></p>
            <?php if ($r['reviewer_name']): ?><p style="font-size:11.5px;color:var(--dim);margin-top:4px">— <?= e($r['reviewer_name']) ?>, <?= date('M j, Y', strtotime($r['reviewed_at'])) ?></p><?php endif; ?>
        </div>
        <?php endif; ?>

        <?php if ($role === 'admin' && $r['status'] === 'submitted'): ?>
        <div class="review-form">
            <p style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:12px;"><i class="fas fa-gavel" style="color:var(--gold);margin-right:6px"></i>Review this Report</p>
            <form method="POST">
                <input type="hidden" name="action"     value="review_report">
                <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
                <input type="hidden" name="report_id"  value="<?= $r['id'] ?>">
                <div class="field">
                    <label>Reviewer Notes</label>
                    <textarea name="reviewer_notes" placeholder="Add your review comments..."></textarea>
                </div>
                <div style="display:flex;gap:10px;">
                    <button type="submit" name="review_status" value="approved" class="btn btn-success">
                        <i class="fas fa-check"></i> Approve
                    </button>
                    <button type="submit" name="review_status" value="rejected" class="btn btn-danger">
                        <i class="fas fa-xmark"></i> Reject
                    </button>
                    <button type="submit" name="review_status" value="reviewed" class="btn btn-outline">
                        <i class="fas fa-eye"></i> Mark Reviewed
                    </button>
                </div>
            </form>
        </div>
        <?php endif; ?>
    </div>
</div>
<?php endforeach; endif; ?>

</div></div></div>

<div class="overlay" id="newReportModal" style="display:none" onclick="if(event.target===this)this.style.display='none'">
    <div class="modal">
        <div class="modal-head">
            <h3>Submit <span>Analysis Report</span></h3>
            <button class="xbtn" onclick="closeReportModal()"><i class="fas fa-xmark"></i></button>
        </div>
        <div id="draftIndicator" class="draft-indicator" style="display:none;">
            <i class="fas fa-file-circle-xmark"></i>
            <span>Editing existing draft</span>
        </div>
        <form method="POST" id="reportForm">
            <input type="hidden" name="action" value="submit_report">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <input type="hidden" name="draft_id" id="draftId" value="">
            <div class="modal-body">
                <div class="form-grid">
                    <div class="field">
                        <label>Report Type *</label>
                        <select name="report_type" id="reportType">
                            <?php foreach($report_types as $k => $v): ?>
                            <option value="<?= $k ?>"><?= $v ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="field">
                        <label>Evidence *</label>
                        <select name="evidence_id" id="evidenceSelect" required onchange="onEvidenceChange()">
                            <option value="">— Select evidence —</option>
                            <?php foreach ($evidence_list as $ev): ?>
                            <option value="<?= $ev['id'] ?>">
                                <?= e($ev['evidence_number']) ?> — <?= e(substr($ev['title'],0,35)) ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>

                <div class="field">
                    <label>Report Title *</label>
                    <input type="text" name="title" id="reportTitle" placeholder="e.g. Malware Analysis - Suspicious Executable" required>
                </div>

                <div class="field">
                    <label>Severity Level</label>
                    <div class="severity-selector">
                        <?php foreach(['critical','high','medium','low'] as $sev): ?>
                        <label class="sev-btn <?= $sev ?> <?= $sev==='medium'?'active':'' ?>">
                            <input type="radio" name="severity" value="<?= $sev ?>" <?= $sev==='medium'?'checked':'' ?> onchange="updateSeverityUI('<?= $sev ?>')">
                            <?= ucfirst($sev) ?>
                        </label>
                        <?php endforeach; ?>
                    </div>
                </div>

                <div class="field">
                    <label>Summary *</label>
                    <textarea name="summary" id="reportSummary" placeholder="Brief overview of the analysis conducted and its purpose..." required oninput="updateCharCount('reportSummary','summaryCount')"></textarea>
                    <div class="char-count" id="summaryCount">0 characters</div>
                </div>

                <div class="field">
                    <label>Findings *</label>
                    <textarea name="findings" id="reportFindings" placeholder="Detailed findings from the analysis with technical details, indicators of compromise (IOCs)..." style="min-height:140px" required oninput="updateCharCount('reportFindings','findingsCount')"></textarea>
                    <div class="char-count" id="findingsCount">0 characters</div>
                </div>

                <div class="form-grid">
                    <div class="field">
                        <label>Conclusions</label>
                        <textarea name="conclusions" placeholder="Conclusions drawn from the findings..."></textarea>
                    </div>
                    <div class="field">
                        <label>Recommendations</label>
                        <textarea name="recommendations" placeholder="Recommended actions or next steps..."></textarea>
                    </div>
                </div>

                <div class="field">
                    <label>Tools Used</label>
                    <input type="text" name="tools_used" id="toolsUsed" placeholder="e.g. Autopsy 4.21, Volatility 3, Wireshark 4.2">
                    <p class="field-hint">Separate multiple tools with commas</p>
                </div>
            </div>
            <div class="modal-foot">
                <div class="modal-foot-left">
                    <button type="button" class="btn btn-outline" onclick="saveDraft()"><i class="fas fa-floppy-disk"></i> Save Draft</button>
                </div>
                <div class="modal-foot-right">
                    <button type="button" class="btn btn-outline" onclick="closeReportModal()">Cancel</button>
                    <button type="submit" class="btn btn-gold"><i class="fas fa-paper-plane"></i> Submit</button>
                </div>
            </div>
        </form>
    </div>
</div>

<script>
function openReportModal() {
    document.getElementById('newReportModal').style.display = 'flex';
    document.getElementById('draftIndicator').style.display = 'none';
    document.getElementById('draftId').value = '';
    document.getElementById('reportForm').reset();
    document.getElementById('reportType').value = 'general';
    updateCharCount('reportSummary','summaryCount');
    updateCharCount('reportFindings','findingsCount');
    document.querySelectorAll('.sev-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('.sev-btn.medium').classList.add('active');
    document.querySelector('input[name="severity"][value="medium"]').checked = true;
}

function editDraft(id) {
    fetch('api/get_draft.php?id=' + id)
        .then(r => r.json())
        .then(data => {
            if(data.success) {
                document.getElementById('draftId').value = data.id;
                document.getElementById('evidenceSelect').value = data.evidence_id;
                document.getElementById('reportTitle').value = data.title || '';
                document.getElementById('reportSummary').value = data.summary || '';
                document.getElementById('reportFindings').value = data.findings || '';
                document.getElementById('reportType').value = data.report_type || 'general';
                document.querySelector('input[name="severity"][value="' + (data.severity || 'medium') + '"]').checked = true;
                updateSeverityUI(data.severity || 'medium');
                document.querySelector('textarea[name="conclusions"]').value = data.conclusions || '';
                document.querySelector('textarea[name="recommendations"]').value = data.recommendations || '';
                document.getElementById('toolsUsed').value = data.tools_used || '';
                updateCharCount('reportSummary','summaryCount');
                updateCharCount('reportFindings','findingsCount');
                document.getElementById('draftIndicator').style.display = 'flex';
                document.getElementById('newReportModal').style.display = 'flex';
            }
        })
        .catch(() => { alert('Failed to load draft'); });
}

function closeReportModal() {
    document.getElementById('newReportModal').style.display = 'none';
}

function saveDraft() {
    const form = document.getElementById('reportForm');
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'action';
    input.value = 'save_draft';
    form.appendChild(input);
    form.submit();
}

function updateCharCount(fieldId, countId) {
    document.getElementById(countId).textContent = document.getElementById(fieldId).value.length + ' characters';
}

function updateSeverityUI(sev) {
    document.querySelectorAll('.sev-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('.sev-btn.' + sev).classList.add('active');
}

function onEvidenceChange() {
    const select = document.getElementById('evidenceSelect');
    const title = document.getElementById('reportTitle');
    if(select.value && !title.value) {
        const opt = select.options[select.selectedIndex];
        title.value = 'Analysis Report - ' + opt.text.split(' — ')[0];
    }
}

function toggleSidebar(){const sb=document.getElementById('sidebar'),ma=document.getElementById('mainArea');if(window.innerWidth<=900){sb.classList.toggle('mobile-open');}else{sb.classList.toggle('collapsed');ma.classList.toggle('collapsed');}localStorage.setItem('sb_collapsed',sb.classList.contains('collapsed')?'1':'0');}
if(localStorage.getItem('sb_collapsed')==='1'&&window.innerWidth>900){document.getElementById('sidebar').classList.add('collapsed');document.getElementById('mainArea').classList.add('collapsed');}
function toggleNotif(){document.getElementById('notifDropdown').classList.toggle('open');document.getElementById('userDropdown').classList.remove('open');}
function toggleUserMenu(){document.getElementById('userDropdown').classList.toggle('open');document.getElementById('notifDropdown').classList.remove('open');}
document.addEventListener('click',function(e){if(!e.target.closest('#notifWrap'))document.getElementById('notifDropdown').classList.remove('open');if(!e.target.closest('#userMenuWrap'))document.getElementById('userDropdown').classList.remove('open');});
function toggleReport(id){
    const c=document.getElementById('rc_'+id);
    const i=document.getElementById('ri_'+id);
    c.style.display=c.style.display==='none'?'block':'none';
    i.className=c.style.display==='none'?'fas fa-chevron-down':'fas fa-chevron-up';
}
var st;document.getElementById('searchInput')?.addEventListener('input',function(){clearTimeout(st);st=setTimeout(function(){document.getElementById('filterForm').submit();},600);});
</script>
<script src="../assets/js/main.js"></script>
</body>
</html>
