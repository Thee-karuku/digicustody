<?php
/**
 * DigiCustody – Advanced Evidence Search
 * Save to: /var/www/html/digicustody/pages/search.php
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login($pdo);

$page_title = 'Search';
$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];

// Get filter parameters
$q = trim($_GET['q'] ?? '');
$ev_type = $_GET['ev_type'] ?? '';
$date_from = $_GET['date_from'] ?? '';
$date_to = $_GET['date_to'] ?? '';
$uploader_id = $_GET['uploader'] ?? '';
$case_id = $_GET['case'] ?? '';
$status = $_GET['status'] ?? '';
$has_filters = $ev_type || $date_from || $date_to || $uploader_id || $case_id || $status;

$s = "%$q%";
$evidence = $cases = $reports = [];

// Build evidence WHERE clause
$ev_conditions = [];
$ev_params = [];

if ($q !== '') {
    // Use FULLTEXT search for terms 3+ characters, fallback to LIKE for short terms
    if (strlen($q) >= 3) {
        $ev_conditions[] = "MATCH(e.title, e.description, e.collection_notes) AGAINST(? IN NATURAL LANGUAGE MODE)";
        $ev_params[] = $q;
    } else {
        $s = "%$q%";
        $ev_conditions[] = "(e.evidence_number LIKE ? OR e.title LIKE ? OR e.description LIKE ? OR e.file_name LIKE ?)";
        $ev_params[] = $s; $ev_params[] = $s; $ev_params[] = $s; $ev_params[] = $s;
    }
}

if ($ev_type) {
    $ev_conditions[] = "e.evidence_type = ?";
    $ev_params[] = $ev_type;
}

if ($date_from) {
    $ev_conditions[] = "DATE(e.uploaded_at) >= ?";
    $ev_params[] = $date_from;
}

if ($date_to) {
    $ev_conditions[] = "DATE(e.uploaded_at) <= ?";
    $ev_params[] = $date_to;
}

if ($uploader_id) {
    $ev_conditions[] = "e.uploaded_by = ?";
    $ev_params[] = (int)$uploader_id;
}

if ($case_id) {
    $ev_conditions[] = "e.case_id = ?";
    $ev_params[] = (int)$case_id;
}

if ($status) {
    $ev_conditions[] = "e.status = ?";
    $ev_params[] = $status;
}

// Role-based access control
if (is_analyst()) {
    $ev_conditions[] = "(e.uploaded_by=? OR e.current_custodian=? OR e.case_id IN (SELECT c.id FROM cases c WHERE c.assigned_to=? OR c.created_by=?))";
    $ev_params = array_merge($ev_params, [$uid, $uid, $uid, $uid]);
}

$ev_where = $ev_conditions ? 'WHERE ' . implode(' AND ', $ev_conditions) : 'WHERE 1=1';

// Get evidence with filters
$ev_sql = "
    SELECT e.id, e.evidence_number, e.title, e.evidence_type, e.status, e.uploaded_at,
           c.case_number, c.case_title, u.full_name AS uploader, u.username AS uploader_username,
           e.sha256_hash, e.file_size, e.collection_location
    FROM evidence e 
    JOIN cases c ON c.id=e.case_id 
    JOIN users u ON u.id=e.uploaded_by
    $ev_where
    ORDER BY e.uploaded_at DESC 
    LIMIT 100
";
$evidence = $pdo->prepare($ev_sql);
$evidence->execute($ev_params);
$evidence = $evidence->fetchAll(PDO::FETCH_ASSOC);

// Case search
$case_conditions = [];
$case_params = [];

if ($q !== '') {
    $case_conditions[] = "(case_number LIKE ? OR case_title LIKE ? OR description LIKE ?)";
    $case_params[] = $s; $case_params[] = $s; $case_params[] = $s;
}

if ($status) {
    $case_conditions[] = "cases.status = ?";
    $case_params[] = $status;
}

if ($case_conditions) {
    $case_where = 'WHERE ' . implode(' AND ', $case_conditions);
} else {
    $case_where = 'WHERE 1=1';
}

if (is_analyst()) {
    $case_where .= " AND (assigned_to=? OR created_by=?)";
    $case_params[] = $uid; $case_params[] = $uid;
}

$case_sql = "
    SELECT id, case_number, case_title, case_type, status, priority, created_at,
           (SELECT COUNT(*) FROM evidence WHERE case_id=cases.id) AS ev_count
    FROM cases
    $case_where
    ORDER BY created_at DESC 
    LIMIT 50
";
$cases = $pdo->prepare($case_sql);
$cases->execute($case_params);
$cases = $cases->fetchAll(PDO::FETCH_ASSOC);

// Reports search
$report_conditions = [];
$report_params = [];

if ($q !== '') {
    $report_conditions[] = "(ar.report_number LIKE ? OR ar.title LIKE ? OR ar.summary LIKE ?)";
    $report_params[] = $s; $report_params[] = $s; $report_params[] = $s;
}

if ($report_conditions) {
    $report_where = 'WHERE ' . implode(' AND ', $report_conditions);
} else {
    $report_where = 'WHERE 1=1';
}

if (is_analyst()) {
    $report_where .= " AND ar.submitted_by=?";
    $report_params[] = $uid;
}

$report_sql = "
    SELECT ar.id, ar.report_number, ar.title, ar.status, ar.created_at, ar.summary,
           e.evidence_number, u.full_name AS analyst
    FROM analysis_reports ar 
    JOIN evidence e ON e.id=ar.evidence_id 
    JOIN users u ON u.id=ar.submitted_by
    $report_where
    ORDER BY ar.created_at DESC 
    LIMIT 50
";
$reports = $pdo->prepare($report_sql);
$reports->execute($report_params);
$reports = $reports->fetchAll(PDO::FETCH_ASSOC);

// Get filter options
$uploaders = $pdo->query("SELECT id, full_name, username FROM users WHERE status='active' ORDER BY full_name")->fetchAll();
$cases_list = $pdo->query("SELECT id, case_number, case_title FROM cases ORDER BY case_number")->fetchAll();

$total = count($evidence) + count($cases) + count($reports);

function highlight($text, $q) {
    if (!$q || !$text) return e($text ?? '');
    return preg_replace('/('.preg_quote(htmlspecialchars($q),'/').')/i',
        '<mark style="background:rgba(201,168,76,0.3);color:var(--text);border-radius:3px;padding:0 2px">$1</mark>',
        htmlspecialchars($text));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Search — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.search-header{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap;}
.search-header input{flex:1;min-width:200px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:12px 16px;font-size:15px;color:var(--text);outline:none;transition:border-color .2s;}
.search-header input:focus{border-color:rgba(201,168,76,0.5);}
.filter-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;}
.filter-row select,.filter-row input{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:8px 12px;font-size:13px;color:var(--text);min-width:140px;}
.filter-row input{min-width:120px;}
.filter-row label{font-size:12px;color:var(--muted);display:flex;align-items:center;gap:4px;}
.result-item{display:flex;align-items:flex-start;gap:14px;padding:16px 0;border-bottom:1px solid var(--border);transition:background .15s;cursor:pointer;}
.result-item:last-child{border-bottom:none;}
.result-item:hover{background:var(--surface2);margin:0 -16px;padding:16px;}
.ri-icon{width:40px;height:40px;border-radius:10px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:16px;}
.ri-title{font-size:14px;font-weight:500;color:var(--text);margin-bottom:4px;}
.ri-meta{font-size:12px;color:var(--muted);line-height:1.5;}
.ri-highlight{padding:8px 12px;background:var(--surface2);border-radius:var(--radius);margin-top:8px;font-size:12px;color:var(--muted);border-left:2px solid var(--gold);}
.result-section{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);margin-bottom:20px;overflow:hidden;}
.rs-head{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;background:var(--surface2);}
.rs-head h2{font-family:'Space Grotesk',sans-serif;font-size:14px;font-weight:600;color:var(--text);}
.rs-body{padding:0 18px;}
.filter-active{color:var(--gold);font-size:12px;margin-left:auto;}
.stats-row{display:flex;gap:20px;margin-bottom:20px;flex-wrap:wrap;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;flex:1;min-width:150px;}
.stat-card h3{font-size:24px;font-weight:700;color:var(--text);margin:0;}
.stat-card p{font-size:12px;color:var(--muted);margin:4px 0 0 0;}
@media(max-width:768px){.filter-row{flex-direction:column;}.filter-row select,.filter-row input{min-width:100%;}}
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
        <h1>Search Evidence</h1>
        <p>Search across evidence, cases and reports with advanced filters</p>
    </div>
</div>

<!-- Search Form with Filters -->
<form method="GET" action="search.php" id="searchForm">
    <div class="search-header">
        <input type="text" name="q" value="<?= e($q) ?>" placeholder="Search by evidence number, title, description, file name..." autofocus id="mainSearch">
        <button type="submit" class="btn btn-gold" style="padding:12px 20px;"><i class="fas fa-search"></i> Search</button>
        <?php if ($has_filters || $q): ?>
        <a href="search.php" class="btn btn-outline" style="padding:12px 16px;"><i class="fas fa-times"></i> Clear</a>
        <?php endif; ?>
    </div>
    
    <div class="filter-row">
        <div>
            <label><i class="fas fa-filter"></i> Filters:</label>
        </div>
        <select name="ev_type">
            <option value="">All Types</option>
            <option value="image" <?= $ev_type === 'image' ? 'selected' : '' ?>>Image</option>
            <option value="video" <?= $ev_type === 'video' ? 'selected' : '' ?>>Video</option>
            <option value="document" <?= $ev_type === 'document' ? 'selected' : '' ?>>Document</option>
            <option value="log_file" <?= $ev_type === 'log_file' ? 'selected' : '' ?>>Log File</option>
            <option value="email" <?= $ev_type === 'email' ? 'selected' : '' ?>>Email</option>
            <option value="database" <?= $ev_type === 'database' ? 'selected' : '' ?>>Database</option>
            <option value="network_capture" <?= $ev_type === 'network_capture' ? 'selected' : '' ?>>Network Capture</option>
            <option value="mobile_data" <?= $ev_type === 'mobile_data' ? 'selected' : '' ?>>Mobile Data</option>
            <option value="other" <?= $ev_type === 'other' ? 'selected' : '' ?>>Other</option>
        </select>
        
        <select name="uploader">
            <option value="">All Uploaders</option>
            <?php foreach ($uploaders as $u): ?>
            <option value="<?= $u['id'] ?>" <?= $uploader_id == $u['id'] ? 'selected' : '' ?>><?= e($u['full_name']) ?> (<?= e($u['username']) ?>)</option>
            <?php endforeach; ?>
        </select>
        
        <select name="case">
            <option value="">All Cases</option>
            <?php foreach ($cases_list as $c): ?>
            <option value="<?= $c['id'] ?>" <?= $case_id == $c['id'] ? 'selected' : '' ?>><?= e($c['case_number']) ?> - <?= e(substr($c['case_title'], 0, 40)) ?></option>
            <?php endforeach; ?>
        </select>
        
        <select name="status">
            <option value="">All Status</option>
            <option value="collected" <?= $status === 'collected' ? 'selected' : '' ?>>Collected</option>
            <option value="in_analysis" <?= $status === 'in_analysis' ? 'selected' : '' ?>>In Analysis</option>
            <option value="transferred" <?= $status === 'transferred' ? 'selected' : '' ?>>Transferred</option>
            <option value="archived" <?= $status === 'archived' ? 'selected' : '' ?>>Archived</option>
            <option value="flagged" <?= $status === 'flagged' ? 'selected' : '' ?>>Flagged</option>
        </select>
        
        <input type="date" name="date_from" value="<?= e($date_from) ?>" placeholder="From date">
        <input type="date" name="date_to" value="<?= e($date_to) ?>" placeholder="To date">
    </div>
</form>

<?php if ($q === '' && !$has_filters): ?>
<div class="section-card">
    <div class="empty-state" style="padding:48px">
        <i class="fas fa-search"></i>
        <p>Enter a search term or use filters to find evidence</p>
        <p style="font-size:12px;margin-top:8px">Search by: evidence number, title, description, file name, case, uploader</p>
    </div>
</div>

<?php elseif ($total === 0): ?>
<div class="section-card">
    <div class="empty-state" style="padding:48px">
        <i class="fas fa-magnifying-glass"></i>
        <p>No results found</p>
        <p style="font-size:12px;margin-top:8px">Try different keywords or adjust your filters</p>
    </div>
</div>

<?php else: ?>

<!-- Results Summary -->
<div class="stats-row">
    <div class="stat-card" style="border-left:3px solid var(--gold);">
        <h3><?= count($evidence) ?></h3>
        <p>Evidence Files</p>
    </div>
    <div class="stat-card" style="border-left:3px solid #3b82f6;">
        <h3><?= count($cases) ?></h3>
        <p>Cases</p>
    </div>
    <div class="stat-card" style="border-left:3px solid #22c55e;">
        <h3><?= count($reports) ?></h3>
        <p>Reports</p>
    </div>
</div>

<?php if (!empty($evidence)): ?>
<div class="result-section">
    <div class="rs-head">
        <i class="fas fa-database"></i>
        <h2>Evidence Files</h2>
        <?php if ($q): ?>
        <span class="filter-active">Matching: "<?= e($q) ?>"</span>
        <?php endif; ?>
    </div>
    <div class="rs-body">
    <?php foreach ($evidence as $ev): ?>
    <a href="evidence_view.php?id=<?= $ev['id'] ?>" style="text-decoration:none;display:block;">
    <div class="result-item">
        <div class="ri-icon stat-icon blue"><i class="fas fa-database"></i></div>
        <div style="flex:1;min-width:0;">
            <p class="ri-title"><?= highlight($ev['evidence_number'],$q) ?> — <?= highlight($ev['title'],$q) ?></p>
            <p class="ri-meta">
                <span class="badge badge-blue" style="margin-right:6px"><?= ucfirst(str_replace('_',' ',$ev['evidence_type'])) ?></span>
                <?= e($ev['case_number']) ?> &nbsp;·&nbsp; 
                <?= e($ev['uploader']) ?> &nbsp;·&nbsp; 
                <?= date('M j, Y',strtotime($ev['uploaded_at'])) ?>
            </p>
            <?php if ($ev['collection_location']): ?>
            <p class="ri-meta" style="margin-top:4px"><i class="fas fa-location-dot"></i> <?= e($ev['collection_location']) ?></p>
            <?php endif; ?>
            <?php if ($q && stripos($ev['description'], $q) !== false): ?>
            <div class="ri-highlight">
                <i class="fas fa-quote-left" style="margin-right:4px"></i>
                <?= highlight(substr($ev['description'], 0, 200), $q) ?>...
            </div>
            <?php endif; ?>
        </div>
        <?= status_badge($ev['status']) ?>
    </div>
    </a>
    <?php endforeach; ?>
    </div>
</div>
<?php endif; ?>

<?php if (!empty($cases)): ?>
<div class="result-section">
    <div class="rs-head">
        <i class="fas fa-folder-open"></i>
        <h2>Cases</h2>
    </div>
    <div class="rs-body">
    <?php foreach ($cases as $c): ?>
    <a href="case_view.php?id=<?= $c['id'] ?>" style="text-decoration:none;display:block;">
    <div class="result-item">
        <div class="ri-icon stat-icon gold"><i class="fas fa-folder-open"></i></div>
        <div style="flex:1;min-width:0;">
            <p class="ri-title"><?= highlight($c['case_number'],$q) ?> — <?= highlight($c['case_title'],$q) ?></p>
            <p class="ri-meta">
                <?php if ($c['case_type']): ?><span class="badge badge-gray" style="margin-right:6px"><?= e($c['case_type']) ?></span><?php endif; ?>
                <?= $c['ev_count'] ?> evidence file<?= $c['ev_count']!=1?'s':'' ?> &nbsp;·&nbsp; <?= date('M j, Y',strtotime($c['created_at'])) ?>
            </p>
        </div>
        <?= status_badge($c['status']) ?>
    </div>
    </a>
    <?php endforeach; ?>
    </div>
</div>
<?php endif; ?>

<?php if (!empty($reports)): ?>
<div class="result-section">
    <div class="rs-head">
        <i class="fas fa-file-lines"></i>
        <h2>Reports</h2>
    </div>
    <div class="rs-body">
    <?php foreach ($reports as $r): ?>
    <a href="reports.php" style="text-decoration:none;display:block;">
    <div class="result-item">
        <div class="ri-icon stat-icon green"><i class="fas fa-file-lines"></i></div>
        <div style="flex:1;min-width:0;">
            <p class="ri-title"><?= highlight($r['report_number'],$q) ?> — <?= highlight($r['title'],$q) ?></p>
            <p class="ri-meta">
                Evidence: <?= e($r['evidence_number']) ?> &nbsp;·&nbsp; <?= e($r['analyst']) ?> &nbsp;·&nbsp; <?= date('M j, Y',strtotime($r['created_at'])) ?>
            </p>
            <?php if ($q && stripos($r['summary'], $q) !== false): ?>
            <div class="ri-highlight">
                <?= highlight(substr($r['summary'], 0, 150), $q) ?>...
            </div>
            <?php endif; ?>
        </div>
        <?= status_badge($r['status']) ?>
    </div>
    </a>
    <?php endforeach; ?>
    </div>
</div>
<?php endif; ?>

<?php endif; ?>

</div></div></div>
<script>
function toggleSidebar(){const sb=document.getElementById('sidebar'),ma=document.getElementById('mainArea');if(window.innerWidth<=900){sb.classList.toggle('mobile-open');}else{sb.classList.toggle('collapsed');ma.classList.toggle('collapsed');}localStorage.setItem('sb_collapsed',sb.classList.contains('collapsed')?'1':'0');}
if(localStorage.getItem('sb_collapsed')==='1'&&window.innerWidth>900){document.getElementById('sidebar').classList.add('collapsed');document.getElementById('mainArea').classList.add('collapsed');}
function toggleNotif(){document.getElementById('notifDropdown').classList.toggle('open');document.getElementById('userDropdown').classList.remove('open');}
function toggleUserMenu(){document.getElementById('userDropdown').classList.toggle('open');document.getElementById('notifDropdown').classList.remove('open');}
document.addEventListener('click',function(e){if(!e.target.closest('#notifWrap'))document.getElementById('notifDropdown').classList.remove('open');if(!e.target.closest('#userMenuWrap'))document.getElementById('userDropdown').classList.remove('open');});
document.addEventListener('DOMContentLoaded',function(){
    const searchInput=document.getElementById('mainSearch');
    if(searchInput) searchInput.focus();
});
</script>
</body>
</html>
