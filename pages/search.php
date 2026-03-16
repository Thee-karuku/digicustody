<?php
/**
 * DigiCustody – Global Search
 * Save to: /var/www/html/digicustody/pages/search.php
 */
session_start();
require_once __DIR__.'/../config/db.php';
require_once __DIR__.'/../config/functions.php';
require_login();

$page_title = 'Search';
$q = trim($_GET['q'] ?? '');
$s = "%$q%";

$evidence = $cases = $reports = [];

if ($q !== '') {
    $evidence = $pdo->prepare("
        SELECT e.id, e.evidence_number, e.title, e.evidence_type, e.status, e.uploaded_at,
               c.case_number, u.full_name AS uploader
        FROM evidence e JOIN cases c ON c.id=e.case_id JOIN users u ON u.id=e.uploaded_by
        WHERE e.evidence_number LIKE ? OR e.title LIKE ? OR e.description LIKE ?
        ORDER BY e.uploaded_at DESC LIMIT 15
    ");
    $evidence->execute([$s,$s,$s]);
    $evidence = $evidence->fetchAll(PDO::FETCH_ASSOC);

    $cases = $pdo->prepare("
        SELECT id, case_number, case_title, case_type, status, priority, created_at,
               (SELECT COUNT(*) FROM evidence WHERE case_id=cases.id) AS ev_count
        FROM cases
        WHERE case_number LIKE ? OR case_title LIKE ? OR description LIKE ?
        ORDER BY created_at DESC LIMIT 10
    ");
    $cases->execute([$s,$s,$s]);
    $cases = $cases->fetchAll(PDO::FETCH_ASSOC);

    $reports = $pdo->prepare("
        SELECT ar.id, ar.report_number, ar.title, ar.status, ar.created_at,
               e.evidence_number, u.full_name AS analyst
        FROM analysis_reports ar JOIN evidence e ON e.id=ar.evidence_id JOIN users u ON u.id=ar.submitted_by
        WHERE ar.report_number LIKE ? OR ar.title LIKE ? OR ar.summary LIKE ?
        ORDER BY ar.created_at DESC LIMIT 10
    ");
    $reports->execute([$s,$s,$s]);
    $reports = $reports->fetchAll(PDO::FETCH_ASSOC);
}

$total = count($evidence) + count($cases) + count($reports);

function highlight($text, $q) {
    if (!$q) return e($text);
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
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.search-big{display:flex;gap:10px;margin-bottom:24px;}
.search-big input{flex:1;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:14px 18px;font-size:16px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.search-big input:focus{border-color:rgba(201,168,76,0.5);box-shadow:0 0 0 3px rgba(201,168,76,0.06);}
.result-item{display:flex;align-items:flex-start;gap:14px;padding:14px 0;border-bottom:1px solid var(--border);transition:background .15s;cursor:pointer;}
.result-item:last-child{border-bottom:none;}
.result-item:hover{background:var(--surface2);margin:0 -16px;padding:14px 16px;}
.ri-icon{width:38px;height:38px;border-radius:9px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:15px;}
.ri-title{font-size:14px;font-weight:500;color:var(--text);margin-bottom:3px;}
.ri-meta{font-size:12px;color:var(--muted);}
.result-section{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);margin-bottom:20px;overflow:hidden;}
.rs-head{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;}
.rs-head h2{font-family:'Space Grotesk',sans-serif;font-size:14px;font-weight:600;color:var(--text);}
.rs-head i{color:var(--gold);font-size:13px;}
.rs-body{padding:0 18px;}
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
        <h1>Search</h1>
        <p><?= $q ? number_format($total).' result'.($total!=1?'s':'').' for &ldquo;'.e($q).'&rdquo;' : 'Search across evidence, cases and reports' ?></p>
    </div>
</div>

<!-- Big search bar -->
<form method="GET" action="search.php">
    <div class="search-big">
        <input type="text" name="q" value="<?= e($q) ?>" placeholder="Search evidence numbers, titles, cases, reports..." autofocus id="mainSearch">
        <button type="submit" class="btn btn-gold" style="padding:14px 22px;font-size:15px;"><i class="fas fa-search"></i> Search</button>
    </div>
</form>

<?php if ($q === ''): ?>
<div class="section-card">
    <div class="empty-state" style="padding:48px">
        <i class="fas fa-search"></i>
        <p>Enter a search term to find evidence, cases or reports</p>
        <p style="font-size:12px;margin-top:8px">Try searching by evidence number, case title, file name or report content</p>
    </div>
</div>

<?php elseif ($total === 0): ?>
<div class="section-card">
    <div class="empty-state" style="padding:48px">
        <i class="fas fa-magnifying-glass"></i>
        <p>No results found for &ldquo;<?= e($q) ?>&rdquo;</p>
        <p style="font-size:12px;margin-top:8px">Try different keywords or check spelling</p>
    </div>
</div>

<?php else: ?>

<!-- Evidence results -->
<?php if (!empty($evidence)): ?>
<div class="result-section">
    <div class="rs-head">
        <i class="fas fa-database"></i>
        <h2>Evidence <span class="badge badge-gold" style="margin-left:6px"><?= count($evidence) ?></span></h2>
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
                <?= e($ev['case_number']) ?> &nbsp;·&nbsp; <?= e($ev['uploader']) ?> &nbsp;·&nbsp; <?= date('M j, Y',strtotime($ev['uploaded_at'])) ?>
            </p>
        </div>
        <?= status_badge($ev['status']) ?>
    </div>
    </a>
    <?php endforeach; ?>
    </div>
</div>
<?php endif; ?>

<!-- Cases results -->
<?php if (!empty($cases)): ?>
<div class="result-section">
    <div class="rs-head">
        <i class="fas fa-folder-open"></i>
        <h2>Cases <span class="badge badge-blue" style="margin-left:6px"><?= count($cases) ?></span></h2>
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

<!-- Reports results -->
<?php if (!empty($reports)): ?>
<div class="result-section">
    <div class="rs-head">
        <i class="fas fa-file-lines"></i>
        <h2>Reports <span class="badge badge-green" style="margin-left:6px"><?= count($reports) ?></span></h2>
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
function handleSearch(e){if(e.key==='Enter'){window.location='search.php?q='+encodeURIComponent(document.getElementById('globalSearch').value);}}
</script>
</body>
</html>
