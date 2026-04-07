<?php
/**
 * DigiCustody – Download History Page
 * Save to: /var/www/html/digicustody/pages/downloads.php
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login();

if (is_viewer()) {
    header('Location: ../dashboard.php?error=access_denied'); exit;
}

$page_title = 'Downloads';
$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];

// Admins can filter by user
$filter_user = is_admin() ? (int)($_GET['user'] ?? 0) : 0;
$search      = trim($_GET['search'] ?? '');
$page_num    = max(1, (int)($_GET['page'] ?? 1));
$per_page    = 20;
$offset      = ($page_num - 1) * $per_page;

// Build query
$where = ['1=1'];
$params = [];

if ($filter_user > 0) {
    $where[] = 'dh.user_id = ?';
    $params[] = $filter_user;
} elseif (!is_admin()) {
    $where[] = 'dh.user_id = ?';
    $params[] = $uid;
}

if ($search !== '') {
    $where[] = '(e.evidence_number LIKE ? OR e.title LIKE ? OR e.file_name LIKE ?)';
    $s = "%$search%";
    $params = array_merge($params, [$s, $s, $s]);
}

$where_sql = implode(' AND ', $where);

// Count
$count_stmt = $pdo->prepare("
    SELECT COUNT(*) FROM download_history dh
    JOIN evidence e ON e.id = dh.evidence_id
    WHERE $where_sql
");
$count_stmt->execute($params);
$total = (int)$count_stmt->fetchColumn();
$total_pages = max(1, (int)ceil($total / $per_page));

// Fetch
$data_stmt = $pdo->prepare("
    SELECT dh.*, e.evidence_number, e.title, e.file_name, e.file_size,
           u.full_name AS downloaded_by
    FROM download_history dh
    JOIN evidence e ON e.id = dh.evidence_id
    JOIN users u ON u.id = dh.user_id
    WHERE $where_sql
    ORDER BY dh.downloaded_at DESC
    LIMIT ? OFFSET ?
");
$data_stmt->execute(array_merge($params, [$per_page, $offset]));
$downloads = $data_stmt->fetchAll(PDO::FETCH_ASSOC);

// Users dropdown (admin only)
$all_users = is_admin()
    ? $pdo->query("SELECT id, full_name, username FROM users WHERE status='active' ORDER BY full_name")->fetchAll()
    : [];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Downloads — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.filter-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:16px 20px;margin-bottom:20px;}
.filter-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.filter-row input,.filter-row select{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:8px 12px;font-size:13px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.filter-row input{flex:1;min-width:180px;}
.filter-row input:focus,.filter-row select:focus{border-color:rgba(201,168,76,0.5);}
.filter-row select option{background:var(--surface2);}
.dl-ip{font-size:10.5px;color:var(--dim);font-family:'Courier New',monospace;}
.pagination{display:flex;align-items:center;gap:6px;margin-top:20px;justify-content:center;flex-wrap:wrap;}
.pg-btn{background:var(--surface);border:1px solid var(--border);border-radius:7px;padding:6px 12px;font-size:13px;color:var(--muted);cursor:pointer;transition:all .2s;text-decoration:none;display:inline-block;}
.pg-btn:hover{border-color:var(--gold);color:var(--gold);}
.pg-btn.active{background:var(--gold);color:#060d1a;border-color:var(--gold);font-weight:600;}
.pg-btn.disabled{opacity:.35;pointer-events:none;}
</style>
</head>
<body>
<div class="app-shell">
<?php include __DIR__.'/../includes/sidebar.php'; ?>
<div class="main-area" id="mainArea">
<?php include __DIR__.'/../includes/navbar.php'; ?>
<div class="page-content">

<!-- Page Header -->
<div class="page-header">
    <div>
        <button type="button" class="btn-back" onclick="goBack()"><i class="fas fa-arrow-left"></i> Back</button>
    </div>
        <p><?= number_format($total) ?> download<?= $total !== 1 ? 's' : '' ?> recorded</p>
    </div>
</div>

<!-- Filters -->
<div class="filter-wrap">
    <form method="GET">
        <div class="filter-row">
            <input type="text" name="search" placeholder="Search evidence number, title, filename..." value="<?= e($search) ?>">
            <?php if (is_admin()): ?>
            <select name="user" onchange="this.form.submit()">
                <option value="">All Users</option>
                <?php foreach ($all_users as $u): ?>
                <option value="<?= $u['id'] ?>" <?= $filter_user == $u['id'] ? 'selected' : '' ?>>
                    <?= e($u['full_name']) ?> (<?= e($u['username']) ?>)
                </option>
                <?php endforeach; ?>
            </select>
            <?php endif; ?>
            <input type="hidden" name="page" value="1">
            <button type="submit" class="btn btn-gold btn-sm"><i class="fas fa-search"></i> Search</button>
            <?php if ($search || $filter_user): ?>
            <a href="downloads.php" class="btn btn-outline btn-sm"><i class="fas fa-xmark"></i> Clear</a>
            <?php endif; ?>
        </div>
    </form>
</div>

<?php if (empty($downloads)): ?>
<div class="section-card">
    <div class="empty-state">
        <i class="fas fa-download" style="color:var(--muted)"></i>
        <p>No downloads recorded yet.</p>
    </div>
</div>
<?php else: ?>
<div class="section-card">
    <div class="section-body">
    <div class="table-responsive"><table class="dc-table" style="table-layout:fixed;width:100%">
        <thead><tr>
            <th style="width:100px">Evidence</th>
            <th style="width:auto">File</th>
            <?php if (is_admin()): ?>
            <th style="width:110px">Downloaded By</th>
            <?php endif; ?>
            <th style="width:55px">Size</th>
            <th style="width:100px">IP Address</th>
            <th style="width:120px">When</th>
        </tr></thead>
        <tbody>
        <?php foreach ($downloads as $d): ?>
        <tr>
            <td data-label="Evidence">
                <a href="evidence_view.php?id=<?= $d['evidence_id'] ?>" style="font-weight:600;font-size:12px;color:var(--gold);text-decoration:none"><?= e($d['evidence_number']) ?></a>
                <p style="font-size:10.5px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="<?= e($d['title']) ?>"><?= e(substr($d['title'],0,20)) ?></p>
            </td>
            <td data-label="File">
                <span style="font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;" title="<?= e($d['file_name']) ?>"><?= e($d['file_name']) ?></span>
                <?php if (!empty($d['reason'])): ?>
                <span style="font-size:10.5px;color:var(--dim);font-style:italic;">"<?= e(substr($d['reason'],0,60)) ?>"</span>
                <?php endif; ?>
            </td>
            <?php if (is_admin()): ?>
            <td data-label="Downloaded By">
                <span style="font-size:12px;"><?= e($d['downloaded_by']) ?></span>
            </td>
            <?php endif; ?>
            <td data-label="Size"><span style="font-size:11px;color:var(--muted)"><?= format_filesize($d['file_size']) ?></span></td>
            <td data-label="IP"><span class="dl-ip"><?= e($d['ip_address']) ?></span></td>
            <td data-label="When">
                <span style="font-size:11.5px;color:var(--muted)"><?= time_ago($d['downloaded_at']) ?></span>
                <span class="dl-ip" style="display:block;"><?= date('M j, Y H:i', strtotime($d['downloaded_at'])) ?></span>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table></div>
    </div>
</div>
<?php endif; ?>

<!-- Pagination -->
<?php if ($total_pages > 1): ?>
<div class="pagination">
    <a href="?<?= http_build_query(array_merge($_GET, ['page'=>1])) ?>" class="pg-btn <?= $page_num <= 1 ? 'disabled' : '' ?>"><i class="fas fa-angles-left"></i></a>
    <a href="?<?= http_build_query(array_merge($_GET, ['page'=>max(1,$page_num-1)])) ?>" class="pg-btn <?= $page_num <= 1 ? 'disabled' : '' ?>"><i class="fas fa-angle-left"></i></a>
    <?php for ($p = max(1,$page_num-2); $p <= min($total_pages,$page_num+2); $p++): ?>
    <a href="?<?= http_build_query(array_merge($_GET, ['page'=>$p])) ?>" class="pg-btn <?= $p === $page_num ? 'active' : '' ?>"><?= $p ?></a>
    <?php endfor; ?>
    <a href="?<?= http_build_query(array_merge($_GET, ['page'=>min($total_pages,$page_num+1)])) ?>" class="pg-btn <?= $page_num >= $total_pages ? 'disabled' : '' ?>"><i class="fas fa-angle-right"></i></a>
    <a href="?<?= http_build_query(array_merge($_GET, ['page'=>$total_pages])) ?>" class="pg-btn <?= $page_num >= $total_pages ? 'disabled' : '' ?>"><i class="fas fa-angles-right"></i></a>
</div>
<?php endif; ?>

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
function handleSearch(e){if(e.key==='Enter'){window.location='evidence.php?search='+encodeURIComponent(document.getElementById('globalSearch').value);}}
</script>
</body>
</html>
