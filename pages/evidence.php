<?php
/**
 * DigiCustody – Evidence List Page
 * Save to: /var/www/html/digicustody/pages/evidence.php
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login();

$page_title = 'Evidence';
$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];

// ── Filters ──────────────────────────────────────────────
$search        = trim($_GET['search'] ?? '');
$filter_status = $_GET['status'] ?? '';
$filter_type   = $_GET['type']   ?? '';
$filter_case   = $_GET['case']   ?? '';
$my_only       = isset($_GET['my']) && $_GET['my'] === '1';
$sort          = in_array($_GET['sort'] ?? '', ['uploaded_at','title','evidence_number','file_size'])
                 ? $_GET['sort'] : 'uploaded_at';
$dir           = strtoupper($_GET['dir'] ?? 'DESC') === 'ASC' ? 'ASC' : 'DESC';
$page_num      = max(1, (int)($_GET['page'] ?? 1));
$per_page      = 15;
$offset        = ($page_num - 1) * $per_page;
$view_mode     = ($_GET['view'] ?? 'table') === 'grid' ? 'grid' : 'table';

// ── Type icons map (defined ONCE, used everywhere) ───────
$type_icons = [
    'image'           => ['fa-file-image',    'blue'],
    'video'           => ['fa-file-video',     'purple'],
    'document'        => ['fa-file-lines',     'green'],
    'log_file'        => ['fa-file-code',      'orange'],
    'email'           => ['fa-envelope',       'info'],
    'database'        => ['fa-database',       'gold'],
    'network_capture' => ['fa-network-wired',  'muted'],
    'mobile_data'     => ['fa-mobile',         'warning'],
    'other'           => ['fa-file',           'gray'],
];

// ── Build WHERE clause ────────────────────────────────────
$where  = ['1=1'];
$params = [];

// Analysts are scoped to cases they have access to via case_access
// Investigators are scoped to evidence they uploaded, are custodian of, or have case_access
// Admins see all evidence
if ($role === 'analyst') {
    $where[] = "e.case_id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id=?)";
    $params[] = $uid;
} elseif ($role === 'investigator') {
    $where[] = "(e.uploaded_by=? OR e.current_custodian=? OR e.case_id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id=?))";
    $params[] = $uid;
    $params[] = $uid;
    $params[] = $uid;
}

if ($search !== '') {
    $where[]  = "(e.evidence_number LIKE ? OR e.title LIKE ? OR e.description LIKE ? OR c.case_number LIKE ? OR c.case_title LIKE ?)";
    $s = "%$search%";
    $params = array_merge($params, [$s, $s, $s, $s, $s]);
}
if ($filter_status !== '') { $where[] = "e.status = ?";      $params[] = $filter_status; }
if ($filter_type   !== '') { $where[] = "e.evidence_type = ?"; $params[] = $filter_type; }
if ($filter_case   !== '') { $where[] = "e.case_id = ?";     $params[] = (int)$filter_case; }
if ($my_only)              { $where[] = "e.uploaded_by = ?"; $params[] = $uid; }

$where_sql = implode(' AND ', $where);

// ── Count total records ───────────────────────────────────
$count_stmt = $pdo->prepare("
    SELECT COUNT(*)
    FROM evidence e
    JOIN cases c ON c.id = e.case_id
    WHERE $where_sql
");
$count_stmt->execute($params);
$total       = (int)$count_stmt->fetchColumn();
$total_pages = max(1, (int)ceil($total / $per_page));

// ── Fetch evidence records ────────────────────────────────
$data_stmt = $pdo->prepare("
    SELECT e.*,
           u_up.full_name  AS uploader_name,
           u_cur.full_name AS custodian_name,
           c.case_number,
           c.case_title,
           (SELECT hv.integrity_status
            FROM hash_verifications hv
            WHERE hv.evidence_id = e.id
            ORDER BY hv.verified_at DESC LIMIT 1) AS last_integrity,
           (SELECT hv.verified_at
            FROM hash_verifications hv
            WHERE hv.evidence_id = e.id
            ORDER BY hv.verified_at DESC LIMIT 1) AS last_verified_at,
           (SELECT COUNT(*)
            FROM evidence_transfers et
            WHERE et.evidence_id = e.id) AS transfer_count
    FROM evidence e
    JOIN users u_up  ON u_up.id  = e.uploaded_by
    JOIN users u_cur ON u_cur.id = e.current_custodian
    JOIN cases c     ON c.id     = e.case_id
    WHERE $where_sql
    ORDER BY e.$sort $dir
    LIMIT ? OFFSET ?
");
$data_stmt->execute(array_merge($params, [$per_page, $offset]));
$evidence_list = $data_stmt->fetchAll(PDO::FETCH_ASSOC);

// ── Cases dropdown (scoped) ───────────────────────────────
$case_filter = is_admin() ? '' : " WHERE c.id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id=$uid) OR c.created_by=$uid OR c.assigned_to=$uid";
$all_cases = $pdo->query("SELECT id, case_number, case_title FROM cases c$case_filter ORDER BY created_at DESC")->fetchAll(PDO::FETCH_ASSOC);

// ── Quick stats (scoped for non-admin) ───────────────────────────────────────────
if (is_admin()) {
    $stat_total     = (int)$pdo->query("SELECT COUNT(*) FROM evidence")->fetchColumn();
    $stat_collected = (int)$pdo->query("SELECT COUNT(*) FROM evidence WHERE status='collected'")->fetchColumn();
    $stat_analysis  = (int)$pdo->query("SELECT COUNT(*) FROM evidence WHERE status='in_analysis'")->fetchColumn();
} else {
    $af = "WHERE case_id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id=$uid) OR uploaded_by=$uid OR current_custodian=$uid";
    $stat_total     = (int)$pdo->query("SELECT COUNT(*) FROM evidence $af")->fetchColumn();
    $stat_collected = (int)$pdo->query("SELECT COUNT(*) FROM evidence $af AND status='collected'")->fetchColumn();
    $stat_analysis  = (int)$pdo->query("SELECT COUNT(*) FROM evidence $af AND status='in_analysis'")->fetchColumn();
}
$stat_tampered  = is_admin()
    ? (int)$pdo->query("SELECT COUNT(*) FROM hash_verifications WHERE integrity_status='tampered'")->fetchColumn()
    : (int)$pdo->query("SELECT COUNT(*) FROM hash_verifications hv JOIN evidence e ON e.id=hv.evidence_id WHERE hv.integrity_status='tampered' AND (e.case_id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id=$uid) OR e.uploaded_by=$uid OR e.current_custodian=$uid)")->fetchColumn();
$stmt_my = $pdo->prepare("SELECT COUNT(*) FROM evidence WHERE uploaded_by=?");
$stmt_my->execute([$uid]);
$stat_my = (int)$stmt_my->fetchColumn();

// ── Helper: sort URL ──────────────────────────────────────
function sort_url(string $col): string {
    global $sort, $dir;
    $new_dir = ($sort === $col && $dir === 'DESC') ? 'asc' : 'desc';
    $params  = array_merge($_GET, ['sort' => $col, 'dir' => $new_dir, 'page' => 1]);
    return '?' . http_build_query($params);
}

function sort_icon(string $col): string {
    global $sort, $dir;
    if ($sort !== $col) return '<i class="fas fa-sort" style="opacity:.3"></i>';
    return $dir === 'DESC'
        ? '<i class="fas fa-sort-down"  style="color:var(--gold)"></i>'
        : '<i class="fas fa-sort-up"    style="color:var(--gold)"></i>';
}

function page_url(int $p): string {
    $params = array_merge($_GET, ['page' => $p]);
    return '?' . http_build_query($params);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Evidence — DigiCustody</title>
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
.filter-tags{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;}
.filter-tag{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;background:var(--gold-dim);border:1px solid rgba(201,168,76,0.25);border-radius:20px;font-size:12px;color:var(--gold);}
.filter-tag a{color:var(--gold);margin-left:2px;font-size:11px;}
.filter-tag a:hover{color:var(--danger);}
.sort-th{cursor:pointer;white-space:nowrap;user-select:none;color:var(--muted);}
.sort-th:hover{color:var(--text);}
.evidence-num{font-weight:700;font-size:12.5px;color:var(--gold);font-family:'Space Grotesk',sans-serif;}
.hash-chip{font-family:'Courier New',monospace;font-size:10.5px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;}
.row-actions{display:flex;gap:5px;align-items:center;}
.pagination{display:flex;align-items:center;gap:6px;margin-top:20px;justify-content:center;flex-wrap:wrap;}
.pg-btn{background:var(--surface);border:1px solid var(--border);border-radius:7px;padding:6px 12px;font-size:13px;color:var(--muted);cursor:pointer;transition:all .2s;text-decoration:none;display:inline-block;}
.pg-btn:hover{border-color:var(--gold);color:var(--gold);}
.pg-btn.active{background:var(--gold);color:#060d1a;border-color:var(--gold);font-weight:600;}
.pg-btn.disabled{opacity:.35;pointer-events:none;}
.stats-mini{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px;}
.sm-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:10px 16px;display:flex;align-items:center;gap:10px;cursor:pointer;transition:all .2s;text-decoration:none;}
.sm-card:hover{border-color:var(--border2);}
.sm-card.active-filter{border-color:var(--gold);background:var(--gold-dim);}
.sm-val{font-family:'Space Grotesk',sans-serif;font-size:18px;font-weight:700;color:var(--text);}
.sm-lbl{font-size:11px;color:var(--muted);}
.view-toggle{display:flex;gap:4px;}
.vt-btn{background:none;border:1px solid var(--border);border-radius:7px;padding:6px 10px;color:var(--muted);cursor:pointer;font-size:13px;transition:all .2s;}
.vt-btn.active,.vt-btn:hover{border-color:var(--gold);color:var(--gold);background:var(--gold-dim);}
/* table column widths */
.dc-table th:nth-child(1){width:110px}
.dc-table th:nth-child(2){width:auto}
.dc-table th:nth-child(3){width:110px}
.dc-table th:nth-child(4){width:130px}
.dc-table th:nth-child(5){width:150px}
.dc-table th:nth-child(6){width:75px}
.dc-table th:nth-child(7){width:100px}
.dc-table th:nth-child(8){width:100px}
.dc-table th:nth-child(9){width:90px}
.dc-table th:nth-child(10){width:220px}
/* card view */
.ev-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:16px;}
.ev-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:16px;transition:all .2s;cursor:pointer;}
.ev-card:hover{border-color:var(--border2);transform:translateY(-1px);}
.ev-card.tampered{border-color:rgba(248,113,113,0.35);}
.ev-card-top{display:flex;align-items:flex-start;gap:10px;margin-bottom:12px;}
.ev-card-icon{width:38px;height:38px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:15px;flex-shrink:0;}
.ev-card-num{font-size:12px;font-weight:700;color:var(--gold);font-family:'Space Grotesk',sans-serif;}
.ev-card-title{font-size:13px;font-weight:500;color:var(--text);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.ev-card-meta{font-size:11.5px;color:var(--muted);margin-top:10px;display:flex;flex-direction:column;gap:4px;}
.ev-card-hashes{background:var(--surface2);border-radius:7px;padding:8px 10px;margin-top:10px;}
.ev-card-hashes p{font-family:'Courier New',monospace;font-size:10.5px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-bottom:2px;}
.ev-card-footer{display:flex;align-items:center;justify-content:space-between;margin-top:12px;padding-top:10px;border-top:1px solid var(--border);}
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
        <p>
            <?= number_format($total) ?> record<?= $total !== 1 ? 's' : '' ?> found
            <?= $search !== '' ? ' for &ldquo;' . e($search) . '&rdquo;' : '' ?>
        </p>
    </div>
    <div style="display:flex;gap:10px;align-items:center;">
        <div class="view-toggle">
            <button class="vt-btn <?= $view_mode === 'table' ? 'active' : '' ?>" onclick="setView('table')" title="Table view">
                <i class="fas fa-list"></i>
            </button>
            <button class="vt-btn <?= $view_mode === 'grid' ? 'active' : '' ?>" onclick="setView('grid')" title="Card view">
                <i class="fas fa-grip"></i>
            </button>
        </div>
        <?php if (can_upload()): ?>
        <a href="evidence_upload.php" class="btn btn-gold">
            <i class="fas fa-upload"></i> Upload Evidence
        </a>
        <?php endif; ?>
    </div>
</div>

<!-- Quick Stats Bar -->
<div class="stats-mini">
    <a href="evidence.php" class="sm-card <?= !$filter_status && !$my_only ? 'active-filter' : '' ?>">
        <i class="fas fa-database" style="color:var(--gold);font-size:14px"></i>
        <div><p class="sm-val"><?= number_format($stat_total) ?></p><p class="sm-lbl">Total</p></div>
    </a>
    <a href="evidence.php?status=collected" class="sm-card <?= $filter_status === 'collected' ? 'active-filter' : '' ?>">
        <i class="fas fa-circle-dot" style="color:var(--info);font-size:14px"></i>
        <div><p class="sm-val"><?= $stat_collected ?></p><p class="sm-lbl">Collected</p></div>
    </a>
    <a href="evidence.php?status=in_analysis" class="sm-card <?= $filter_status === 'in_analysis' ? 'active-filter' : '' ?>">
        <i class="fas fa-microscope" style="color:var(--warning);font-size:14px"></i>
        <div><p class="sm-val"><?= $stat_analysis ?></p><p class="sm-lbl">In Analysis</p></div>
    </a>
    <?php if ($stat_tampered > 0): ?>
    <a href="evidence.php?status=flagged" class="sm-card" style="border-color:rgba(248,113,113,0.3)">
        <i class="fas fa-triangle-exclamation" style="color:var(--danger);font-size:14px"></i>
        <div><p class="sm-val" style="color:var(--danger)"><?= $stat_tampered ?></p><p class="sm-lbl">Tampered</p></div>
    </a>
    <?php endif; ?>
    <a href="evidence.php?my=1" class="sm-card <?= $my_only ? 'active-filter' : '' ?>">
        <i class="fas fa-user" style="color:var(--success);font-size:14px"></i>
        <div><p class="sm-val"><?= $stat_my ?></p><p class="sm-lbl">Mine</p></div>
    </a>
</div>

<!-- Filters -->
<div class="filter-wrap">
    <form method="GET" id="filterForm">
        <div class="filter-row">
            <input type="text" name="search" id="searchInput"
                placeholder="Search evidence number, title, case..."
                value="<?= e($search) ?>">
            <select name="status" onchange="this.form.submit()">
                <option value="">All Statuses</option>
                <?php foreach (['collected','in_analysis','transferred','archived','flagged'] as $s): ?>
                <option value="<?= $s ?>" <?= $filter_status === $s ? 'selected' : '' ?>>
                    <?= ucwords(str_replace('_', ' ', $s)) ?>
                </option>
                <?php endforeach; ?>
            </select>
            <select name="type" onchange="this.form.submit()">
                <option value="">All Types</option>
                <?php foreach (array_keys($type_icons) as $t): ?>
                <option value="<?= $t ?>" <?= $filter_type === $t ? 'selected' : '' ?>>
                    <?= ucwords(str_replace('_', ' ', $t)) ?>
                </option>
                <?php endforeach; ?>
            </select>
            <select name="case" onchange="this.form.submit()">
                <option value="">All Cases</option>
                <?php foreach ($all_cases as $c): ?>
                <option value="<?= $c['id'] ?>" <?= (string)$filter_case === (string)$c['id'] ? 'selected' : '' ?>>
                    <?= e($c['case_number']) ?> — <?= e(substr($c['case_title'], 0, 28)) ?>
                </option>
                <?php endforeach; ?>
            </select>
            <input type="hidden" name="my"   value="<?= $my_only ? '1' : '' ?>">
            <input type="hidden" name="sort" value="<?= e($sort) ?>">
            <input type="hidden" name="dir"  value="<?= strtolower($dir) ?>">
            <input type="hidden" name="view" value="<?= e($view_mode) ?>">
            <button type="submit" class="btn btn-gold btn-sm"><i class="fas fa-search"></i> Search</button>
            <?php if ($search || $filter_status || $filter_type || $filter_case || $my_only): ?>
            <a href="evidence.php" class="btn btn-outline btn-sm"><i class="fas fa-xmark"></i> Clear</a>
            <?php endif; ?>
        </div>
    </form>

    <!-- Active filter tags -->
    <?php if ($search || $filter_status || $filter_type || $filter_case || $my_only): ?>
    <div class="filter-tags">
        <?php if ($search): ?>
        <span class="filter-tag"><i class="fas fa-search"></i> "<?= e($search) ?>"
            <a href="evidence.php?<?= http_build_query(array_diff_key($_GET, ['search'=>'','page'=>''])) ?>">×</a>
        </span>
        <?php endif; ?>
        <?php if ($filter_status): ?>
        <span class="filter-tag"><i class="fas fa-circle-dot"></i> <?= ucwords(str_replace('_',' ',$filter_status)) ?>
            <a href="evidence.php?<?= http_build_query(array_diff_key($_GET, ['status'=>'','page'=>''])) ?>">×</a>
        </span>
        <?php endif; ?>
        <?php if ($filter_type): ?>
        <span class="filter-tag"><i class="fas fa-file"></i> <?= ucwords(str_replace('_',' ',$filter_type)) ?>
            <a href="evidence.php?<?= http_build_query(array_diff_key($_GET, ['type'=>'','page'=>''])) ?>">×</a>
        </span>
        <?php endif; ?>
        <?php if ($filter_case): ?>
        <span class="filter-tag"><i class="fas fa-folder"></i> Case filter
            <a href="evidence.php?<?= http_build_query(array_diff_key($_GET, ['case'=>'','page'=>''])) ?>">×</a>
        </span>
        <?php endif; ?>
        <?php if ($my_only): ?>
        <span class="filter-tag"><i class="fas fa-user"></i> My evidence
            <a href="evidence.php?<?= http_build_query(array_diff_key($_GET, ['my'=>'','page'=>''])) ?>">×</a>
        </span>
        <?php endif; ?>
    </div>
    <?php endif; ?>
</div>

<?php if (empty($evidence_list)): ?>
<!-- Empty State -->
<div class="section-card">
    <div class="empty-state">
        <i class="fas fa-database"></i>
        <p>No evidence found<?= $search ? ' matching &ldquo;' . e($search) . '&rdquo;' : '' ?>.</p>
        <?php if (can_upload()): ?>
        <a href="evidence_upload.php" class="btn btn-gold" style="margin-top:14px">
            <i class="fas fa-upload"></i> Upload Evidence
        </a>
        <?php endif; ?>
    </div>
</div>

<?php elseif ($view_mode === 'grid'): ?>
<!-- ══ CARD VIEW ══ -->
<div class="ev-grid">
<?php foreach ($evidence_list as $ev):
    $tampered = ($ev['last_integrity'] === 'tampered');
    [$ico, $col] = $type_icons[$ev['evidence_type']] ?? ['fa-file', 'gray'];
?>
<div class="ev-card <?= $tampered ? 'tampered' : '' ?>"
     onclick="window.location='evidence_view.php?id=<?= (int)$ev['id'] ?>'">
    <div class="ev-card-top">
        <div class="ev-card-icon stat-icon <?= $col ?>"><i class="fas <?= $ico ?>"></i></div>
        <div style="flex:1;min-width:0;">
            <p class="ev-card-num"><?= e($ev['evidence_number']) ?></p>
            <p class="ev-card-title" title="<?= e($ev['title']) ?>"><?= e($ev['title']) ?></p>
        </div>
        <?php if ($tampered): ?>
            <span class="badge badge-red"><i class="fas fa-triangle-exclamation"></i></span>
        <?php elseif ($ev['last_integrity'] === 'intact'): ?>
            <span class="badge badge-green"><i class="fas fa-check"></i></span>
        <?php endif; ?>
    </div>
    <div class="ev-card-meta">
        <span><i class="fas fa-folder-open" style="width:14px;color:var(--gold)"></i>
            <?= e($ev['case_number']) ?> — <?= e(substr($ev['case_title'], 0, 26)) ?>
        </span>
        <span><i class="fas fa-user" style="width:14px;color:var(--muted)"></i>
            Custodian: <?= e($ev['custodian_name']) ?>
        </span>
        <span><i class="fas fa-hard-drive" style="width:14px;color:var(--muted)"></i>
            <?= format_filesize($ev['file_size']) ?>
            &nbsp;·&nbsp; <?= (int)$ev['transfer_count'] ?> transfer<?= $ev['transfer_count'] != 1 ? 's' : '' ?>
        </span>
    </div>
    <div class="ev-card-footer">
        <?= status_badge($ev['status']) ?>
        <span style="font-size:11.5px;color:var(--dim)"><?= date('M j, Y', strtotime($ev['uploaded_at'])) ?></span>
    </div>
</div>
<?php endforeach; ?>
</div>

<?php else: ?>
<!-- ══ TABLE VIEW ══ -->
<div class="section-card">
    <div class="section-body">
    <div class="table-responsive"><table class="dc-table" style="table-layout:fixed;width:100%">
        <thead>
        <tr>
            <th style="width:115px"><a href="<?= sort_url('evidence_number') ?>" class="sort-th" style="display:flex;align-items:center;gap:5px;text-decoration:none;color:inherit;">No. <?= sort_icon('evidence_number') ?></a></th>
            <th style="width:200px"><a href="<?= sort_url('title') ?>" class="sort-th" style="display:flex;align-items:center;gap:5px;text-decoration:none;color:inherit;">Title &amp; Case <?= sort_icon('title') ?></a></th>
            <th style="width:80px">Custodian</th>
            <th style="width:60px"><a href="<?= sort_url('file_size') ?>" class="sort-th" style="display:flex;align-items:center;gap:5px;text-decoration:none;color:inherit;">Size <?= sort_icon('file_size') ?></a></th>
            <th style="width:80px">Status</th>
            <th style="width:80px">Integrity</th>
            <th style="width:75px"><a href="<?= sort_url('uploaded_at') ?>" class="sort-th" style="display:flex;align-items:center;gap:5px;text-decoration:none;color:inherit;">Date <?= sort_icon('uploaded_at') ?></a></th>
            <th style="width:120px">Actions</th>
        </tr>
        </thead>
        <tbody>
        <?php foreach ($evidence_list as $ev):
            $tampered = ($ev['last_integrity'] === 'tampered');
            [$ico, $col] = $type_icons[$ev['evidence_type']] ?? ['fa-file', 'gray'];
        ?>
        <tr onclick="window.location='evidence_view.php?id=<?= (int)$ev['id'] ?>'" style="cursor:pointer;<?= $tampered ? 'background:rgba(248,113,113,0.04);border-left:3px solid var(--danger)' : '' ?>">
            <!-- Evidence number -->
            <td data-label="Evidence">
                <span class="evidence-num"><?= e($ev['evidence_number']) ?></span>
            </td>
            <!-- Title + type + case (merged, no overflow) -->
            <td data-label="Title & Case">
                <div style="display:flex;align-items:flex-start;gap:0;flex-direction:column;">
                    <p style="font-weight:500;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%;"
                       title="<?= e($ev['title']) ?>"><?= e($ev['title']) ?></p>
                    <div style="display:flex;align-items:center;gap:5px;margin-top:3px;flex-wrap:nowrap;">
                        <span class="badge badge-<?= $col ?>" style="font-size:10px;padding:1px 6px;white-space:nowrap;flex-shrink:0;">
                            <i class="fas <?= $ico ?>" style="font-size:9px"></i>
                            <?= ucfirst(str_replace('_',' ',e($ev['evidence_type']))) ?>
                        </span>
                        <a href="case_view.php?id=<?= $ev['case_id'] ?>" style="font-size:11px;color:var(--info);text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
                           title="<?= e($ev['case_title']) ?>">
                            <?= e($ev['case_number']) ?>
                        </a>
                    </div>
                    <p style="font-size:10.5px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:1px;max-width:100%;">
                        <?= e(substr($ev['case_title'],0,28)) ?>
                    </p>
                </div>
            </td>
            <!-- Custodian -->
            <td data-label="Custodian">
                <span style="font-size:12.5px;font-weight:500;white-space:nowrap;"><?= e($ev['custodian_name']) ?></span>
                <?php if ((int)$ev['current_custodian'] === $uid): ?>
                <span class="badge badge-gold" style="display:block;width:fit-content;margin-top:2px;font-size:10px">Me</span>
                <?php endif; ?>
            </td>
            <!-- Size -->
            <td data-label="Size"><span style="font-size:12px;color:var(--muted);white-space:nowrap"><?= format_filesize($ev['file_size']) ?></span></td>
            <!-- Status -->
            <td data-label="Status"><?= status_badge($ev['status']) ?></td>
            <td data-label="Integrity">
                <?php if ($tampered): ?>
                    <span class="badge badge-red"><i class="fas fa-triangle-exclamation"></i> Tampered</span>
                <?php elseif ($ev['last_integrity'] === 'intact'): ?>
                    <span class="badge badge-green"><i class="fas fa-check"></i> Intact</span>
                <?php else: ?>
                    <span class="badge badge-gray"><i class="fas fa-question"></i> Unchecked</span>
                <?php endif; ?>
            </td>
            <td data-label="Date">
                <span style="font-size:11.5px;color:var(--muted);white-space:nowrap">
                    <?= date('M j, Y', strtotime($ev['uploaded_at'])) ?>
                </span>
            </td>
            <td data-label="Actions">
                <div style="display:flex;flex-direction:column;gap:4px;">
                    <a href="evidence_download.php?id=<?= (int)$ev['id'] ?>" class="btn btn-download btn-sm" style="width:100%;justify-content:center;" title="Download" onclick="event.stopPropagation()"><i class="fas fa-download"></i> Download</a>
                    <div style="display:flex;gap:4px;">
                        <a href="evidence_verify.php?id=<?= (int)$ev['id'] ?>" class="btn btn-outline btn-sm" style="flex:1;justify-content:center;" title="Verify Integrity" onclick="event.stopPropagation()"><i class="fas fa-fingerprint"></i> Verify</a>
                        <a href="coc_report.php?id=<?= (int)$ev['id'] ?>" class="btn btn-coc btn-sm" style="flex:1;justify-content:center;" title="COC Report" onclick="event.stopPropagation()"><i class="fas fa-file-shield"></i> COC</a>
                    </div>
                </div>
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
    <a href="<?= page_url(1) ?>"
       class="pg-btn <?= $page_num <= 1 ? 'disabled' : '' ?>">
        <i class="fas fa-angles-left"></i>
    </a>
    <a href="<?= page_url(max(1, $page_num - 1)) ?>"
       class="pg-btn <?= $page_num <= 1 ? 'disabled' : '' ?>">
        <i class="fas fa-angle-left"></i>
    </a>
    <?php
    $pg_start = max(1, $page_num - 2);
    $pg_end   = min($total_pages, $page_num + 2);
    for ($p = $pg_start; $p <= $pg_end; $p++):
    ?>
    <a href="<?= page_url($p) ?>" class="pg-btn <?= $p === $page_num ? 'active' : '' ?>"><?= $p ?></a>
    <?php endfor; ?>
    <a href="<?= page_url(min($total_pages, $page_num + 1)) ?>"
       class="pg-btn <?= $page_num >= $total_pages ? 'disabled' : '' ?>">
        <i class="fas fa-angle-right"></i>
    </a>
    <a href="<?= page_url($total_pages) ?>"
       class="pg-btn <?= $page_num >= $total_pages ? 'disabled' : '' ?>">
        <i class="fas fa-angles-right"></i>
    </a>
    <span style="font-size:12px;color:var(--muted);margin-left:8px">
        Page <?= $page_num ?> of <?= $total_pages ?> &nbsp;·&nbsp; <?= number_format($total) ?> records
    </span>
</div>
<?php endif; ?>

</div><!-- /page-content -->
</div><!-- /main-area -->
</div><!-- /app-shell -->

<script>
// Sidebar
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
// Dropdowns
function toggleNotif(){document.getElementById('notifDropdown').classList.toggle('open');document.getElementById('userDropdown').classList.remove('open');}
function toggleUserMenu(){document.getElementById('userDropdown').classList.toggle('open');document.getElementById('notifDropdown').classList.remove('open');}
document.addEventListener('click',function(e){
    if(!e.target.closest('#notifWrap'))document.getElementById('notifDropdown').classList.remove('open');
    if(!e.target.closest('#userMenuWrap'))document.getElementById('userDropdown').classList.remove('open');
});
// Top search bar
function handleSearch(e){if(e.key==='Enter'){window.location='evidence.php?search='+encodeURIComponent(document.getElementById('globalSearch').value);}}
// View toggle
function setView(v){
    var p=new URLSearchParams(window.location.search);
    p.set('view',v);p.set('page',1);
    window.location='evidence.php?'+p.toString();
}
// Live search debounce
var st;
document.getElementById('searchInput').addEventListener('input',function(){
    clearTimeout(st);
    st=setTimeout(function(){document.getElementById('filterForm').submit();},700);
});
</script>
<script src="../assets/js/main.js"></script>
</body>
</html>
