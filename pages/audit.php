<?php
/**
 * DigiCustody – Audit Log Page
 * Save to: /var/www/html/digicustody/pages/audit.php
 */
session_start();
require_once __DIR__.'/../config/db.php';
require_once __DIR__.'/../config/functions.php';
require_login();

// Only admin can see full audit log
// Other roles see only their own logs
$page_title = 'Audit Logs';
$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];

// ── Filters ──────────────────────────────────────────────
$search       = trim($_GET['search'] ?? '');
$filter_action= $_GET['action_type'] ?? '';
$filter_user  = $_GET['user_id'] ?? '';
$filter_date_from = $_GET['date_from'] ?? '';
$filter_date_to   = $_GET['date_to']   ?? '';
$page_num     = max(1, (int)($_GET['page'] ?? 1));
$per_page     = 20;
$offset       = ($page_num - 1) * $per_page;

// ── Build WHERE ───────────────────────────────────────────
$where  = ['1=1'];
$params = [];

// Non-admins only see their own logs
if ($role !== 'admin') {
    $where[]  = "al.user_id = ?";
    $params[] = $uid;
}

if ($search !== '') {
    $where[]  = "(al.description LIKE ? OR al.username LIKE ? OR al.target_label LIKE ?)";
    $s = "%$search%";
    $params = array_merge($params, [$s, $s, $s]);
}
if ($filter_action !== '') {
    $where[]  = "al.action_type = ?";
    $params[] = $filter_action;
}
if ($filter_user !== '' && $role === 'admin') {
    $where[]  = "al.user_id = ?";
    $params[] = (int)$filter_user;
}
if ($filter_date_from !== '') {
    $where[]  = "al.created_at >= ?";
    $params[] = $filter_date_from . ' 00:00:00';
}
if ($filter_date_to !== '') {
    $where[]  = "al.created_at <= ?";
    $params[] = $filter_date_to . ' 23:59:59';
}

$where_sql = implode(' AND ', $where);

// ── Count ─────────────────────────────────────────────────
$count_stmt = $pdo->prepare("SELECT COUNT(*) FROM audit_logs al WHERE $where_sql");
$count_stmt->execute($params);
$total       = (int)$count_stmt->fetchColumn();
$total_pages = max(1, (int)ceil($total / $per_page));

// ── Fetch logs ────────────────────────────────────────────
$logs_stmt = $pdo->prepare("
    SELECT al.*,
           u.full_name, u.role AS user_role_db
    FROM audit_logs al
    LEFT JOIN users u ON u.id = al.user_id
    WHERE $where_sql
    ORDER BY al.created_at DESC
    LIMIT ? OFFSET ?
");
$logs_stmt->execute(array_merge($params, [$per_page, $offset]));
$logs = $logs_stmt->fetchAll(PDO::FETCH_ASSOC);

// ── Stats ─────────────────────────────────────────────────
$total_logs   = (int)$pdo->query("SELECT COUNT(*) FROM audit_logs")->fetchColumn();
$today_logs   = (int)$pdo->query("SELECT COUNT(*) FROM audit_logs WHERE DATE(created_at)=CURDATE()")->fetchColumn();
$login_logs   = (int)$pdo->query("SELECT COUNT(*) FROM audit_logs WHERE action_type='login'")->fetchColumn();
$upload_logs  = (int)$pdo->query("SELECT COUNT(*) FROM audit_logs WHERE action_type='evidence_uploaded'")->fetchColumn();
$failed_logins= (int)$pdo->query("SELECT COUNT(*) FROM audit_logs WHERE action_type='login_failed' AND created_at >= DATE_SUB(NOW(),INTERVAL 24 HOUR)")->fetchColumn();
$tamper_alerts= (int)$pdo->query("SELECT COUNT(*) FROM audit_logs WHERE action_type='hash_verified' AND extra_data LIKE '%tampered%'")->fetchColumn();

// Users list for filter (admin only)
$users_list = [];
if ($role === 'admin') {
    $users_list = $pdo->query("SELECT id, full_name, username, role FROM users ORDER BY full_name")->fetchAll(PDO::FETCH_ASSOC);
}

// All action types for filter
$action_types = [
    'login'                      => ['Login',                   'fa-right-to-bracket', 'blue'],
    'logout'                     => ['Logout',                  'fa-right-from-bracket','muted'],
    'login_failed'               => ['Login Failed',            'fa-ban',              'red'],
    'evidence_uploaded'          => ['Evidence Uploaded',       'fa-upload',           'green'],
    'evidence_viewed'            => ['Evidence Viewed',         'fa-eye',              'blue'],
    'evidence_downloaded'        => ['Evidence Downloaded',     'fa-download',         'warning'],
    'evidence_transferred'       => ['Evidence Transferred',    'fa-right-left',       'purple'],
    'evidence_transfer_accepted' => ['Transfer Accepted',       'fa-circle-check',     'green'],
    'evidence_transfer_rejected' => ['Transfer Rejected',       'fa-circle-xmark',     'red'],
    'evidence_flagged'           => ['Evidence Flagged',        'fa-flag',             'red'],
    'hash_verified'              => ['Hash Verified',           'fa-fingerprint',      'gold'],
    'integrity_check'            => ['Integrity Check',         'fa-shield-check',     'gold'],
    'report_submitted'           => ['Report Submitted',        'fa-file-lines',       'blue'],
    'report_approved'            => ['Report Approved',         'fa-file-circle-check','green'],
    'account_created'            => ['Account Created',         'fa-user-plus',        'green'],
    'account_request_submitted'  => ['Access Request',          'fa-user-clock',       'warning'],
    'account_request_approved'   => ['Request Approved',        'fa-user-check',       'green'],
    'account_request_rejected'   => ['Request Rejected',        'fa-user-xmark',       'red'],
    'case_created'               => ['Case Created',            'fa-folder-plus',      'blue'],
    'download_token_generated'   => ['Download Token',          'fa-key',              'warning'],
];

function get_action_meta(string $type, array $map): array {
    return $map[$type] ?? [ucwords(str_replace('_',' ',$type)), 'fa-circle-dot', 'gray'];
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
<title>Audit Logs — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
/* filter bar */
.filter-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:16px 20px;margin-bottom:20px;}
.filter-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.filter-row input,.filter-row select{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:8px 12px;font-size:13px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.filter-row input:focus,.filter-row select:focus{border-color:rgba(201,168,76,0.5);}
.filter-row select option{background:var(--surface2);}
.filter-row input[type=text]{flex:1;min-width:180px;}
.filter-row input[type=date]{width:150px;}

/* log item */
.log-row{display:flex;align-items:flex-start;gap:14px;padding:13px 20px;border-bottom:1px solid var(--border);transition:background .15s;}
.log-row:last-child{border-bottom:none;}
.log-row:hover{background:var(--surface2);}
.log-row.critical{border-left:3px solid var(--danger);background:rgba(248,113,113,0.03);}
.log-row.warning-row{border-left:3px solid var(--warning);background:rgba(251,191,36,0.02);}

/* action dot */
.action-dot{width:36px;height:36px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:13px;}
.dot-blue   {background:rgba(96,165,250,0.12); color:var(--info);}
.dot-green  {background:rgba(74,222,128,0.12); color:var(--success);}
.dot-red    {background:rgba(248,113,113,0.12);color:var(--danger);}
.dot-gold   {background:rgba(201,168,76,0.12); color:var(--gold);}
.dot-warning{background:rgba(251,191,36,0.12); color:var(--warning);}
.dot-purple {background:rgba(167,139,250,0.12);color:#a78bfa;}
.dot-muted  {background:rgba(107,130,160,0.1); color:var(--muted);}
.dot-gray   {background:rgba(107,130,160,0.1); color:var(--muted);}

.log-main{flex:1;min-width:0;}
.log-desc{font-size:13.5px;color:var(--text);margin-bottom:4px;line-height:1.45;}
.log-meta{display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
.log-meta span{font-size:11.5px;color:var(--dim);display:flex;align-items:center;gap:4px;}
.log-meta i{font-size:10px;}

/* action badge */
.action-badge{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:20px;font-size:11px;font-weight:500;white-space:nowrap;flex-shrink:0;}

/* stats mini */
.stats-mini{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:20px;}
.sm-stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:16px;display:flex;align-items:center;gap:14px;}
.sm-stat-icon{width:40px;height:40px;border-radius:var(--radius);display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0;}
.sm-stat-val{font-family:'Space Grotesk',sans-serif;font-size:22px;font-weight:700;color:var(--text);line-height:1;}
.sm-stat-lbl{font-size:11.5px;color:var(--muted);margin-top:3px;}

/* export bar */
.export-bar{display:flex;align-items:center;justify-content:space-between;padding:10px 20px;background:rgba(201,168,76,0.04);border-bottom:1px solid var(--border);}
.export-bar p{font-size:12.5px;color:var(--muted);}
.export-bar p strong{color:var(--text);}

/* chart */
.chart-wrap{padding:16px 20px;height:180px;position:relative;}

/* pagination */
.pagination{display:flex;align-items:center;gap:6px;margin-top:20px;justify-content:center;flex-wrap:wrap;}
.pg-btn{background:var(--surface);border:1px solid var(--border);border-radius:7px;padding:6px 12px;font-size:13px;color:var(--muted);text-decoration:none;display:inline-block;transition:all .2s;}
.pg-btn:hover{border-color:var(--gold);color:var(--gold);}
.pg-btn.active{background:var(--gold);color:#060d1a;border-color:var(--gold);font-weight:600;}
.pg-btn.disabled{opacity:.35;pointer-events:none;}

/* extra data popover */
.extra-toggle{background:none;border:none;color:var(--dim);cursor:pointer;font-size:11px;padding:2px 6px;border-radius:4px;transition:all .2s;margin-left:4px;}
.extra-toggle:hover{color:var(--gold);background:var(--gold-dim);}
.extra-data{display:none;margin-top:6px;background:var(--surface);border:1px solid var(--border);border-radius:7px;padding:8px 12px;font-family:'Courier New',monospace;font-size:11px;color:var(--muted);white-space:pre-wrap;word-break:break-all;}
.extra-data.open{display:block;}

/* immutable notice */
.immutable-notice{display:flex;align-items:center;gap:8px;padding:10px 16px;background:rgba(74,222,128,0.05);border:1px solid rgba(74,222,128,0.15);border-radius:var(--radius);margin-bottom:16px;font-size:12.5px;color:var(--muted);}
.immutable-notice i{color:var(--success);}
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
        <h1>Audit Logs</h1>
        <p><?= $role === 'admin' ? 'Complete system activity trail — all user actions recorded' : 'Your personal activity log' ?></p>
    </div>
    <?php if ($role === 'admin'): ?>
    <div style="display:flex;gap:10px;">
        <button class="btn btn-outline" onclick="exportCSV()">
            <i class="fas fa-file-csv"></i> Export CSV
        </button>
        <button class="btn btn-outline" onclick="window.print()">
            <i class="fas fa-print"></i> Print
        </button>
    </div>
    <?php endif; ?>
</div>

<!-- Immutable notice -->
<div class="immutable-notice">
    <i class="fas fa-lock"></i>
    <span>Audit logs are <strong style="color:var(--success)">immutable and tamper-proof</strong> — records cannot be edited or deleted. Every action in the system is permanently recorded here.</span>
</div>

<!-- Stats -->
<div class="stats-mini">
    <div class="sm-stat">
        <div class="sm-stat-icon stat-icon gold"><i class="fas fa-scroll"></i></div>
        <div><p class="sm-stat-val"><?= number_format($total_logs) ?></p><p class="sm-stat-lbl">Total Entries</p></div>
    </div>
    <div class="sm-stat">
        <div class="sm-stat-icon stat-icon blue"><i class="fas fa-calendar-day"></i></div>
        <div><p class="sm-stat-val"><?= number_format($today_logs) ?></p><p class="sm-stat-lbl">Today</p></div>
    </div>
    <div class="sm-stat">
        <div class="sm-stat-icon stat-icon green"><i class="fas fa-right-to-bracket"></i></div>
        <div><p class="sm-stat-val"><?= number_format($login_logs) ?></p><p class="sm-stat-lbl">Total Logins</p></div>
    </div>
    <div class="sm-stat">
        <div class="sm-stat-icon stat-icon blue"><i class="fas fa-upload"></i></div>
        <div><p class="sm-stat-val"><?= number_format($upload_logs) ?></p><p class="sm-stat-lbl">Uploads</p></div>
    </div>
    <div class="sm-stat" style="<?= $failed_logins > 0 ? 'border-color:rgba(248,113,113,0.3)' : '' ?>">
        <div class="sm-stat-icon stat-icon <?= $failed_logins > 0 ? 'red' : 'gray' ?>"><i class="fas fa-ban"></i></div>
        <div>
            <p class="sm-stat-val" style="<?= $failed_logins > 0 ? 'color:var(--danger)' : '' ?>"><?= $failed_logins ?></p>
            <p class="sm-stat-lbl">Failed Logins (24h)</p>
        </div>
    </div>
    <?php if ($role === 'admin'): ?>
    <div class="sm-stat" style="<?= $tamper_alerts > 0 ? 'border-color:rgba(248,113,113,0.3)' : '' ?>">
        <div class="sm-stat-icon stat-icon <?= $tamper_alerts > 0 ? 'red' : 'green' ?>"><i class="fas fa-fingerprint"></i></div>
        <div>
            <p class="sm-stat-val" style="<?= $tamper_alerts > 0 ? 'color:var(--danger)' : '' ?>"><?= $tamper_alerts ?></p>
            <p class="sm-stat-lbl">Tamper Alerts</p>
        </div>
    </div>
    <?php endif; ?>
</div>

<!-- Activity chart (admin only) -->
<?php if ($role === 'admin'):
    $chart_data = $pdo->query("
        SELECT DATE(created_at) as day, COUNT(*) as cnt
        FROM audit_logs
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 14 DAY)
        GROUP BY DATE(created_at)
        ORDER BY day ASC
    ")->fetchAll(PDO::FETCH_ASSOC);
    $chart_labels = array_map(fn($r) => date('M j', strtotime($r['day'])), $chart_data);
    $chart_vals   = array_map(fn($r) => (int)$r['cnt'], $chart_data);
?>
<div class="section-card" style="margin-bottom:20px;">
    <div class="section-head">
        <h2><i class="fas fa-chart-bar"></i> Activity — Last 14 Days</h2>
    </div>
    <div class="chart-wrap">
        <canvas id="activityChart"></canvas>
    </div>
</div>
<?php endif; ?>

<!-- Filters -->
<div class="filter-wrap">
    <form method="GET" id="filterForm">
        <div class="filter-row">
            <input type="text" name="search" id="searchInput"
                placeholder="Search description, username, target..."
                value="<?= e($search) ?>">

            <select name="action_type" onchange="this.form.submit()">
                <option value="">All Actions</option>
                <?php foreach ($action_types as $key => [$label, $ico, $col]): ?>
                <option value="<?= $key ?>" <?= $filter_action === $key ? 'selected' : '' ?>><?= $label ?></option>
                <?php endforeach; ?>
            </select>

            <?php if ($role === 'admin'): ?>
            <select name="user_id" onchange="this.form.submit()">
                <option value="">All Users</option>
                <?php foreach ($users_list as $u): ?>
                <option value="<?= $u['id'] ?>" <?= (string)$filter_user === (string)$u['id'] ? 'selected' : '' ?>>
                    <?= e($u['full_name']) ?> (<?= $u['role'] ?>)
                </option>
                <?php endforeach; ?>
            </select>
            <?php endif; ?>

            <input type="date" name="date_from" value="<?= e($filter_date_from) ?>" title="From date" onchange="this.form.submit()">
            <input type="date" name="date_to"   value="<?= e($filter_date_to) ?>"   title="To date"   onchange="this.form.submit()">

            <button type="submit" class="btn btn-gold btn-sm"><i class="fas fa-search"></i> Filter</button>
            <?php if ($search || $filter_action || $filter_user || $filter_date_from || $filter_date_to): ?>
            <a href="audit.php" class="btn btn-outline btn-sm"><i class="fas fa-xmark"></i> Clear</a>
            <?php endif; ?>
        </div>
    </form>
</div>

<!-- Log Table -->
<div class="section-card">
    <!-- Export bar -->
    <div class="export-bar">
        <p>Showing <strong><?= number_format(count($logs)) ?></strong> of <strong><?= number_format($total) ?></strong> entries
            <?= $filter_action ? ' · filtered by: <strong>'.e(($action_types[$filter_action][0] ?? $filter_action)).'</strong>' : '' ?>
            <?= $filter_date_from ? ' · from <strong>'.e($filter_date_from).'</strong>' : '' ?>
            <?= $filter_date_to   ? ' to <strong>'.e($filter_date_to).'</strong>' : '' ?>
        </p>
        <div style="display:flex;gap:6px;align-items:center;">
            <span style="font-size:11.5px;color:var(--muted)">Per page:</span>
            <select onchange="changePage(this.value)" style="background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:3px 8px;font-size:12px;color:var(--text);outline:none;">
                <option value="20" <?= $per_page===20?'selected':'' ?>>20</option>
                <option value="50" <?= $per_page===50?'selected':'' ?>>50</option>
                <option value="100">100</option>
            </select>
        </div>
    </div>

    <!-- Log entries -->
    <div id="logContainer">
    <?php if (empty($logs)): ?>
        <div class="empty-state">
            <i class="fas fa-scroll"></i>
            <p>No audit log entries found for the selected filters.</p>
        </div>
    <?php else: ?>
        <?php foreach ($logs as $log):
            [$label, $ico, $col] = get_action_meta($log['action_type'], $action_types);
            $is_critical = in_array($log['action_type'], ['login_failed','evidence_flagged','integrity_check']) ||
                           (isset($log['extra_data']) && str_contains((string)$log['extra_data'], 'tampered'));
            $is_warning  = in_array($log['action_type'], ['download_token_generated','evidence_downloaded','account_request_submitted']);
            $row_class   = $is_critical ? 'critical' : ($is_warning ? 'warning-row' : '');
        ?>
        <div class="log-row <?= $row_class ?>" id="log-<?= $log['id'] ?>">

            <!-- Action icon -->
            <div class="action-dot dot-<?= $col ?>">
                <i class="fas <?= $ico ?>"></i>
            </div>

            <!-- Main content -->
            <div class="log-main">
                <p class="log-desc"><?= e($log['description']) ?></p>
                <div class="log-meta">
                    <span>
                        <i class="fas fa-user"></i>
                        <?php if ($log['full_name']): ?>
                            <strong style="color:var(--text)"><?= e($log['full_name']) ?></strong>
                            (<?= e($log['username'] ?? '') ?>)
                            <?php if ($log['user_role_db']): ?>
                                <?= role_badge($log['user_role_db']) ?>
                            <?php endif; ?>
                        <?php else: ?>
                            <span><?= e($log['username'] ?? 'System') ?></span>
                        <?php endif; ?>
                    </span>
                    <span><i class="fas fa-clock"></i> <?= date('M j, Y', strtotime($log['created_at'])) ?> at <?= date('H:i:s', strtotime($log['created_at'])) ?></span>
                    <?php if ($log['ip_address']): ?>
                    <span><i class="fas fa-network-wired"></i> <?= e($log['ip_address']) ?></span>
                    <?php endif; ?>
                    <?php if ($log['target_label']): ?>
                    <span><i class="fas fa-tag"></i> <?= e($log['target_label']) ?></span>
                    <?php endif; ?>
                    <?php if ($log['target_type'] && $log['target_id']): ?>
                    <span><i class="fas fa-link"></i>
                        <?php
                        $link_map = ['evidence'=>'evidence_view.php','case'=>'cases.php','account_request'=>'requests.php'];
                        $link = $link_map[$log['target_type']] ?? null;
                        if ($link): ?>
                        <a href="<?= $link ?>?id=<?= $log['target_id'] ?>" style="color:var(--info)">
                            View <?= ucfirst($log['target_type']) ?>
                        </a>
                        <?php else: echo e(ucfirst($log['target_type'])).' #'.$log['target_id']; endif; ?>
                    </span>
                    <?php endif; ?>
                </div>

                <!-- Extra data (expandable) -->
                <?php if ($log['extra_data'] && $log['extra_data'] !== 'null'): ?>
                <button class="extra-toggle" onclick="toggleExtra(<?= $log['id'] ?>)">
                    <i class="fas fa-code"></i> Details
                </button>
                <div class="extra-data" id="extra-<?= $log['id'] ?>">
                    <?php
                    $extra = json_decode($log['extra_data'], true);
                    echo $extra ? json_encode($extra, JSON_PRETTY_PRINT) : e($log['extra_data']);
                    ?>
                </div>
                <?php endif; ?>
            </div>

            <!-- Action badge + ID -->
            <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;flex-shrink:0;">
                <span class="action-badge badge-<?= $col ?>">
                    <i class="fas <?= $ico ?>" style="font-size:9px"></i>
                    <?= $label ?>
                </span>
                <span style="font-size:10.5px;color:var(--dim)">#<?= $log['id'] ?></span>
            </div>
        </div>
        <?php endforeach; ?>
    <?php endif; ?>
    </div>
</div>

<!-- Pagination -->
<?php if ($total_pages > 1): ?>
<div class="pagination">
    <a href="<?= page_url(1) ?>" class="pg-btn <?= $page_num<=1?'disabled':'' ?>"><i class="fas fa-angles-left"></i></a>
    <a href="<?= page_url(max(1,$page_num-1)) ?>" class="pg-btn <?= $page_num<=1?'disabled':'' ?>"><i class="fas fa-angle-left"></i></a>
    <?php
    $ps = max(1,$page_num-2); $pe = min($total_pages,$page_num+2);
    for ($p=$ps;$p<=$pe;$p++): ?>
    <a href="<?= page_url($p) ?>" class="pg-btn <?= $p===$page_num?'active':'' ?>"><?= $p ?></a>
    <?php endfor; ?>
    <a href="<?= page_url(min($total_pages,$page_num+1)) ?>" class="pg-btn <?= $page_num>=$total_pages?'disabled':'' ?>"><i class="fas fa-angle-right"></i></a>
    <a href="<?= page_url($total_pages) ?>" class="pg-btn <?= $page_num>=$total_pages?'disabled':'' ?>"><i class="fas fa-angles-right"></i></a>
    <span style="font-size:12px;color:var(--muted);margin-left:8px">
        Page <?= $page_num ?> of <?= $total_pages ?> &nbsp;·&nbsp; <?= number_format($total) ?> entries
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
function toggleNotif(){document.getElementById('notifDropdown').classList.toggle('open');document.getElementById('userDropdown').classList.remove('open');}
function toggleUserMenu(){document.getElementById('userDropdown').classList.toggle('open');document.getElementById('notifDropdown').classList.remove('open');}
document.addEventListener('click',function(e){
    if(!e.target.closest('#notifWrap'))document.getElementById('notifDropdown').classList.remove('open');
    if(!e.target.closest('#userMenuWrap'))document.getElementById('userDropdown').classList.remove('open');
});
function handleSearch(e){if(e.key==='Enter'){window.location='evidence.php?search='+encodeURIComponent(document.getElementById('globalSearch').value);}}

// Extra data toggle
function toggleExtra(id){
    const el=document.getElementById('extra-'+id);
    if(el) el.classList.toggle('open');
}

// Live search debounce
var st;
var si=document.getElementById('searchInput');
if(si) si.addEventListener('input',function(){clearTimeout(st);st=setTimeout(function(){document.getElementById('filterForm').submit();},600);});

// Chart
<?php if ($role === 'admin' && !empty($chart_data)): ?>
const ctx=document.getElementById('activityChart').getContext('2d');
new Chart(ctx,{
    type:'bar',
    data:{
        labels:[<?= implode(',', array_map(fn($l) => '"'.addslashes($l).'"', $chart_labels)) ?>],
        datasets:[{
            label:'Actions',
            data:[<?= implode(',', $chart_vals) ?>],
            backgroundColor:'rgba(201,168,76,0.15)',
            borderColor:'#c9a84c',
            borderWidth:1.5,
            borderRadius:4,
        }]
    },
    options:{
        responsive:true,maintainAspectRatio:false,
        plugins:{legend:{display:false},tooltip:{backgroundColor:'#0c1526',borderColor:'rgba(201,168,76,0.3)',borderWidth:1,titleColor:'#f0f4fa',bodyColor:'#6b82a0'}},
        scales:{
            x:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#6b82a0',font:{size:10}}},
            y:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#6b82a0',font:{size:10},stepSize:1},beginAtZero:true}
        }
    }
});
<?php endif; ?>

// CSV Export
function exportCSV(){
    const rows=[['ID','Action','Description','Username','Role','IP Address','Target','Date/Time']];
    document.querySelectorAll('.log-row').forEach(row=>{
        const id=row.id.replace('log-','');
        const badge=row.querySelector('.action-badge');
        const desc=row.querySelector('.log-desc');
        const metas=row.querySelectorAll('.log-meta span');
        rows.push([
            id,
            badge?badge.textContent.trim():'',
            desc?desc.textContent.trim():'',
            metas[0]?metas[0].textContent.trim():'',
            '',
            metas[2]?metas[2].textContent.trim():'',
            metas[3]?metas[3].textContent.trim():'',
            metas[1]?metas[1].textContent.trim():'',
        ]);
    });
    const csv=rows.map(r=>r.map(c=>'"'+String(c).replace(/"/g,'""')+'"').join(',')).join('\n');
    const a=document.createElement('a');
    a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
    a.download='digicustody_audit_log_'+new Date().toISOString().slice(0,10)+'.csv';
    a.click();
}
</script>
</body>
</html>