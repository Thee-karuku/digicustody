<?php
// pages/dashboard_admin.php
$page_title = 'Admin Dashboard';

// ── Fetch all stats ──────────────────────────────────────
$stats = [];
$stats['total_users']     = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE status='active'")->fetchColumn();
$stats['total_evidence']  = (int)$pdo->query("SELECT COUNT(*) FROM evidence")->fetchColumn();
$stats['total_cases']     = (int)$pdo->query("SELECT COUNT(*) FROM cases")->fetchColumn();
$stats['open_cases']      = (int)$pdo->query("SELECT COUNT(*) FROM cases WHERE status IN ('open','under_investigation')")->fetchColumn();
$stats['pending_requests']= (int)$pdo->query("SELECT COUNT(*) FROM account_requests WHERE status='pending'")->fetchColumn();
$stats['tampered']        = (int)$pdo->query("SELECT COUNT(*) FROM hash_verifications WHERE integrity_status='tampered'")->fetchColumn();
$stats['unassigned']      = (int)$pdo->query("SELECT COUNT(*) FROM evidence WHERE analysis_status='pending_assignment'")->fetchColumn();
$stats['in_analysis']     = (int)$pdo->query("SELECT COUNT(*) FROM evidence WHERE analysis_status IN ('assigned','in_progress')")->fetchColumn();
// Transfers feature removed - using shared access model

// Storage usage
$storage_bytes = $pdo->query("SELECT COALESCE(SUM(file_size),0) FROM evidence")->fetchColumn();

// Evidence by type
$ev_types = $pdo->query("SELECT evidence_type, COUNT(*) as cnt FROM evidence GROUP BY evidence_type ORDER BY cnt DESC LIMIT 6")->fetchAll();

// Evidence by status
$ev_status = $pdo->query("SELECT status, COUNT(*) as cnt FROM evidence GROUP BY status")->fetchAll();

// Recent account requests
$recent_requests = $pdo->query("SELECT * FROM account_requests WHERE status='pending' ORDER BY created_at DESC LIMIT 8")->fetchAll();

// Recent audit logs
$recent_logs = $pdo->query("
    SELECT al.*, u.full_name FROM audit_logs al
    LEFT JOIN users u ON u.id = al.user_id
    ORDER BY al.created_at DESC LIMIT 12")->fetchAll();

// Recent evidence uploads
$recent_evidence = $pdo->query("
    SELECT e.*, u.full_name as uploader, c.case_number, c.case_title
    FROM evidence e
    JOIN users u ON u.id = e.uploaded_by
    JOIN cases c ON c.id = e.case_id
    ORDER BY e.uploaded_at DESC LIMIT 8")->fetchAll();

// Users by role
$users_by_role = $pdo->query("SELECT role, COUNT(*) as cnt FROM users WHERE status='active' GROUP BY role")->fetchAll();

// Integrity check history (last 5 runs)
$integrity_checks = $pdo->query("
    SELECT * FROM integrity_checks 
    ORDER BY run_at DESC 
    LIMIT 5")->fetchAll();

// Monthly evidence uploads (last 6 months)
$monthly = $pdo->query("
    SELECT DATE_FORMAT(uploaded_at,'%b %Y') as month,
           DATE_FORMAT(uploaded_at,'%Y-%m') as sort_key,
           COUNT(*) as cnt
    FROM evidence
    WHERE uploaded_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
    GROUP BY month, sort_key ORDER BY sort_key ASC")->fetchAll();

// Case status breakdown (for doughnut chart)
$case_status_data = $pdo->query("
    SELECT status, COUNT(*) as cnt 
    FROM cases 
    GROUP BY status")->fetchAll();

// Evidence uploads per day (last 30 days - for bar chart)
$daily_uploads = $pdo->query("
    SELECT DATE(uploaded_at) as date, COUNT(*) as cnt
    FROM evidence
    WHERE uploaded_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    GROUP BY DATE(uploaded_at)
    ORDER BY date ASC")->fetchAll();

// Evidence count per analyst (for horizontal bar chart)
$analyst_workload = $pdo->query("
    SELECT u.full_name, COUNT(e.id) as evidence_count
    FROM users u
    LEFT JOIN evidence e ON e.uploaded_by = u.id
    WHERE u.role = 'analyst' AND u.status = 'active'
    GROUP BY u.id, u.full_name
    ORDER BY evidence_count DESC")->fetchAll();

// Handle approve/reject requests inline
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['req_action'])) {
    $req_id  = (int)$_POST['req_id'];
    $action  = $_POST['req_action'];
    $notes   = trim($_POST['admin_notes'] ?? '');

    if (in_array($action, ['approved','rejected'])) {
        $pdo->prepare("UPDATE account_requests SET status=?, admin_notes=?, reviewed_by=?, reviewed_at=NOW() WHERE id=?")
            ->execute([$action, $notes, $_SESSION['user_id'], $req_id]);

        if ($action === 'approved') {
            // Get request details and create user account
            $req = $pdo->prepare("SELECT * FROM account_requests WHERE id=?")->execute([$req_id]) ? $pdo->prepare("SELECT * FROM account_requests WHERE id=?")->execute([$req_id]) : null;
            $stmt = $pdo->prepare("SELECT * FROM account_requests WHERE id=?");
            $stmt->execute([$req_id]);
            $req = $stmt->fetch();
            if ($req) {
                $username = strtolower(preg_replace('/\s+/', '.', $req['full_name'])) . rand(10,99);
                $temp_pass = 'DC@' . rand(10000,99999);
                $hashed    = password_hash($temp_pass, PASSWORD_BCRYPT, ['cost'=>12]);
                $pdo->prepare("INSERT INTO users (full_name,email,username,password,role,status,phone,department,badge_number,created_by)
                    VALUES(?,?,?,?,?,?,?,?,?,?)")
                    ->execute([$req['full_name'],$req['email'],$username,$hashed,$req['requested_role'],'active',
                               $req['phone'],$req['department'],$req['badge_number'],$_SESSION['user_id']]);
                $new_uid = $pdo->lastInsertId();
                send_notification($pdo,$new_uid,'Account Approved',
                    "Your account has been approved. Username: $username | Temp Password: $temp_pass",'success');
                audit_log($pdo,$_SESSION['user_id'],$_SESSION['username'],'admin','account_request_approved','account_request',$req_id,$req['full_name'],"Request approved, account created: $username");
                send_account_approval_email($req['email'], $req['full_name'], $username, $temp_pass, $req['requested_role']);
            }
        } else {
            audit_log($pdo,$_SESSION['user_id'],$_SESSION['username'],'admin','account_request_rejected','account_request',$req_id,'','Request rejected');
        }
        header('Location: ../dashboard.php?msg=request_'.$action);
        exit;
    }
}

$msg = $_GET['msg'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Admin Dashboard — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/global.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
.integrity-bar{height:8px;border-radius:4px;background:var(--surface2);overflow:hidden;margin-top:8px;}
.integrity-fill{height:100%;border-radius:4px;background:var(--success);transition:width 1s ease;}
.integrity-fill.warn{background:var(--danger);}
.req-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;margin-bottom:10px;transition:border-color .2s;}
.req-card:hover{border-color:var(--border2);}
.req-info{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:10px;}
.req-name{font-size:13.5px;font-weight:500;color:var(--text);}
.req-detail{font-size:12px;color:var(--muted);margin-top:2px;}
.req-actions{display:flex;gap:8px;margin-top:10px;}
.chart-wrap{padding:16px 20px;height:220px;position:relative;}
.log-item{display:flex;align-items:flex-start;gap:11px;padding:10px 16px;border-bottom:1px solid var(--border);font-size:12.5px;}
.log-item:last-child{border-bottom:none;}
.log-icon{width:28px;height:28px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:11px;}
.log-icon.login{background:rgba(96,165,250,0.1);color:var(--info);}
.log-icon.upload{background:rgba(74,222,128,0.1);color:var(--success);}
.log-icon.download{background:rgba(251,191,36,0.1);color:var(--warning);}
.log-icon.transfer{background:rgba(167,139,250,0.1);color:#a78bfa;}
.log-icon.verify{background:rgba(201,168,76,0.1);color:var(--gold);}
.log-icon.default{background:rgba(107,130,160,0.1);color:var(--muted);}
.log-body{flex:1;min-width:0;}
.log-desc{color:var(--text);margin-bottom:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.log-meta{color:var(--dim);font-size:11.5px;}
.storage-bar{height:10px;border-radius:5px;background:var(--surface2);overflow:hidden;margin:8px 0;}
.storage-fill{height:100%;border-radius:5px;background:linear-gradient(90deg,var(--gold),var(--info));}
.role-pill{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:20px;font-size:11px;}
</style>
</head>
<body>
<div class="app-shell">
<?php include __DIR__.'/../includes/sidebar.php'; ?>
<div class="main-area" id="mainArea">
<?php include __DIR__.'/../includes/navbar.php'; ?>
<div class="page-content">

<?php if($msg==='request_approved'): ?><div class="alert alert-success"><i class="fas fa-circle-check"></i> Account request approved and user account created successfully.</div><?php endif; ?>
<?php if($msg==='request_rejected'): ?><div class="alert alert-warning"><i class="fas fa-triangle-exclamation"></i> Account request has been rejected.</div><?php endif; ?>

<!-- Page Header -->
<div class="page-header">
    <div>
        <h1>Admin Dashboard</h1>
        <p>Welcome back, <?= e($_SESSION['full_name']) ?> &nbsp;·&nbsp; <?= date('l, F j, Y') ?></p>
    </div>
    <div style="display:flex;gap:10px;">
        <a href="pages/users.php" class="btn btn-outline"><i class="fas fa-user-plus"></i> Add User</a>
        <a href="pages/cases.php" class="btn btn-gold"><i class="fas fa-folder-plus"></i> New Case</a>
    </div>
</div>

<!-- Quick Actions -->
<div class="quick-actions">
    <a href="pages/evidence.php" class="btn btn-outline"><i class="fas fa-database"></i> All Evidence</a>
    <a href="pages/users.php" class="btn btn-outline"><i class="fas fa-users"></i> Manage Users</a>
    <a href="pages/requests.php" class="btn btn-outline" style="<?= $stats['pending_requests']>0?'border-color:var(--warning);color:var(--warning)':'' ?>">
        <i class="fas fa-user-clock"></i> Access Requests <?= $stats['pending_requests']>0?"<span class='badge badge-orange'>{$stats['pending_requests']}</span>":'' ?>
    </a>
    <a href="pages/audit.php" class="btn btn-outline"><i class="fas fa-scroll"></i> Full Audit Log</a>

</div>

<!-- Stats Row -->
<div class="stats-grid">
    <div class="stat-card gold">
        <div class="stat-icon gold"><i class="fas fa-database"></i></div>
        <div class="stat-body">
            <p class="stat-label">Total Evidence</p>
            <p class="stat-value"><?= number_format($stats['total_evidence']) ?></p>
            <p class="stat-sub">Files in custody</p>
        </div>
    </div>
    <div class="stat-card blue">
        <div class="stat-icon blue"><i class="fas fa-folder-open"></i></div>
        <div class="stat-body">
            <p class="stat-label">Active Cases</p>
            <p class="stat-value"><?= number_format($stats['open_cases']) ?></p>
            <p class="stat-sub"><?= $stats['total_cases'] ?> total cases</p>
        </div>
    </div>
    <div class="stat-card green">
        <div class="stat-icon green"><i class="fas fa-users"></i></div>
        <div class="stat-body">
            <p class="stat-label">Active Users</p>
            <p class="stat-value"><?= number_format($stats['total_users']) ?></p>
            <p class="stat-sub"><?= $stats['pending_requests'] ?> pending requests</p>
        </div>
    </div>
    <div class="stat-card <?= $stats['tampered']>0?'red':'green' ?>">
        <div class="stat-icon <?= $stats['tampered']>0?'red':'green' ?>"><i class="fas fa-fingerprint"></i></div>
        <div class="stat-body">
            <p class="stat-label">Integrity Alerts</p>
            <p class="stat-value"><?= $stats['tampered'] ?></p>
            <p class="stat-sub"><?= $stats['tampered']>0?'<span class="down">Tampered files detected</span>':'<span class="up">All files intact</span>' ?></p>
        </div>
    </div>
    <div class="stat-card orange">
        <div class="stat-icon orange"><i class="fas fa-file-lines"></i></div>
        <div class="stat-body">
            <p class="stat-label">Pending Reports</p>
            <p class="stat-value"><?= (int)$pdo->query("SELECT COUNT(*) FROM analysis_reports WHERE status='submitted'")->fetchColumn() ?></p>
            <p class="stat-sub">Awaiting review</p>
        </div>
    </div>
    <div class="stat-card purple">
        <div class="stat-icon purple"><i class="fas fa-hard-drive"></i></div>
        <div class="stat-body">
            <p class="stat-label">Storage Used</p>
            <p class="stat-value"><?= format_filesize($storage_bytes) ?></p>
            <p class="stat-sub">Evidence files total</p>
        </div>
    </div>
</div>

<!-- Row 1: Charts -->
<div class="grid-3" style="margin-bottom:20px;">

    <!-- Case Status Doughnut Chart -->
    <div class="section-card">
        <div class="section-head">
            <h2><i class="fas fa-chart-pie"></i> Case Status</h2>
        </div>
        <div class="chart-wrap" style="height:200px;">
            <canvas id="caseStatusChart"></canvas>
        </div>
    </div>

    <!-- Evidence Uploads per Day (Last 30 Days) Bar Chart -->
    <div class="section-card" style="grid-column:span 2;">
        <div class="section-head">
            <h2><i class="fas fa-chart-bar"></i> Evidence Uploads (Last 30 Days)</h2>
        </div>
        <div class="chart-wrap" style="height:200px;">
            <canvas id="dailyUploadsChart"></canvas>
        </div>
    </div>
</div>

<!-- Row 2: More Charts + Integrity -->
<div class="grid-3" style="margin-bottom:20px;">

    <!-- Monthly uploads chart -->
    <div class="section-card" style="grid-column:span 2;">
        <div class="section-head">
            <h2><i class="fas fa-chart-line"></i> Evidence Uploads (Last 6 Months)</h2>
        </div>
        <div class="chart-wrap">
            <canvas id="uploadsChart"></canvas>
        </div>
    </div>

    <!-- System overview -->
    <div class="section-card">
        <div class="section-head"><h2><i class="fas fa-circle-nodes"></i> System Overview</h2></div>
        <div class="section-body padded">

            <p style="font-size:11.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px;">Users by Role</p>
            <?php
            $role_colors = ['admin'=>'gold','investigator'=>'blue','analyst'=>'green'];
            foreach ($users_by_role as $r): $c=$role_colors[$r['role']]??'gray'; ?>
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
                <span class="badge badge-<?= $c ?>"><?= ucfirst(e($r['role'])) ?></span>
                <span style="font-size:13px;font-weight:600;color:var(--text)"><?= $r['cnt'] ?></span>
            </div>
            <?php endforeach; ?>

            <div style="height:1px;background:var(--border);margin:14px 0;"></div>

            <p style="font-size:11.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px;">Evidence by Status</p>
            <?php
            $status_colors=['collected'=>'blue','in_analysis'=>'orange','transferred'=>'purple','archived'=>'gray','flagged'=>'red'];
            foreach ($ev_status as $s): $c=$status_colors[$s['status']]??'gray'; ?>
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
                <span class="badge badge-<?= $c ?>"><?= ucwords(str_replace('_',' ',e($s['status']))) ?></span>
                <span style="font-size:13px;font-weight:600;color:var(--text)"><?= $s['cnt'] ?></span>
            </div>
            <?php endforeach; ?>

            <!-- Storage bar -->
            <div style="height:1px;background:var(--border);margin:14px 0;"></div>
            <p style="font-size:11.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px;">Storage</p>
            <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--muted);margin-bottom:4px;">
                <span><?= format_filesize($storage_bytes) ?> used</span>
                <span>500 MB limit</span>
            </div>
            <div class="storage-bar">
                <?php $pct = min(100, round(($storage_bytes/(500*1024*1024))*100)); ?>
                <div class="storage-fill" style="width:<?= $pct ?>%"></div>
            </div>
            <p style="font-size:11.5px;color:var(--muted);"><?= $pct ?>% of storage used</p>
        </div>
    </div>

    <!-- Analyst Workload Chart -->
    <div class="section-card">
        <div class="section-head">
            <h2><i class="fas fa-users"></i> Analyst Workload</h2>
        </div>
        <div class="chart-wrap" style="height:220px;">
            <canvas id="analystWorkloadChart"></canvas>
        </div>
    </div>
</div>

<!-- Row 2: Pending Requests + Recent Evidence -->
<div class="grid-2" style="margin-bottom:20px;">

    <!-- Pending access requests -->
    <div class="section-card">
        <div class="section-head">
            <h2><i class="fas fa-user-clock"></i> Pending Access Requests
                <?php if($stats['pending_requests']>0): ?><span class="badge badge-orange" style="margin-left:6px"><?= $stats['pending_requests'] ?></span><?php endif; ?>
            </h2>
            <a href="pages/requests.php" class="see-all">View all</a>
        </div>
        <div class="section-body padded">
            <?php if(empty($recent_requests)): ?>
            <div class="empty-state" style="padding:28px 0">
                <i class="fas fa-user-check"></i><p>No pending requests</p>
            </div>
            <?php else: foreach($recent_requests as $req): ?>
            <div class="req-card">
                <div class="req-info">
                    <div>
                        <p class="req-name"><?= e($req['full_name']) ?></p>
                        <p class="req-detail"><?= e($req['email']) ?> &nbsp;·&nbsp;
                            <span class="badge badge-<?= ['investigator'=>'blue','analyst'=>'green'][$req['requested_role']]??'gray' ?>"><?= ucfirst(e($req['requested_role'])) ?></span>
                        </p>
                        <?php if($req['department']): ?><p class="req-detail"><?= e($req['department']) ?></p><?php endif; ?>
                        <p class="req-detail" style="margin-top:4px;font-size:11.5px;color:var(--dim)"><?= time_ago($req['created_at']) ?></p>
                    </div>
                </div>
                <?php if($req['reason']): ?>
                <p style="font-size:12px;color:var(--muted);margin-bottom:8px;font-style:italic;">"<?= e(substr($req['reason'],0,80)) ?>..."</p>
                <?php endif; ?>
                <form method="POST" style="display:flex;gap:8px;align-items:center;">
                    <input type="hidden" name="req_id" value="<?= $req['id'] ?>">
                    <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                    <input type="text" name="admin_notes" placeholder="Optional notes..." style="flex:1;background:var(--surface);border:1px solid var(--border);border-radius:7px;padding:6px 10px;font-size:12px;color:var(--text);outline:none;font-family:'Inter',sans-serif;">
                    <button type="submit" name="req_action" value="approved" class="btn btn-success btn-sm"><i class="fas fa-check"></i> Approve</button>
                    <button type="submit" name="req_action" value="rejected" class="btn btn-danger btn-sm"><i class="fas fa-xmark"></i> Reject</button>
                </form>
            </div>
            <?php endforeach; endif; ?>
        </div>
    </div>

    <!-- Recent evidence -->
    <div class="section-card">
        <div class="section-head">
            <h2><i class="fas fa-database"></i> Recent Evidence</h2>
            <a href="pages/evidence.php" class="see-all">View all</a>
        </div>
        <div class="section-body">
            <?php if(empty($recent_evidence)): ?>
            <div class="empty-state"><i class="fas fa-database"></i><p>No evidence uploaded yet</p></div>
            <?php else: ?>
            <div class="table-responsive"><table class="dc-table">
                <thead><tr>
                    <th>Evidence</th><th>Case</th><th>Type</th><th>Uploaded</th><th>Status</th>
                </tr></thead>
                <tbody>
                <?php foreach($recent_evidence as $ev): ?>
                <tr>
                    <td data-label="Evidence">
                        <p style="font-weight:500;font-size:13px;"><?= e($ev['evidence_number']) ?></p>
                        <p style="font-size:11.5px;color:var(--muted);"><?= e(substr($ev['title'],0,28)) ?>...</p>
                    </td>
                    <td data-label="Case"><a href="pages/case_view.php?id=<?= $ev['case_id'] ?>" style="font-size:12px;color:var(--info);text-decoration:none"><?= e($ev['case_number']) ?></a></td>
                    <td data-label="Type"><span class="badge badge-blue"><?= ucfirst(str_replace('_',' ',e($ev['evidence_type']))) ?></span></td>
                    <td data-label="Uploaded"><span style="font-size:12px;color:var(--muted)"><?= time_ago($ev['uploaded_at']) ?></span></td>
                    <td data-label="Status"><?= status_badge($ev['status']) ?></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table></div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Row 2b: Integrity Check History -->
<div class="section-card" style="grid-column: span 2;">
    <div class="section-head">
        <h2><i class="fas fa-shield-halved"></i> Integrity Check Results</h2>
        <a href="pages/audit.php?filter=integrity" class="see-all">View all</a>
    </div>
    <div class="section-body" style="padding:0;">
        <?php if (empty($integrity_checks)): ?>
            <div style="padding:24px;text-align:center;color:var(--muted);">
                <i class="fas fa-circle-check" style="font-size:28px;margin-bottom:8px;opacity:0.4"></i>
                <p>No integrity checks have been run yet.</p>
            </div>
        <?php else: ?>
            <table class="dc-table">
                <thead>
                    <tr>
                        <th>Run Date</th>
                        <th>Total</th>
                        <th>Intact</th>
                        <th>Tampered</th>
                        <th>Missing</th>
                        <th>Duration</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($integrity_checks as $check): ?>
                    <tr>
                        <td data-label="Run Date">
                            <?= date('M j, Y H:i', strtotime($check['run_at'])) ?>
                        </td>
                        <td data-label="Total"><?= (int)$check['total_records'] ?></td>
                        <td data-label="Intact">
                            <?php if ($check['intact'] > 0): ?>
                                <span style="color:var(--success)"><?= (int)$check['intact'] ?></span>
                            <?php else: ?>
                                <?= (int)$check['intact'] ?>
                            <?php endif; ?>
                        </td>
                        <td data-label="Tampered">
                            <?php if ($check['tampered'] > 0): ?>
                                <span class="badge badge-red"><?= (int)$check['tampered'] ?></span>
                            <?php else: ?>
                                0
                            <?php endif; ?>
                        </td>
                        <td data-label="Missing">
                            <?php if ($check['missing'] > 0): ?>
                                <span class="badge badge-orange"><?= (int)$check['missing'] ?></span>
                            <?php else: ?>
                                0
                            <?php endif; ?>
                        </td>
                        <td data-label="Duration"><?= number_format($check['duration_seconds'], 2) ?>s</td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>

<!-- Row 3: Audit Log -->
<div class="section-card">
    <div class="section-head">
        <h2><i class="fas fa-scroll"></i> Recent System Activity</h2>
        <a href="pages/audit.php" class="see-all">Full audit log</a>
    </div>
    <div class="section-body">
        <?php
        $icon_map = [
            'login'=>['login','fa-right-to-bracket'],'logout'=>['login','fa-right-from-bracket'],
            'evidence_uploaded'=>['upload','fa-upload'],'evidence_downloaded'=>['download','fa-download'],
            'evidence_transferred'=>['transfer','fa-right-left'],'evidence_viewed'=>['login','fa-eye'],
            'hash_verified'=>['verify','fa-fingerprint'],'integrity_check'=>['verify','fa-shield-check'],
            'account_created'=>['upload','fa-user-plus'],'account_request_approved'=>['upload','fa-user-check'],
        ];
        foreach($recent_logs as $log):
            [$cls,$ico] = $icon_map[$log['action_type']] ?? ['default','fa-circle-dot'];
        ?>
        <div class="log-item">
            <div class="log-icon <?= $cls ?>"><i class="fas <?= $ico ?>"></i></div>
            <div class="log-body">
                <p class="log-desc"><?= e($log['description']) ?></p>
                <p class="log-meta">
                    <?= e($log['username'] ?? 'System') ?> &nbsp;·&nbsp;
                    <?= date('M j, Y H:i', strtotime($log['created_at'])) ?> &nbsp;·&nbsp;
                    <?= e($log['ip_address'] ?? '') ?>
                </p>
            </div>
            <span class="badge badge-gray" style="font-size:10.5px;flex-shrink:0;"><?= str_replace('_',' ',e($log['action_type'])) ?></span>
        </div>
        <?php endforeach; ?>
    </div>
</div>

</div><!-- /page-content -->
</div><!-- /main-area -->
</div><!-- /app-shell -->

<script>
// Sidebar toggle
function toggleSidebar(){
    const sb=document.getElementById('sidebar');
    const ma=document.getElementById('mainArea');
    const isMobile=window.innerWidth<=900;
    if(isMobile){sb.classList.toggle('mobile-open');}
    else{sb.classList.toggle('collapsed');ma.classList.toggle('collapsed');}
    localStorage.setItem('sb_collapsed',sb.classList.contains('collapsed')?'1':'0');
}
// Restore sidebar state
if(localStorage.getItem('sb_collapsed')==='1'&&window.innerWidth>900){
    document.getElementById('sidebar').classList.add('collapsed');
    document.getElementById('mainArea').classList.add('collapsed');
}

// Dropdowns
function toggleNotif(){
    document.getElementById('notifDropdown').classList.toggle('open');
    document.getElementById('userDropdown').classList.remove('open');
}
function toggleUserMenu(){
    document.getElementById('userDropdown').classList.toggle('open');
    document.getElementById('notifDropdown').classList.remove('open');
}
document.addEventListener('click',e=>{
    if(!e.target.closest('#notifWrap'))document.getElementById('notifDropdown').classList.remove('open');
    if(!e.target.closest('#userMenuWrap'))document.getElementById('userDropdown').classList.remove('open');
});

function handleSearch(e){if(e.key==='Enter'){const v=document.getElementById('globalSearch').value.trim();if(v)window.location='evidence.php?search='+encodeURIComponent(v);}}

// Chart
const ctx=document.getElementById('uploadsChart').getContext('2d');
const labels=[<?= implode(',',array_map(fn($m)=>"'".e($m['month'])."'",$monthly)) ?>];
const data=[<?= implode(',',array_map(fn($m)=>$m['cnt'],$monthly)) ?>];
new Chart(ctx,{
    type:'line',
    data:{labels,datasets:[{
        label:'Evidence Uploads',data,
        borderColor:'#c9a84c',backgroundColor:'rgba(201,168,76,0.08)',
        borderWidth:2,pointBackgroundColor:'#c9a84c',pointRadius:4,
        tension:.4,fill:true
    }]},
    options:{
        responsive:true,maintainAspectRatio:false,
        plugins:{legend:{display:false},tooltip:{backgroundColor:'#0c1526',borderColor:'rgba(201,168,76,0.3)',borderWidth:1,titleColor:'#f0f4fa',bodyColor:'#6b82a0'}},
        scales:{
            x:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#6b82a0',font:{size:11}}},
            y:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#6b82a0',font:{size:11},stepSize:1}}
        }
    }
});

// Case Status Doughnut Chart
(function(){
    const ctx=document.getElementById('caseStatusChart');
    if(!ctx)return;
    const labels=[<?= implode(',',array_map(fn($s)=>"'".e($s['status'])."'",$case_status_data)) ?>];
    const data=[<?= implode(',',array_map(fn($s)=>$s['cnt'],$case_status_data)) ?>];
    const colors=['#3b82f6','#10b981','#6b7280','#f59e0b'];
    new Chart(ctx,{
        type:'doughnut',
        data:{labels,datasets:[{data,backgroundColor:colors,borderWidth:0}]},
        options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:'#6b82a0',padding:12,usePointStyle:true}}}}
    });
})();

// Daily Uploads Bar Chart (Last 30 Days)
(function(){
    const ctx=document.getElementById('dailyUploadsChart');
    if(!ctx)return;
    const labels=[<?= implode(',',array_map(fn($d)=>"'".e($d['date'])."'",$daily_uploads)) ?>];
    const data=[<?= implode(',',array_map(fn($d)=>$d['cnt'],$daily_uploads)) ?>];
    new Chart(ctx,{
        type:'bar',
        data:{labels,datasets:[{label:'Uploads',data,backgroundColor:'#c9a84c',borderRadius:4}]},
        options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:'#6b82a0',font:{size:9},maxRotation:45}},y:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#6b82a0',font:{size:10},stepSize:1}}}}
    });
})();

// Analyst Workload Horizontal Bar Chart
(function(){
    const ctx=document.getElementById('analystWorkloadChart');
    if(!ctx)return;
    const labels=[<?= implode(',',array_map(fn($a)=>"'".e($a['full_name'])."'",$analyst_workload)) ?>];
    const data=[<?= implode(',',array_map(fn($a)=>$a['evidence_count'],$analyst_workload)) ?>];
    new Chart(ctx,{
        type:'bar',
        data:{labels,datasets:[{label:'Evidence',data,backgroundColor:'#10b981',borderRadius:4}]},
        options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#6b82a0',font:{size:10}}},y:{grid:{display:false},ticks:{color:'#f0f4fa',font:{size:11}}}}}
    });
})();
</script>
</body>
</html>
