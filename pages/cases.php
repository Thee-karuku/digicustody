<?php
/**
 * DigiCustody – Cases Management
 * Save to: /var/www/html/digicustody/pages/cases.php
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login();

$page_title = 'Cases';
$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];
$msg  = ''; $err = '';

// ── Handle create/edit case ───────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $err = 'Security token mismatch.';
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'create_case' && in_array($role, ['admin','investigator'])) {
            $title    = trim($_POST['case_title'] ?? '');
            $desc     = trim($_POST['description'] ?? '');
            $type     = trim($_POST['case_type'] ?? '');
            $priority = in_array($_POST['priority']??'',['low','medium','high','critical']) ? $_POST['priority'] : 'medium';
            $suggested_analyst = (int)($_POST['suggested_analyst'] ?? 0);

            if (empty($title)) { $err = 'Case title is required.'; }
            else {
                $case_num = generate_case_number($pdo);
                $pdo->prepare("INSERT INTO cases (case_number,case_title,description,case_type,priority,status,created_by)
                    VALUES(?,?,?,?,?,'open',?)")
                    ->execute([$case_num,$title,$desc,$type,$priority,$uid]);
                $cid = $pdo->lastInsertId();
                // Auto-grant case_access to creator
                grant_case_access($pdo, $cid, $uid, $uid);
                cache_delete_prefix('cases_list');
                
                // If analyst suggested (investigators) or assigned (admins), add to case
                if ($suggested_analyst > 0) {
                    // Verify user is actually an analyst
                    $chk = $pdo->prepare("SELECT role FROM users WHERE id=? AND status='active'");
                    $chk->execute([$suggested_analyst]);
                    $user_role = $chk->fetchColumn();
                    
                    if ($user_role === 'analyst') {
                        $pdo->prepare("UPDATE cases SET assigned_analyst=?,updated_at=NOW() WHERE id=?")
                            ->execute([$suggested_analyst, $cid]);
                        grant_case_access($pdo, $cid, $suggested_analyst, $uid);
                        
                        // Get analyst name for notification
                        $analyst_name = $pdo->prepare("SELECT full_name FROM users WHERE id=?")->execute([$suggested_analyst]);
                        $analyst_name = $pdo->query("SELECT full_name FROM users WHERE id=$suggested_analyst")->fetchColumn();
                        
                        send_notification($pdo, $suggested_analyst, 'Case Assigned',
                            "You have been assigned to case $case_num: $title", 'info', 'case', $cid);
                        
                        $msg = "Case <strong>$case_num</strong> created successfully. Analyst <strong>$analyst_name</strong> has been assigned.";
                    } else {
                        $msg = "Case <strong>$case_num</strong> created successfully.";
                    }
                } else {
                    $msg = "Case <strong>$case_num</strong> created successfully.";
                }
                
                audit_log($pdo,$uid,$_SESSION['username'],$role,'case_created','case',$cid,$case_num,"Case created: $case_num — $title");
            }
        }

        elseif ($action === 'update_status' && $role === 'admin') {
            $cid    = (int)$_POST['case_id'];
            $status = in_array($_POST['status']??'',['open','under_investigation','closed','archived']) ? $_POST['status'] : 'open';
            $pdo->prepare("UPDATE cases SET status=?,updated_at=NOW() WHERE id=?")->execute([$status,$cid]);
            audit_log($pdo,$uid,$_SESSION['username'],$role,'case_updated','case',$cid,'', "Case status updated to: $status");
            $msg = "Case status updated.";
        }
    }
}

// ── Fetch cases ───────────────────────────────────────────
$search        = trim($_GET['search'] ?? '');
$filter_status = $_GET['status'] ?? '';
$filter_priority = $_GET['priority'] ?? '';
$sort = in_array($_GET['sort']??'',['case_number','case_title','status','priority','created_at']) ? $_GET['sort'] : 'created_at';
$dir  = strtoupper($_GET['dir']??'DESC')==='ASC' ? 'ASC' : 'DESC';

$where = ['1=1']; $params = [];

// Analysts only see cases via case_access
// Investigators see all cases (no filter)
// Admins see all cases
if ($role === 'analyst') {
    $where[] = "c.id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id=?)";
    $params[] = $uid;
}

if ($search !== '') {
    $where[] = "(case_number LIKE ? OR case_title LIKE ? OR description LIKE ?)";
    $s = "%$search%"; $params = array_merge($params,[$s,$s,$s]);
}
if ($filter_status   !== '') { $where[] = "status=?";   $params[] = $filter_status; }
if ($filter_priority !== '') { $where[] = "priority=?"; $params[] = $filter_priority; }

$where_sql = implode(' AND ', $where);
$cache_key = "cases_list_{$role}_{$uid}_" . md5($where_sql . implode('', $params));
$cases = cache_get($cache_key, 60);
if ($cases === null) {
    $cases_stmt = $pdo->prepare("
        SELECT c.*, u.full_name AS creator_name,
               (SELECT COUNT(*) FROM evidence e WHERE e.case_id=c.id) AS evidence_count
        FROM cases c
        JOIN users u ON u.id=c.created_by
        WHERE $where_sql
        ORDER BY c.$sort $dir
    ");
    $cases_stmt->execute($params);
    $cases = $cases_stmt->fetchAll(PDO::FETCH_ASSOC);
    cache_set($cache_key, $cases, 60);
}

// Stats — scoped by role
if (is_admin()) {
    $total_cases = (int)$pdo->query("SELECT COUNT(*) FROM cases")->fetchColumn();
    $open_cases  = (int)$pdo->query("SELECT COUNT(*) FROM cases WHERE status='open'")->fetchColumn();
    $active_cases= (int)$pdo->query("SELECT COUNT(*) FROM cases WHERE status='under_investigation'")->fetchColumn();
    $closed_cases= (int)$pdo->query("SELECT COUNT(*) FROM cases WHERE status='closed'")->fetchColumn();
} elseif ($role === 'analyst') {
    $cf = "WHERE id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id=$uid)";
    $total_cases = (int)$pdo->query("SELECT COUNT(*) FROM cases $cf")->fetchColumn();
    $open_cases  = (int)$pdo->query("SELECT COUNT(*) FROM cases $cf AND status='open'")->fetchColumn();
    $active_cases= (int)$pdo->query("SELECT COUNT(*) FROM cases $cf AND status='under_investigation'")->fetchColumn();
    $closed_cases= (int)$pdo->query("SELECT COUNT(*) FROM cases $cf AND status='closed'")->fetchColumn();
} else {
    // Investigators see cases they created or have case_access
    $cf = "WHERE created_by=$uid OR id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id=$uid)";
    $total_cases = (int)$pdo->query("SELECT COUNT(*) FROM cases $cf")->fetchColumn();
    $open_cases  = (int)$pdo->query("SELECT COUNT(*) FROM cases $cf AND status='open'")->fetchColumn();
    $active_cases= (int)$pdo->query("SELECT COUNT(*) FROM cases $cf AND status='under_investigation'")->fetchColumn();
    $closed_cases= (int)$pdo->query("SELECT COUNT(*) FROM cases $cf AND status='closed'")->fetchColumn();
}

$csrf = csrf_token();

$priority_colors = ['low'=>'gray','medium'=>'blue','high'=>'orange','critical'=>'red'];
$status_colors   = ['open'=>'green','under_investigation'=>'blue','closed'=>'gray','archived'=>'muted'];

function cu($col){global $sort,$dir;$nd=($sort===$col&&$dir==='DESC')?'asc':'desc';return '?'.http_build_query(array_merge($_GET,['sort'=>$col,'dir'=>$nd]));}
function ci($col){global $sort,$dir;if($sort!==$col)return '<i class="fas fa-sort" style="opacity:.3"></i>';return $dir==='DESC'?'<i class="fas fa-sort-down" style="color:var(--gold)"></i>':'<i class="fas fa-sort-up" style="color:var(--gold)"></i>';}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Cases — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.filter-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:14px 18px;margin-bottom:20px;}
.filter-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.filter-row input,.filter-row select{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:8px 12px;font-size:13px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.filter-row input{flex:1;min-width:180px;}
.filter-row input:focus,.filter-row select:focus{border-color:rgba(201,168,76,0.5);}
.filter-row select option{background:var(--surface2);}
.stats-mini{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:20px;}
.sm-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:14px 16px;text-align:center;text-decoration:none;transition:border-color .2s;}
.sm-card:hover{border-color:var(--border2);}
.sm-val{font-family:'Space Grotesk',sans-serif;font-size:22px;font-weight:700;color:var(--text);}
.sm-lbl{font-size:11.5px;color:var(--muted);margin-top:3px;}
.sort-th{cursor:pointer;display:flex;align-items:center;gap:5px;color:var(--muted);text-decoration:none;}
.sort-th:hover{color:var(--text);}
.dc-table{table-layout:fixed;width:100%}
.dc-table th:nth-child(1){width:120px}
.dc-table th:nth-child(2){width:auto}
.dc-table th:nth-child(3){width:120px}
.dc-table th:nth-child(4){width:100px}
.dc-table th:nth-child(5){width:80px}
.dc-table th:nth-child(6){width:120px}
.dc-table th:nth-child(7){width:100px}
.dc-table th:nth-child(8){width:110px}
/* modal */
.overlay{position:fixed;inset:0;z-index:300;background:rgba(4,8,18,.9);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;padding:20px;animation:fi .2s ease;}
@keyframes fi{from{opacity:0}to{opacity:1}}
.modal{background:var(--surface);border:1px solid var(--border2);border-radius:var(--radius-lg);width:100%;max-width:500px;max-height:90vh;overflow-y:auto;animation:up .3s cubic-bezier(.22,.68,0,1.15);}
@keyframes up{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
.modal-head{padding:22px 26px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;}
.modal-head h3{font-family:'Space Grotesk',sans-serif;font-size:17px;font-weight:600;color:var(--text);}
.modal-head h3 span{color:var(--gold);}
.modal-body{padding:22px 26px;}
.modal-foot{padding:14px 26px 22px;display:flex;gap:10px;justify-content:flex-end;}
.xbtn{background:none;border:none;color:var(--muted);font-size:15px;cursor:pointer;padding:3px 5px;border-radius:5px;transition:all .2s;}
.xbtn:hover{color:var(--danger);}
.field{margin-bottom:14px;}
.field label{display:block;font-size:11px;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px;}
.field input,.field select,.field textarea{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:9px;padding:10px 13px;font-size:13.5px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.field input:focus,.field select:focus,.field textarea:focus{border-color:rgba(201,168,76,0.5);}
.field select option{background:var(--surface2);}
.field textarea{resize:vertical;min-height:80px;}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
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
        <h1 style="margin-top:8px;">Cases</h1>
        <p><?= $total_cases ?> total &nbsp;·&nbsp; <?= $open_cases ?> open &nbsp;·&nbsp; <?= $active_cases ?> under investigation</p>
    </div>
    <?php if (in_array($role,['admin','investigator'])): ?>
    <button class="btn btn-gold" onclick="document.getElementById('createModal').style.display='flex'">
        <i class="fas fa-folder-plus"></i> New Case
    </button>
    <?php endif; ?>
</div>

<?php if ($msg): ?><div class="alert alert-success"><i class="fas fa-circle-check"></i> <?= $msg ?></div><?php endif; ?>
<?php if ($err): ?><div class="alert alert-danger"><i class="fas fa-circle-exclamation"></i> <?= e($err) ?></div><?php endif; ?>

<!-- Stats -->
<div class="stats-mini">
    <a href="cases.php" class="sm-card"><p class="sm-val"><?= $total_cases ?></p><p class="sm-lbl">Total Cases</p></a>
    <a href="cases.php?status=open" class="sm-card"><p class="sm-val" style="color:var(--success)"><?= $open_cases ?></p><p class="sm-lbl">Open</p></a>
    <a href="cases.php?status=under_investigation" class="sm-card"><p class="sm-val" style="color:var(--info)"><?= $active_cases ?></p><p class="sm-lbl">Under Investigation</p></a>
    <a href="cases.php?status=closed" class="sm-card"><p class="sm-val" style="color:var(--muted)"><?= $closed_cases ?></p><p class="sm-lbl">Closed</p></a>
</div>

<!-- Filters -->
<div class="filter-wrap">
    <form method="GET" id="filterForm">
        <div class="filter-row">
            <input type="text" name="search" id="searchInput" placeholder="Search case number, title..." value="<?= e($search) ?>">
            <select name="status" onchange="this.form.submit()">
                <option value="">All Statuses</option>
                <?php foreach(['open','under_investigation','closed','archived'] as $s): ?>
                <option value="<?= $s ?>" <?= $filter_status===$s?'selected':'' ?>><?= ucwords(str_replace('_',' ',$s)) ?></option>
                <?php endforeach; ?>
            </select>
            <select name="priority" onchange="this.form.submit()">
                <option value="">All Priorities</option>
                <?php foreach(['low','medium','high','critical'] as $p): ?>
                <option value="<?= $p ?>" <?= $filter_priority===$p?'selected':'' ?>><?= ucfirst($p) ?></option>
                <?php endforeach; ?>
            </select>
            <input type="hidden" name="sort" value="<?= e($sort) ?>">
            <input type="hidden" name="dir"  value="<?= strtolower($dir) ?>">
            <button type="submit" class="btn btn-gold btn-sm"><i class="fas fa-search"></i> Search</button>
            <?php if ($search||$filter_status||$filter_priority): ?><a href="cases.php" class="btn btn-outline btn-sm"><i class="fas fa-xmark"></i> Clear</a><?php endif; ?>
        </div>
    </form>
</div>

<!-- Table -->
<div class="section-card">
    <?php if (empty($cases)): ?>
    <div class="empty-state"><i class="fas fa-folder-open"></i><p>No cases found.</p></div>
    <?php else: ?>
    <div class="table-responsive"><table class="dc-table">
        <thead><tr>
            <th><a href="<?= cu('case_number') ?>" class="sort-th">Case No. <?= ci('case_number') ?></a></th>
            <th><a href="<?= cu('case_title') ?>" class="sort-th">Title <?= ci('case_title') ?></a></th>
            <th><a href="<?= cu('status') ?>" class="sort-th">Status <?= ci('status') ?></a></th>
            <th><a href="<?= cu('priority') ?>" class="sort-th">Priority <?= ci('priority') ?></a></th>
            <th>Evidence</th>
            <th>Created By</th>
            <th><a href="<?= cu('created_at') ?>" class="sort-th">Date <?= ci('created_at') ?></a></th>
            <th>Actions</th>
        </tr></thead>
        <tbody>
        <?php foreach ($cases as $c):
            // Check if investigator has access to this case
            $inv_has_access = false;
            if ($role === 'investigator') {
                $stmt = $pdo->prepare("SELECT 1 FROM case_access WHERE case_id=? AND user_id=?");
                $stmt->execute([$c['id'], $uid]);
                $inv_has_access = $stmt->fetchColumn() || (int)$c['created_by'] === (int)$uid;
            }
        ?>
        <tr>
            <td data-label="Case No."><a href="case_view.php?id=<?= $c['id'] ?>" style="font-weight:700;font-size:12.5px;color:var(--gold);font-family:'Space Grotesk',sans-serif;text-decoration:none;"><?= e($c['case_number']) ?></a></td>
            <td data-label="Title">
                <a href="case_view.php?id=<?= $c['id'] ?>" style="text-decoration:none;">
                <p style="font-weight:500;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="<?= e($c['case_title']) ?>"><?= e($c['case_title']) ?></p></a>
                <?php if ($c['case_type']): ?><p style="font-size:11px;color:var(--muted)"><?= e($c['case_type']) ?></p><?php endif; ?>
            </td>
            <td data-label="Status"><?= status_badge($c['status']) ?></td>
            <td data-label="Priority"><span class="badge badge-<?= $priority_colors[$c['priority']]??'gray' ?>"><?= ucfirst($c['priority']) ?></span></td>
            <td data-label="Evidence">
                <a href="evidence.php?case=<?= $c['id'] ?>" class="badge badge-<?= $c['evidence_count']>0?'blue':'gray' ?>" style="text-decoration:none">
                    <i class="fas fa-database" style="font-size:9px"></i> <?= $c['evidence_count'] ?>
                </a>
            </td>
            <td data-label="Created By"><span style="font-size:12.5px"><?= e($c['creator_name']) ?></span></td>
            <td data-label="Date"><span style="font-size:12px;color:var(--muted)"><?= date('M j, Y',strtotime($c['created_at'])) ?></span></td>
            <td data-label="Actions">
                <div style="display:flex;gap:6px;flex-wrap:wrap;">
                    <?php if ($role === 'investigator' && !$inv_has_access): ?>
                    <a href="case_view.php?id=<?= $c['id'] ?>" class="btn btn-outline btn-sm" style="opacity:0.5;cursor:not-allowed;" title="Request access or contact an admin" onclick="event.preventDefault();alert('You do not have access to this case. Request access or contact an admin.');">
                        <i class="fas fa-lock"></i> View Case
                    </a>
                    <?php else: ?>
                    <a href="case_view.php?id=<?= $c['id'] ?>" class="btn btn-outline btn-sm">
                        <i class="fas fa-eye"></i> View Case
                    </a>
                    <?php endif; ?>
                    <a href="evidence.php?case=<?= $c['id'] ?>" class="btn btn-outline btn-sm">
                        <i class="fas fa-database"></i> Evidence
                    </a>
                    <?php if ($role==='admin'): ?>
                    <button class="btn btn-outline btn-sm"
                        onclick="openStatusModal(<?= $c['id'] ?>,'<?= $c['status'] ?>')">
                        <i class="fas fa-pen"></i> Status
                    </button>
                    <?php endif; ?>
                </div>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table></div>
    <?php endif; ?>
</div>

</div></div></div>

<!-- Create Case Modal -->
<div class="overlay" id="createModal" style="display:none" onclick="if(event.target===this)this.style.display='none'">
    <div class="modal">
        <div class="modal-head">
            <h3>New <span>Case / Crime Scene</span></h3>
            <button class="xbtn" onclick="document.getElementById('createModal').style.display='none'"><i class="fas fa-xmark"></i></button>
        </div>
        <form method="POST">
            <input type="hidden" name="action"     value="create_case">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <div class="modal-body">
                <div class="field"><label>Case Title *</label><input type="text" name="case_title" placeholder="e.g. Nairobi CBD Cybercrime 2026" required></div>
                <div class="grid-2">
                    <div class="field">
                        <label>Case Type</label>
                        <select name="case_type">
                            <option value="">— Select —</option>
                            <?php foreach(['Cybercrime','Financial Fraud','Identity Theft','Ransomware','Data Breach','Online Harassment','Hacking','Mobile Forensics','Network Intrusion','Other'] as $t): ?>
                            <option><?= $t ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="field">
                        <label>Priority</label>
                        <select name="priority">
                            <option value="low">Low</option>
                            <option value="medium" selected>Medium</option>
                            <option value="high">High</option>
                            <option value="critical">Critical</option>
                        </select>
                    </div>
                </div>
                <div class="field"><label>Description</label><textarea name="description" placeholder="Brief description of the case and crime scene..."></textarea></div>
            </div>
            <div class="modal-foot">
                <button type="button" class="btn btn-outline" onclick="document.getElementById('createModal').style.display='none'">Cancel</button>
                <button type="submit" class="btn btn-gold"><i class="fas fa-folder-plus"></i> Create Case</button>
            </div>
        </form>
    </div>
</div>

<!-- Update Status Modal -->
<div class="overlay" id="statusModal" style="display:none" onclick="if(event.target===this)this.style.display='none'">
    <div class="modal" style="max-width:380px">
        <div class="modal-head">
            <h3>Update <span>Case Status</span></h3>
            <button class="xbtn" onclick="document.getElementById('statusModal').style.display='none'"><i class="fas fa-xmark"></i></button>
        </div>
        <form method="POST">
            <input type="hidden" name="action"     value="update_status">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <input type="hidden" name="case_id"    id="statusCaseId">
            <div class="modal-body">
                <div class="field">
                    <label>New Status</label>
                    <select name="status" id="statusSelect">
                        <option value="open">Open</option>
                        <option value="under_investigation">Under Investigation</option>
                        <option value="closed">Closed</option>
                        <option value="archived">Archived</option>
                    </select>
                </div>
            </div>
            <div class="modal-foot">
                <button type="button" class="btn btn-outline" onclick="document.getElementById('statusModal').style.display='none'">Cancel</button>
                <button type="submit" class="btn btn-gold"><i class="fas fa-save"></i> Update Status</button>
            </div>
        </form>
    </div>
</div>

<script>
function toggleSidebar(){const sb=document.getElementById('sidebar'),ma=document.getElementById('mainArea');if(window.innerWidth<=900){sb.classList.toggle('mobile-open');}else{sb.classList.toggle('collapsed');ma.classList.toggle('collapsed');}localStorage.setItem('sb_collapsed',sb.classList.contains('collapsed')?'1':'0');}
if(localStorage.getItem('sb_collapsed')==='1'&&window.innerWidth>900){document.getElementById('sidebar').classList.add('collapsed');document.getElementById('mainArea').classList.add('collapsed');}
function toggleNotif(){document.getElementById('notifDropdown').classList.toggle('open');document.getElementById('userDropdown').classList.remove('open');}
function toggleUserMenu(){document.getElementById('userDropdown').classList.toggle('open');document.getElementById('notifDropdown').classList.remove('open');}
document.addEventListener('click',function(e){if(!e.target.closest('#notifWrap'))document.getElementById('notifDropdown').classList.remove('open');if(!e.target.closest('#userMenuWrap'))document.getElementById('userDropdown').classList.remove('open');});
function handleSearch(e){if(e.key==='Enter'){window.location='cases.php?search='+encodeURIComponent(document.getElementById('globalSearch').value);}}
function openStatusModal(id,status){
    document.getElementById('statusCaseId').value=id;
    document.getElementById('statusSelect').value=status;
    document.getElementById('statusModal').style.display='flex';
}
var st;var si=document.getElementById('searchInput');
if(si) si.addEventListener('input',function(){clearTimeout(st);st=setTimeout(function(){document.getElementById('filterForm').submit();},500);});
</script>
<script src="../assets/js/main.js"></script>
</body>
</html>
