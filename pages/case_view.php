<?php
/**
 * DigiCustody – Case Detail View
 * Save to: /var/www/html/digicustody/pages/case_view.php
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
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

// Access control: investigators/admins see all, analysts only see assigned cases
if ($role === 'analyst') {
    $has_access = can_see_case($pdo, $id, $uid, $role);
    if (!$has_access) {
        header('Location: cases.php?error=access_denied');
        exit;
    }
} elseif ($role === 'investigator') {
    // Check if investigator has case_access or is the creator
    $stmt = $pdo->prepare("SELECT 1 FROM case_access WHERE case_id=? AND user_id=?");
    $stmt->execute([$id, $uid]);
    $has_access = $stmt->fetchColumn() || (int)$case['created_by'] === (int)$uid;
    if (!$has_access) {
        send_notification($pdo, $uid, 'Access Denied',
            "You attempted to access case {$case['case_number']} without permission.", 'warning', 'case', $id);
        header('Location: cases.php?error=access_denied&msg=You+do+not+have+access+to+this+case.+Access+has+been+logged.');
        exit;
    }
}

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

// Handle analyst assignment (admin only)
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['assign_analyst']) && $role==='admin') {
    if (verify_csrf($_POST['csrf_token']??'')) {
        $analyst_id = (int)($_POST['analyst_id'] ?? 0);
        if ($analyst_id > 0) {
            // Check if user exists and is an analyst (not investigator)
            $chk = $pdo->prepare("SELECT full_name, role FROM users WHERE id=?");
            $chk->execute([$analyst_id]);
            $user = $chk->fetch();
            if (!$user) {
                $assign_error = 'User not found.';
            } elseif ($user['role'] === 'investigator') {
                $assign_error = 'Investigators cannot be assigned as analysts.';
            } elseif ($user['role'] !== 'analyst') {
                $assign_error = 'Only analysts can be assigned as case analysts.';
            } else {
                $analyst = $user;
                $pdo->prepare("UPDATE cases SET assigned_analyst=?,updated_at=NOW() WHERE id=?")->execute([$analyst_id,$id]);
                $case['assigned_analyst'] = $analyst_id;
                grant_case_access($pdo, $id, $analyst_id, $uid);
                send_notification($pdo, $analyst_id, 'Case Assignment',
                    "You have been assigned to case {$case['case_number']}: {$case['case_title']}", 'info', 'case', $id);
                audit_log($pdo,$uid,$_SESSION['username'],$role,'case_updated','case',$id,
                    $case['case_number'],"Assigned analyst: {$analyst['full_name']}");
            }
        } elseif ($analyst_id === 0 && isset($_POST['remove_analyst'])) {
            // Remove analyst assignment
            $old_analyst = $case['assigned_analyst'];
            if ($old_analyst) {
                $pdo->prepare("UPDATE cases SET assigned_analyst=NULL,updated_at=NOW() WHERE id=?")->execute([$id]);
                $case['assigned_analyst'] = null;
                revoke_case_access($pdo, $id, $old_analyst);
                audit_log($pdo,$uid,$_SESSION['username'],$role,'case_updated','case',$id,
                    $case['case_number'],"Removed analyst assignment");
            }
        }
    }
}

// Handle collaborator add/remove (admin and investigators only)
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['collab_action']) && in_array($role, ['admin', 'investigator'])) {
    if (verify_csrf($_POST['csrf_token']??'')) {
        $sub_action = $_POST['sub_action'] ?? '';
        $collab_user_id = (int)($_POST['collab_user_id'] ?? 0);
        
        if ($sub_action === 'add' && $collab_user_id > 0) {
            $access_role = in_array($_POST['access_role'] ?? '', ['analyst', 'collaborator', 'investigator']) 
                ? $_POST['access_role'] : 'analyst';
            $notes = trim($_POST['collab_notes'] ?? '') ?: null;
            
            $chk = $pdo->prepare("SELECT full_name FROM users WHERE id=? AND status='active'");
            $chk->execute([$collab_user_id]);
            $collab = $chk->fetch();
            
            if ($collab) {
                grant_case_access($pdo, $id, $collab_user_id, $uid, $access_role, $notes);
                send_notification($pdo, $collab_user_id, 'Case Collaboration',
                    "You have been added as $access_role to case {$case['case_number']}: {$case['case_title']}" . ($notes ? ". Notes: $notes" : ''), 
                    'info', 'case', $id);
                audit_log($pdo, $uid, $_SESSION['username'], $role, 'case_updated', 'case', $id,
                    $case['case_number'], "Added collaborator: {$collab['full_name']} as $access_role");
            }
        } elseif ($sub_action === 'remove' && $collab_user_id > 0) {
            revoke_case_access($pdo, $id, $collab_user_id);
            audit_log($pdo, $uid, $_SESSION['username'], $role, 'case_updated', 'case', $id,
                $case['case_number'], "Removed collaborator user_id: $collab_user_id");
        }
    }
}

// Fetch analysts for dropdown
$analysts_stmt = $pdo->prepare("SELECT id, full_name, email FROM users WHERE role='analyst' ORDER BY full_name");
$analysts_stmt->execute();
$analysts = $analysts_stmt->fetchAll(PDO::FETCH_ASSOC);

// Fetch current collaborators for this case
$collaborators = get_case_collaborators($pdo, $id);

// Fetch all active users except current user for add-collaborator dropdown
$all_users_stmt = $pdo->prepare("SELECT id, full_name, username, role FROM users WHERE status='active' AND id != ? ORDER BY role, full_name");
$all_users_stmt->execute([$uid]);
$all_users = $all_users_stmt->fetchAll(PDO::FETCH_ASSOC);

// Get currently assigned analyst info
$assigned_analyst_info = null;
if ($case['assigned_analyst']) {
    $stmt = $pdo->prepare("SELECT id, full_name, email FROM users WHERE id=?");
    $stmt->execute([$case['assigned_analyst']]);
    $assigned_analyst_info = $stmt->fetch();
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
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
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
        <button type="button" class="btn-back" onclick="goBack()"><i class="fas fa-arrow-left"></i> Back</button>
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
                <?php if ($assigned_analyst_info): ?>
                <span class="meta-item"><i class="fas fa-user-check" style="color:var(--success)"></i>Analyst: <?= e($assigned_analyst_info['full_name']) ?></span>
                <?php elseif ($role === 'admin'): ?>
                <span class="meta-item"><i class="fas fa-user-clock" style="color:var(--warning)"></i>No analyst assigned</span>
                <?php endif; ?>
            </div>
        </div>

        <!-- Admin: quick status update & analyst assignment -->
        <?php if ($role === 'admin'): ?>
        <?php if (!empty($assign_error)): ?>
        <div style="background:rgba(248,113,113,0.1);border:1px solid rgba(248,113,113,0.3);border-radius:8px;padding:10px 14px;margin-bottom:8px;font-size:13px;color:var(--danger);">
            <i class="fas fa-circle-exclamation" style="margin-right:6px"></i><?= e($assign_error) ?>
        </div>
        <?php endif; ?>
        <div style="display:flex;flex-direction:column;gap:8px;min-width:200px;">
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
                <span style="font-size:12px;color:var(--dim)">Status</span>
            </form>
            <form method="POST" style="display:flex;align-items:center;gap:8px;">
                <input type="hidden" name="csrf_token"      value="<?= $csrf ?>">
                <input type="hidden" name="assign_analyst" value="1">
                <select name="analyst_id" class="status-select" style="flex:1;">
                    <option value="0">-- Remove Analyst --</option>
                    <?php foreach($analysts as $a): ?>
                    <option value="<?= $a['id'] ?>" <?= $case['assigned_analyst']==$a['id']?'selected':'' ?>>
                        <?= e($a['full_name']) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
                <?php if ($case['assigned_analyst']): ?>
                <button type="submit" name="remove_analyst" value="1" class="btn btn-outline btn-sm" title="Remove">
                    <i class="fas fa-xmark"></i>
                </button>
                <?php endif; ?>
                <button type="submit" class="btn btn-gold btn-sm"><i class="fas fa-user-check"></i></button>
            </form>
        </div>
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

<!-- Collaborators Section -->
<div class="section-card" style="margin-bottom:20px;">
    <div class="section-head" style="padding:14px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;">
        <h3 style="display:flex;align-items:center;gap:8px;font-size:15px;font-weight:600;color:var(--text);">
            <i class="fas fa-users" style="color:var(--gold)"></i>
            Collaborators
            <span class="badge badge-gold" style="margin-left:4px"><?= count($collaborators) ?></span>
        </h3>
        <?php if (in_array($role, ['admin', 'investigator'])): ?>
        <button type="button" class="btn btn-gold btn-sm" onclick="openCollabModal()">
            <i class="fas fa-user-plus"></i> Add Collaborator
        </button>
        <?php endif; ?>
    </div>
    <div class="section-body padded">
        <?php if (empty($collaborators)): ?>
        <div class="empty-state" style="padding:20px 0;">
            <i class="fas fa-users"></i>
            <p>No collaborators added to this case yet.</p>
        </div>
        <?php else: ?>
        <div style="display:flex;flex-direction:column;gap:8px;">
            <?php foreach ($collaborators as $collab): 
                $role_colors = ['admin'=>'red','investigator'=>'blue','analyst'=>'green','collaborator'=>'purple'];
                $role_color = $role_colors[$collab['role']] ?? 'gray';
            ?>
            <div style="display:flex;align-items:center;gap:12px;padding:10px 14px;background:var(--surface2);border-radius:var(--radius);">
                <div style="width:36px;height:36px;border-radius:50%;background:var(--gold-dim);display:flex;align-items:center;justify-content:center;color:var(--gold);font-size:13px;">
                    <i class="fas fa-user"></i>
                </div>
                <div style="flex:1;min-width:0;">
                    <p style="font-size:14px;font-weight:500;color:var(--text);"><?= e($collab['full_name']) ?></p>
                    <p style="font-size:12px;color:var(--muted);">
                        <span class="badge badge-<?= $role_color ?>" style="font-size:10px;padding:1px 6px;"><?= ucfirst($collab['role']) ?></span>
                        <span style="margin-left:8px;">Added <?= date('M j, Y', strtotime($collab['granted_at'])) ?></span>
                    </p>
                </div>
                <?php if (in_array($role, ['admin', 'investigator'])): ?>
                <form method="POST" style="display:inline;">
                    <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
                    <input type="hidden" name="collab_action" value="1">
                    <input type="hidden" name="sub_action" value="remove">
                    <input type="hidden" name="collab_user_id" value="<?= $collab['id'] ?>">
                    <button type="submit" class="btn btn-outline btn-sm" onclick="return confirm('Remove this collaborator?')">
                        <i class="fas fa-user-minus"></i> Remove
                    </button>
                </form>
                <?php endif; ?>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>
</div>

<!-- Add Collaborator Modal -->
<div id="collabModal" class="modal-overlay" style="display:none;position:fixed;inset:0;z-index:1000;background:rgba(4,8,18,.85);backdrop-filter:blur(6px);align-items:center;justify-content:center;padding:20px;">
    <div class="section-card" style="max-width:440px;width:100%;animation:up .3s ease;">
        <div class="section-head" style="padding:18px 22px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;">
            <h3 style="font-size:16px;font-weight:600;color:var(--text);"><i class="fas fa-user-plus" style="color:var(--gold);margin-right:8px"></i>Add Collaborator</h3>
            <button type="button" onclick="closeCollabModal()" style="background:none;border:none;color:var(--muted);font-size:18px;cursor:pointer;padding:4px;"><i class="fas fa-xmark"></i></button>
        </div>
        <div class="section-body padded">
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
                <input type="hidden" name="collab_action" value="1">
                <input type="hidden" name="sub_action" value="add">
                
                <div class="field">
                    <label>Select User *</label>
                    <select name="collab_user_id" required>
                        <option value="">-- Choose a user --</option>
                        <?php 
                        $added_ids = array_column($collaborators, 'id');
                        foreach ($all_users as $u): 
                            if (in_array($u['id'], $added_ids)) continue;
                        ?>
                        <option value="<?= $u['id'] ?>"><?= e($u['full_name']) ?> (<?= e($u['username']) ?>) — <?= ucfirst($u['role']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                
                <div class="field">
                    <label>Access Role *</label>
                    <select name="access_role" required>
                        <option value="analyst">Analyst</option>
                        <option value="collaborator">Collaborator</option>
                        <option value="investigator">Investigator</option>
                    </select>
                </div>
                
                <div class="field">
                    <label>Notes (optional)</label>
                    <input type="text" name="collab_notes" placeholder="e.g., External consultant, specific task...">
                </div>
                
                <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:20px;">
                    <button type="button" class="btn btn-outline" onclick="closeCollabModal()">Cancel</button>
                    <button type="submit" class="btn btn-gold"><i class="fas fa-user-plus"></i> Add Collaborator</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
function openCollabModal(){document.getElementById('collabModal').style.display='flex';}
function closeCollabModal(){document.getElementById('collabModal').style.display='none';}
document.getElementById('collabModal').addEventListener('click',function(e){if(e.target===this)closeCollabModal();});
</script>

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
        <div class="table-responsive"><table class="dc-table" style="table-layout:fixed;width:100%">
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
                <td data-label="Evidence No."><span style="font-weight:700;font-size:12.5px;color:var(--gold);font-family:'Space Grotesk',sans-serif"><?= e($ev['evidence_number']) ?></span></td>
                <td data-label="Title">
                    <p style="font-weight:500;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="<?= e($ev['title']) ?>"><?= e($ev['title']) ?></p>
                    <?php if ($ev['description']): ?>
                    <p style="font-size:11px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><?= e(substr($ev['description'],0,40)) ?></p>
                    <?php endif; ?>
                </td>
                <td data-label="Type"><span class="badge badge-blue"><i class="fas <?= $ico ?>" style="font-size:9px"></i> <?= ucfirst(str_replace('_',' ',$ev['evidence_type'])) ?></span></td>
                <td data-label="Uploaded By"><span style="font-size:12.5px"><?= e($ev['uploader_name']) ?></span></td>
                <td data-label="Hashes">
                    <span class="hash-chip" title="SHA-256: <?= e($ev['sha256_hash']) ?>">SHA: <?= e(substr($ev['sha256_hash'],0,14)) ?>...</span>
                    <span class="hash-chip" title="MD5: <?= e($ev['md5_hash']) ?>">MD5: <?= e(substr($ev['md5_hash'],0,14)) ?>...</span>
                </td>
                <td data-label="Size"><span style="font-size:12px;color:var(--muted)"><?= format_filesize($ev['file_size']) ?></span></td>
                <td data-label="Status"><?= status_badge($ev['status']) ?></td>
                <td data-label="Integrity">
                    <?php if ($tampered): ?>
                        <span class="badge badge-red"><i class="fas fa-triangle-exclamation"></i> Tampered</span>
                    <?php elseif ($ev['last_integrity']==='intact'): ?>
                        <span class="badge badge-green"><i class="fas fa-check"></i> Intact</span>
                    <?php else: ?>
                        <span class="badge badge-gray">Unchecked</span>
                    <?php endif; ?>
                </td>
                <td data-label="Reports">
                    <span class="badge <?= (int)$ev['report_count']>0?'badge-green':'badge-gray' ?>">
                        <i class="fas fa-file-lines" style="font-size:9px"></i> <?= (int)$ev['report_count'] ?>
                    </span>
                </td>
                <td data-label="Date"><span style="font-size:11.5px;color:var(--muted)"><?= date('M j, Y',strtotime($ev['uploaded_at'])) ?></span></td>
                <td data-label="Actions">
                    <div style="display:flex;gap:5px;flex-wrap:wrap;">
                        <a href="evidence_view.php?id=<?= $ev['id'] ?>" class="btn btn-outline btn-sm">
                            <i class="fas fa-eye"></i> View
                        </a>
                        <?php if (can_write()): ?>
                        <a href="evidence_download.php?id=<?= $ev['id'] ?>" class="btn btn-download btn-sm">
                            <i class="fas fa-download"></i> Download
                        </a>
                        <?php endif; ?>
                        <?php if (can_report()): ?>
                        <a href="reports.php?evidence_id=<?= $ev['id'] ?>" class="btn btn-gold btn-sm">
                            <i class="fas fa-file-plus"></i> Report
                        </a>
                        <?php endif; ?>
                    </div>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table></div>
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
<script src="../assets/js/main.js"></script>
</body>
</html>
