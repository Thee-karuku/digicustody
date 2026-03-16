<?php
/**
 * DigiCustody – Evidence Transfer Page
 * Save to: /var/www/html/digicustody/pages/evidence_transfer.php
 */
session_start();
require_once __DIR__.'/../config/db.php';
require_once __DIR__.'/../config/functions.php';
require_login();

if (!can_transfer()) {
    header('Location: ../dashboard.php?error=access_denied'); exit;
}

$page_title = 'Transfer Evidence';
$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];
$id   = (int)($_GET['id'] ?? 0);

if (!$id) { header('Location: evidence.php'); exit; }

// Fetch evidence
$stmt = $pdo->prepare("
    SELECT e.*, c.case_number, c.case_title,
           u.full_name AS custodian_name
    FROM evidence e
    JOIN cases c ON c.id = e.case_id
    JOIN users u ON u.id = e.current_custodian
    WHERE e.id = ?
");
$stmt->execute([$id]);
$ev = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$ev) { header('Location: evidence.php?error=not_found'); exit; }

// Only current custodian or admin can initiate transfer
if ((int)$ev['current_custodian'] !== $uid && $role !== 'admin') {
    header('Location: evidence.php?error=not_custodian'); exit;
}

$error = '';

// Handle transfer submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Security token mismatch. Please try again.';
    } else {
        $to_user_id    = (int)($_POST['to_user_id'] ?? 0);
        $reason        = trim($_POST['transfer_reason'] ?? '');
        $notes         = trim($_POST['transfer_notes'] ?? '');
        $verify_hash   = isset($_POST['verify_hash']) ? 1 : 0;

        if (!$to_user_id) {
            $error = 'Please select a recipient user.';
        } elseif ($to_user_id === $uid) {
            $error = 'You cannot transfer evidence to yourself.';
        } elseif (empty($reason)) {
            $error = 'Transfer reason is required.';
        } else {
            // Verify recipient exists
            $chk = $pdo->prepare("SELECT id FROM users WHERE id=? AND status='active'");
            $chk->execute([$to_user_id]);
            if (!$chk->fetch()) {
                $error = 'Selected user not found or inactive.';
            } else {
                // Get current hash for verification record
                $hash_at_transfer = $ev['sha256_hash'];
                if ($verify_hash && file_exists($ev['file_path'])) {
                    $hash_at_transfer = hash_file('sha256', $ev['file_path']);
                }

                // Create transfer record
                $pdo->prepare("INSERT INTO evidence_transfers
                    (evidence_id, from_user, to_user, transfer_reason, transfer_notes,
                     hash_verified, hash_at_transfer, status)
                    VALUES (?,?,?,?,?,?,?,'pending')")
                    ->execute([$id, $uid, $to_user_id, $reason, $notes,
                               $verify_hash, $hash_at_transfer]);

                $transfer_id = $pdo->lastInsertId();

                // Update evidence status
                $pdo->prepare("UPDATE evidence SET status='transferred' WHERE id=?")
                    ->execute([$id]);

                // Notify recipient
                send_notification($pdo, $to_user_id, 'Evidence Transfer Request',
                    "You have a pending custody transfer for {$ev['evidence_number']}: {$ev['title']}",
                    'info', 'evidence_transfer', $transfer_id);

                // Audit log
                audit_log($pdo, $uid, $_SESSION['username'], $role,
                    'evidence_transferred', 'evidence', $id, $ev['evidence_number'],
                    "Evidence {$ev['evidence_number']} transferred to user ID $to_user_id. Reason: $reason",
                    $_SERVER['REMOTE_ADDR'] ?? '',
                    $_SERVER['HTTP_USER_AGENT'] ?? '',
                    ['to_user_id' => $to_user_id, 'hash_verified' => $verify_hash,
                     'hash_at_transfer' => $hash_at_transfer]);

                header('Location: evidence_view.php?id='.$id.'&msg=transfer_sent'); exit;
            }
        }
    }
}

// Fetch eligible recipients (all active users except self)
$recipients = $pdo->prepare("
    SELECT id, full_name, username, role, department
    FROM users
    WHERE status='active' AND id != ?
    ORDER BY role, full_name
");
$recipients->execute([$uid]);
$recipients = $recipients->fetchAll(PDO::FETCH_ASSOC);

// Transfer history for this evidence
$history = $pdo->prepare("
    SELECT et.*,
           uf.full_name AS from_name,
           ut.full_name AS to_name
    FROM evidence_transfers et
    JOIN users uf ON uf.id = et.from_user
    JOIN users ut ON ut.id = et.to_user
    WHERE et.evidence_id = ?
    ORDER BY et.transferred_at DESC
");
$history->execute([$id]);
$history = $history->fetchAll(PDO::FETCH_ASSOC);

$csrf = csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Transfer Evidence — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.ev-info-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-lg);padding:20px;margin-bottom:24px;}
.field{margin-bottom:18px;}
.field label{display:block;font-size:11.5px;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:7px;}
.field input,.field select,.field textarea{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:11px 14px;font-size:14px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.field input:focus,.field select:focus,.field textarea:focus{border-color:rgba(201,168,76,0.5);box-shadow:0 0 0 3px rgba(201,168,76,0.06);}
.field select option{background:var(--surface2);}
.field textarea{resize:vertical;min-height:90px;}
.user-option{display:flex;align-items:center;gap:10px;padding:10px 14px;border:1px solid var(--border);border-radius:var(--radius);cursor:pointer;transition:all .2s;margin-bottom:8px;}
.user-option:hover{border-color:var(--border2);background:var(--surface2);}
.user-option.selected{border-color:var(--gold);background:rgba(201,168,76,0.06);}
.user-option input[type=radio]{display:none;}
.user-avatar-sm{width:36px;height:36px;border-radius:50%;background:var(--gold-dim);border:1px solid rgba(201,168,76,0.2);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;color:var(--gold);flex-shrink:0;}
.user-info{flex:1;}
.user-info .uname{font-size:13.5px;font-weight:500;color:var(--text);}
.user-info .umeta{font-size:12px;color:var(--muted);margin-top:2px;}
.hash-verify-box{background:rgba(201,168,76,0.05);border:1px solid rgba(201,168,76,0.15);border-radius:var(--radius);padding:14px 16px;margin-bottom:18px;}
.hash-verify-box label{display:flex;align-items:center;gap:10px;cursor:pointer;font-size:13.5px;color:var(--text);}
.hash-verify-box input[type=checkbox]{width:16px;height:16px;accent-color:var(--gold);cursor:pointer;}
.transfer-step{display:flex;align-items:flex-start;gap:14px;padding:12px 0;border-bottom:1px solid var(--border);}
.transfer-step:last-child{border-bottom:none;}
.step-num{width:28px;height:28px;border-radius:50%;background:var(--gold-dim);border:1px solid rgba(201,168,76,0.25);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:var(--gold);flex-shrink:0;}
.user-search{margin-bottom:12px;}
.user-search input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:10px 14px;font-size:13.5px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.user-search input:focus{border-color:rgba(201,168,76,0.5);}
.users-list{max-height:280px;overflow-y:auto;padding-right:4px;}
.users-list::-webkit-scrollbar{width:3px;}
.users-list::-webkit-scrollbar-thumb{background:var(--dim);border-radius:3px;}
.timeline-dot{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;flex-shrink:0;}
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
        <h1>Transfer Custody</h1>
        <p>Transfer evidence to another authorized user</p>
    </div>
    <a href="evidence_view.php?id=<?= $id ?>" class="btn btn-outline">
        <i class="fas fa-arrow-left"></i> Back to Evidence
    </a>
</div>

<?php if ($error): ?>
<div class="alert alert-danger"><i class="fas fa-circle-exclamation"></i> <?= e($error) ?></div>
<?php endif; ?>

<!-- Evidence Info Card -->
<div class="ev-info-card">
    <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;">
        <div class="stat-icon gold" style="width:46px;height:46px;border-radius:12px;flex-shrink:0;">
            <i class="fas fa-database"></i>
        </div>
        <div style="flex:1;">
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px;">
                <span style="font-family:'Space Grotesk',sans-serif;font-size:16px;font-weight:700;color:var(--gold)"><?= e($ev['evidence_number']) ?></span>
                <?= status_badge($ev['status']) ?>
            </div>
            <p style="font-size:14px;font-weight:500;color:var(--text);margin-bottom:4px;"><?= e($ev['title']) ?></p>
            <p style="font-size:12.5px;color:var(--muted)">
                <i class="fas fa-folder-open" style="color:var(--gold);margin-right:5px"></i>
                <?= e($ev['case_number']) ?> — <?= e($ev['case_title']) ?>
                &nbsp;·&nbsp;
                <i class="fas fa-user" style="margin-right:5px"></i>
                Current custodian: <strong style="color:var(--text)"><?= e($ev['custodian_name']) ?></strong>
            </p>
        </div>
        <div style="text-align:right;">
            <p style="font-size:11px;color:var(--muted);margin-bottom:4px;">SHA-256</p>
            <p style="font-family:'Courier New',monospace;font-size:11px;color:var(--text);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="<?= e($ev['sha256_hash']) ?>"><?= e($ev['sha256_hash']) ?></p>
        </div>
    </div>
</div>

<div class="grid-2" style="gap:24px;">

    <!-- Transfer Form -->
    <div>
        <div class="section-card">
            <div class="section-head">
                <h2><i class="fas fa-right-left"></i> Transfer Details</h2>
            </div>
            <div class="section-body padded">
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= $csrf ?>">

                    <!-- Step 1: Select recipient -->
                    <div style="margin-bottom:20px;">
                        <p style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:12px;">
                            <span style="background:var(--gold);color:#060d1a;width:20px;height:20px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:11px;margin-right:8px;">1</span>
                            Select recipient
                        </p>
                        <div class="user-search">
                            <input type="text" id="userSearchInput" placeholder="Search by name, username or department..." oninput="filterUsers(this.value)">
                        </div>
                        <div class="users-list" id="usersList">
                            <?php
                            $role_groups = ['admin'=>[], 'investigator'=>[], 'analyst'=>[], 'viewer'=>[]];
                            foreach ($recipients as $u) $role_groups[$u['role']][] = $u;
                            foreach ($role_groups as $grole => $group_users):
                                if (empty($group_users)) continue;
                            ?>
                            <p style="font-size:10.5px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.8px;margin:10px 0 6px;"><?= ucfirst($grole) ?>s</p>
                            <?php foreach ($group_users as $u): ?>
                            <label class="user-option" id="uo_<?= $u['id'] ?>" onclick="selectUser(<?= $u['id'] ?>)">
                                <input type="radio" name="to_user_id" value="<?= $u['id'] ?>" id="ru_<?= $u['id'] ?>">
                                <div class="user-avatar-sm"><?= strtoupper(substr($u['full_name'],0,2)) ?></div>
                                <div class="user-info">
                                    <p class="uname"><?= e($u['full_name']) ?></p>
                                    <p class="umeta">@<?= e($u['username']) ?><?= $u['department'] ? ' · '.e($u['department']) : '' ?></p>
                                </div>
                                <?= role_badge($u['role']) ?>
                            </label>
                            <?php endforeach; endforeach; ?>
                        </div>
                    </div>

                    <!-- Step 2: Reason -->
                    <div style="margin-bottom:20px;">
                        <p style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:12px;">
                            <span style="background:var(--gold);color:#060d1a;width:20px;height:20px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:11px;margin-right:8px;">2</span>
                            Transfer reason
                        </p>
                        <div class="field">
                            <label>Reason for Transfer *</label>
                            <select name="transfer_reason" id="reasonSelect" onchange="checkCustomReason(this.value)" required>
                                <option value="">— Select a reason —</option>
                                <option value="For forensic analysis">For forensic analysis</option>
                                <option value="For court presentation">For court presentation</option>
                                <option value="For further investigation">For further investigation</option>
                                <option value="Handover to supervisor">Handover to supervisor</option>
                                <option value="End of shift handover">End of shift handover</option>
                                <option value="Transfer to specialized unit">Transfer to specialized unit</option>
                                <option value="other">Other (specify below)</option>
                            </select>
                        </div>
                        <div class="field" id="customReasonWrap" style="display:none;">
                            <label>Specify Reason *</label>
                            <input type="text" name="custom_reason" id="customReason" placeholder="Enter your reason...">
                        </div>
                        <div class="field">
                            <label>Additional Notes</label>
                            <textarea name="transfer_notes" placeholder="Any additional notes about this transfer..."></textarea>
                        </div>
                    </div>

                    <!-- Step 3: Integrity check -->
                    <div style="margin-bottom:20px;">
                        <p style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:12px;">
                            <span style="background:var(--gold);color:#060d1a;width:20px;height:20px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:11px;margin-right:8px;">3</span>
                            Integrity verification
                        </p>
                        <div class="hash-verify-box">
                            <label>
                                <input type="checkbox" name="verify_hash" value="1" checked>
                                <div>
                                    <p style="font-weight:500">Verify file integrity before transfer</p>
                                    <p style="font-size:12px;color:var(--muted);margin-top:2px">Recalculates SHA-256 hash and records it at the time of transfer for chain of custody</p>
                                </div>
                            </label>
                        </div>
                    </div>

                    <button type="submit" class="btn btn-gold" style="width:100%;padding:13px;font-size:15px;" onclick="return confirmTransfer()">
                        <i class="fas fa-right-left"></i> Initiate Transfer
                    </button>
                </form>
            </div>
        </div>
    </div>

    <!-- Transfer History + Info -->
    <div>
        <!-- Chain of custody so far -->
        <div class="section-card" style="margin-bottom:20px;">
            <div class="section-head">
                <h2><i class="fas fa-link"></i> Transfer History</h2>
            </div>
            <div class="section-body padded">
                <?php if (empty($history)): ?>
                <div class="empty-state" style="padding:20px 0">
                    <i class="fas fa-link"></i>
                    <p>No transfers yet — this is the first transfer for this evidence.</p>
                </div>
                <?php else: foreach ($history as $h):
                    $status_colors = ['pending'=>'warning','accepted'=>'green','rejected'=>'red'];
                    $sc = $status_colors[$h['status']] ?? 'gray';
                ?>
                <div class="transfer-step">
                    <div class="timeline-dot stat-icon <?= $sc ?>">
                        <i class="fas <?= $h['status']==='accepted'?'fa-check':($h['status']==='rejected'?'fa-xmark':'fa-clock') ?>"></i>
                    </div>
                    <div style="flex:1;">
                        <p style="font-size:13.5px;font-weight:500;color:var(--text);">
                            <?= e($h['from_name']) ?> <i class="fas fa-arrow-right" style="font-size:10px;color:var(--muted)"></i> <?= e($h['to_name']) ?>
                        </p>
                        <p style="font-size:12px;color:var(--muted);margin-top:3px"><?= e($h['transfer_reason']) ?></p>
                        <div style="display:flex;gap:8px;margin-top:5px;flex-wrap:wrap;">
                            <span class="badge badge-<?= $sc ?>"><?= ucfirst($h['status']) ?></span>
                            <span style="font-size:11.5px;color:var(--dim)"><?= date('M j, Y H:i', strtotime($h['transferred_at'])) ?></span>
                        </div>
                    </div>
                </div>
                <?php endforeach; endif; ?>
            </div>
        </div>

        <!-- Transfer guidelines -->
        <div class="section-card">
            <div class="section-head"><h2><i class="fas fa-circle-info"></i> Transfer Guidelines</h2></div>
            <div class="section-body padded">
                <div style="display:flex;flex-direction:column;gap:12px;">
                    <div style="display:flex;gap:10px;font-size:13px;">
                        <i class="fas fa-shield-check" style="color:var(--success);margin-top:2px;flex-shrink:0"></i>
                        <p style="color:var(--muted)">Always verify integrity before transferring to ensure the file has not been altered since collection.</p>
                    </div>
                    <div style="display:flex;gap:10px;font-size:13px;">
                        <i class="fas fa-scroll" style="color:var(--gold);margin-top:2px;flex-shrink:0"></i>
                        <p style="color:var(--muted)">All transfers are permanently recorded in the audit log and chain of custody timeline.</p>
                    </div>
                    <div style="display:flex;gap:10px;font-size:13px;">
                        <i class="fas fa-user-check" style="color:var(--info);margin-top:2px;flex-shrink:0"></i>
                        <p style="color:var(--muted)">The recipient must accept the transfer to become the new custodian.</p>
                    </div>
                    <div style="display:flex;gap:10px;font-size:13px;">
                        <i class="fas fa-triangle-exclamation" style="color:var(--warning);margin-top:2px;flex-shrink:0"></i>
                        <p style="color:var(--muted)">Evidence status will be set to "Transferred" until the recipient accepts.</p>
                    </div>
                </div>
            </div>
        </div>
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

function selectUser(id){
    document.querySelectorAll('.user-option').forEach(el=>el.classList.remove('selected'));
    document.getElementById('uo_'+id)?.classList.add('selected');
    document.getElementById('ru_'+id).checked=true;
}

function filterUsers(val){
    val=val.toLowerCase();
    document.querySelectorAll('.user-option').forEach(el=>{
        el.style.display=el.textContent.toLowerCase().includes(val)?'':'none';
    });
}

function checkCustomReason(val){
    const wrap=document.getElementById('customReasonWrap');
    const input=document.getElementById('customReason');
    if(val==='other'){wrap.style.display='block';input.required=true;}
    else{wrap.style.display='none';input.required=false;}
}

function confirmTransfer(){
    const sel=document.querySelector('input[name="to_user_id"]:checked');
    if(!sel){alert('Please select a recipient user.');return false;}
    const reason=document.getElementById('reasonSelect').value;
    if(!reason){alert('Please select a transfer reason.');return false;}
    const uname=document.getElementById('uo_'+sel.value)?.querySelector('.uname')?.textContent||'selected user';
    return confirm('Transfer this evidence to '+uname+'?\n\nThis will be permanently recorded in the chain of custody.');
}
</script>
</body>
</html>
