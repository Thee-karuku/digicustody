<?php
/**
 * DigiCustody – Evidence Transfer Page
 * Handles transfer initiation, acceptance, and rejection
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login($pdo);

$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];
$id   = (int)($_GET['id'] ?? 0);

if (!$id) { header('Location: evidence.php'); exit; }

$access = validate_evidence_access($pdo, $id, $uid, $role);
if (!$access['allowed']) {
    header('Location: evidence.php?error=access_denied'); exit;
}

$stmt = $pdo->prepare("
    SELECT e.*, u.full_name AS custodian_name, c.case_number, c.case_title, c.status AS case_status
    FROM evidence e
    JOIN users u ON u.id = e.current_custodian
    JOIN cases c ON c.id = e.case_id
    WHERE e.id = ?
");
$stmt->execute([$id]);
$ev = $stmt->fetch();
if (!$ev) { header('Location: evidence.php?error=not_found'); exit; }

if ($ev['status'] === 'flagged') {
    header('Location: evidence_view.php?id='.$id.'&error=flagged_integrity&msg='.urlencode('This evidence is flagged for an integrity issue and cannot be transferred until an admin reviews it.')); exit;
}

if (in_array($ev['case_status'], ['closed', 'archived'])) {
    header('Location: evidence_view.php?id='.$id.'&error=transfer_not_allowed&msg='.urlencode('Transfers are not permitted on closed cases.')); exit;
}

$transfer_action = $_GET['action'] ?? 'initiate';
$error = '';
$success = '';

if ($transfer_action === 'initiate' && can_transfer()) {
    if ((int)$ev['current_custodian'] !== $uid && !is_admin()) {
        header('Location: evidence_view.php?id='.$id.'&error=not_custodian'); exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['transfer_action'] ?? '') === 'create') {
        require_csrf();

        if (!rate_limit_check($pdo, 'transfer_create', $uid, 10, 300)) {
            $error = 'Too many transfer attempts. Please wait a few minutes.';
        } else {
            $to_user       = (int)($_POST['to_user'] ?? 0);
            $transfer_reason = trim($_POST['transfer_reason'] ?? '');
            $transfer_notes  = trim($_POST['transfer_notes'] ?? '');
            $hash_verify     = isset($_POST['hash_verify']) ? 1 : 0;

            if ($to_user <= 0) {
                $error = 'Please select a recipient.';
            } elseif ($to_user === $uid) {
                $error = 'You cannot transfer evidence to yourself.';
            } elseif (empty($transfer_reason)) {
                $error = 'Transfer reason is required.';
            } elseif (strlen($transfer_reason) > 500) {
                $error = 'Transfer reason must not exceed 500 characters.';
            } else {
                $stmt = $pdo->prepare("SELECT id, full_name, role, status FROM users WHERE id = ? AND status = 'active'");
                $stmt->execute([$to_user]);
                $recipient = $stmt->fetch();

                if (!$recipient) {
                    $error = 'Selected recipient does not exist or is inactive.';
                } elseif (!in_array($recipient['role'], ['admin', 'investigator', 'analyst'])) {
                    $error = 'Evidence can only be transferred to Admin, Investigator, or Analyst roles.';
                } else {
                    $hash_at_transfer = null;
                    if ($hash_verify && file_exists($ev['file_path'])) {
                        $hash_at_transfer = hash_file('sha256', $ev['file_path']);
                    }

                    $pdo->prepare("
                        INSERT INTO evidence_transfers (evidence_id, from_user, to_user, transfer_reason, transfer_notes, hash_verified, hash_at_transfer, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
                    ")->execute([$id, $uid, $to_user, $transfer_reason, $transfer_notes ?: null, $hash_verify, $hash_at_transfer]);

                    $transfer_id = $pdo->lastInsertId();

                    audit_log($pdo, $uid, $_SESSION['username'], $role, 'evidence_transferred',
                        'evidence', $id, $ev['evidence_number'],
                        "Transfer initiated: {$ev['evidence_number']} -> {$recipient['full_name']}",
                        $_SERVER['REMOTE_ADDR'] ?? '', '', [
                            'transfer_id' => $transfer_id,
                            'to_user' => $to_user,
                            'reason' => $transfer_reason,
                            'hash_verified' => $hash_verify,
                        ]);

                    send_notification($pdo, $to_user, 'Evidence Transfer Request',
                        "You have received a custody transfer request for evidence {$ev['evidence_number']} — {$ev['title']}. Reason: {$transfer_reason}",
                        'warning', 'evidence_transfer', $transfer_id);

                    send_notification($pdo, $uid, 'Transfer Initiated',
                        "Your transfer request for evidence {$ev['evidence_number']} has been sent to {$recipient['full_name']}.",
                        'info', 'evidence_transfer', $transfer_id);

                    header("Location: evidence_transfer.php?id=$id&action=success&transfer_id=$transfer_id"); exit;
                }
            }
        }
    }

    $stmt = $pdo->prepare("SELECT id, full_name, role, department FROM users WHERE status = 'active' AND id != ? AND role IN ('admin','investigator','analyst') ORDER BY full_name");
    $stmt->execute([$uid]);
    $eligible_users = $stmt->fetchAll();

    $stmt = $pdo->prepare("
        SELECT et.*, u_from.full_name AS from_name, u_to.full_name AS to_name
        FROM evidence_transfers et
        JOIN users u_from ON u_from.id = et.from_user
        JOIN users u_to ON u_to.id = et.to_user
        WHERE et.evidence_id = ?
        ORDER BY et.transferred_at DESC
    ");
    $stmt->execute([$id]);
    $transfer_history = $stmt->fetchAll();

} elseif ($transfer_action === 'accept' || $transfer_action === 'reject') {
    $transfer_id = (int)($_POST['transfer_id'] ?? 0);
    if ($transfer_id <= 0) { header('Location: evidence_view.php?id='.$id); exit; }

    $stmt = $pdo->prepare("SELECT * FROM evidence_transfers WHERE id = ? AND evidence_id = ? AND status = 'pending'");
    $stmt->execute([$transfer_id, $id]);
    $transfer = $stmt->fetch();

    if (!$transfer) {
        header('Location: evidence_view.php?id='.$id.'&error=transfer_not_found'); exit;
    }

    if ((int)$transfer['to_user'] !== $uid && !is_admin()) {
        header('Location: evidence_view.php?id='.$id.'&error=access_denied'); exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['confirm_action'])) {
        require_csrf();

        $confirm_action = $_POST['confirm_action'];
        $rejection_reason = trim($_POST['rejection_reason'] ?? '');

        if ($confirm_action === 'accept') {
            $pdo->beginTransaction();
            try {
                $pdo->prepare("
                    UPDATE evidence_transfers SET status = 'accepted', accepted_at = NOW(), accepted_by = ?
                    WHERE id = ?
                ")->execute([$uid, $transfer_id]);

                // Check status transition
                if (!can_change_evidence_status($ev['status'], 'transferred')) {
                    $error = 'Cannot transfer evidence from ' . $ev['status'] . ' status.';
                    return;
                }
                
                $pdo->prepare("UPDATE evidence SET current_custodian = ?, status = 'transferred' WHERE id = ?")
                    ->execute([$uid, $id]);

                audit_log($pdo, $uid, $_SESSION['username'], $role, 'evidence_transfer_accepted',
                    'evidence', $id, $ev['evidence_number'],
                    "Transfer accepted: {$ev['evidence_number']} from {$transfer['from_user']}",
                    $_SERVER['REMOTE_ADDR'] ?? '', '', [
                        'transfer_id' => $transfer_id,
                    ]);

                send_notification($pdo, $transfer['from_user'], 'Transfer Accepted',
                    "Your transfer request for evidence {$ev['evidence_number']} has been accepted by you.",
                    'success', 'evidence_transfer', $transfer_id);

                $pdo->commit();
                header("Location: evidence_transfer.php?id=$id&action=accepted&transfer_id=$transfer_id"); exit;
            } catch (Exception $e) {
                $pdo->rollBack();
                $error = 'Failed to accept transfer. Please try again.';
            }
        } elseif ($confirm_action === 'reject') {
            if (empty($rejection_reason)) {
                $error = 'Rejection reason is required.';
            } else {
                $pdo->prepare("
                    UPDATE evidence_transfers SET status = 'rejected', rejection_reason = ?
                    WHERE id = ?
                ")->execute([$rejection_reason, $transfer_id]);

                audit_log($pdo, $uid, $_SESSION['username'], $role, 'evidence_transfer_rejected',
                    'evidence', $id, $ev['evidence_number'],
                    "Transfer rejected: {$ev['evidence_number']}",
                    $_SERVER['REMOTE_ADDR'] ?? '', '', [
                        'transfer_id' => $transfer_id,
                        'reason' => $rejection_reason,
                    ]);

                send_notification($pdo, $transfer['from_user'], 'Transfer Rejected',
                    "Your transfer request for evidence {$ev['evidence_number']} has been rejected. Reason: {$rejection_reason}",
                    'danger', 'evidence_transfer', $transfer_id);

                header("Location: evidence_transfer.php?id=$id&action=rejected&transfer_id=$transfer_id"); exit;
            }
        }
    }

    $stmt = $pdo->prepare("
        SELECT et.*, u_from.full_name AS from_name, u_to.full_name AS to_name
        FROM evidence_transfers et
        JOIN users u_from ON u_from.id = et.from_user
        JOIN users u_to ON u_to.id = et.to_user
        WHERE et.evidence_id = ?
        ORDER BY et.transferred_at DESC
    ");
    $stmt->execute([$id]);
    $transfer_history = $stmt->fetchAll();

} elseif ($transfer_action === 'success' || $transfer_action === 'accepted' || $transfer_action === 'rejected') {
    $stmt = $pdo->prepare("
        SELECT et.*, u_from.full_name AS from_name, u_to.full_name AS to_name
        FROM evidence_transfers et
        JOIN users u_from ON u_from.id = et.from_user
        JOIN users u_to ON u_to.id = et.to_user
        WHERE et.evidence_id = ?
        ORDER BY et.transferred_at DESC
    ");
    $stmt->execute([$id]);
    $transfer_history = $stmt->fetchAll();
}

$page_title = 'Transfer — ' . $ev['evidence_number'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title><?= e($page_title) ?> — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.transfer-card { background: var(--surface2); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; margin-bottom: 16px; }
.transfer-card.pending { border-left: 3px solid #f59e0b; }
.transfer-card.accepted { border-left: 3px solid #3ecf8e; }
.transfer-card.rejected { border-left: 3px solid #ef4444; }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; margin-bottom: 6px; }
.form-group input, .form-group select, .form-group textarea {
    width: 100%; padding: 10px 14px; background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; color: var(--text); font-size: 14px; font-family: 'Inter', sans-serif;
    transition: border-color .2s;
}
.form-group input:focus, .form-group select:focus, .form-group textarea:focus {
    outline: none; border-color: var(--gold);
}
.form-group textarea { resize: vertical; min-height: 80px; }
.form-group select { cursor: pointer; }
.checkbox-group { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; }
.checkbox-group input[type="checkbox"] { width: 18px; height: 18px; accent-color: var(--gold); cursor: pointer; }
.checkbox-group label { font-size: 13px; color: var(--text); cursor: pointer; }
.evidence-summary { display: flex; align-items: center; gap: 16px; padding: 16px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 20px; }
.evidence-summary .es-icon { width: 48px; height: 48px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 20px; background: rgba(201,168,76,0.1); color: var(--gold); flex-shrink: 0; }
.evidence-summary .es-info h3 { font-size: 15px; font-weight: 600; color: var(--text); margin-bottom: 2px; }
.evidence-summary .es-info p { font-size: 12px; color: var(--muted); }
.transfer-timeline { position: relative; padding-left: 30px; }
.transfer-timeline::before { content: ''; position: absolute; left: 14px; top: 0; bottom: 0; width: 2px; background: var(--border); }
.transfer-timeline-item { position: relative; padding-bottom: 20px; }
.transfer-timeline-item:last-child { padding-bottom: 0; }
.transfer-timeline-dot {
    position: absolute; left: -23px; top: 4px; width: 24px; height: 24px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center; font-size: 10px; border: 2px solid;
}
.transfer-timeline-dot.pending { background: rgba(245,158,11,0.15); border-color: #f59e0b; color: #f59e0b; }
.transfer-timeline-dot.accepted { background: rgba(62,207,142,0.15); border-color: #3ecf8e; color: #3ecf8e; }
.transfer-timeline-dot.rejected { background: rgba(239,68,68,0.15); border-color: #ef4444; color: #ef4444; }
.transfer-meta { font-size: 12px; color: var(--muted); margin-top: 4px; }
.transfer-reason { font-size: 12px; color: var(--dim); font-style: italic; margin-top: 4px; }
.btn-group { display: flex; gap: 10px; margin-top: 20px; }
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
        <h1><i class="fas fa-right-left" style="color:var(--gold);margin-right:10px"></i>Evidence Transfer</h1>
        <p><?= e($ev['evidence_number']) ?> — <?= e($ev['title']) ?></p>
    </div>
    <div style="display:flex;gap:10px;">
        <a href="evidence_view.php?id=<?= $id ?>" class="btn-back"><i class="fas fa-arrow-left"></i> Back to Details</a>
    </div>
</div>

<?php if ($error): ?>
<div class="alert alert-danger"><i class="fas fa-circle-xmark"></i> <?= e($error) ?></div>
<?php endif; ?>

<?php if ($transfer_action === 'success'): ?>
<div class="alert alert-success"><i class="fas fa-circle-check"></i> Transfer request sent successfully. The recipient will be notified and can accept or reject the transfer.</div>
<?php elseif ($transfer_action === 'accepted'): ?>
<div class="alert alert-success"><i class="fas fa-circle-check"></i> You have accepted this transfer. Custody has been updated.</div>
<?php elseif ($transfer_action === 'rejected'): ?>
<div class="alert alert-warning"><i class="fas fa-triangle-exclamation"></i> Transfer has been rejected.</div>
<?php endif; ?>

<div class="evidence-summary">
    <div class="es-icon"><i class="fas fa-file-shield"></i></div>
    <div class="es-info">
        <h3><?= e($ev['title']) ?></h3>
        <p><?= e($ev['evidence_number']) ?> &nbsp;·&nbsp; <?= e($ev['case_number']) ?> &nbsp;·&nbsp; Current custodian: <?= e($ev['custodian_name']) ?></p>
    </div>
    <?= status_badge($ev['status']) ?>
</div>

<?php if ($transfer_action === 'initiate' && can_transfer()): ?>

<div class="transfer-card">
    <h3 style="font-size:15px;font-weight:600;color:var(--text);margin-bottom:16px;"><i class="fas fa-paper-plane" style="color:var(--gold);margin-right:8px"></i>Initiate Transfer</h3>
    <form method="POST">
        <?= generate_csrf_input() ?>
        <input type="hidden" name="transfer_action" value="create">

        <div class="form-group">
            <label for="to_user">Transfer To <span style="color:var(--danger)">*</span></label>
            <select name="to_user" id="to_user" required>
                <option value="">— Select recipient —</option>
                <?php foreach ($eligible_users as $u): ?>
                <option value="<?= $u['id'] ?>"><?= e($u['full_name']) ?> (<?= e(ucfirst($u['role'])) ?><?= $u['department'] ? ' — '.e($u['department']) : '' ?>)</option>
                <?php endforeach; ?>
            </select>
        </div>

        <div class="form-group">
            <label for="transfer_reason">Transfer Reason <span style="color:var(--danger)">*</span></label>
            <textarea name="transfer_reason" id="transfer_reason" required maxlength="500" placeholder="Why is this evidence being transferred?"></textarea>
        </div>

        <div class="form-group">
            <label for="transfer_notes">Additional Notes</label>
            <textarea name="transfer_notes" id="transfer_notes" placeholder="Any additional context or instructions (optional)"></textarea>
        </div>

        <div class="checkbox-group">
            <input type="checkbox" name="hash_verify" id="hash_verify" checked>
            <label for="hash_verify">Verify and record SHA-256 hash at time of transfer</label>
        </div>

        <div class="btn-group">
            <button type="submit" class="btn btn-gold"><i class="fas fa-paper-plane"></i> Initiate Transfer</button>
            <a href="evidence_view.php?id=<?= $id ?>" class="btn btn-outline">Cancel</a>
        </div>
    </form>
</div>

<?php elseif ($transfer_action === 'accept' || $transfer_action === 'reject'): ?>

<?php if ($transfer && $error === ''): ?>
<div class="transfer-card pending">
    <h3 style="font-size:15px;font-weight:600;color:var(--text);margin-bottom:12px;">
        <i class="fas fa-<?= $transfer_action === 'accept' ? 'circle-check' : 'circle-xmark' ?>" style="color:<?= $transfer_action === 'accept' ? 'var(--success)' : 'var(--danger)' ?>;margin-right:8px"></i>
        <?= $transfer_action === 'accept' ? 'Accept' : 'Reject' ?> Transfer
    </h3>
    <p style="font-size:13px;color:var(--muted);margin-bottom:16px;">
        Transfer from <strong style="color:var(--text)"><?= e($transfer['from_name']) ?></strong>
        &nbsp;·&nbsp; Requested: <?= date('M j, Y H:i', strtotime($transfer['transferred_at'])) ?>
    </p>
    <div style="background:var(--surface);border-radius:8px;padding:12px 16px;margin-bottom:16px;">
        <p style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;">Reason</p>
        <p style="font-size:13px;color:var(--text);"><?= e($transfer['transfer_reason']) ?></p>
        <?php if ($transfer['transfer_notes']): ?>
        <p style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;margin-top:10px;">Notes</p>
        <p style="font-size:13px;color:var(--dim);"><?= nl2br(e($transfer['transfer_notes'])) ?></p>
        <?php endif; ?>
        <?php if ($transfer['hash_verified'] && $transfer['hash_at_transfer']): ?>
        <p style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;margin-top:10px;">SHA-256 at transfer</p>
        <p style="font-size:11px;color:var(--text);font-family:'Courier New',monospace;word-break:break-all;"><?= e($transfer['hash_at_transfer']) ?></p>
        <?php endif; ?>
    </div>
    <form method="POST">
        <?= generate_csrf_input() ?>
        <input type="hidden" name="transfer_id" value="<?= $transfer['id'] ?>">
        <input type="hidden" name="confirm_action" value="<?= $transfer_action ?>">
        <?php if ($transfer_action === 'reject'): ?>
        <div class="form-group">
            <label for="rejection_reason">Rejection Reason <span style="color:var(--danger)">*</span></label>
            <textarea name="rejection_reason" id="rejection_reason" required placeholder="Why is this transfer being rejected?"></textarea>
        </div>
        <?php endif; ?>
        <div class="btn-group">
            <button type="submit" class="btn btn-<?= $transfer_action === 'accept' ? 'gold' : 'danger' ?>">
                <i class="fas fa-<?= $transfer_action === 'accept' ? 'check' : 'xmark' ?>"></i>
                Confirm <?= ucfirst($transfer_action) ?>
            </button>
            <a href="evidence_view.php?id=<?= $id ?>" class="btn btn-outline">Cancel</a>
        </div>
    </form>
</div>
<?php endif; ?>

<?php endif; ?>

<?php if (!empty($transfer_history)): ?>
<div class="section-card" style="margin-top:20px;">
    <div class="section-header"><h3><i class="fas fa-clock-rotate-left" style="color:var(--gold);margin-right:8px"></i>Transfer History</h3></div>
    <div class="section-body padded">
        <div class="transfer-timeline">
            <?php foreach ($transfer_history as $th): ?>
            <div class="transfer-timeline-item">
                <div class="transfer-timeline-dot <?= $th['status'] ?>">
                    <i class="fas fa-<?= $th['status'] === 'accepted' ? 'check' : ($th['status'] === 'rejected' ? 'xmark' : 'clock') ?>"></i>
                </div>
                <div class="transfer-card <?= $th['status'] ?>" style="margin-bottom:0;">
                    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
                        <div>
                            <span style="font-size:13px;font-weight:600;color:var(--text);">
                                <?= e($th['from_name']) ?> <i class="fas fa-arrow-right" style="color:var(--muted);margin:0 6px;font-size:11px;"></i> <?= e($th['to_name']) ?>
                            </span>
                            <?= status_badge($th['status']) ?>
                        </div>
                        <span style="font-size:11px;color:var(--muted);"><?= date('M j, Y H:i', strtotime($th['transferred_at'])) ?></span>
                    </div>
                    <p class="transfer-reason" style="margin-top:8px;"><i class="fas fa-quote-left" style="margin-right:4px;opacity:.5;"></i><?= e($th['transfer_reason']) ?></p>
                    <?php if ($th['status'] === 'accepted' && $th['accepted_at']): ?>
                    <p class="transfer-meta">Accepted: <?= date('M j, Y H:i', strtotime($th['accepted_at'])) ?></p>
                    <?php endif; ?>
                    <?php if ($th['status'] === 'rejected' && $th['rejection_reason']): ?>
                    <p class="transfer-meta" style="color:var(--danger);">Rejection reason: <?= e($th['rejection_reason']) ?></p>
                    <?php endif; ?>
                    <?php if ($th['hash_verified'] && $th['hash_at_transfer']): ?>
                    <p class="transfer-meta">SHA-256: <span style="font-family:'Courier New',monospace;"><?= e($th['hash_at_transfer']) ?></span></p>
                    <?php endif; ?>
                    <?php if ($th['transfer_notes']): ?>
                    <p class="transfer-meta" style="margin-top:4px;"><?= nl2br(e($th['transfer_notes'])) ?></p>
                    <?php endif; ?>
                    <?php if ($th['status'] === 'pending' && ((int)$th['to_user'] === $uid || is_admin())): ?>
                    <div style="display:flex;gap:8px;margin-top:10px;">
                        <a href="evidence_transfer.php?id=<?= $id ?>&action=accept" class="btn btn-gold btn-sm"><i class="fas fa-check"></i> Accept</a>
                        <a href="evidence_transfer.php?id=<?= $id ?>&action=reject" class="btn btn-danger btn-sm"><i class="fas fa-xmark"></i> Reject</a>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>
<?php endif; ?>

</div></div></div>
<script>
function toggleSidebar(){const sb=document.getElementById('sidebar'),ma=document.getElementById('mainArea');if(window.innerWidth<=900){sb.classList.toggle('mobile-open');}else{sb.classList.toggle('collapsed');ma.classList.toggle('collapsed');}localStorage.setItem('sb_collapsed',sb.classList.contains('collapsed')?'1':'0');}
if(localStorage.getItem('sb_collapsed')==='1'&&window.innerWidth>900){document.getElementById('sidebar').classList.add('collapsed');document.getElementById('mainArea').classList.add('collapsed');}
function toggleNotif(){document.getElementById('notifDropdown').classList.toggle('open');document.getElementById('userDropdown').classList.remove('open');}
function toggleUserMenu(){document.getElementById('userDropdown').classList.toggle('open');document.getElementById('notifDropdown').classList.remove('open');}
document.addEventListener('click',e=>{if(!e.target.closest('#notifWrap'))document.getElementById('notifDropdown').classList.remove('open');if(!e.target.closest('#userMenuWrap'))document.getElementById('userDropdown').classList.remove('open');});
function handleSearch(e){if(e.key==='Enter'){window.location='evidence.php?search='+encodeURIComponent(document.getElementById('globalSearch').value);}}
</script>
<script src="../assets/js/main.js"></script>
</body>
</html>
