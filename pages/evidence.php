<?php
/**
 * DigiCustody – Evidence List Page
 * Save to: /var/www/html/digicustody/pages/evidence.php
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login($pdo);

$page_title = 'Evidence';
$uid  = $_SESSION['user_id'];
$role = $_SESSION['role'];
$csrf = csrf_token();

// Get users for bulk transfer modal
$transfer_users = $pdo->query("
    SELECT id, full_name, username, role
    FROM users
    WHERE status = 'active' AND id != $uid AND role IN ('admin', 'investigator', 'analyst')
    ORDER BY role, full_name
")->fetchAll(PDO::FETCH_ASSOC);

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
$per_page      = (int)($_GET['per_page'] ?? 25);
if (!in_array($per_page, [25, 50, 100])) $per_page = 25;
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

// ── Handle Bulk Actions ───────────────────────────────────────
$bulk_msg = '';
$bulk_err = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['bulk_action'])) {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $bulk_err = 'Security token mismatch.';
    } else {
        $action = $_POST['bulk_action'];
        $evidence_ids = array_filter(array_map('intval', $_POST['evidence_ids'] ?? []));
        
        if (empty($evidence_ids)) {
            $bulk_err = 'No evidence items selected.';
        } elseif ($action === 'export') {
            // Export is allowed for all roles that can view evidence
        } elseif ($action === 'delete' && !is_admin()) {
            $bulk_err = 'Admin access required for bulk delete.';
        } elseif (!is_admin() && !is_investigator()) {
            $bulk_err = 'You do not have permission for bulk operations.';
        } else {
            $allowed_ids = [];
            foreach ($evidence_ids as $eid) {
                if (user_can_access_evidence($pdo, $uid, $role, $eid)) {
                    $allowed_ids[] = $eid;
                }
            }
            
            $processed = 0;
            if ($action === 'delete' && is_admin()) {
                header('Content-Type: application/json');
                $evidence_ids_json = $_POST['evidence_ids_json'] ?? '[]';
                $evidence_ids = json_decode($evidence_ids_json, true) ?: [];
                $evidence_ids = array_filter(array_map('intval', $evidence_ids));
                
                $deleted = 0;
                $errors = [];
                $stmt = $pdo->prepare("SELECT id, file_path, evidence_number, title FROM evidence WHERE id=?");
                $delStmt = $pdo->prepare("DELETE FROM evidence WHERE id=?");
                $hvDelStmt = $pdo->prepare("DELETE FROM hash_verifications WHERE evidence_id=?");
                
                foreach ($evidence_ids as $eid) {
                    if (!user_can_access_evidence($pdo, $uid, $role, $eid)) {
                        $errors[] = "ID $eid: Access denied";
                        continue;
                    }
                    try {
                        $stmt->execute([$eid]);
                        $ev = $stmt->fetch(PDO::FETCH_ASSOC);
                        
                        if (!$ev) {
                            $errors[] = "ID $eid: Evidence not found";
                            continue;
                        }
                        
                        if ($ev['file_path'] && file_exists($ev['file_path'])) {
                            if (!@unlink($ev['file_path'])) {
                                $errors[] = "{$ev['evidence_number']}: Failed to delete file";
                                continue;
                            }
                        }
                        
                        try {
                            $hvDelStmt->execute([$eid]);
                            $delStmt->execute([$eid]);
                        } catch (PDOException $e) {
                            $errors[] = "{$ev['evidence_number']}: Database error - " . $e->getMessage();
                            continue;
                        }
                        
                        audit_log($pdo, $uid, $_SESSION['username'], $role, 'evidence_deleted', 'evidence', $eid, $ev['evidence_number'], 'Bulk delete');
                        $deleted++;
                    } catch (Exception $e) {
                        $errors[] = "ID $eid: " . $e->getMessage();
                    }
                }
                
                echo json_encode([
                    'success' => true,
                    'deleted' => $deleted,
                    'errors' => $errors,
                ]);
                exit;
            }
            $evStmt = $pdo->prepare("SELECT * FROM evidence WHERE id=?");
            foreach ($allowed_ids as $eid) {
                if ($action === 'verify') {
                    $evStmt->execute([$eid]);
                    $ev = $evStmt->fetch(PDO::FETCH_ASSOC);
                    if ($ev && file_exists($ev['file_path'])) {
                        $cur_sha = hash_file('sha256', $ev['file_path']);
                        $cur_sha3 = hash_file('sha3-256', $ev['file_path']);
                        $status = ($cur_sha === $ev['sha256_hash'] && $cur_sha3 === $ev['sha3_256_hash']) ? 'intact' : 'tampered';
                        $pdo->prepare("INSERT INTO hash_verifications (evidence_id, verified_by, sha256_at_verification, sha3_256_at_verification, original_sha256, original_sha3_256, integrity_status, notes) VALUES(?,?,?,?,?,?,?,?)")
                            ->execute([$eid, $uid, $cur_sha, $cur_sha3, $ev['sha256_hash'], $ev['sha3_256_hash'], $status, 'Bulk verification']);
                        if ($status === 'tampered') {
                            $pdo->prepare("UPDATE evidence SET status='flagged', pre_flag_status=COALESCE(pre_flag_status, status) WHERE id=?")->execute([$eid]);
                            foreach ($pdo->query("SELECT id FROM users WHERE role='admin' AND status='active'")->fetchAll() as $adm)
                                send_notification($pdo, $adm['id'], '⚠ Integrity Alert', "Evidence {$ev['evidence_number']} FAILED integrity check — possible tampering!", 'danger', 'evidence', $eid);
                        }
                        audit_log($pdo, $uid, $_SESSION['username'], $role, 'hash_verified', 'evidence', $eid, $ev['evidence_number'], "Bulk integrity check: $status");
                        $processed++;
                    }
                } elseif ($action === 'bulk_transfer') {
                    header('Content-Type: application/json');
                    $to_user = (int)($_POST['to_user'] ?? 0);
                    $transfer_reason = trim($_POST['transfer_reason'] ?? '');
                    $transfer_notes = trim($_POST['transfer_notes'] ?? '');
                    $hash_verify = !empty($_POST['hash_verify']);
                    $evidence_ids_json = $_POST['evidence_ids_json'] ?? '[]';
                    $evidence_ids = json_decode($evidence_ids_json, true) ?: [];
                    $evidence_ids = array_filter(array_map('intval', $evidence_ids));
                    
                    if (!$to_user) {
                        echo json_encode(['success' => false, 'error' => 'Please select a recipient.']);
                        exit;
                    }
                    if (!$transfer_reason) {
                        echo json_encode(['success' => false, 'error' => 'Transfer reason is required.']);
                        exit;
                    }
                    if (strlen($transfer_reason) > 500) {
                        echo json_encode(['success' => false, 'error' => 'Transfer reason must be 500 characters or less.']);
                        exit;
                    }
                    
                    $recipient_stmt = $pdo->prepare("SELECT id, full_name FROM users WHERE id=? AND status='active'");
                    $recipient_stmt->execute([$to_user]);
                    $recipient = $recipient_stmt->fetch(PDO::FETCH_ASSOC);
                    if (!$recipient) {
                        echo json_encode(['success' => false, 'error' => 'Invalid recipient.']);
                        exit;
                    }
                    
                    $allowed_ids = [];
                    foreach ($evidence_ids as $eid) {
                        if (user_can_access_evidence($pdo, $uid, $role, $eid)) {
                            $allowed_ids[] = $eid;
                        }
                    }
                    
                    $success_count = 0;
                    $skipped = [];
                    $caseStmt = $pdo->prepare("SELECT status FROM cases WHERE id=?");
                    foreach ($allowed_ids as $eid) {
                        $evStmt->execute([$eid]);
                        $ev = $evStmt->fetch(PDO::FETCH_ASSOC);
                        if (!$ev) {
                            $skipped[] = "ID $eid: Evidence not found";
                            continue;
                        }
                        if ($ev['status'] === 'flagged') {
                            $skipped[] = "{$ev['evidence_number']} is flagged and cannot be transferred";
                            continue;
                        }
                        $caseStmt->execute([$ev['case_id']]);
                        $case = $caseStmt->fetch(PDO::FETCH_ASSOC);
                        if ($case && in_array($case['status'], ['closed', 'archived'])) {
                            $skipped[] = "{$ev['evidence_number']}: Case is closed";
                            continue;
                        }
                        if ($ev['current_custodian'] !== $uid && $role !== 'admin') {
                            $skipped[] = "{$ev['evidence_number']}: You are not the current custodian";
                            continue;
                        }
                        
                        $hash_at_transfer = null;
                        if ($hash_verify && file_exists($ev['file_path'])) {
                            $hash_at_transfer = hash_file('sha256', $ev['file_path']);
                        }
                        
                        $pdo->prepare("
                            INSERT INTO evidence_transfers (evidence_id, from_user, to_user, transfer_reason, transfer_notes, hash_verified, hash_at_transfer, status)
                            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
                        ")->execute([$eid, $uid, $to_user, $transfer_reason, $transfer_notes ?: null, $hash_verify ? 1 : 0, $hash_at_transfer]);
                        
                        $transfer_id = $pdo->lastInsertId();
                        
                        audit_log($pdo, $uid, $_SESSION['username'], $role, 'evidence_transferred',
                            'evidence', $eid, $ev['evidence_number'],
                            "Bulk transfer initiated: {$ev['evidence_number']} -> {$recipient['full_name']}",
                            $_SERVER['REMOTE_ADDR'] ?? '', '', [
                                'transfer_id' => $transfer_id,
                                'to_user' => $to_user,
                                'reason' => $transfer_reason,
                                'hash_verified' => $hash_verify,
                            ]);
                        
                        send_notification($pdo, $to_user, 'Evidence Transfer Request',
                            "You have received a custody transfer request for evidence {$ev['evidence_number']} — {$ev['title']}. Reason: {$transfer_reason}",
                            'warning', 'evidence_transfer', $transfer_id);
                        
                        $success_count++;
                    }
                    
                    echo json_encode([
                        'success' => true,
                        'message' => "$success_count transfer" . ($success_count !== 1 ? 's' : '') . " initiated successfully. Recipients have been notified.",
                        'success_count' => $success_count,
                        'skipped' => $skipped,
                    ]);
                    exit;
                } elseif ($action === 'export') {
                    $export_ids = array_filter(array_map('intval', $_POST['evidence_ids'] ?? []));
                    if (empty($export_ids)) {
                        $bulk_err = 'No evidence items selected for export.';
                    } else {
                        $allowed_export_ids = [];
                        foreach ($export_ids as $eid) {
                            if (user_can_access_evidence($pdo, $uid, $role, $eid)) {
                                $allowed_export_ids[] = $eid;
                            }
                        }
                        
                        if (empty($allowed_export_ids)) {
                            $bulk_err = 'No accessible evidence items to export.';
                        } else {
                            $placeholders = implode(',', array_fill(0, count($allowed_export_ids), '?'));
                            $export_stmt = $pdo->prepare("
                                SELECT e.evidence_number, e.title, c.case_number,
                                       u.full_name AS custodian_name,
                                       e.file_size, e.status, e.sha256_hash, e.uploaded_at,
                                       (SELECT integrity_status FROM hash_verifications hv 
                                        WHERE hv.evidence_id = e.id 
                                        ORDER BY verified_at DESC LIMIT 1) as last_integrity
                                FROM evidence e
                                JOIN cases c ON c.id = e.case_id
                                JOIN users u ON u.id = e.current_custodian
                                WHERE e.id IN ($placeholders)
                            ");
                            $export_stmt->execute($allowed_export_ids);
                            $export_data = $export_stmt->fetchAll(PDO::FETCH_ASSOC);
                            
                            $filename = 'evidence_export_' . date('Y-m-d_His') . '.csv';
                            header('Content-Type: text/csv');
                            header('Content-Disposition: attachment; filename="' . $filename . '"');
                            header('Cache-Control: no-cache, no-store, must-revalidate');
                            header('Pragma: no-cache');
                            header('Expires: 0');
                            
                            $output = fopen('php://output', 'w');
                            fputcsv($output, ['Evidence No.', 'Title', 'Case', 'Custodian', 'Size (bytes)', 'Status', 'Integrity', 'Date Uploaded', 'SHA-256 Hash']);
                            
                            $exported_numbers = [];
                            foreach ($export_data as $row) {
                                fputcsv($output, [
                                    $row['evidence_number'],
                                    $row['title'],
                                    $row['case_number'],
                                    $row['custodian_name'],
                                    $row['file_size'],
                                    $row['status'],
                                    $row['last_integrity'] ?? 'unchecked',
                                    $row['uploaded_at'],
                                    $row['sha256_hash'],
                                ]);
                                $exported_numbers[] = $row['evidence_number'];
                            }
                            fclose($output);
                            
                            audit_log($pdo, $uid, $_SESSION['username'], $role, 'evidence_exported', 'evidence', 0, implode(', ', $exported_numbers), 'Bulk export: ' . count($exported_numbers) . ' records');
                            exit;
                        }
                    }
                }
            }
            
            if ($action !== 'transfer' && $action !== 'export') {
                $bulk_msg = "Bulk $action completed: $processed items processed.";
            }
        }
    }
}

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
    $params = array_merge($_GET, ['page' => $p, 'per_page' => $GLOBALS['per_page']]);
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
<script>var transferUsers=<?= json_encode($transfer_users) ?>;</script>
<style>
/* STAT CARDS - 5-column grid */
.stats-row{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:16px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:14px 16px;display:flex;flex-direction:column;align-items:center;gap:6px;cursor:pointer;transition:all .2s;text-decoration:none;}
.stat-card:hover{border-color:var(--border2);}
.stat-card.active,.stat-card.active-filter{border-color:var(--gold);background:var(--gold-dim);}
.stat-card.tampered{--border-color:var(--danger);}
.stat-card.tampered:hover,.stat-card.tampered.active{border-color:var(--danger);background:rgba(248,113,113,0.1);}
.stat-val{font-family:'Space Grotesk',sans-serif;font-size:20px;font-weight:700;color:var(--text);}
.stat-card.tampered .stat-val{color:var(--danger);}
.stat-label{display:flex;align-items:center;gap:5px;font-size:11px;color:var(--muted);}
/* FILTER BAR */
.filter-bar{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:12px 16px;margin-bottom:16px;}
.filter-bar form{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.filter-bar input[type="text"]{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:8px 12px;font-size:13px;color:var(--text);outline:none;flex:1;min-width:150px;}
.filter-bar input:focus{border-color:rgba(201,168,76,0.5);}
.filter-bar select{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:8px 12px;font-size:13px;color:var(--text);outline:none;}
.filter-bar select option{background:var(--surface2);}
.filter-tag{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;background:var(--gold-dim);border:1px solid rgba(201,168,76,0.25);border-radius:20px;font-size:12px;color:var(--gold);}
.filter-tag a{color:var(--gold);margin-left:4px;font-size:11px;}
.filter-tag a:hover{color:var(--danger);}
.view-toggle{display:flex;gap:4px;margin-left:auto;}
.vt-btn{background:none;border:1px solid var(--border);border-radius:7px;padding:6px 10px;color:var(--muted);cursor:pointer;font-size:13px;transition:all .2s;}
.vt-btn.active,.vt-btn:hover{border-color:var(--gold);color:var(--gold);background:var(--gold-dim);}
/* TABLE */
.table-header{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid var(--border);}
.table-header-left{font-size:13px;color:var(--muted);}
.per-page-select{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:4px 8px;font-size:12px;color:var(--text);}
.type-icon{width:18px;height:18px;border-radius:4px;display:inline-flex;align-items:center;justify-content:center;font-size:9px;flex-shrink:0;}
.type-icon.blue{background:rgba(59,130,246,0.2);color:#3b82f6;}
.type-icon.purple{background:rgba(139,92,246,0.2);color:#8b5cf6;}
.type-icon.green{background:rgba(34,197,94,0.2);color:#22c55e;}
.type-icon.orange{background:rgba(249,115,22,0.2);color:#f97316;}
.type-icon.info{background:rgba(96,165,250,0.2);color:#60a5fa;}
.type-icon.gold{background:rgba(201,168,76,0.2);color:#c9a227;}
.type-icon.muted{background:rgba(148,163,184,0.2);color:#94a3b8;}
.type-icon.warning{background:rgba(234,179,8,0.2);color:#eab308;}
.type-icon.gray{background:rgba(148,163,184,0.2);color:#94a3b8;}
.integrity-dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:5px;}
.integrity-dot.green{background:var(--success);}
.integrity-dot.red{background:var(--danger);}
.integrity-dot.gray{background:var(--dim);}
/* Action buttons hidden by default */
tr:hover .row-actions{opacity:1;}
.row-actions{opacity:0;transition:opacity .2s;}
.row-actions a{font-size:11px;padding:4px 8px;}
/* Tampered row */
tr.tampered-row{border-left:3px solid var(--danger);background:rgba(248,113,113,0.04);}
/* PAGINATION inside section-card */
.pagination{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-top:1px solid var(--border);flex-wrap:wrap;gap:10px;}
.pagination-left{font-size:12px;color:var(--muted);}
.pagination-right{display:flex;align-items:center;gap:6px;}
.pg-btn{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:5px 10px;font-size:12px;color:var(--muted);cursor:pointer;transition:all .2s;text-decoration:none;}
.pg-btn:hover{border-color:var(--gold);color:var(--gold);}
.pg-btn.active{background:var(--gold);color:#060d1a;border-color:var(--gold);font-weight:600;}
.pg-btn.disabled{opacity:.35;pointer-events:none;}
/* BULK TOOLBAR - sticky bottom */
.bulk-toolbar{display:none;position:sticky;bottom:0;left:0;right:0;background:#1a2436;border-top:1px solid var(--border);padding:12px 20px;display:flex;gap:12px;align-items:center;justify-content:center;}
.bulk-toolbar.active{display:flex;}
.bulk-toolbar-inner{display:flex;align-items:center;gap:12px;}
.bulk-count{font-size:13px;color:var(--text);}
.bulk-separator{width:1px;height:24px;background:var(--border);}
.sort-th{cursor:pointer;white-space:nowrap;user-select:none;color:var(--muted);}
.sort-th:hover{color:var(--text);}
.evidence-num{font-weight:700;font-size:12.5px;color:var(--gold);font-family:'Space Grotesk',sans-serif;}
/* table column widths */
.dc-table th:nth-child(1){width:40px}
.dc-table th:nth-child(2){width:110px}
.dc-table th:nth-child(3){width:auto}
.dc-table th:nth-child(4){width:110px}
.dc-table th:nth-child(5){width:70px}
.dc-table th:nth-child(6){width:80px}
.dc-table th:nth-child(7){width:80px}
.dc-table th:nth-child(8){width:80px}
.dc-table th:nth-child(9){width:100px}
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
.ev-card-footer{display:flex;align-items:center;justify-content:space-between;margin-top:12px;padding-top:10px;border-top:1px solid var(--border);}
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

<!-- Merged Toolbar -->
<div class="ev-toolbar" style="position:sticky;top:0;z-index:100;background:var(--surface);padding:12px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
    <button type="button" class="btn-back" onclick="goBack()"><i class="fas fa-arrow-left"></i> Back</button>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:nowrap;">
        <a href="evidence.php" class="stat-card <?= !$filter_status && !$my_only ? 'active' : '' ?>" style="padding:6px 12px;min-width:70px;display:flex;flex-direction:column;align-items:center;gap:2px;">
            <span class="stat-val" style="font-size:16px;line-height:1;"><?= number_format($stat_total) ?></span>
            <span class="stat-label" style="font-size:10px;white-space:nowrap;"><i class="fas fa-circle" style="color:var(--gold)"></i> Total</span>
        </a>
        <a href="evidence.php?status=collected" class="stat-card <?= $filter_status === 'collected' ? 'active' : '' ?>" style="padding:6px 12px;min-width:70px;display:flex;flex-direction:column;align-items:center;gap:2px;">
            <span class="stat-val" style="font-size:16px;line-height:1;"><?= $stat_collected ?></span>
            <span class="stat-label" style="font-size:10px;white-space:nowrap;"><i class="fas fa-circle" style="color:var(--info)"></i> Collected</span>
        </a>
        <a href="evidence.php?status=in_analysis" class="stat-card <?= $filter_status === 'in_analysis' ? 'active' : '' ?>" style="padding:6px 12px;min-width:70px;display:flex;flex-direction:column;align-items:center;gap:2px;">
            <span class="stat-val" style="font-size:16px;line-height:1;"><?= $stat_analysis ?></span>
            <span class="stat-label" style="font-size:10px;white-space:nowrap;"><i class="fas fa-circle" style="color:var(--warning)"></i> Analysis</span>
        </a>
        <?php if ($stat_tampered > 0): ?>
        <a href="evidence.php?status=flagged" class="stat-card tampered <?= $filter_status === 'flagged' ? 'active' : '' ?>" style="padding:6px 12px;min-width:70px;display:flex;flex-direction:column;align-items:center;gap:2px;">
            <span class="stat-val" style="font-size:16px;line-height:1;"><?= $stat_tampered ?></span>
            <span class="stat-label" style="font-size:10px;white-space:nowrap;"><i class="fas fa-circle" style="color:var(--danger)"></i> Flagged</span>
        </a>
        <?php endif; ?>
        <a href="evidence.php?my=1" class="stat-card <?= $my_only ? 'active' : '' ?>" style="padding:6px 12px;min-width:70px;display:flex;flex-direction:column;align-items:center;gap:2px;">
            <span class="stat-val" style="font-size:16px;line-height:1;"><?= $stat_my ?></span>
            <span class="stat-label" style="font-size:10px;white-space:nowrap;"><i class="fas fa-circle" style="color:var(--success)"></i> Mine</span>
        </a>
        <div class="view-toggle">
            <button class="vt-btn <?= $view_mode === 'table' ? 'active' : '' ?>" onclick="setView('table')" title="Table view">
                <i class="fas fa-list"></i>
            </button>
            <button class="vt-btn <?= $view_mode === 'grid' ? 'active' : '' ?>" onclick="setView('grid')" title="Card view">
                <i class="fas fa-grip"></i>
            </button>
        </div>
        <span style="font-size:13px;color:var(--muted);"><?= number_format($total) ?> record<?= $total !== 1 ? 's' : '' ?><?= $search !== '' ? ' for &ldquo;' . e($search) . '&rdquo;' : '' ?></span>
    </div>
    <?php if (can_upload()): ?>
    <a href="evidence_upload.php" class="btn btn-gold">
        <i class="fas fa-upload"></i> Upload Evidence
    </a>
    <?php endif; ?>
</div>

<!-- Scrollable Content Wrapper -->
<div style="overflow-y:auto;height:calc(100vh - 128px);">

<!-- FILTER BAR -->
<div class="filter-bar">
    <form method="GET" id="filterForm">
        <input type="text" name="search" id="searchInput" placeholder="Search evidence..." value="<?= e($search) ?>">
        <select name="status" onchange="this.form.submit()">
            <option value="">All Statuses</option>
            <?php foreach (['collected','in_analysis','transferred','archived','flagged'] as $s): ?>
            <option value="<?= $s ?>" <?= $filter_status === $s ? 'selected' : '' ?>><?= ucwords(str_replace('_', ' ', $s)) ?></option>
            <?php endforeach; ?>
        </select>
        <select name="type" onchange="this.form.submit()">
            <option value="">All Types</option>
            <?php foreach (array_keys($type_icons) as $t): ?>
            <option value="<?= $t ?>" <?= $filter_type === $t ? 'selected' : '' ?>><?= ucwords(str_replace('_', ' ', $t)) ?></option>
            <?php endforeach; ?>
        </select>
        <select name="case" onchange="this.form.submit()">
            <option value="">All Cases</option>
            <?php foreach ($all_cases as $c): ?>
            <option value="<?= $c['id'] ?>" <?= (string)$filter_case === (string)$c['id'] ? 'selected' : '' ?>><?= e($c['case_number']) ?></option>
            <?php endforeach; ?>
        </select>
        <input type="hidden" name="my" value="<?= $my_only ? '1' : '' ?>">
        <input type="hidden" name="sort" value="<?= e($sort) ?>">
        <input type="hidden" name="dir" value="<?= strtolower($dir) ?>">
        <input type="hidden" name="view" value="<?= e($view_mode) ?>">
        <button type="submit" class="btn btn-gold btn-sm"><i class="fas fa-search"></i></button>
        <?php if ($search || $filter_status || $filter_type || $filter_case || $my_only): ?>
        <!-- Active filter tags inline -->
        <span class="filter-tag"><?= e($search ?: ucwords(str_replace('_',' ',$filter_status ?: $filter_type ?: ''))) ?>
            <a href="evidence.php?<?= http_build_query(array_diff_key($_GET, ['search'=>'','status'=>'','type'=>'','case'=>'','my'=>'','page'=>''])) ?>">×</a>
        </span>
        <?php endif; ?>
    </form>
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
<div class="table-scroll-wrapper">
<div class="section-card">
    <div class="table-header">
        <div class="table-header-left"><?= number_format($total) ?> record<?= $total !== 1 ? 's' : '' ?></div>
        <select class="per-page-select" onchange="window.location=this.value">
            <option value="<?= page_url(1) . '&per_page=25' ?>" <?= $per_page === 25 ? 'selected' : '' ?>>25 per page</option>
            <option value="<?= page_url(1) . '&per_page=50' ?>" <?= $per_page === 50 ? 'selected' : '' ?>>50 per page</option>
            <option value="<?= page_url(1) . '&per_page=100' ?>" <?= $per_page === 100 ? 'selected' : '' ?>>100 per page</option>
        </select>
    </div>
    <div class="table-responsive"><table class="dc-table" style="table-layout:fixed;width:100%">
        <colgroup>
            <col style="width:40px">
            <col style="width:90px">
            <col style="width:22%">
            <col style="width:130px">
            <col style="width:80px">
            <col style="width:90px">
            <col style="width:100px">
            <col style="width:100px">
            <col style="width:130px">
        </colgroup>
        <thead>
        <tr>
            <th style="width:40px"><input type="checkbox" id="selectAllEvidence" onclick="toggleAllEvidence(this)"></th>
            <th style="width:90px"><a href="<?= sort_url('evidence_number') ?>" class="sort-th" style="text-decoration:none;color:inherit;">No. <?= sort_icon('evidence_number') ?></a></th>
            <th style="width:22%"><a href="<?= sort_url('title') ?>" class="sort-th" style="text-decoration:none;color:inherit;">Title &amp; Case <?= sort_icon('title') ?></a></th>
            <th style="width:130px">Custodian</th>
            <th style="width:80px"><a href="<?= sort_url('file_size') ?>" class="sort-th" style="text-decoration:none;color:inherit;">Size <?= sort_icon('file_size') ?></a></th>
            <th style="width:90px">Status</th>
            <th style="width:100px">Integrity</th>
            <th style="width:100px"><a href="<?= sort_url('uploaded_at') ?>" class="sort-th" style="text-decoration:none;color:inherit;">Date <?= sort_icon('uploaded_at') ?></a></th>
            <th style="width:130px;white-space:nowrap;">Actions</th>
        </tr>
        </thead>
        <tbody>
        <?php foreach ($evidence_list as $ev):
            $tampered = ($ev['last_integrity'] === 'tampered');
            [$ico, $col] = $type_icons[$ev['evidence_type']] ?? ['fa-file', 'gray'];
        ?>
        <tr class="<?= $tampered ? 'tampered-row' : '' ?>" onclick="window.location='evidence_view.php?id=<?= (int)$ev['id'] ?>'" style="cursor:pointer;">
            <td onclick="event.stopPropagation()">
                <input type="checkbox" class="evidence-checkbox" name="evidence_ids[]" value="<?= (int)$ev['id'] ?>">
            </td>
            <td><span class="evidence-num"><?= e($ev['evidence_number']) ?></span></td>
            <td>
                <div style="display:flex;align-items:center;gap:8px;">
                    <span class="type-icon <?= $col ?>"><i class="fas <?= $ico ?>"></i></span>
                    <div style="flex:1;min-width:0;">
                        <p style="font-weight:500;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:160px;display:inline-block;vertical-align:middle;" title="<?= e($ev['title']) ?>"><?= e($ev['title']) ?></p>
                        <div style="display:flex;align-items:center;gap:6px;margin-top:2px;">
                            <span style="max-width:160px;display:inline-block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:middle;" title="<?= e($ev['case_number']) ?>">
                                <a href="case_view.php?id=<?= $ev['case_id'] ?>" style="font-size:11px;color:var(--info);text-decoration:none;"><?= e($ev['case_number']) ?></a>
                            </span>
                            <span style="font-size:10px;color:var(--dim);"><?= e(substr($ev['case_title'],0,22)) ?></span>
                        </div>
                    </div>
                </div>
            </td>
            <td>
                <span style="font-size:12px;white-space:nowrap;"><?= e($ev['custodian_name']) ?></span>
                <?php if ((int)$ev['current_custodian'] === $uid): ?>
                <span class="badge badge-gold" style="display:block;width:fit-content;margin-top:2px;font-size:9px">Me</span>
                <?php endif; ?>
            </td>
            <td><span style="font-size:12px;color:var(--muted)"><?= format_filesize($ev['file_size']) ?></span></td>
            <td><?= status_badge($ev['status']) ?></td>
            <td>
                <?php if ($tampered): ?>
                    <span><i class="integrity-dot red"></i>Tampered</span>
                <?php elseif ($ev['last_integrity'] === 'intact'): ?>
                    <span><i class="integrity-dot green"></i>Intact</span>
                <?php else: ?>
                    <span><i class="integrity-dot gray"></i>Unchecked</span>
                <?php endif; ?>
            </td>
            <td><span style="font-size:11px;color:var(--muted)"><?= date('M j, Y', strtotime($ev['uploaded_at'])) ?></span></td>
            <td>
                <div class="row-actions" style="display:flex;gap:4px;">
                    <a href="evidence_download.php?id=<?= (int)$ev['id'] ?>" class="btn btn-download btn-sm" title="Download" onclick="event.stopPropagation()"><i class="fas fa-download"></i></a>
                    <a href="evidence_verify.php?id=<?= (int)$ev['id'] ?>" class="btn btn-outline btn-sm" title="Verify" onclick="event.stopPropagation()"><i class="fas fa-fingerprint"></i></a>
                    <a href="coc_report.php?id=<?= (int)$ev['id'] ?>" class="btn btn-coc btn-sm" title="COC" onclick="event.stopPropagation()"><i class="fas fa-file-shield"></i></a>
                </div>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <!-- Pagination inside section-card -->
    <?php if ($total_pages > 1): ?>
    <div class="pagination">
        <div class="pagination-left">
            Showing <?= ($offset + 1) ?>-<?= min($offset + $per_page, $total) ?> of <?= number_format($total) ?> · Page <?= $page_num ?> of <?= $total_pages ?>
        </div>
        <div class="pagination-right">
            <a href="<?= page_url(1) ?>" class="pg-btn <?= $page_num <= 1 ? 'disabled' : '' ?>"><i class="fas fa-angles-left"></i></a>
            <a href="<?= page_url(max(1, $page_num - 1)) ?>" class="pg-btn <?= $page_num <= 1 ? 'disabled' : '' ?>"><i class="fas fa-angle-left"></i></a>
            <?php $pg_start = max(1, $page_num - 2); $pg_end = min($total_pages, $page_num + 2); for ($p = $pg_start; $p <= $pg_end; $p++): ?>
            <a href="<?= page_url($p) ?>" class="pg-btn <?= $p === $page_num ? 'active' : '' ?>"><?= $p ?></a>
            <?php endfor; ?>
            <a href="<?= page_url(min($total_pages, $page_num + 1)) ?>" class="pg-btn <?= $page_num >= $total_pages ? 'disabled' : '' ?>"><i class="fas fa-angle-right"></i></a>
            <a href="<?= page_url($total_pages) ?>" class="pg-btn <?= $page_num >= $total_pages ? 'disabled' : '' ?>"><i class="fas fa-angles-right"></i></a>
        </div>
    </div>
    <?php endif; ?>
</div>
</div><!-- /table-scroll-wrapper -->
<?php endif; ?>

</div><!-- /scrollable-wrapper -->

</div><!-- /page-content -->
</div><!-- /main-area -->

<!-- Bulk Actions Floating Toolbar -->
<div id="bulkToolbar">
    <div class="bulk-toolbar-inner">
        <div class="bulk-toolbar-left">
            <i class="fas fa-check-square" style="color:var(--gold);"></i>
            <span><span id="selectedCount">0</span> selected</span>
            <span class="clear-link" onclick="clearSelection()">× Clear</span>
        </div>
        <div class="bulk-separator"></div>
        <div class="bulk-toolbar-actions">
            <form method="POST" style="display:inline;">
                <?= isset($csrf) ? '<input type="hidden" name="csrf_token" value="'.$csrf.'">' : '' ?>
                <input type="hidden" name="bulk_action" id="bulkActionInput">
                <button type="button" class="bulk-btn btn-transfer" onclick="openBulkTransferModal()" title="Transfer selected evidence">
                    <i class="fas fa-paper-plane"></i> Transfer
                    <span class="tooltip">Transfer selected evidence to another custodian</span>
                </button>
                <button type="button" class="bulk-btn btn-export" onclick="submitBulkExport()" title="Export evidence">
                    <i class="fas fa-file-export"></i> Export
                    <span class="tooltip">Export selected evidence records</span>
                </button>
                <?php if (is_admin()): ?>
                <button type="button" class="bulk-btn btn-delete" onclick="openBulkDeleteModal()" title="Delete evidence">
                    <i class="fas fa-trash"></i> Delete
                    <span class="tooltip">Permanently delete selected evidence</span>
                </button>
                <?php endif; ?>
            </form>
        </div>
        <div class="bulk-separator"></div>
        <button type="button" class="bulk-btn btn-verify" onclick="openBulkVerifyModal()" title="Verify integrity">
            <i class="fas fa-fingerprint"></i> Verify
            <span class="tooltip">Run integrity check on selected evidence</span>
        </button>
        <div class="bulk-separator"></div>
        <button type="button" class="bulk-toolbar-cancel" onclick="clearSelection()" title="Cancel selection">
            <i class="fas fa-times"></i>
        </button>
    </div>
</div>

<!-- Bulk Verify Modal -->
<div id="bulkVerifyModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:2000;align-items:center;justify-content:center;">
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;width:90%;max-width:520px;max-height:80vh;display:flex;flex-direction:column;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
            <h3 style="font-size:18px;font-weight:600;color:var(--text);"><i class="fas fa-fingerprint" style="color:var(--gold);margin-right:8px;"></i>Bulk Integrity Verification</h3>
            <button type="button" onclick="closeBulkVerifyModal()" style="background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;"><i class="fas fa-times"></i></button>
        </div>
        <div id="bulkVerifyList" style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px;margin-bottom:16px;max-height:120px;overflow-y:auto;font-size:12px;color:var(--muted);"></div>
        <div style="margin-bottom:12px;">
            <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--muted);margin-bottom:6px;">
                <span>Progress</span>
                <span id="bulkVerifyProgressText">0 / 0</span>
            </div>
            <div style="background:var(--surface2);border-radius:6px;height:8px;overflow:hidden;">
                <div id="verifyProgress" style="background:linear-gradient(90deg,var(--gold),#d4a84b);height:100%;width:0%;transition:width 0.3s ease;border-radius:6px;"></div>
            </div>
        </div>
        <div id="verifyLog" style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;flex:1;overflow-y:auto;font-size:12px;min-height:100px;max-height:200px;margin-bottom:16px;"></div>
        <div id="bulkVerifySummary" style="display:none;padding:12px;background:rgba(201,168,76,0.1);border:1px solid rgba(201,168,76,0.3);border-radius:8px;margin-bottom:16px;font-size:13px;color:var(--text);text-align:center;"></div>
        <div style="display:flex;gap:10px;justify-content:flex-end;">
            <button type="button" id="bulkVerifyCloseBtn" class="btn btn-outline" onclick="closeBulkVerifyModal()" disabled style="padding:10px 20px;">Close</button>
        </div>
    </div>
</div>

<!-- Bulk Transfer Modal -->
<div id="bulkTransferModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:2000;align-items:center;justify-content:center;">
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;width:90%;max-width:520px;max-height:80vh;display:flex;flex-direction:column;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
            <h3 style="font-size:18px;font-weight:600;color:var(--text);"><i class="fas fa-paper-plane" style="color:var(--info);margin-right:8px;"></i><span id="bulkTransferTitle">Bulk Transfer Evidence</span></h3>
            <button type="button" onclick="closeBulkTransferModal()" style="background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;"><i class="fas fa-times"></i></button>
        </div>
        <form id="bulkTransferForm" onsubmit="submitBulkTransfer(event)">
            <div style="margin-bottom:16px;">
                <label style="display:block;font-size:12px;font-weight:500;color:var(--muted);margin-bottom:6px;text-transform:uppercase;">Recipient *</label>
                <select id="bulkTransferRecipient" required style="width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;font-size:14px;color:var(--text);outline:none;">
                    <option value="">Select a recipient...</option>
                </select>
            </div>
            <div style="margin-bottom:16px;">
                <label style="display:block;font-size:12px;font-weight:500;color:var(--muted);margin-bottom:6px;text-transform:uppercase;">Transfer Reason * <span style="font-weight:400;text-transform:none;">(max 500 chars)</span></label>
                <textarea id="bulkTransferReason" required maxlength="500" rows="3" placeholder="Reason for this transfer..." style="width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;font-size:14px;color:var(--text);outline:none;resize:vertical;font-family:inherit;"></textarea>
                <div style="text-align:right;font-size:11px;color:var(--muted);margin-top:4px;"><span id="reasonCount">0</span>/500</div>
            </div>
            <div style="margin-bottom:16px;">
                <label style="display:block;font-size:12px;font-weight:500;color:var(--muted);margin-bottom:6px;text-transform:uppercase;">Transfer Notes <span style="font-weight:400;text-transform:none;">(optional)</span></label>
                <textarea id="bulkTransferNotes" rows="2" placeholder="Additional notes..." style="width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;font-size:14px;color:var(--text);outline:none;resize:vertical;font-family:inherit;"></textarea>
            </div>
            <div style="margin-bottom:20px;">
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px;color:var(--text);">
                    <input type="checkbox" id="bulkTransferHashVerify" style="width:16px;height:16px;accent-color:var(--gold);">
                    Verify hash before transfer
                </label>
            </div>
            <div id="bulkTransferResult" style="display:none;padding:12px;background:rgba(74,222,128,0.1);border:1px solid rgba(74,222,128,0.3);border-radius:8px;margin-bottom:16px;font-size:13px;color:var(--text);text-align:center;"></div>
            <div style="display:flex;gap:10px;justify-content:flex-end;">
                <button type="button" onclick="closeBulkTransferModal()" class="btn btn-outline" style="padding:10px 20px;">Cancel</button>
                <button type="submit" id="bulkTransferSubmitBtn" class="btn btn-info" style="padding:10px 20px;background:var(--info);color:#fff;border:none;"><i class="fas fa-paper-plane"></i> Initiate Transfer</button>
            </div>
        </form>
    </div>
</div>

<!-- Bulk Delete Modal -->
<div id="bulkDeleteModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:2000;align-items:center;justify-content:center;">
    <div style="background:var(--surface);border:1px solid rgba(248,113,113,0.3);border-radius:16px;padding:24px;width:90%;max-width:520px;max-height:80vh;display:flex;flex-direction:column;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
            <h3 style="font-size:18px;font-weight:600;color:var(--danger);"><i class="fas fa-exclamation-triangle" style="margin-right:8px;"></i>Permanent Delete</h3>
            <button type="button" onclick="closeBulkDeleteModal()" style="background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;"><i class="fas fa-times"></i></button>
        </div>
        <div style="background:rgba(248,113,113,0.1);border:1px solid rgba(248,113,113,0.3);border-radius:8px;padding:12px;margin-bottom:16px;font-size:13px;color:var(--danger);text-align:center;">
            <strong>This action is permanent and cannot be undone.</strong>
        </div>
        <div id="bulkDeleteList" style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px;margin-bottom:16px;max-height:150px;overflow-y:auto;font-size:12px;"></div>
        <div style="margin-bottom:16px;">
            <label style="display:block;font-size:12px;font-weight:500;color:var(--muted);margin-bottom:6px;text-transform:uppercase;">Type DELETE to confirm</label>
            <input type="text" id="bulkDeleteConfirm" placeholder="DELETE" autocomplete="off" style="width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;font-size:14px;color:var(--text);outline:none;text-transform:uppercase;">
        </div>
        <div id="bulkDeleteResult" style="display:none;padding:12px;border-radius:8px;margin-bottom:16px;font-size:13px;text-align:center;"></div>
        <div style="display:flex;gap:10px;justify-content:flex-end;">
            <button type="button" onclick="closeBulkDeleteModal()" class="btn btn-outline" style="padding:10px 20px;">Cancel</button>
            <button type="button" id="bulkDeleteSubmitBtn" class="btn" onclick="submitBulkDelete()" disabled style="padding:10px 20px;background:var(--danger);color:#fff;border:none;opacity:0.5;cursor:not-allowed;"><i class="fas fa-trash"></i> Confirm Delete</button>
        </div>
    </div>
</div>

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
// Bulk selection
function toggleAllEvidence(cb){
    document.querySelectorAll('.evidence-checkbox').forEach(function(el){el.checked=cb.checked;});
    updateBulkToolbar();
}
function updateBulkToolbar(){
    var checked=document.querySelectorAll('.evidence-checkbox:checked');
    var tb=document.getElementById('bulkToolbar');
    var count=document.getElementById('selectedCount');
    if(checked.length>0){
        tb.classList.add('show');
        count.textContent=checked.length;
    }else{
        tb.classList.remove('show');
    }
}
document.querySelectorAll('.evidence-checkbox').forEach(function(el){
    el.addEventListener('change',updateBulkToolbar);
});
function setBulkAction(action){
    var checked=document.querySelectorAll('.evidence-checkbox:checked');
    if(checked.length===0){event.preventDefault();return;}
    if(action==='delete'&&!confirm('Are you sure you want to delete '+checked.length+' evidence items? This action cannot be undone.')){event.preventDefault();return;}
    document.getElementById('bulkActionInput').value=action;
}
function submitBulkExport(){
    var checked=document.querySelectorAll('.evidence-checkbox:checked');
    if(checked.length===0)return;
    if(!confirm('Export '+checked.length+' evidence record'+(checked.length!==1?'s':'')+' to CSV?'))return;
    document.getElementById('bulkActionInput').value='export';
    var form=document.createElement('form');
    form.method='POST';
    form.action='evidence.php';
    var csrfInput=document.createElement('input');
    csrfInput.type='hidden';
    csrfInput.name='csrf_token';
    csrfInput.value=document.querySelector('input[name="csrf_token"]')?.value||'';
    form.appendChild(csrfInput);
    var actionInput=document.createElement('input');
    actionInput.type='hidden';
    actionInput.name='bulk_action';
    actionInput.value='export';
    form.appendChild(actionInput);
    checked.forEach(function(el){
        var input=document.createElement('input');
        input.type='hidden';
        input.name='evidence_ids[]';
        input.value=el.value;
        form.appendChild(input);
    });
    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);
}
function clearSelection(){
    document.querySelectorAll('.evidence-checkbox').forEach(function(el){el.checked=false;});
    document.getElementById('selectAllEvidence').checked=false;
    updateBulkToolbar();
}
function openBulkVerifyModal(){
    var checked=document.querySelectorAll('.evidence-checkbox:checked');
    if(checked.length===0)return;
    var ids=Array.from(checked).map(function(el){return el.value;});
    var modal=document.getElementById('bulkVerifyModal');
    var list=document.getElementById('bulkVerifyList');
    var log=document.getElementById('verifyLog');
    var progress=document.getElementById('verifyProgress');
    var progressText=document.getElementById('bulkVerifyProgressText');
    var summary=document.getElementById('bulkVerifySummary');
    var closeBtn=document.getElementById('bulkVerifyCloseBtn');
    progress.style.width='0%';
    progressText.textContent='0 / '+ids.length;
    log.innerHTML='';
    summary.style.display='none';
    closeBtn.disabled=true;
    list.innerHTML='Verifying: '+ids.length+' item'+(ids.length!==1?'s':'');
    modal.style.display='flex';
    runBulkVerify(ids,0,{intact:0,tampered:0,missing:0});
}
async function runBulkVerify(ids,index,counts){
    if(index>=ids.length){
        finishBulkVerify(ids.length,counts);
        return;
    }
    var id=ids[index];
    var log=document.getElementById('verifyLog');
    var progress=document.getElementById('verifyProgress');
    var progressText=document.getElementById('bulkVerifyProgressText');
    var csrf=document.querySelector('input[name="csrf_token"]')?.value||'';
    var row=document.createElement('div');
    row.style.marginBottom='6px';
    row.innerHTML='<i class="fas fa-spinner fa-spin" style="color:var(--gold);margin-right:6px;"></i> Checking #'+id+'...';
    log.appendChild(row);
    log.scrollTop=log.scrollHeight;
    try{
        var formData=new FormData();
        formData.append('ajax','1');
        formData.append('csrf_token',csrf);
        var response=await fetch('evidence_verify.php?id='+id,{method:'POST',body:formData});
        var data=await response.json();
        row.innerHTML='';
        if(data.status==='intact'){
            row.innerHTML='<span style="color:var(--success);"><i class="fas fa-check-circle" style="margin-right:6px;"></i> #'+id+'</span> — Intact';
            counts.intact++;
        }else if(data.status==='tampered'){
            row.innerHTML='<span style="color:var(--danger);"><i class="fas fa-times-circle" style="margin-right:6px;"></i> #'+id+'</span> — Tampered!';
            counts.tampered++;
        }else{
            row.innerHTML='<span style="color:var(--warning);"><i class="fas fa-exclamation-triangle" style="margin-right:6px;"></i> #'+id+'</span> — File Missing';
            counts.missing++;
        }
    }catch(err){
        row.innerHTML='<span style="color:var(--danger);"><i class="fas fa-times-circle" style="margin-right:6px;"></i> #'+id+'</span> — Error: '+err.message;
    }
    log.scrollTop=log.scrollHeight;
    var pct=Math.round(((index+1)/ids.length)*100);
    progress.style.width=pct+'%';
    progressText.textContent=(index+1)+' / '+ids.length;
    runBulkVerify(ids,index+1,counts);
}
function finishBulkVerify(total,counts){
    var summary=document.getElementById('bulkVerifySummary');
    var closeBtn=document.getElementById('bulkVerifyCloseBtn');
    var parts=[];
    if(counts.intact>0)parts.push('<span style="color:var(--success);">'+counts.intact+' intact</span>');
    if(counts.tampered>0)parts.push('<span style="color:var(--danger);">'+counts.tampered+' tampered</span>');
    if(counts.missing>0)parts.push('<span style="color:var(--warning);">'+counts.missing+' missing</span>');
    summary.innerHTML='<strong>Complete:</strong> '+parts.join(', ');
    summary.style.display='block';
    if(counts.tampered>0){
        var viewBtn=document.createElement('a');
        viewBtn.href='evidence.php?status=flagged';
        viewBtn.className='btn btn-danger';
        viewBtn.style.cssText='margin-left:12px;padding:8px 16px;text-decoration:none;';
        viewBtn.textContent='View Flagged';
        summary.appendChild(viewBtn);
    }
    closeBtn.disabled=false;
}
function closeBulkVerifyModal(){
    document.getElementById('bulkVerifyModal').style.display='none';
    clearSelection();
}
function populateTransferRecipients(){
    var select=document.getElementById('bulkTransferRecipient');
    select.innerHTML='<option value="">Select a recipient...</option>';
    if(typeof transferUsers!=='undefined'&&transferUsers){
        var grouped={};
        transferUsers.forEach(function(u){
            if(!grouped[u.role])grouped[u.role]=[];
            grouped[u.role].push(u);
        });
        var roleOrder=['admin','investigator','analyst'];
        roleOrder.forEach(function(role){
            if(grouped[role]){
                var optgroup=document.createElement('optgroup');
                optgroup.label=role.charAt(0).toUpperCase()+role.slice(1)+'s';
                grouped[role].forEach(function(u){
                    var opt=document.createElement('option');
                    opt.value=u.id;
                    opt.textContent=u.full_name+' ('+u.username+')';
                    optgroup.appendChild(opt);
                });
                select.appendChild(optgroup);
            }
        });
    }
}
function openBulkTransferModal(){
    var checked=document.querySelectorAll('.evidence-checkbox:checked');
    if(checked.length===0)return;
    var ids=Array.from(checked).map(function(el){return el.value;});
    var modal=document.getElementById('bulkTransferModal');
    var title=document.getElementById('bulkTransferTitle');
    var result=document.getElementById('bulkTransferResult');
    var form=document.getElementById('bulkTransferForm');
    var submitBtn=document.getElementById('bulkTransferSubmitBtn');
    title.textContent='Bulk Transfer '+ids.length+' Evidence Item'+(ids.length!==1?'s':'');
    result.style.display='none';
    form.style.display='block';
    submitBtn.disabled=false;
    submitBtn.innerHTML='<i class="fas fa-paper-plane"></i> Initiate Transfer';
    document.getElementById('bulkTransferRecipient').value='';
    document.getElementById('bulkTransferReason').value='';
    document.getElementById('bulkTransferNotes').value='';
    document.getElementById('bulkTransferHashVerify').checked=false;
    document.getElementById('reasonCount').textContent='0';
    populateTransferRecipients();
    modal.style.display='flex';
}
function submitBulkTransfer(e){
    e.preventDefault();
    var checked=document.querySelectorAll('.evidence-checkbox:checked');
    if(checked.length===0)return;
    var ids=Array.from(checked).map(function(el){return el.value;});
    var toUser=document.getElementById('bulkTransferRecipient').value;
    var reason=document.getElementById('bulkTransferReason').value.trim();
    var notes=document.getElementById('bulkTransferNotes').value.trim();
    var hashVerify=document.getElementById('bulkTransferHashVerify').checked;
    var csrf=document.querySelector('input[name="csrf_token"]')?.value||'';
    var submitBtn=document.getElementById('bulkTransferSubmitBtn');
    var form=document.getElementById('bulkTransferForm');
    var result=document.getElementById('bulkTransferResult');
    
    if(!toUser){
        result.style.display='block';
        result.style.background='rgba(248,113,113,0.1)';
        result.style.borderColor='rgba(248,113,113,0.3)';
        result.textContent='Please select a recipient.';
        return;
    }
    if(!reason){
        result.style.display='block';
        result.style.background='rgba(248,113,113,0.1)';
        result.style.borderColor='rgba(248,113,113,0.3)';
        result.textContent='Please provide a transfer reason.';
        return;
    }
    
    submitBtn.disabled=true;
    submitBtn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Processing...';
    result.style.display='none';
    
    var formData=new FormData();
    formData.append('bulk_action','bulk_transfer');
    formData.append('csrf_token',csrf);
    formData.append('to_user',toUser);
    formData.append('transfer_reason',reason);
    formData.append('transfer_notes',notes);
    formData.append('hash_verify',hashVerify?'1':'0');
    formData.append('evidence_ids_json',JSON.stringify(ids));
    
    fetch('evidence.php',{method:'POST',body:formData})
        .then(function(res){return res.json();})
        .then(function(data){
            if(data.success){
                result.style.background='rgba(74,222,128,0.1)';
                result.style.borderColor='rgba(74,222,128,0.3)';
                result.style.color='var(--success)';
                result.innerHTML='<i class="fas fa-check-circle" style="margin-right:6px;"></i>'+data.message;
                form.style.display='none';
                submitBtn.innerHTML='<i class="fas fa-check"></i> Done';
                setTimeout(function(){
                    closeBulkTransferModal();
                    location.reload();
                },2000);
            }else{
                result.style.background='rgba(248,113,113,0.1)';
                result.style.borderColor='rgba(248,113,113,0.3)';
                result.textContent=data.error||'An error occurred.';
                submitBtn.disabled=false;
                submitBtn.innerHTML='<i class="fas fa-paper-plane"></i> Initiate Transfer';
            }
        })
        .catch(function(err){
            result.style.display='block';
            result.style.background='rgba(248,113,113,0.1)';
            result.style.borderColor='rgba(248,113,113,0.3)';
            result.textContent='Error: '+err.message;
            submitBtn.disabled=false;
            submitBtn.innerHTML='<i class="fas fa-paper-plane"></i> Initiate Transfer';
        });
}
function closeBulkTransferModal(){
    document.getElementById('bulkTransferModal').style.display='none';
    clearSelection();
}
document.getElementById('bulkTransferReason').addEventListener('input',function(){
    document.getElementById('reasonCount').textContent=this.value.length;
});
function openBulkDeleteModal(){
    var checked=document.querySelectorAll('.evidence-checkbox:checked');
    if(checked.length===0)return;
    var modal=document.getElementById('bulkDeleteModal');
    var list=document.getElementById('bulkDeleteList');
    var confirmInput=document.getElementById('bulkDeleteConfirm');
    var submitBtn=document.getElementById('bulkDeleteSubmitBtn');
    var result=document.getElementById('bulkDeleteResult');
    result.style.display='none';
    confirmInput.value='';
    submitBtn.disabled=true;
    submitBtn.style.opacity='0.5';
    submitBtn.style.cursor='not-allowed';
    list.innerHTML='<ol style="margin:0;padding-left:20px;color:var(--text);">';
    checked.forEach(function(el){
        var tr=el.closest('tr');
        var num=tr.querySelector('.evidence-num')?.textContent||el.value;
        var title=tr.querySelector('p[style*="text-overflow"]')?.textContent||'';
        list.innerHTML+='<li style="margin-bottom:4px;color:var(--danger);">'+num+(title?' - '+title:'')+'</li>';
    });
    list.innerHTML+='</ol>';
    modal.style.display='flex';
}
document.getElementById('bulkDeleteConfirm').addEventListener('input',function(){
    var submitBtn=document.getElementById('bulkDeleteSubmitBtn');
    if(this.value.toUpperCase()==='DELETE'){
        submitBtn.disabled=false;
        submitBtn.style.opacity='1';
        submitBtn.style.cursor='pointer';
    }else{
        submitBtn.disabled=true;
        submitBtn.style.opacity='0.5';
        submitBtn.style.cursor='not-allowed';
    }
});
function submitBulkDelete(){
    var checked=document.querySelectorAll('.evidence-checkbox:checked');
    if(checked.length===0)return;
    var ids=Array.from(checked).map(function(el){return el.value;});
    var csrf=document.querySelector('input[name="csrf_token"]')?.value||'';
    var submitBtn=document.getElementById('bulkDeleteSubmitBtn');
    var result=document.getElementById('bulkDeleteResult');
    submitBtn.disabled=true;
    submitBtn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Deleting...';
    var formData=new FormData();
    formData.append('bulk_action','delete');
    formData.append('csrf_token',csrf);
    formData.append('evidence_ids_json',JSON.stringify(ids));
    fetch('evidence.php',{method:'POST',body:formData})
        .then(function(res){return res.json();})
        .then(function(data){
            if(data.success){
                result.style.display='block';
                result.style.background='rgba(74,222,128,0.1)';
                result.style.borderColor='rgba(74,222,128,0.3)';
                result.style.color='var(--success)';
                var msg=data.deleted+' evidence item'+(data.deleted!==1?'s':'')+' permanently deleted.';
                if(data.errors&&data.errors.length>0){
                    msg+=' '+data.errors.length+' skipped.';
                }
                result.innerHTML='<i class="fas fa-check-circle" style="margin-right:6px;"></i>'+msg;
                submitBtn.innerHTML='<i class="fas fa-check"></i> Done';
                setTimeout(function(){
                    closeBulkDeleteModal();
                    location.reload();
                },1500);
            }else{
                result.style.display='block';
                result.style.background='rgba(248,113,113,0.1)';
                result.style.borderColor='rgba(248,113,113,0.3)';
                result.textContent=data.error||'An error occurred.';
                submitBtn.disabled=false;
                submitBtn.innerHTML='<i class="fas fa-trash"></i> Confirm Delete';
            }
        })
        .catch(function(err){
            result.style.display='block';
            result.style.background='rgba(248,113,113,0.1)';
            result.style.borderColor='rgba(248,113,113,0.3)';
            result.textContent='Error: '+err.message;
            submitBtn.disabled=false;
            submitBtn.innerHTML='<i class="fas fa-trash"></i> Confirm Delete';
        });
}
function closeBulkDeleteModal(){
    document.getElementById('bulkDeleteModal').style.display='none';
}
</script>
<script src="../assets/js/main.js"></script>
</body>
</html>
