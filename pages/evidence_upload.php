<?php
/**
 * DigiCustody – Evidence Upload (Full Chain of Custody)
 * Save to: /var/www/html/digicustody/pages/evidence_upload.php
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login();

if (!is_admin() && !is_investigator()) {
    header('Location: ../dashboard.php?error=access_denied'); exit;
}

$page_title      = 'Upload Evidence';
$uid             = $_SESSION['user_id'];
$role            = $_SESSION['role'];
$preselect_case  = (int)($_GET['case_id'] ?? 0);

// Fetch cases
$cases = $pdo->query("
    SELECT id, case_number, case_title, status
    FROM cases
    WHERE status IN ('open','under_investigation')
    ORDER BY created_at DESC
")->fetchAll(PDO::FETCH_ASSOC);

// Fetch active analysts with workload info (one case at a time)
$analysts = $pdo->query("
    SELECT u.id, u.full_name, u.username, u.department,
           (SELECT COUNT(DISTINCT c.id) FROM cases c
            WHERE c.assigned_analyst = u.id AND c.status IN ('open','under_investigation')) AS active_cases,
           (SELECT COUNT(DISTINCT e.id) FROM evidence e
            WHERE e.assigned_analyst = u.id AND e.analysis_status IN ('assigned','in_progress')) AS active_evidence
    FROM users u
    WHERE u.role='analyst' AND u.status='active'
    ORDER BY u.full_name
")->fetchAll(PDO::FETCH_ASSOC);

// ── Handle new case creation (AJAX) ──────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'create_case') {
    header('Content-Type: application/json');
    
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        echo json_encode(['success'=>false,'error'=>'Security token mismatch.']); exit;
    }
    
    // Rate limit case creation
    if (!rate_limit_check($pdo, 'create_case', $_SERVER['REMOTE_ADDR'] ?? 'unknown', 10, 60)) {
        echo json_encode(['success'=>false,'error'=>'Too many attempts. Please wait.']); exit;
    }
    
    $title    = trim($_POST['case_title'] ?? '');
    $desc     = trim($_POST['case_description'] ?? '');
    $type     = trim($_POST['case_type'] ?? '');
    $priority = in_array($_POST['priority']??'',['low','medium','high','critical']) ? $_POST['priority'] : 'medium';
    if (empty($title)) { echo json_encode(['success'=>false,'error'=>'Case title is required.']); exit; }
    if (strlen($title) > 255) { echo json_encode(['success'=>false,'error'=>'Case title too long.']); exit; }
    $cn = generate_case_number($pdo);
    $pdo->prepare("INSERT INTO cases (case_number,case_title,description,case_type,priority,status,created_by) VALUES(?,?,?,?,?,'open',?)")
        ->execute([$cn,$title,$desc,$type,$priority,$uid]);
    $cid = $pdo->lastInsertId();
    audit_log($pdo,$uid,$_SESSION['username'],$role,'case_created','case',$cid,$cn,"Case created: $cn — $title");
    echo json_encode(['success'=>true,'case_id'=>$cid,'case_number'=>$cn,'case_title'=>$title]);
    exit;
}

// ── Handle evidence upload (AJAX per file) ───────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'upload_file') {
    header('Content-Type: application/json');

    // Rate limit uploads
    if (!rate_limit_check($pdo, 'upload', $_SERVER['REMOTE_ADDR'] ?? 'unknown', 30, 60)) {
        echo json_encode(['success'=>false,'error'=>'Too many upload attempts. Please wait.']); exit;
    }

    // ── Core fields ──
    $case_id         = (int)($_POST['case_id'] ?? 0);
    
    // Check case status - block upload if case is closed or archived
    $stmt = $pdo->prepare("SELECT status, case_number FROM cases WHERE id=?");
    $stmt->execute([$case_id]);
    $case_info = $stmt->fetch();
    if ($case_info && in_array($case_info['status'], ['closed', 'archived'])) {
        echo json_encode(['success'=>false,'error'=>'This case is closed and no new evidence can be added.']); exit;
    }
    
    $title           = trim($_POST['ev_title'] ?? '');
    $description     = trim($_POST['ev_description'] ?? '');
    $evidence_type   = $_POST['evidence_type'] ?? 'other';

    // ── Collection details ──
    $collection_date      = trim($_POST['collection_date'] ?? '');
    $collection_time      = trim($_POST['collection_time'] ?? '');
    $collection_location  = trim($_POST['collection_location'] ?? '');
    $collection_address   = trim($_POST['collection_address'] ?? '');

    // ── Collector / officer ──
    $collected_by_name    = trim($_POST['collected_by_name'] ?? $_SESSION['full_name']);
    $collector_badge      = trim($_POST['collector_badge'] ?? '');
    $collector_unit       = trim($_POST['collector_unit'] ?? '');
    $collector_contact    = trim($_POST['collector_contact'] ?? '');

    // ── Evidence condition ──
    $condition_on_receipt = trim($_POST['condition_on_receipt'] ?? '');
    $packaging_type       = trim($_POST['packaging_type'] ?? '');
    $seal_number          = trim($_POST['seal_number'] ?? '');
    $evidence_tag_number  = trim($_POST['evidence_tag_number'] ?? '');

    // ── Acquisition details ──
    $acquisition_method   = trim($_POST['acquisition_method'] ?? '');
    $tools_used           = trim($_POST['tools_used'] ?? '');
    $write_blocker_used   = isset($_POST['write_blocker_used']) ? 'Yes' : 'No';
    $original_device      = trim($_POST['original_device'] ?? '');
    $device_serial        = trim($_POST['device_serial'] ?? '');
    $device_type          = trim($_POST['device_type'] ?? '');
    $device_make_model    = trim($_POST['device_make_model'] ?? '');
    $os_detected          = trim($_POST['os_detected'] ?? '');

    // ── Witness ──
    $witness_name         = trim($_POST['witness_name'] ?? '');
    $witness_badge        = trim($_POST['witness_badge'] ?? '');
    $witness2_name        = trim($_POST['witness2_name'] ?? '');
    $witness2_badge       = trim($_POST['witness2_badge'] ?? '');

    // ── Legal authority ──
    $legal_basis          = trim($_POST['legal_basis'] ?? '');
    $warrant_number       = trim($_POST['warrant_number'] ?? '');
    $issuing_court        = trim($_POST['issuing_court'] ?? '');
    $ob_number            = trim($_POST['ob_number'] ?? '');

    $transport_method     = trim($_POST['transport_method'] ?? '');

    // ── Network Evidence Specifics ──
    $ip_address           = trim($_POST['ip_address'] ?? '');
    $mac_address          = trim($_POST['mac_address'] ?? '');
    $hostname             = trim($_POST['hostname'] ?? '');

    // ── Handling Precautions ──
    $handle_fragile       = isset($_POST['handle_fragile']) ? 'Yes' : 'No';
    $handle_emf           = isset($_POST['handle_emf']) ? 'Yes' : 'No';
    $handle_temp          = isset($_POST['handle_temp']) ? 'Yes' : 'No';
    $handle_bio           = isset($_POST['handle_bio']) ? 'Yes' : 'No';
    $handle_remote_wipe   = isset($_POST['handle_remote']) ? 'Yes' : 'No';
    $handle_encrypted     = isset($_POST['handle_encrypted']) ? 'Yes' : 'No';

    // ── Notes ──
    $collection_notes     = trim($_POST['collection_notes'] ?? '');
    $chain_of_custody_notes = trim($_POST['chain_of_custody_notes'] ?? '');

    $allowed_ev_types = ['image','video','document','log_file','email','database','network_capture','mobile_data','other'];
    if (!in_array($evidence_type, $allowed_ev_types)) $evidence_type = 'other';

    if (!$case_id) { echo json_encode(['success'=>false,'error'=>'Please select a case.']); exit; }
    if (empty($title)) { echo json_encode(['success'=>false,'error'=>'Evidence title is required.']); exit; }
    if (!isset($_FILES['ev_file']) || $_FILES['ev_file']['error'] !== UPLOAD_ERR_OK) {
        echo json_encode(['success'=>false,'error'=>'File upload failed. Code: '.($_FILES['ev_file']['error']??'?')]); exit;
    }

    // Build full collection datetime
    $collection_datetime = $collection_date && $collection_time
        ? $collection_date.' '.$collection_time.':00'
        : date('Y-m-d H:i:s');

    // Keep collection_notes for free-form notes, but store structured data in individual columns
    $structured_notes = '';
    if ($condition_on_receipt) $structured_notes .= "Condition: $condition_on_receipt\n";
    if ($packaging_type) $structured_notes .= "Packaging: $packaging_type\n";
    if ($seal_number) $structured_notes .= "Seal: $seal_number\n";
    if ($acquisition_method) $structured_notes .= "Acquisition: $acquisition_method\n";
    if ($device_make_model) $structured_notes .= "Device: $device_make_model\n";
    if ($os_detected) $structured_notes .= "OS: $os_detected\n";
    if ($chain_of_custody_notes) $structured_notes .= "COC: $chain_of_custody_notes\n";
    if ($legal_basis) $structured_notes .= "Legal: $legal_basis\n";
    if ($warrant_number) $structured_notes .= "Warrant: $warrant_number\n";
    if ($issuing_court) $structured_notes .= "Court: $issuing_court\n";
    if ($ob_number) $structured_notes .= "OB: $ob_number\n";
    if ($transport_method) $structured_notes .= "Handover: $transport_method\n";
    if ($collector_unit) $structured_notes .= "Unit: $collector_unit\n";
    if ($collector_contact) $structured_notes .= "Contact: $collector_contact\n";
    if ($collection_notes) $structured_notes .= "Notes: $collection_notes\n";
    if ($ip_address) $structured_notes .= "IP: $ip_address\n";
    if ($mac_address) $structured_notes .= "MAC: $mac_address\n";
    if ($hostname) $structured_notes .= "Hostname: $hostname\n";
    
    // Legacy concatenated notes (for backwards compatibility)
    $full_coc_notes = "";
    if ($collected_by_name)    $full_coc_notes .= "Collected by: $collected_by_name\n";
    if ($collector_badge)      $full_coc_notes .= "Badge/ID: $collector_badge\n";
    if ($collector_unit)       $full_coc_notes .= "Unit/Department: $collector_unit\n";
    if ($collector_contact)    $full_coc_notes .= "Contact: $collector_contact\n";
    if ($condition_on_receipt) $full_coc_notes .= "Condition on receipt: $condition_on_receipt\n";
    if ($packaging_type)       $full_coc_notes .= "Packaging: $packaging_type\n";
    if ($seal_number)          $full_coc_notes .= "Seal number: $seal_number\n";
    if ($evidence_tag_number)  $full_coc_notes .= "Evidence tag: $evidence_tag_number\n";
    if ($acquisition_method)   $full_coc_notes .= "Acquisition method: $acquisition_method\n";
    if ($tools_used)           $full_coc_notes .= "Tools used: $tools_used\n";
    if ($write_blocker_used)   $full_coc_notes .= "Write blocker used: $write_blocker_used\n";
    if ($original_device)      $full_coc_notes .= "Original device: $original_device\n";
    if ($device_serial)        $full_coc_notes .= "Device serial: $device_serial\n";
    if ($device_make_model)    $full_coc_notes .= "Device make/model: $device_make_model\n";
    if ($os_detected)          $full_coc_notes .= "OS detected: $os_detected\n";
    if ($witness_name)         $full_coc_notes .= "Witness: $witness_name";
    if ($witness_badge)        $full_coc_notes .= " (Badge: $witness_badge)";
    if ($witness_name)         $full_coc_notes .= "\n";
    if ($witness2_name)        $full_coc_notes .= "Witness 2: $witness2_name";
    if ($witness2_badge)       $full_coc_notes .= " (Badge: $witness2_badge)";
    if ($witness2_name)        $full_coc_notes .= "\n";
    if ($collection_notes)     $full_coc_notes .= "Collection notes: $collection_notes\n";
    if ($chain_of_custody_notes) $full_coc_notes .= "COC notes: $chain_of_custody_notes\n";
    if ($legal_basis)          $full_coc_notes .= "Legal basis: $legal_basis\n";
    if ($warrant_number)       $full_coc_notes .= "Warrant/Order: $warrant_number\n";
    if ($issuing_court)        $full_coc_notes .= "Issuing court: $issuing_court\n";
    if ($ob_number)            $full_coc_notes .= "OB/Case number: $ob_number\n";
    if ($transport_method)     $full_coc_notes .= "Handover: $transport_method\n";
    if ($ip_address)           $full_coc_notes .= "IP address(es): $ip_address\n";
    if ($mac_address)          $full_coc_notes .= "MAC address(es): $mac_address\n";
    if ($hostname)             $full_coc_notes .= "Hostname: $hostname\n";
    $precautions = [];
    if ($handle_fragile)       $precautions[] = 'Fragile';
    if ($handle_emf)           $precautions[] = 'EMF/RF shielded';
    if ($handle_temp)          $precautions[] = 'Temperature sensitive';
    if ($handle_bio)           $precautions[] = 'Biohazard';
    if ($handle_remote_wipe)   $precautions[] = 'Remote wipe risk';
    if ($handle_encrypted)     $precautions[] = 'Encrypted';
    if (!empty($precautions))  $full_coc_notes .= "Precautions: " . implode(', ', $precautions) . "\n";

    // Required field validation
    $required = [
        'Collection Date' => $collection_date,
        'Collection Time' => $collection_time,
        'Collection Location' => $collection_location,
        'Collected By' => $collected_by_name,
        'Badge Number' => $collector_badge,
        'Legal Basis' => $legal_basis,
        'Condition on Receipt' => $condition_on_receipt,
        'Witness 1 Name' => $witness_name,
    ];
    $missing = [];
    foreach ($required as $field => $value) {
        if (trim($value) === '') {
            $missing[] = $field;
        }
    }
    if (!empty($missing)) {
        echo json_encode(['success' => false, 'error' => 'Required fields missing: ' . implode(', ', $missing)]);
        exit;
    }

    // Examiner declaration must be confirmed
    if (!isset($_POST['examiner_declaration']) || $_POST['examiner_declaration'] !== '1') {
        echo json_encode(['success' => false, 'error' => 'You must confirm the examiner declaration before uploading.']);
        exit;
    }

    $ev_number = generate_evidence_number($pdo);
    $upload    = handle_evidence_upload($_FILES['ev_file'], $ev_number, $pdo, $uid, $_SESSION['username'], $role, $collection_datetime, $full_location, trim($structured_notes));

    if (!$upload['success']) { echo json_encode(['success'=>false,'error'=>$upload['error']]); exit; }

    // ── Disk Quota Enforcement (10GB per case) ───────────────────────
    $case_quota_bytes = 10 * 1024 * 1024 * 1024; // 10GB
    $stmt_case_size = $pdo->prepare("SELECT COALESCE(SUM(file_size), 0) FROM evidence WHERE case_id = ?");
    $stmt_case_size->execute([$case_id]);
    $current_case_size = (int)$stmt_case_size->fetchColumn();
    $new_total_size = $current_case_size + $upload['file_size'];

    if ($new_total_size > $case_quota_bytes) {
        @unlink($upload['filepath']);
        $quota_gb = $case_quota_bytes / (1024 * 1024 * 1024);
        $current_gb = $current_case_size / (1024 * 1024 * 1024);
        $error_msg = "Upload rejected: Case storage quota ({$quota_gb}GB) exceeded. Current: " . round($current_gb, 2) . "GB + " . format_filesize($upload['file_size']) . " = " . format_filesize($new_total_size);
        echo json_encode(['success' => false, 'error' => $error_msg]);
        
        foreach ($pdo->query("SELECT id FROM users WHERE role='admin' AND status='active'")->fetchAll() as $adm) {
            send_notification($pdo, $adm['id'], 'Storage Quota Exceeded', "Evidence upload rejected for case {$case_id}: quota exceeded by " . $_SESSION['full_name'], 'warning', 'case', $case_id);
        }
        exit;
    }

    // Full location
    $full_location = $collection_location;
    if ($collection_address) $full_location .= ($full_location ? ', ' : '') . $collection_address;

    $pdo->prepare("INSERT INTO evidence
        (evidence_number,case_id,title,description,evidence_type,acquisition_method,file_name,file_path,
         file_size,mime_type,sha256_hash,sha3_256_hash,collection_date,collection_location,
         collection_notes,collector_badge,tools_used,write_blocker_used,device_serial,device_type,
         device_make_model,os_detected,seal_number,condition_on_receipt,
         witness_name,witness_badge,witness2_name,witness2_badge,
         current_custodian,status,uploaded_by)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'collected',?)")
        ->execute([
            $ev_number, $case_id, $title, $description, $evidence_type,
            $acquisition_method, $upload['filename'], $upload['filepath'],
            $upload['file_size'], $upload['mime_type'],
            $upload['sha256'], $upload['sha3_256'],
            $upload['collection_date'], $upload['collection_location'],
            $upload['collection_notes'], $collector_badge, $tools_used, ($write_blocker_used ? 1 : 0), $device_serial, $device_type, $device_make_model, $os_detected, $seal_number, $condition_on_receipt, $witness_name, $witness_badge, $witness2_name, $witness2_badge, $uid, $uid
        ]);
    $ev_id = $pdo->lastInsertId();

    // Detailed audit log with all COC fields
    audit_log($pdo,$uid,$_SESSION['username'],$role,'evidence_uploaded','evidence',$ev_id,$ev_number,
        "Evidence uploaded: $ev_number — $title | Collected by: $collected_by_name | Location: $full_location | Tools: $tools_used",
        $_SERVER['REMOTE_ADDR']??'', $_SERVER['HTTP_USER_AGENT']??'',
        [
            'sha256'=>$upload['sha256'], 'sha3_256'=>$upload['sha3_256'],
            'size'=>$upload['file_size'], 'mime'=>$upload['mime_type'],
            'collected_by'=>$collected_by_name, 'badge'=>$collector_badge,
            'unit'=>$collector_unit, 'location'=>$full_location,
            'acquisition_method'=>$acquisition_method, 'tools'=>$tools_used,
            'write_blocker'=>$write_blocker_used, 'device'=>$original_device,
            'serial'=>$device_serial, 'witness'=>$witness_name,
            'condition'=>$condition_on_receipt, 'seal'=>$seal_number,
            'legal_basis'=>$legal_basis, 'warrant_number'=>$warrant_number,
            'issuing_court'=>$issuing_court, 'ob_number'=>$ob_number,
            'transport_method'=>$transport_method,
            'ip_address'=>$ip_address, 'mac_address'=>$mac_address,
            'hostname'=>$hostname,
            'precautions'=>array_filter([
                'fragile'=>$handle_fragile==='Yes','emf'=>$handle_emf==='Yes',
                'temp'=>$handle_temp==='Yes','bio'=>$handle_bio==='Yes',
                'remote_wipe'=>$handle_remote_wipe==='Yes','encrypted'=>$handle_encrypted==='Yes',
            ]),
        ]);

    // Save evidence links
    $linked_json = $_POST['linked_evidence'] ?? '';
    if ($linked_json) {
        $linked = json_decode($linked_json, true);
        if (is_array($linked)) {
            $stmt_link = $pdo->prepare("INSERT IGNORE INTO evidence_links (evidence_id, linked_evidence_id, link_type) VALUES (?, ?, ?)");
            foreach ($linked as $link) {
                if (!empty($link['id']) && !empty($link['link_type'])) {
                    $stmt_link->execute([$ev_id, $link['id'], $link['link_type']]);
                    audit_log($pdo, $uid, $_SESSION['username'], $role, 'evidence_linked', 'evidence', $ev_id, $ev_number,
                        "Linked evidence {$link['id']} as {$link['link_type']}", $_SERVER['REMOTE_ADDR'] ?? '');
                }
            }
        }
    }

    // Notify admins
    foreach ($pdo->query("SELECT id FROM users WHERE role='admin' AND status='active'")->fetchAll() as $adm) {
        send_notification($pdo,$adm['id'],'New Evidence Uploaded',
            "$ev_number uploaded by {$_SESSION['full_name']}",'info','evidence',$ev_id);
    }

    // Assign to analyst if selected
    $assigned_analyst_id = (int)($_POST['assigned_analyst'] ?? 0);
    $assignment_notes = trim($_POST['assignment_notes'] ?? '');
    if ($assigned_analyst_id > 0) {
        // Check analyst is not already assigned to an active case
        $stmt = $pdo->prepare("
            SELECT COUNT(DISTINCT c.id) as cnt
            FROM cases c
            WHERE c.assigned_analyst = ? AND c.status IN ('open','under_investigation')
        ");
        $stmt->execute([$assigned_analyst_id]);
        $active = (int)$stmt->fetchColumn();
        if ($active > 0) {
            echo json_encode(['success'=>false,'error'=>'This analyst is already assigned to an active case. Please wait for them to complete their current work or select another analyst.']); exit;
        }

        // Grant case access to analyst
        grant_case_access($pdo, $case_id, $assigned_analyst_id, $uid);
        // Assign case-level analyst
        $pdo->prepare("UPDATE cases SET assigned_analyst=?, updated_at=NOW() WHERE id=?")
            ->execute([$assigned_analyst_id, $case_id]);
        // Assign analyst and set status to in_analysis (atomically)
        $assign_result = assign_analyst_to_evidence($pdo, $ev_id, $assigned_analyst_id, $uid, $assignment_notes);
        if (!$assign_result['success']) {
            echo json_encode(['success'=>false,'error'=>$assign_result['error']??'Failed to assign analyst']); exit;
        }
        // Log assignment
        audit_log($pdo,$uid,$_SESSION['username'],$role,'evidence_assigned','evidence',$ev_id,$ev_number,
            "Evidence assigned to analyst for investigation",
            $_SERVER['REMOTE_ADDR']??'', $_SERVER['HTTP_USER_AGENT']??'',
            ['assigned_to'=>$assigned_analyst_id,'notes'=>$assignment_notes]);
        // Notify analyst
        $stmt = $pdo->prepare("SELECT full_name FROM users WHERE id=?");
        $stmt->execute([$assigned_analyst_id]);
        $analyst = $stmt->fetch();
        if ($analyst) {
            send_notification($pdo,$assigned_analyst_id,'Evidence Assigned for Investigation',
                "$ev_number ($title) has been assigned to you by {$_SESSION['full_name']}. ".($assignment_notes?"Notes: $assignment_notes":''),
                'warning','evidence',$ev_id);
        }
    }

    echo json_encode([
        'success'         => true,
        'evidence_id'     => $ev_id,
        'evidence_number' => $ev_number,
        'sha256'          => $upload['sha256'],
        'sha3_256'        => $upload['sha3_256'],
        'file_size'       => format_filesize($upload['file_size']),
        'mime_type'       => $upload['mime_type'],
        'assigned_to'     => $assigned_analyst_id > 0 ? $assigned_analyst_id : null,
    ]);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Upload Evidence — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
/* ── form sections ── */
.form-section{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);margin-bottom:18px;overflow:hidden;}
.form-section-head{padding:14px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;background:rgba(255,255,255,0.02);}
.form-section-head h3{font-family:'Space Grotesk',sans-serif;font-size:14px;font-weight:600;color:var(--text);}
.form-section-head i{color:var(--gold);font-size:13px;}
.form-section-head .badge-req{font-size:10.5px;color:var(--danger);margin-left:4px;}
.form-section-body{padding:18px 20px;}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
.grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;}
/* ── fields ── */
.field{margin-bottom:0;}
.field label{display:block;font-size:11px;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px;}
.field label .req{color:var(--danger);margin-left:2px;}
.field input,.field select,.field textarea{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:10px 13px;font-size:13.5px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.field input:focus,.field select:focus,.field textarea:focus{border-color:rgba(201,168,76,0.5);box-shadow:0 0 0 3px rgba(201,168,76,0.06);}
.field select option{background:var(--surface2);}
.field textarea{resize:vertical;min-height:80px;}
.field .hint{font-size:11.5px;color:var(--dim);margin-top:4px;}
/* ── case selector ── */
.case-new-btn{background:none;border:none;color:var(--gold);font-size:12.5px;cursor:pointer;padding:0;font-family:'Inter',sans-serif;display:inline-flex;align-items:center;gap:5px;margin-top:6px;}
.case-new-btn:hover{text-decoration:underline;}
/* ── upload zone ── */
.upload-zone{border:2px dashed var(--border2);border-radius:var(--radius-lg);padding:40px 20px;text-align:center;cursor:pointer;transition:all .25s;background:var(--surface2);position:relative;}
.upload-zone:hover,.upload-zone.drag-over{border-color:var(--gold);background:rgba(201,168,76,0.04);}
.upload-zone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%;}
.upload-zone.drag-over .uz-icon{color:var(--gold);}
.uz-icon{font-size:32px;color:var(--dim);margin-bottom:10px;transition:color .25s;}
.uz-title{font-size:15px;font-weight:500;color:var(--text);margin-bottom:5px;}
.uz-sub{font-size:13px;color:var(--muted);}
/* ── file queue ── */
.file-queue{margin-top:16px;display:flex;flex-direction:column;gap:10px;}
.file-item{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;animation:fi .25s ease;}
@keyframes fi{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
.file-item.success{border-color:rgba(74,222,128,0.3);}
.file-item.error{border-color:rgba(248,113,113,0.3);}
.file-item.uploading{border-color:rgba(201,168,76,0.3);}
.fi-top{display:flex;align-items:center;gap:10px;margin-bottom:10px;}
.fi-icon{width:34px;height:34px;border-radius:8px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:14px;}
.fi-name{font-size:13px;font-weight:500;color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.fi-size{font-size:12px;color:var(--muted);flex-shrink:0;}
.fi-remove{background:none;border:none;color:var(--dim);cursor:pointer;font-size:13px;padding:3px;border-radius:5px;transition:all .2s;flex-shrink:0;}
.fi-remove:hover{color:var(--danger);background:rgba(248,113,113,0.1);}
.fi-progress{height:4px;border-radius:2px;background:var(--surface);overflow:hidden;margin-bottom:10px;}
.fi-progress-fill{height:100%;border-radius:2px;background:var(--gold);transition:width .3s ease;width:0%;}
.fi-progress-fill.done{background:var(--success);}
.fi-progress-fill.err{background:var(--danger);}
.fi-meta{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
.fi-meta .full{grid-column:span 2;}
.fi-meta label{display:block;font-size:10.5px;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;}
.fi-meta input,.fi-meta select,.fi-meta textarea{width:100%;background:var(--surface);border:1px solid var(--border);border-radius:7px;padding:8px 10px;font-size:13px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.fi-meta input:focus,.fi-meta select:focus,.fi-meta textarea:focus{border-color:rgba(201,168,76,0.4);}
.fi-meta select option{background:var(--surface2);}
.fi-meta textarea{resize:vertical;min-height:60px;}
/* hash result */
.hash-result{background:var(--surface);border:1px solid rgba(74,222,128,0.2);border-radius:8px;padding:12px 14px;margin-top:10px;}
.hash-result .hr-title{font-size:11px;font-weight:600;color:var(--success);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;display:flex;align-items:center;gap:5px;}
.hash-row{display:flex;align-items:center;gap:8px;margin-bottom:4px;}
.hash-label{font-size:10.5px;font-weight:600;color:var(--muted);width:46px;flex-shrink:0;}
.hash-val{font-family:'Courier New',monospace;font-size:11px;color:var(--text);flex:1;word-break:break-all;}
.copy-hash{background:none;border:none;color:var(--dim);cursor:pointer;font-size:11px;padding:2px 5px;border-radius:4px;transition:all .2s;flex-shrink:0;}
.copy-hash:hover{color:var(--gold);background:var(--gold-dim);}
/* thumb */
.fi-thumb{width:54px;height:54px;object-fit:cover;border-radius:7px;border:1px solid var(--border);flex-shrink:0;}
/* progress steps */
.progress-steps{display:flex;align-items:center;margin-bottom:28px;gap:0;}
.ps-step{display:flex;align-items:center;gap:8px;flex:1;}
.ps-step:last-child{flex:none;}
.ps-num{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;flex-shrink:0;transition:all .3s;}
.ps-num.done{background:var(--success);color:#060d1a;}
.ps-num.active{background:var(--gold);color:#060d1a;}
.ps-num.pending{background:var(--surface2);border:1px solid var(--border);color:var(--dim);}
.ps-label{font-size:12px;color:var(--muted);white-space:nowrap;}
.ps-label.active{color:var(--text);font-weight:500;}
.ps-line{flex:1;height:1px;background:var(--border);margin:0 8px;}
.ps-line.done{background:var(--success);}
/* modal */
.overlay{position:fixed;inset:0;z-index:300;background:rgba(4,8,18,.9);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;padding:20px;animation:fo .2s ease;}
@keyframes fo{from{opacity:0}to{opacity:1}}
.modal{background:var(--surface);border:1px solid var(--border2);border-radius:var(--radius-lg);width:100%;max-width:500px;max-height:90vh;overflow-y:auto;animation:mu .3s cubic-bezier(.22,.68,0,1.15);}
@keyframes mu{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
.modal-head{padding:20px 24px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;}
.modal-head h3{font-family:'Space Grotesk',sans-serif;font-size:16px;font-weight:600;color:var(--text);}
.modal-head h3 span{color:var(--gold);}
.modal-body{padding:20px 24px;}
.modal-foot{padding:12px 24px 20px;display:flex;gap:10px;justify-content:flex-end;}
.xbtn{background:none;border:none;color:var(--muted);font-size:14px;cursor:pointer;padding:3px 5px;border-radius:5px;}
.xbtn:hover{color:var(--danger);}
/* confirm list */
.confirm-list{list-style:none;display:flex;flex-direction:column;gap:8px;}
.confirm-list li{display:flex;align-items:center;gap:10px;font-size:13px;padding:8px 12px;background:var(--surface2);border-radius:8px;}
.confirm-list li i{color:var(--success);font-size:12px;flex-shrink:0;}
/* summary */
.summary-table{width:100%;border-collapse:collapse;font-size:13px;}
.summary-table td{padding:7px 0;border-bottom:1px solid var(--border);color:var(--text);}
.summary-table td:first-child{color:var(--muted);width:40%;padding-right:10px;}
.summary-table tr:last-child td{border-bottom:none;}
.coc-row{display:flex;gap:8px;padding:3px 0;border-bottom:1px solid var(--border);font-size:12px;}
.coc-row:last-child{border-bottom:none;}
.coc-label{color:var(--muted);min-width:140px;flex-shrink:0;font-weight:500;}
.coc-val{color:var(--text);flex:1;word-break:break-word;}
@media(max-width:680px){.grid-2,.grid-3{grid-template-columns:1fr;}.fi-meta{grid-template-columns:1fr;}.fi-meta .full{grid-column:span 1;}.progress-steps{display:none;}}
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
        <h1>Upload Evidence</h1>
        <p>All uploads are hashed, logged and permanently recorded in the chain of custody</p>
    </div>
    <div style="display:flex;gap:10px;">
        <button type="button" class="btn-back" onclick="goBack()"><i class="fas fa-arrow-left"></i> Back</button>
        <a href="../dashboard.php" class="btn btn-outline"><i class="fas fa-arrow-left"></i> Dashboard</a>
    </div>
</div>

<!-- Progress steps -->
<div class="progress-steps">
    <div class="ps-step">
        <div class="ps-num active" id="ps1">1</div>
        <span class="ps-label active">Case</span>
    </div>
    <div class="ps-line" id="pl1"></div>
    <div class="ps-step">
        <div class="ps-num pending" id="ps2">2</div>
        <span class="ps-label" id="psl2">Assign</span>
    </div>
    <div class="ps-line" id="pl2"></div>
    <div class="ps-step">
        <div class="ps-num pending" id="ps3">3</div>
        <span class="ps-label" id="psl3">Collection Details</span>
    </div>
    <div class="ps-line" id="pl3"></div>
    <div class="ps-step">
        <div class="ps-num pending" id="ps4">4</div>
        <span class="ps-label" id="psl4">Files</span>
    </div>
    <div class="ps-line" id="pl4"></div>
    <div class="ps-step">
        <div class="ps-num pending" id="ps5">5</div>
        <span class="ps-label" id="psl5">Upload</span>
    </div>
</div>

<!-- ══ SECTION 1: CASE ══ -->
<div class="form-section" id="sec-case">
    <div class="form-section-head">
        <i class="fas fa-folder-open"></i>
        <h3>Step 1 — Select or Create a Case / Crime Scene</h3>
    </div>
    <div class="form-section-body">
        <div class="grid-2">
            <div class="field">
                <label>Attach to Existing Case <span class="req">*</span></label>
                <select id="caseSelect" onchange="caseSelected(this)">
                    <option value="">— Select a case —</option>
                    <?php foreach($cases as $cv): ?>
                    <option value="<?= $cv['id'] ?>"
                        data-number="<?= e($cv['case_number']) ?>"
                        data-title="<?= e($cv['case_title']) ?>"
                        <?= $preselect_case===$cv['id']?'selected':'' ?>>
                        <?= e($cv['case_number']) ?> — <?= e($cv['case_title']) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
                <button type="button" class="case-new-btn" onclick="openCaseModal()">
                    <i class="fas fa-plus-circle"></i> Create new case / crime scene
                </button>
            </div>
            <div id="selectedCaseInfo" style="display:none;">
                <div class="field">
                    <label>Selected Case</label>
                    <div style="background:var(--surface2);border:1px solid rgba(74,222,128,0.25);border-radius:var(--radius);padding:10px 14px;">
                        <p style="font-size:13.5px;font-weight:700;color:var(--gold)" id="selCaseNum"></p>
                        <p style="font-size:12.5px;color:var(--muted);margin-top:3px" id="selCaseTitle"></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- ══ SECTION 1.5: ASSIGNMENT ══ -->
<div class="form-section" id="sec-assignment" style="opacity:.5;pointer-events:none;">
    <div class="form-section-head">
        <i class="fas fa-user-check"></i>
        <h3>Step 2 — Assign to Analyst</h3>
        <span style="font-size:11.5px;color:var(--muted);margin-left:auto">Optional — assign for investigation</span>
    </div>
    <div class="form-section-body">
        <div class="grid-2">
            <div class="field">
                <label>Assign to Analyst</label>
                <select id="assignAnalyst">
                    <option value="">— Skip assignment (assign later) —</option>
                    <?php foreach($analysts as $a):
                        $busy = $a['active_cases'] > 0;
                    ?>
                    <option value="<?= $a['id'] ?>"
                        data-name="<?= e($a['full_name']) ?>"
                        data-dept="<?= e($a['department'] ?? 'N/A') ?>"
                        <?= $busy ? 'disabled' : '' ?>>
                        <?= e($a['full_name']) ?> (<?= e($a['username']) ?>)<?= $busy ? ' — BUSY (on a case)' : ' — Available' ?><?= $a['department']?' · '.e($a['department']):'' ?>
                    </option>
                    <?php endforeach; ?>
                </select>
                <p class="hint">Analysts can only work on one case at a time. Busy analysts are unavailable until their current case is complete.</p>
            </div>
            <div class="field">
                <label>Assignment Notes</label>
                <textarea id="assignmentNotes" placeholder="What should the analyst focus on? Any special instructions?" style="min-height:80px;"></textarea>
            </div>
        </div>
    </div>
</div>

<!-- ══ SECTION 2: COLLECTION DETAILS ══ -->
<div class="form-section" id="sec-collection" style="opacity:.5;pointer-events:none;">
    <div class="form-section-head">
        <i class="fas fa-shield-halved"></i>
        <h3>Step 2 — Collection &amp; Chain of Custody Details</h3>
        <span style="font-size:11.5px;color:var(--muted);margin-left:auto">Required for court admissibility</span>
    </div>
    <div class="form-section-body">

        <!-- Collection info -->
        <p style="font-size:11px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px;display:flex;align-items:center;gap:6px;"><i class="fas fa-map-marker-alt"></i> Collection Information</p>
        <div class="grid-3" style="margin-bottom:16px;">
            <div class="field">
                <label>Collection Date <span class="req">*</span></label>
                <input type="date" id="collDate" value="<?= date('Y-m-d') ?>">
            </div>
            <div class="field">
                <label>Collection Time <span class="req">*</span></label>
                <input type="time" id="collTime" value="<?= date('H:i') ?>">
            </div>
            <div class="field">
                <label>Location / Scene Name <span class="req">*</span></label>
                <input type="text" id="collLocation" placeholder="e.g. Scene A, Office 4B">
            </div>
        </div>
        <div class="field" style="margin-bottom:16px;">
            <label>Full Physical Address</label>
            <input type="text" id="collAddress" placeholder="e.g. 4th Floor, Anniversary Towers, Nairobi CBD, Kenya">
        </div>

        <!-- Collector / Officer -->
        <p style="font-size:11px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px;display:flex;align-items:center;gap:6px;"><i class="fas fa-user-shield"></i> Collecting Officer</p>
        <div class="grid-2" style="margin-bottom:16px;">
            <div class="field">
                <label>Collected By (Full Name) <span class="req">*</span></label>
                <input type="text" id="collectedByName" value="<?= e($_SESSION['full_name']) ?>">
            </div>
            <div class="field">
                <label>Badge / Staff Number <span class="req">*</span></label>
                <input type="text" id="collectorBadge" placeholder="e.g. DCI-00123">
            </div>
            <div class="field">
                <label>Unit / Department</label>
                <input type="text" id="collectorUnit" placeholder="e.g. Cyber Crime Unit, DCI">
            </div>
            <div class="field">
                <label>Contact / Phone</label>
                <input type="text" id="collectorContact" placeholder="+254 7XX XXX XXX">
            </div>
        </div>

        <!-- Evidence condition -->
        <p style="font-size:11px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px;display:flex;align-items:center;gap:6px;"><i class="fas fa-box"></i> Evidence Condition &amp; Packaging</p>
        <div class="grid-2" style="margin-bottom:16px;">
            <div class="field">
                <label>Condition on Receipt <span class="req">*</span></label>
                <select id="conditionOnReceipt">
                    <option value="">— Select condition —</option>
                    <option>Sealed / Intact packaging</option>
                    <option>Intact / Undamaged</option>
                    <option>Previously opened</option>
                    <option>Powered On</option>
                    <option>Powered Off</option>
                    <option>Corrupted / Unreadable</option>
                    <option>Encrypted / Password protected</option>
                    <option>Damaged — Screen cracked</option>
                    <option>Damaged — Physical damage</option>
                    <option>Water damaged</option>
                    <option>Partial — Missing components</option>
                    <option>Unknown / Unverified</option>
                </select>
            </div>
            <div class="field">
                <label>Packaging Type</label>
                <select id="packagingType">
                    <option value="">— Select packaging —</option>
                    <option>Anti-static bag</option>
                    <option>Evidence bag (sealed)</option>
                    <option>Hard case / Container</option>
                    <option>Faraday bag</option>
                    <option>Faraday cage</option>
                    <option>Write-protected media</option>
                    <option>Tamper-evident container</option>
                    <option>Cardboard box</option>
                    <option>No packaging</option>
                    <option>Other</option>
                </select>
            </div>
            <div class="field">
                <label>Evidence Seal Number</label>
                <input type="text" id="sealNumber" placeholder="Tamper-evident seal ID">
            </div>
            <div class="field">
                <label>Evidence Tag / Label Number</label>
                <input type="text" id="evidenceTagNumber" placeholder="e.g. EXH-001-2026">
            </div>
        </div>

        <!-- Acquisition / Forensic details -->
        <div id="deviceSection">
        <p style="font-size:11px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px;display:flex;align-items:center;gap:6px;"><i class="fas fa-microchip"></i> Acquisition &amp; Forensic Details</p>
        <div class="grid-2" style="margin-bottom:16px;">
            <div class="field">
                <label>Acquisition Method</label>
                <select id="acquisitionMethod">
                    <option value="">— Select method —</option>
                    <optgroup label="Physical Device">
                        <option>UFED extraction</option>
                        <option>Oxygen Forensic extraction</option>
                        <option>EnCase acquisition</option>
                        <option>Logical acquisition</option>
                        <option>Physical acquisition</option>
                        <option>Full disk image (dd/E01)</option>
                        <option>Live acquisition</option>
                    </optgroup>
                    <optgroup label="Network &amp; Cloud">
                        <option>Cloud extraction</option>
                        <option>Network capture</option>
                    </optgroup>
                    <optgroup label="Manual">
                        <option>Manual file copy</option>
                        <option>Manual collection</option>
                        <option>Autopsy</option>
                        <option>Selective file copy</option>
                    </optgroup>
                    <option>Other</option>
                </select>
            </div>
            <div class="field">
                <label>Forensic Tools Used</label>
                <input type="text" id="toolsUsed" placeholder="e.g. FTK Imager 4.7, Cellebrite UFED">
            </div>
            <div class="field">
                <label>Original Device / Source</label>
                <input type="text" id="originalDevice" placeholder="e.g. Laptop, Mobile Phone, Server">
            </div>
            <div class="field">
                <label>Device Make &amp; Model</label>
                <input type="text" id="deviceMakeModel" placeholder="e.g. Samsung Galaxy S22, Dell Latitude">
            </div>
            <div class="field">
                <label>Device Serial Number / IMEI</label>
                <input type="text" id="deviceSerial" placeholder="Serial or IMEI number">
            </div>
            <div class="field">
                <label>Operating System Detected</label>
                <input type="text" id="osDetected" placeholder="e.g. Windows 11 Pro, Android 13">
            </div>
        </div>
        </div>

        <!-- Write blocker -->
        <div style="background:rgba(201,168,76,0.05);border:1px solid rgba(201,168,76,0.15);border-radius:var(--radius);padding:13px 16px;margin-bottom:16px;display:flex;align-items:center;gap:12px;">
            <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:13.5px;color:var(--text);margin:0;">
                <input type="checkbox" id="writeBlockerUsed" checked style="width:16px;height:16px;accent-color:var(--gold);cursor:pointer;">
                <div>
                    <p style="font-weight:500">Write blocker was used during acquisition</p>
                    <p style="font-size:12px;color:var(--muted);margin-top:1px">Confirms the original evidence was not modified during the acquisition process</p>
                </div>
            </label>
        </div>

        <!-- Legal authority -->
        <p style="font-size:11px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px;display:flex;align-items:center;gap:6px;"><i class="fas fa-gavel"></i> Legal Authority</p>
        <div class="grid-2" style="margin-bottom:16px;">
            <div class="field">
                <label>Legal Basis for Collection <span class="req">*</span></label>
                <select id="legalBasis">
                    <option value="">— Select —</option>
                    <option>Search Warrant</option>
                    <option>Court Order</option>
                    <option>Production Order</option>
                    <option>Mutual Legal Assistance Treaty (MLAT)</option>
                    <option>Regulatory Authority Order</option>
                    <option>Employer Authorization</option>
                    <option>Consent (Written)</option>
                    <option>Consent (Verbal)</option>
                    <option>Exigent Circumstances</option>
                    <option>Plain View Doctrine</option>
                    <option>Incident to Arrest</option>
                    <option>Administrative Subpoena</option>
                    <option>Voluntary Surrender</option>
                    <option>Other</option>
                </select>
            </div>
            <div class="field">
                <label>Warrant / Order Number</label>
                <input type="text" id="warrantNumber" placeholder="e.g. CW-2026-00456">
            </div>
            <div class="field">
                <label>Issuing Court / Authority</label>
                <input type="text" id="issuingCourt" placeholder="e.g. Chief Magistrate's Court, Nairobi">
            </div>
            <div class="field">
                <label>Case / OB Number</label>
                <input type="text" id="obNumber" placeholder="e.g. OB 123/2026">
            </div>
        </div>

        <!-- Witness -->
        <p style="font-size:11px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px;display:flex;align-items:center;gap:6px;"><i class="fas fa-eye"></i> Witness Information</p>
        <div class="grid-2" style="margin-bottom:16px;">
            <div class="field">
                <label>Witness 1 Name <span class="req">*</span></label>
                <input type="text" id="witnessName" placeholder="Full name of witness present">
            </div>
            <div class="field">
                <label>Witness 1 Badge / ID</label>
                <input type="text" id="witnessBadge" placeholder="Badge or ID number">
            </div>
            <div class="field">
                <label>Witness 2 Name</label>
                <input type="text" id="witness2Name" placeholder="Second witness (if any)">
            </div>
            <div class="field">
                <label>Witness 2 Badge / ID</label>
                <input type="text" id="witness2Badge" placeholder="Badge or ID number">
            </div>
        </div>

        <!-- Chain of Custody Handover -->
        <p style="font-size:11px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px;display:flex;align-items:center;gap:6px;"><i class="fas fa-hand-holding"></i> Chain of Custody Handover</p>
        <div class="grid-2" style="margin-bottom:16px;">
            <div class="field">
                <label>Handover Method</label>
                <select id="transportMethod">
                    <option value="">— Select —</option>
                    <option>In person</option>
                    <option>Evidence locker</option>
                    <option>Secure courier</option>
                    <option>Digital transfer (encrypted)</option>
                    <option>Internal mail</option>
                </select>
            </div>
        </div>

        <!-- Network evidence specifics -->
        <div id="networkSection" style="display:none;">
        <p style="font-size:11px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px;display:flex;align-items:center;gap:6px;"><i class="fas fa-network-wired"></i> Network &amp; Digital Evidence Specifics</p>
        <div class="grid-2" style="margin-bottom:16px;">
            <div class="field">
                <label>IP Address(es)</label>
                <input type="text" id="ipAddress" placeholder="e.g. 192.168.1.100, 10.0.0.5">
            </div>
            <div class="field">
                <label>MAC Address(es)</label>
                <input type="text" id="macAddress" placeholder="e.g. AA:BB:CC:DD:EE:FF">
            </div>
            <div class="field">
                <label>Domain / Hostname</label>
                <input type="text" id="hostname" placeholder="e.g. WORKSTATION-01, server.local">
            </div>
        </div>
        </div>

        <!-- Evidence handling precautions -->
        <p style="font-size:11px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px;display:flex;align-items:center;gap:6px;"><i class="fas fa-triangle-exclamation"></i> Handling Precautions</p>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:16px;">
            <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text);cursor:pointer;">
                <input type="checkbox" id="handleFragile" style="width:16px;height:16px;accent-color:var(--gold);cursor:pointer;">
                Fragile / Handle with care
            </label>
            <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text);cursor:pointer;">
                <input type="checkbox" id="handleEMF" style="width:16px;height:16px;accent-color:var(--gold);cursor:pointer;">
                Shield from EMF / RF
            </label>
            <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text);cursor:pointer;">
                <input type="checkbox" id="handleTemp" style="width:16px;height:16px;accent-color:var(--gold);cursor:pointer;">
                Temperature sensitive
            </label>
            <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text);cursor:pointer;">
                <input type="checkbox" id="handleBio" style="width:16px;height:16px;accent-color:var(--gold);cursor:pointer;">
                Biohazard precautions
            </label>
            <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text);cursor:pointer;">
                <input type="checkbox" id="handleRemote" style="width:16px;height:16px;accent-color:var(--gold);cursor:pointer;">
                Remote wipe risk — isolate
            </label>
            <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text);cursor:pointer;">
                <input type="checkbox" id="handleEncrypted" style="width:16px;height:16px;accent-color:var(--gold);cursor:pointer;">
                Encrypted / password protected
            </label>
        </div>

        <!-- Notes -->
        <p style="font-size:11px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px;display:flex;align-items:center;gap:6px;"><i class="fas fa-notes-medical"></i> Notes</p>
        <div class="grid-2">
            <div class="field">
                <label>Collection Notes</label>
                <textarea id="collectionNotes" placeholder="Describe how the evidence was found, its context, and any relevant observations at the scene. Include network SSID if applicable..."></textarea>
            </div>
            <div class="field">
                <label>Chain of Custody Notes</label>
                <textarea id="cocNotes" placeholder="Any special handling instructions, restrictions, or notes relevant to maintaining custody integrity..."></textarea>
            </div>
        </div>
    </div>
</div>

<!-- ══ SECTION 3: FILES ══ -->
<div class="form-section" id="sec-files" style="opacity:.5;pointer-events:none;">
    <div class="form-section-head">
        <i class="fas fa-upload"></i>
        <h3>Step 3 — Evidence Files</h3>
    </div>
    <div class="form-section-body">
        <div class="upload-zone" id="dropZone">
            <input type="file" id="fileInput" multiple accept="*/*" onchange="handleFiles(this.files)">
            <div class="uz-icon"><i class="fas fa-cloud-arrow-up"></i></div>
            <p class="uz-title">Drag &amp; drop files here</p>
            <p class="uz-sub">or click to browse — supports all file types</p>
        </div>
        <div class="file-queue" id="fileQueue"></div>
        <div id="uploadAllWrap" style="display:none;margin-top:16px;">
            <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;">
                <p style="font-size:13px;color:var(--muted)">
                    <span id="queueCount">0</span> file(s) ready &nbsp;·&nbsp;
                    <span id="queueSize">0 B</span> total
                </p>
                <!-- Examiner Declaration -->
                <div style="background:rgba(201,168,76,0.08);border:1px solid rgba(201,168,76,0.25);border-radius:var(--radius);padding:14px 16px;margin-bottom:14px;">
                    <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;font-size:13.5px;color:var(--text);line-height:1.5;">
                        <input type="checkbox" id="examinerDeclaration" onchange="toggleUploadBtn()" style="width:18px;height:18px;margin-top:2px;accent-color:var(--gold);cursor:pointer;flex-shrink:0;">
                        <span>I confirm that this evidence was collected lawfully, has not been altered, and the file submitted is an exact copy of the original.</span>
                    </label>
                </div>
                <div style="display:flex;gap:10px;">
                    <button type="button" class="btn btn-outline" onclick="clearQueue()">
                        <i class="fas fa-trash"></i> Clear All
                    </button>
                    <button type="button" class="btn btn-gold" onclick="uploadAll()" id="uploadAllBtn" disabled>
                        <i class="fas fa-upload"></i> Upload All Evidence
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- ══ SUMMARY (after upload) ══ -->
<div id="summarySection" style="display:none;">
    <div class="form-section">
        <div class="form-section-head">
            <i class="fas fa-circle-check" style="color:var(--success)"></i>
            <h3>Upload Complete — Chain of Custody Established</h3>
        </div>
        <div style="padding:20px;" id="summaryBody"></div>
    </div>
    <div style="display:flex;gap:12px;margin-top:4px;flex-wrap:wrap;">
        <a href="../dashboard.php" class="btn btn-outline"><i class="fas fa-gauge-high"></i> Dashboard</a>
        <a href="evidence.php" class="btn btn-outline"><i class="fas fa-database"></i> All Evidence</a>
        <button type="button" class="btn btn-gold" onclick="resetUpload()">
            <i class="fas fa-plus"></i> Upload More Evidence
        </button>
    </div>
</div>

</div></div></div>

<!-- ══ CREATE CASE MODAL ══ -->
<div class="overlay" id="caseModal" style="display:none" onclick="if(event.target===this)closeCaseModal()">
    <div class="modal">
        <div class="modal-head">
            <h3>Create New <span>Case / Crime Scene</span></h3>
            <button class="xbtn" onclick="closeCaseModal()"><i class="fas fa-xmark"></i></button>
        </div>
        <form onsubmit="createCase(event)">
            <div class="modal-body">
                <div style="display:grid;gap:12px;">
                    <div class="field"><label>Case Title <span class="req">*</span></label><input type="text" id="newCaseTitle" placeholder="e.g. Nairobi CBD Cybercrime 2026" required></div>
                    <div class="grid-2">
                        <div class="field">
                            <label>Case Type</label>
                            <select id="newCaseType">
                                <option value="">— Select —</option>
                                <?php foreach(['Cybercrime','Financial Fraud','Identity Theft','Ransomware','Data Breach','Online Harassment','Hacking','Mobile Forensics','Network Intrusion','Other'] as $t): ?>
                                <option><?= $t ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="field">
                            <label>Priority</label>
                            <select id="newCasePriority">
                                <option value="low">Low</option>
                                <option value="medium" selected>Medium</option>
                                <option value="high">High</option>
                                <option value="critical">Critical</option>
                            </select>
                        </div>
                    </div>
                    <div class="field"><label>Description</label><textarea id="newCaseDesc" style="min-height:70px" placeholder="Brief description of the case..."></textarea></div>
                    <div id="caseModalError" class="alert alert-danger" style="display:none;"></div>
                </div>
            </div>
            <div class="modal-foot">
                <button type="button" class="btn btn-outline" onclick="closeCaseModal()">Cancel</button>
                <button type="submit" class="btn btn-gold" id="createCaseBtn"><i class="fas fa-folder-plus"></i> Create Case</button>
            </div>
        </form>
    </div>
</div>

<!-- ══ CONFIRM MODAL ══ -->
<div class="overlay" id="confirmModal" style="display:none">
    <div class="modal">
        <div class="modal-head">
            <h3>Confirm <span>Upload</span></h3>
            <button class="xbtn" onclick="closeConfirm()"><i class="fas fa-xmark"></i></button>
        </div>
        <div style="padding:20px 24px;">
            <p style="font-size:13px;color:var(--muted);margin-bottom:14px;">Review before uploading. Once submitted, all data is permanently recorded in the chain of custody.</p>
            <ul class="confirm-list" id="confirmList"></ul>
            <div id="cocPreview" style="margin-top:16px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;max-height:260px;overflow-y:auto;">
                <p style="font-size:11px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px;"><i class="fas fa-shield-halved" style="margin-right:5px"></i>Chain of Custody Preview</p>
            </div>
        </div>
        <div style="padding:12px 24px 20px;display:flex;gap:10px;justify-content:flex-end;">
            <button type="button" class="btn btn-outline" onclick="closeConfirm()">Go Back</button>
            <button type="button" class="btn btn-gold" onclick="confirmUpload()">
                <i class="fas fa-lock"></i> Confirm &amp; Upload Securely
            </button>
        </div>
    </div>
</div>

<script>
// ── sidebar/nav boilerplate ──
function toggleSidebar(){const sb=document.getElementById('sidebar'),ma=document.getElementById('mainArea');if(window.innerWidth<=900){sb.classList.toggle('mobile-open');}else{sb.classList.toggle('collapsed');ma.classList.toggle('collapsed');}localStorage.setItem('sb_collapsed',sb.classList.contains('collapsed')?'1':'0');}

// ── Show/hide network section based on evidence type ──
const networkTypes=['network_capture','database','mobile_data','log_file'];
const deviceTypes=['mobile_data','database','image'];
function toggleNetworkSection(evType){
    const ns=document.getElementById('networkSection');
    if(ns) ns.style.display=networkTypes.includes(evType)?'block':'none';
}
function toggleDeviceSection(evType){
    const ds=document.getElementById('deviceSection');
    if(ds) ds.style.display=deviceTypes.includes(evType)?'block':'none';
}
function toggleAllConditionalSections(evType){
    toggleNetworkSection(evType);
    toggleDeviceSection(evType);
}
function toggleUploadBtn(){
    const btn=document.getElementById('uploadAllBtn');
    const cb=document.getElementById('examinerDeclaration');
    btn.disabled=!cb.checked;
}
function checkAllTypeSelects(){
    document.querySelectorAll('select[id^="type_"]').forEach(function(sel){
        toggleAllConditionalSections(sel.value);
    });
}
if(localStorage.getItem('sb_collapsed')==='1'&&window.innerWidth>900){document.getElementById('sidebar').classList.add('collapsed');document.getElementById('mainArea').classList.add('collapsed');}
function toggleNotif(){document.getElementById('notifDropdown').classList.toggle('open');document.getElementById('userDropdown').classList.remove('open');}
function toggleUserMenu(){document.getElementById('userDropdown').classList.toggle('open');document.getElementById('notifDropdown').classList.remove('open');}
document.addEventListener('click',function(e){if(!e.target.closest('#notifWrap'))document.getElementById('notifDropdown').classList.remove('open');if(!e.target.closest('#userMenuWrap'))document.getElementById('userDropdown').classList.remove('open');});
function handleSearch(e){if(e.key==='Enter'){window.location='evidence.php?search='+encodeURIComponent(document.getElementById('globalSearch').value);}}

// ── state ──
let selectedCaseId = null;
let fileQueue      = [];
let uploadResults  = [];
let fileIdCounter  = 0;
let linkedEvidence = {}; // { fileId: [{id, evidence_number, title, link_type}] }

// ── load related evidence for dropdowns ──
async function loadRelatedEvidence(){
    if(!selectedCaseId) return;
    try {
        const res = await fetch(`../api/search_evidence.php?case_id=${selectedCaseId}`);
        const data = await res.json();
        document.querySelectorAll('select[id^="related_"]').forEach(sel => {
            const fileId = sel.id.replace('related_','');
            const current = linkedEvidence[fileId] || [];
            const currentIds = current.map(x=>x.id);
            const opts = current.map(x=>`<option value="${x.id}|${x.link_type}">${x.evidence_number} — ${x.title.substring(0,30)} [${x.link_type}]</option>`).join('');
            sel.innerHTML = `<option value="">— Link related evidence (optional) —</option>${opts}`+
                data.filter(e=>!currentIds.includes(e.id)).map(e=>`<option value="${e.id}|related_to">${e.evidence_number} — ${e.title.substring(0,40)}</option>`).join('');
        });
    } catch(e){console.error('Failed to load related evidence',e);}
}

function addRelatedEvidence(fileId, sel){
    if(!sel.value) return;
    const [evId, linkType] = sel.value.split('|');
    const label = sel.options[sel.selectedIndex].text;
    const evNum = label.split('—')[0].trim();
    const evTitle = label.split('—')[1]?.trim() || '';
    if(!linkedEvidence[fileId]) linkedEvidence[fileId]=[];
    if(!linkedEvidence[fileId].find(x=>x.id==evId)){
        linkedEvidence[fileId].push({id:evId, evidence_number:evNum, title:evTitle, link_type:linkType});
    }
    sel.value='';
    renderRelatedList(fileId);
}

function removeRelatedEvidence(fileId, evId){
    linkedEvidence[fileId] = linkedEvidence[fileId].filter(x=>x.id!=evId);
    renderRelatedList(fileId);
}

function renderRelatedList(fileId){
    const container = document.getElementById('relatedList_'+fileId);
    if(!container) return;
    const items = linkedEvidence[fileId] || [];
    container.innerHTML = items.map(x=>`
        <span style="display:inline-flex;align-items:center;gap:4px;background:var(--gold-dim);border:1px solid rgba(201,168,76,0.3);border-radius:5px;padding:2px 8px;font-size:11px;color:var(--text);">
            ${x.evidence_number}
            <span style="color:var(--muted);font-size:10px;">(${x.link_type})</span>
            <button type="button" onclick="removeRelatedEvidence('${fileId}',${x.id})" style="background:none;border:none;color:var(--muted);cursor:pointer;padding:0;margin-left:2px;font-size:12px;">&times;</button>
        </span>
    `).join('');
}

// ── step indicator ──
function setStep(n){
    for(let i=1;i<=5;i++){
        const el=document.getElementById('ps'+i);
        const ll=document.getElementById('pl'+i);
        const lb=document.getElementById('psl'+i);
        if(!el)continue;
        if(i<n){el.className='ps-num done';el.innerHTML='<i class="fas fa-check" style="font-size:10px"></i>';}
        else if(i===n){el.className='ps-num active';el.innerHTML=i;if(lb)lb.className='ps-label active';}
        else{el.className='ps-num pending';el.innerHTML=i;if(lb)lb.className='ps-label';}
        if(ll){ll.className=i<n?'ps-line done':'ps-line';}
    }
}

// ── case selection ──
function caseSelected(sel){
    selectedCaseId = sel.value || null;
    const info = document.getElementById('selectedCaseInfo');
    if(selectedCaseId){
        document.getElementById('selCaseNum').textContent   = sel.options[sel.selectedIndex].dataset.number;
        document.getElementById('selCaseTitle').textContent = sel.options[sel.selectedIndex].dataset.title;
        info.style.display = 'block';
        enableSection('sec-assignment');
        enableSection('sec-collection');
        enableSection('sec-files');
        setStep(2);
        loadRelatedEvidence();
    } else {
        info.style.display = 'none';
        disableSection('sec-assignment');
        disableSection('sec-collection');
        disableSection('sec-files');
        setStep(1);
    }
}
function enableSection(id){const s=document.getElementById(id);s.style.opacity='1';s.style.pointerEvents='auto';}
function disableSection(id){const s=document.getElementById(id);s.style.opacity='.5';s.style.pointerEvents='none';}

// ── case modal ──
function openCaseModal(){document.getElementById('caseModal').style.display='flex';}
function closeCaseModal(){document.getElementById('caseModal').style.display='none';}
async function createCase(e){
    e.preventDefault();
    const title=document.getElementById('newCaseTitle').value.trim();
    if(!title){showCaseErr('Case title is required.');return;}
    const btn=document.getElementById('createCaseBtn');
    btn.disabled=true;btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Creating...';
    const fd=new FormData();
    fd.append('action','create_case');
    fd.append('case_title',title);
    fd.append('case_description',document.getElementById('newCaseDesc').value);
    fd.append('case_type',document.getElementById('newCaseType').value);
    fd.append('priority',document.getElementById('newCasePriority').value);
    try{
        const r=await fetch('evidence_upload.php',{method:'POST',body:fd});
        const d=await r.json();
        if(d.success){
            const sel=document.getElementById('caseSelect');
            const opt=document.createElement('option');
            opt.value=d.case_id;opt.dataset.number=d.case_number;opt.dataset.title=d.case_title;
            opt.textContent=d.case_number+' — '+d.case_title;opt.selected=true;
            sel.appendChild(opt);
            selectedCaseId=d.case_id;
            document.getElementById('selCaseNum').textContent=d.case_number;
            document.getElementById('selCaseTitle').textContent=d.case_title;
            document.getElementById('selectedCaseInfo').style.display='block';
            enableSection('sec-assignment');enableSection('sec-collection');enableSection('sec-files');setStep(2);
            closeCaseModal();
            document.getElementById('newCaseTitle').value='';
            document.getElementById('newCaseDesc').value='';
        } else { showCaseErr(d.error||'Failed.'); }
    }catch(ex){showCaseErr('Network error.');}
    btn.disabled=false;btn.innerHTML='<i class="fas fa-folder-plus"></i> Create Case';
}
function showCaseErr(m){const el=document.getElementById('caseModalError');el.style.display='flex';el.innerHTML='<i class="fas fa-circle-exclamation"></i> '+m;}

// ── drag & drop ──
const dz=document.getElementById('dropZone');
dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('drag-over');});
dz.addEventListener('dragleave',()=>dz.classList.remove('drag-over'));
dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('drag-over');handleFiles(e.dataTransfer.files);});

function handleFiles(files){Array.from(files).forEach(f=>addFile(f));updateQueueInfo();}

function addFile(file){
    const id='f'+(++fileIdCounter);
    fileQueue.push({id,file});
    const ext=file.name.split('.').pop().toLowerCase();
    const isImg=['jpg','jpeg','png','gif','bmp','webp','tiff'].includes(ext);
    const isVid=['mp4','avi','mkv','mov','wmv'].includes(ext);
    const isDoc=['pdf','doc','docx','xls','xlsx','txt','csv'].includes(ext);
    const iconClass=isImg?'blue':isVid?'purple':isDoc?'green':'gray';
    const iconIco=isImg?'fa-file-image':isVid?'fa-file-video':isDoc?'fa-file-lines':'fa-file';

    // Auto-detect evidence type
    let autoType='other';
    if(isImg) autoType='image';
    else if(isVid) autoType='video';
    else if(isDoc) autoType='document';
    else if(['log','txt','syslog'].includes(ext)) autoType='log_file';
    else if(['eml','msg','mbox'].includes(ext)) autoType='email';
    else if(['db','sqlite','mdf','sql'].includes(ext)) autoType='database';
    else if(['pcap','pcapng','cap'].includes(ext)) autoType='network_capture';
    else if(['bak','dmp','ab','nandroid'].includes(ext)) autoType='mobile_data';

    const div=document.createElement('div');
    div.className='file-item';div.id=id;
    div.innerHTML=`
        <div class="fi-top">
            ${isImg?`<img class="fi-thumb" id="thumb_${id}" src="" alt="">`:
              `<div class="fi-icon stat-icon ${iconClass}"><i class="fas ${iconIco}"></i></div>`}
            <span class="fi-name" title="${esc(file.name)}">${esc(file.name)}</span>
            <span class="fi-size">${fmtSize(file.size)}</span>
            <button class="fi-remove" onclick="removeFile('${id}')"><i class="fas fa-xmark"></i></button>
        </div>
        <div class="fi-progress"><div class="fi-progress-fill" id="prog_${id}"></div></div>
        <div class="fi-meta">
            <div><label>Evidence Title <span style="color:var(--danger)">*</span></label>
                <input type="text" id="title_${id}" value="${esc(file.name.replace(/\.[^/.]+$/,''))}" placeholder="Descriptive title">
            </div>
            <div><label>Evidence Type</label>
                <select id="type_${id}" onchange="toggleAllConditionalSections(this.value)">
                    <option value="image" ${autoType==='image'?'selected':''}>Image</option>
                    <option value="video" ${autoType==='video'?'selected':''}>Video</option>
                    <option value="document" ${autoType==='document'?'selected':''}>Document</option>
                    <option value="log_file" ${autoType==='log_file'?'selected':''}>Log File</option>
                    <option value="email" ${autoType==='email'?'selected':''}>Email</option>
                    <option value="database" ${autoType==='database'?'selected':''}>Database</option>
                    <option value="network_capture" ${autoType==='network_capture'?'selected':''}>Network Capture</option>
                    <option value="mobile_data">Mobile Data</option>
                    <option value="other" ${autoType==='other'?'selected':''}>Other</option>
                </select>
            </div>
            <div class="full"><label>Description</label>
                <textarea id="desc_${id}" placeholder="What does this file contain? Why is it relevant to the investigation?">${esc(file.name)}</textarea>
            </div>
            <div class="full">
                <label>Related Evidence</label>
                <select id="related_${id}" style="width:100%;padding:8px 10px;border-radius:7px;border:1px solid var(--border);background:var(--surface2);color:var(--text);font-size:13px;" onchange="addRelatedEvidence('${id}',this)">
                    <option value="">— Link related evidence (optional) —</option>
                </select>
                <div id="relatedList_${id}" style="margin-top:6px;display:flex;flex-wrap:wrap;gap:5px;"></div>
            </div>
        </div>
        <div id="hash_${id}" style="display:none;"></div>
        <div id="status_${id}" style="margin-top:8px;font-size:12.5px;color:var(--muted);">Ready to upload</div>
    `;
    document.getElementById('fileQueue').appendChild(div);
    setStep(3);
    checkAllTypeSelects();
    if(isImg){const r=new FileReader();r.onload=e=>{const t=document.getElementById('thumb_'+id);if(t)t.src=e.target.result;};r.readAsDataURL(file);}
}

function removeFile(id){fileQueue=fileQueue.filter(f=>f.id!==id);const el=document.getElementById(id);if(el)el.remove();updateQueueInfo();if(fileQueue.length===0)setStep(2);}
function clearQueue(){fileQueue=[];document.getElementById('fileQueue').innerHTML='';updateQueueInfo();setStep(2);}
function updateQueueInfo(){
    const n=fileQueue.length;
    document.getElementById('uploadAllWrap').style.display=n>0?'block':'none';
    document.getElementById('queueCount').textContent=n;
    document.getElementById('queueSize').textContent=fmtSize(fileQueue.reduce((s,f)=>s+f.file.size,0));
}

// ── confirm + upload ──
function uploadAll(){
    if(!selectedCaseId){alert('Please select a case first.');return;}
    if(fileQueue.length===0){alert('Please add at least one file.');return;}
    const list=document.getElementById('confirmList');
    list.innerHTML='';
    fileQueue.forEach(({id,file})=>{
        const title=document.getElementById('title_'+id)?.value||file.name;
        const type=document.getElementById('type_'+id)?.value||'other';
        const li=document.createElement('li');
        li.innerHTML=`<i class="fas fa-file-shield"></i><span><strong>${esc(title)}</strong> &nbsp;·&nbsp; ${esc(type)} &nbsp;·&nbsp; ${fmtSize(file.size)}</span>`;
        list.appendChild(li);
    });

    // COC preview in confirm modal
    const cocPreview=document.getElementById('cocPreview');
    if(cocPreview){
        const rows=[];
        const v=id=>{const el=document.getElementById(id);return el?.value?.trim()||'';};
        const addRow=(label,val)=>{if(val)rows.push(`<div class="coc-row"><span class="coc-label">${esc(label)}</span><span class="coc-val">${esc(val)}</span></div>`);};
        addRow('Collected by',v('collectedByName'));
        addRow('Badge/ID',v('collectorBadge'));
        addRow('Unit',v('collectorUnit'));
        addRow('Collection date',v('collDate')+' '+v('collTime'));
        addRow('Location',v('collLocation'));
        addRow('Address',v('collAddress'));
        addRow('Condition',v('conditionOnReceipt'));
        addRow('Packaging',v('packagingType'));
        addRow('Seal number',v('sealNumber'));
        addRow('Evidence tag',v('evidenceTagNumber'));
        addRow('Acquisition',v('acquisitionMethod'));
        addRow('Tools',v('toolsUsed'));
        addRow('Write blocker',document.getElementById('writeBlockerUsed')?.checked?'Yes':'No');
        addRow('Device',v('originalDevice'));
        addRow('Device model',v('deviceMakeModel'));
        addRow('Serial/IMEI',v('deviceSerial'));
        addRow('OS detected',v('osDetected'));
        addRow('Legal basis',v('legalBasis'));
        addRow('Warrant/Order',v('warrantNumber'));
        addRow('Issuing court',v('issuingCourt'));
        addRow('OB Number',v('obNumber'));
        addRow('Handover',v('transportMethod'));
        addRow('IP address',v('ipAddress'));
        addRow('MAC address',v('macAddress'));
        addRow('Hostname',v('hostname'));
        const precautions=[];
        if(document.getElementById('handleFragile')?.checked) precautions.push('Fragile');
        if(document.getElementById('handleEMF')?.checked) precautions.push('EMF/RF shielded');
        if(document.getElementById('handleTemp')?.checked) precautions.push('Temperature sensitive');
        if(document.getElementById('handleBio')?.checked) precautions.push('Biohazard');
        if(document.getElementById('handleRemote')?.checked) precautions.push('Remote wipe risk');
        if(document.getElementById('handleEncrypted')?.checked) precautions.push('Encrypted');
        if(precautions.length) addRow('Precautions',precautions.join(', '));
        addRow('Witness',v('witnessName')+(v('witnessBadge')?' ('+v('witnessBadge')+')':''));
        addRow('Witness 2',v('witness2Name')+(v('witness2Badge')?' ('+v('witness2Badge')+')':''));
        addRow('Collection notes',v('collectionNotes'));
        addRow('COC notes',v('cocNotes'));
        cocPreview.innerHTML=rows.length?rows.join(''):'<p style="font-size:12px;color:var(--dim);font-style:italic;">No COC details filled in.</p>';
    }

    document.getElementById('confirmModal').style.display='flex';
}
function closeConfirm(){document.getElementById('confirmModal').style.display='none';}
async function confirmUpload(){
    closeConfirm();setStep(4);
    document.getElementById('uploadAllBtn').disabled=true;
    document.getElementById('uploadAllBtn').innerHTML='<i class="fas fa-spinner fa-spin"></i> Uploading...';
    uploadResults=[];
    for(const item of [...fileQueue]) await uploadSingle(item);
    showSummary();
}

async function uploadSingle({id,file}){
    const prog=document.getElementById('prog_'+id);
    const statusEl=document.getElementById('status_'+id);
    const card=document.getElementById(id);
    card.classList.add('uploading');
    statusEl.innerHTML='<span style="color:var(--warning)"><i class="fas fa-spinner fa-spin"></i> Uploading & hashing...</span>';
    let pct=0;const iv=setInterval(()=>{pct=Math.min(pct+7,85);prog.style.width=pct+'%';},90);
    const fd=new FormData();
    fd.append('action','upload_file');
    fd.append('case_id',selectedCaseId);
    fd.append('ev_title',document.getElementById('title_'+id)?.value||file.name);
    fd.append('ev_description',document.getElementById('desc_'+id)?.value||'');
    fd.append('evidence_type',document.getElementById('type_'+id)?.value||'other');
    // Collection details
    fd.append('collection_date',document.getElementById('collDate')?.value||'');
    fd.append('collection_time',document.getElementById('collTime')?.value||'');
    fd.append('collection_location',document.getElementById('collLocation')?.value||'');
    fd.append('collection_address',document.getElementById('collAddress')?.value||'');
    fd.append('collected_by_name',document.getElementById('collectedByName')?.value||'');
    fd.append('collector_badge',document.getElementById('collectorBadge')?.value||'');
    fd.append('collector_unit',document.getElementById('collectorUnit')?.value||'');
    fd.append('collector_contact',document.getElementById('collectorContact')?.value||'');
    fd.append('condition_on_receipt',document.getElementById('conditionOnReceipt')?.value||'');
    fd.append('packaging_type',document.getElementById('packagingType')?.value||'');
    fd.append('seal_number',document.getElementById('sealNumber')?.value||'');
    fd.append('evidence_tag_number',document.getElementById('evidenceTagNumber')?.value||'');
    fd.append('acquisition_method',document.getElementById('acquisitionMethod')?.value||'');
    fd.append('tools_used',document.getElementById('toolsUsed')?.value||'');
    if(document.getElementById('writeBlockerUsed')?.checked) fd.append('write_blocker_used','1');
    fd.append('original_device',document.getElementById('originalDevice')?.value||'');
    fd.append('device_serial',document.getElementById('deviceSerial')?.value||'');
    fd.append('device_make_model',document.getElementById('deviceMakeModel')?.value||'');
    fd.append('os_detected',document.getElementById('osDetected')?.value||'');
    fd.append('witness_name',document.getElementById('witnessName')?.value||'');
    fd.append('witness_badge',document.getElementById('witnessBadge')?.value||'');
    fd.append('witness2_name',document.getElementById('witness2Name')?.value||'');
    fd.append('witness2_badge',document.getElementById('witness2Badge')?.value||'');
    fd.append('legal_basis',document.getElementById('legalBasis')?.value||'');
    fd.append('warrant_number',document.getElementById('warrantNumber')?.value||'');
    fd.append('issuing_court',document.getElementById('issuingCourt')?.value||'');
    fd.append('ob_number',document.getElementById('obNumber')?.value||'');
    fd.append('transport_method',document.getElementById('transportMethod')?.value||'');
    fd.append('ip_address',document.getElementById('ipAddress')?.value||'');
    fd.append('mac_address',document.getElementById('macAddress')?.value||'');
    fd.append('hostname',document.getElementById('hostname')?.value||'');
    if(document.getElementById('handleFragile')?.checked) fd.append('handle_fragile','1');
    if(document.getElementById('handleEMF')?.checked) fd.append('handle_emf','1');
    if(document.getElementById('handleTemp')?.checked) fd.append('handle_temp','1');
    if(document.getElementById('handleBio')?.checked) fd.append('handle_bio','1');
    if(document.getElementById('handleRemote')?.checked) fd.append('handle_remote','1');
    if(document.getElementById('handleEncrypted')?.checked) fd.append('handle_encrypted','1');
    fd.append('collection_notes',document.getElementById('collectionNotes')?.value||'');
    fd.append('chain_of_custody_notes',document.getElementById('cocNotes')?.value||'');
    // Assignment
    fd.append('assigned_analyst',document.getElementById('assignAnalyst')?.value||'');
    fd.append('assignment_notes',document.getElementById('assignmentNotes')?.value||'');
    fd.append('examiner_declaration',document.getElementById('examinerDeclaration')?.checked?'1':'0');
    const linked = linkedEvidence[id] || [];
    fd.append('linked_evidence',JSON.stringify(linked));
    fd.append('ev_file',file);
    try{
        const res=await fetch('evidence_upload.php',{method:'POST',body:fd});
        const d=await res.json();
        clearInterval(iv);
        if(d.success){
            prog.style.width='100%';prog.classList.add('done');
            card.classList.remove('uploading');card.classList.add('success');
            statusEl.innerHTML=`<span style="color:var(--success)"><i class="fas fa-circle-check"></i> Uploaded — <strong>${esc(d.evidence_number)}</strong></span>`;
            document.getElementById('hash_'+id).style.display='block';
            document.getElementById('hash_'+id).innerHTML=`
                <div class="hash-result">
                    <div class="hr-title"><i class="fas fa-fingerprint"></i> Integrity Hashes Recorded</div>
                    <div class="hash-row"><span class="hash-label">SHA-256</span><span class="hash-val" id="sha_${id}">${esc(d.sha256)}</span><button class="copy-hash" onclick="copyHash('sha_${id}')"><i class="fas fa-copy"></i></button></div>
                    <div class="hash-row"><span class="hash-label">SHA3-256</span><span class="hash-val" id="sha3_${id}">${esc(d.sha3_256)}</span><button class="copy-hash" onclick="copyHash('sha3_${id}')"><i class="fas fa-copy"></i></button></div>
                    <div class="hash-row"><span class="hash-label">Size</span><span class="hash-val">${esc(d.file_size)}</span></div>
                    <div class="hash-row"><span class="hash-label">Type</span><span class="hash-val">${esc(d.mime_type)}</span></div>
                </div>`;
            uploadResults.push({...d,title:document.getElementById('title_'+id)?.value||file.name,success:true});
        } else {
            clearInterval(iv);prog.classList.add('err');prog.style.width='100%';
            card.classList.remove('uploading');card.classList.add('error');
            statusEl.innerHTML=`<span style="color:var(--danger)"><i class="fas fa-circle-exclamation"></i> Failed: ${esc(d.error)}</span>`;
            uploadResults.push({title:document.getElementById('title_'+id)?.value||file.name,success:false,error:d.error});
        }
    }catch(ex){
        clearInterval(iv);prog.classList.add('err');
        card.classList.remove('uploading');card.classList.add('error');
        statusEl.innerHTML=`<span style="color:var(--danger)"><i class="fas fa-circle-exclamation"></i> Network error</span>`;
        uploadResults.push({title:file.name,success:false,error:'Network error'});
    }
}

function showSummary(){
    const ok=uploadResults.filter(r=>r.success).length;
    const err=uploadResults.filter(r=>!r.success).length;
    let html=`
        <div style="display:flex;gap:16px;margin-bottom:20px;flex-wrap:wrap;">
            <div style="background:rgba(74,222,128,0.08);border:1px solid rgba(74,222,128,0.2);border-radius:var(--radius);padding:14px 20px;text-align:center;">
                <p style="font-size:28px;font-weight:700;color:var(--success);font-family:'Space Grotesk',sans-serif">${ok}</p>
                <p style="font-size:12px;color:var(--muted)">Successfully uploaded</p>
            </div>
            ${err>0?`<div style="background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.2);border-radius:var(--radius);padding:14px 20px;text-align:center;">
                <p style="font-size:28px;font-weight:700;color:var(--danger);font-family:'Space Grotesk',sans-serif">${err}</p>
                <p style="font-size:12px;color:var(--muted)">Failed</p></div>`:''}
        </div>`;
    // COC summary
    const v=id=>{const el=document.getElementById(id);return el?.value?.trim()||'—';};
    const cocRows=[];
    cocRows.push(['Collected by',v('collectedByName')]);
    cocRows.push(['Badge / ID',v('collectorBadge')]);
    cocRows.push(['Unit',v('collectorUnit')]);
    cocRows.push(['Collection date/time',v('collDate')+' '+v('collTime')]);
    cocRows.push(['Location',v('collLocation')]);
    const addr=v('collAddress');if(addr!=='—')cocRows.push(['Address',addr]);
    cocRows.push(['Condition on receipt',v('conditionOnReceipt')]);
    cocRows.push(['Packaging',v('packagingType')]);
    const seal=v('sealNumber');if(seal!=='—')cocRows.push(['Seal number',seal]);
    const tag=v('evidenceTagNumber');if(tag!=='—')cocRows.push(['Evidence tag',tag]);
    cocRows.push(['Acquisition method',v('acquisitionMethod')]);
    cocRows.push(['Tools used',v('toolsUsed')]);
    cocRows.push(['Write blocker',document.getElementById('writeBlockerUsed')?.checked?'Yes':'No']);
    const dev=v('originalDevice');if(dev!=='—')cocRows.push(['Device',dev]);
    const model=v('deviceMakeModel');if(model!=='—')cocRows.push(['Device model',model]);
    const serial=v('deviceSerial');if(serial!=='—')cocRows.push(['Serial/IMEI',serial]);
    const os=v('osDetected');if(os!=='—')cocRows.push(['OS detected',os]);
    const legal=v('legalBasis');if(legal!=='—')cocRows.push(['Legal basis',legal]);
    const warrant=v('warrantNumber');if(warrant!=='—')cocRows.push(['Warrant/Order',warrant]);
    const court=v('issuingCourt');if(court!=='—')cocRows.push(['Issuing court',court]);
    const ob=v('obNumber');if(ob!=='—')cocRows.push(['OB/Case number',ob]);
    const trans=v('transportMethod');if(trans!=='—')cocRows.push(['Handover',trans]);
    const ip=v('ipAddress');if(ip!=='—')cocRows.push(['IP address',ip]);
    const mac=v('macAddress');if(mac!=='—')cocRows.push(['MAC address',mac]);
    const host=v('hostname');if(host!=='—')cocRows.push(['Hostname',host]);
    const precautions=[];
    if(document.getElementById('handleFragile')?.checked) precautions.push('Fragile');
    if(document.getElementById('handleEMF')?.checked) precautions.push('EMF/RF shielded');
    if(document.getElementById('handleTemp')?.checked) precautions.push('Temperature sensitive');
    if(document.getElementById('handleBio')?.checked) precautions.push('Biohazard');
    if(document.getElementById('handleRemote')?.checked) precautions.push('Remote wipe risk');
    if(document.getElementById('handleEncrypted')?.checked) precautions.push('Encrypted');
    if(precautions.length) cocRows.push(['Precautions',precautions.join(', ')]);
    const w1=v('witnessName');if(w1!=='—')cocRows.push(['Witness',w1+(v('witnessBadge')!=='—'?' ('+v('witnessBadge')+')':'')]);
    const w2=v('witness2Name');if(w2!=='—')cocRows.push(['Witness 2',w2+(v('witness2Badge')!=='—'?' ('+v('witness2Badge')+')':'')]);

    html+=`<div style="background:rgba(201,168,76,0.05);border:1px solid rgba(201,168,76,0.15);border-radius:var(--radius);padding:14px 16px;margin-bottom:18px;">
        <p style="font-size:11.5px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px;"><i class="fas fa-shield-halved" style="margin-right:5px"></i>Chain of Custody Record</p>
        <table class="summary-table">`;
    cocRows.forEach(([label,val])=>{html+=`<tr><td>${esc(label)}</td><td>${esc(val)}</td></tr>`;});
    html+=`</table></div>`;
    html+=`<table class="dc-table"><thead><tr><th>Evidence Number</th><th>Title</th><th>SHA-256</th><th>SHA3-256</th><th>Size</th><th>Status</th></tr></thead><tbody>`;
    uploadResults.forEach(r=>{
        html+=r.success
            ?`<tr><td style="color:var(--gold);font-weight:700">${esc(r.evidence_number)}</td><td>${esc(r.title)}</td><td class="mono">${esc(r.sha256?.substring(0,16))}...</td><td class="mono">${esc(r.sha3_256?.substring(0,16))}...</td><td>${esc(r.file_size)}</td><td><span class="badge badge-green"><i class="fas fa-check"></i> Uploaded</span></td></tr>`
            :`<tr><td>—</td><td>${esc(r.title)}</td><td colspan="4" style="color:var(--danger)">${esc(r.error)}</td><td><span class="badge badge-red"><i class="fas fa-xmark"></i> Failed</span></td></tr>`;
    });
    html+='</tbody></table>';
    document.getElementById('summaryBody').innerHTML=html;
    document.getElementById('summarySection').style.display='block';
    document.getElementById('summarySection').scrollIntoView({behavior:'smooth'});
    document.getElementById('uploadAllBtn').disabled=false;
    document.getElementById('uploadAllBtn').innerHTML='<i class="fas fa-upload"></i> Upload All Evidence';
}

function resetUpload(){
    fileQueue=[];uploadResults=[];
    document.getElementById('fileQueue').innerHTML='';
    document.getElementById('summarySection').style.display='none';
    updateQueueInfo();setStep(selectedCaseId?2:1);
    window.scrollTo({top:0,behavior:'smooth'});
}

function copyHash(id){
    const val=document.getElementById(id)?.textContent;
    if(val){navigator.clipboard.writeText(val).then(()=>{const btn=event.target.closest('button');if(btn){btn.innerHTML='<i class="fas fa-check"></i>';setTimeout(()=>btn.innerHTML='<i class="fas fa-copy"></i>',1200);}});}
}
function esc(s){const d=document.createElement('div');d.textContent=s||'';return d.innerHTML;}
function fmtSize(b){if(b>=1073741824)return(b/1073741824).toFixed(2)+' GB';if(b>=1048576)return(b/1048576).toFixed(2)+' MB';if(b>=1024)return(b/1024).toFixed(1)+' KB';return b+' B';}

// Auto-select preloaded case
<?php if($preselect_case>0): ?>
window.addEventListener('load',function(){
    const sel=document.getElementById('caseSelect');
    if(sel&&sel.value) caseSelected(sel);
});
<?php endif; ?>
</script>
</body>
</html>
