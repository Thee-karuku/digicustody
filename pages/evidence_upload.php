<?php
/**
 * DigiCustody – Evidence Upload (Full Chain of Custody)
 * Save to: /var/www/html/digicustody/pages/evidence_upload.php
 */
session_start();
require_once __DIR__.'/../config/db.php';
require_once __DIR__.'/../config/functions.php';
require_login();

if (is_viewer()) {
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

// ── Handle new case creation (AJAX) ──────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'create_case') {
    header('Content-Type: application/json');
    $title    = trim($_POST['case_title'] ?? '');
    $desc     = trim($_POST['case_description'] ?? '');
    $type     = trim($_POST['case_type'] ?? '');
    $priority = in_array($_POST['priority']??'',['low','medium','high','critical']) ? $_POST['priority'] : 'medium';
    if (empty($title)) { echo json_encode(['success'=>false,'error'=>'Case title is required.']); exit; }
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

    // ── Core fields ──
    $case_id         = (int)($_POST['case_id'] ?? 0);
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
    $device_make_model    = trim($_POST['device_make_model'] ?? '');
    $os_detected          = trim($_POST['os_detected'] ?? '');

    // ── Witness ──
    $witness_name         = trim($_POST['witness_name'] ?? '');
    $witness_badge        = trim($_POST['witness_badge'] ?? '');

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

    // Merge all COC notes into collection_notes field
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
    if ($collection_notes)     $full_coc_notes .= "Collection notes: $collection_notes\n";
    if ($chain_of_custody_notes) $full_coc_notes .= "COC notes: $chain_of_custody_notes\n";

    $ev_number = generate_evidence_number($pdo);
    $upload    = handle_evidence_upload($_FILES['ev_file'], $ev_number);

    if (!$upload['success']) { echo json_encode(['success'=>false,'error'=>$upload['error']]); exit; }

    // Full location
    $full_location = $collection_location;
    if ($collection_address) $full_location .= ($full_location ? ', ' : '') . $collection_address;

    $pdo->prepare("INSERT INTO evidence
        (evidence_number,case_id,title,description,evidence_type,file_name,file_path,
         file_size,mime_type,sha256_hash,md5_hash,collection_date,collection_location,
         collection_notes,current_custodian,status,uploaded_by)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'collected',?)")
        ->execute([
            $ev_number, $case_id, $title, $description, $evidence_type,
            $upload['filename'], $upload['filepath'],
            $upload['file_size'], $upload['mime_type'],
            $upload['sha256'], $upload['md5'],
            $collection_datetime, $full_location,
            trim($full_coc_notes), $uid, $uid
        ]);
    $ev_id = $pdo->lastInsertId();

    // Detailed audit log with all COC fields
    audit_log($pdo,$uid,$_SESSION['username'],$role,'evidence_uploaded','evidence',$ev_id,$ev_number,
        "Evidence uploaded: $ev_number — $title | Collected by: $collected_by_name | Location: $full_location | Tools: $tools_used",
        $_SERVER['REMOTE_ADDR']??'', $_SERVER['HTTP_USER_AGENT']??'',
        [
            'sha256'=>$upload['sha256'], 'md5'=>$upload['md5'],
            'size'=>$upload['file_size'], 'mime'=>$upload['mime_type'],
            'collected_by'=>$collected_by_name, 'badge'=>$collector_badge,
            'unit'=>$collector_unit, 'location'=>$full_location,
            'acquisition_method'=>$acquisition_method, 'tools'=>$tools_used,
            'write_blocker'=>$write_blocker_used, 'device'=>$original_device,
            'serial'=>$device_serial, 'witness'=>$witness_name,
            'condition'=>$condition_on_receipt, 'seal'=>$seal_number,
        ]);

    // Notify admins
    foreach ($pdo->query("SELECT id FROM users WHERE role='admin' AND status='active'")->fetchAll() as $adm) {
        send_notification($pdo,$adm['id'],'New Evidence Uploaded',
            "$ev_number uploaded by {$_SESSION['full_name']}",'info','evidence',$ev_id);
    }

    echo json_encode([
        'success'         => true,
        'evidence_id'     => $ev_id,
        'evidence_number' => $ev_number,
        'sha256'          => $upload['sha256'],
        'md5'             => $upload['md5'],
        'file_size'       => format_filesize($upload['file_size']),
        'mime_type'       => $upload['mime_type'],
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
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
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
    <a href="../dashboard.php" class="btn btn-outline"><i class="fas fa-arrow-left"></i> Dashboard</a>
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
        <span class="ps-label" id="psl2">Collection Details</span>
    </div>
    <div class="ps-line" id="pl2"></div>
    <div class="ps-step">
        <div class="ps-num pending" id="ps3">3</div>
        <span class="ps-label" id="psl3">Files</span>
    </div>
    <div class="ps-line" id="pl3"></div>
    <div class="ps-step">
        <div class="ps-num pending" id="ps4">4</div>
        <span class="ps-label" id="psl4">Upload</span>
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
                <label>Badge / Staff Number</label>
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
                    <option>Intact / Undamaged</option>
                    <option>Powered On</option>
                    <option>Powered Off</option>
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
        <p style="font-size:11px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px;display:flex;align-items:center;gap:6px;"><i class="fas fa-microchip"></i> Acquisition &amp; Forensic Details</p>
        <div class="grid-2" style="margin-bottom:16px;">
            <div class="field">
                <label>Acquisition Method</label>
                <select id="acquisitionMethod">
                    <option value="">— Select method —</option>
                    <option>Logical acquisition</option>
                    <option>Physical acquisition</option>
                    <option>Full disk image (dd/E01)</option>
                    <option>Selective file copy</option>
                    <option>Live acquisition</option>
                    <option>Cloud extraction</option>
                    <option>Network capture</option>
                    <option>Manual collection</option>
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

        <!-- Witness -->
        <p style="font-size:11px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px;display:flex;align-items:center;gap:6px;"><i class="fas fa-eye"></i> Witness Information</p>
        <div class="grid-2" style="margin-bottom:16px;">
            <div class="field">
                <label>Witness Name</label>
                <input type="text" id="witnessName" placeholder="Full name of witness present">
            </div>
            <div class="field">
                <label>Witness Badge / ID</label>
                <input type="text" id="witnessBadge" placeholder="Badge or ID number">
            </div>
        </div>

        <!-- Notes -->
        <p style="font-size:11px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px;display:flex;align-items:center;gap:6px;"><i class="fas fa-notes-medical"></i> Notes</p>
        <div class="grid-2">
            <div class="field">
                <label>Collection Notes</label>
                <textarea id="collectionNotes" placeholder="Describe how the evidence was found, its context, and any relevant observations at the scene..."></textarea>
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
                <div style="display:flex;gap:10px;">
                    <button type="button" class="btn btn-outline" onclick="clearQueue()">
                        <i class="fas fa-trash"></i> Clear All
                    </button>
                    <button type="button" class="btn btn-gold" onclick="uploadAll()" id="uploadAllBtn">
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

// ── step indicator ──
function setStep(n){
    for(let i=1;i<=4;i++){
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
        enableSection('sec-collection');
        enableSection('sec-files');
        setStep(2);
    } else {
        info.style.display = 'none';
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
            enableSection('sec-collection');enableSection('sec-files');setStep(2);
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
                <select id="type_${id}">
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
        </div>
        <div id="hash_${id}" style="display:none;"></div>
        <div id="status_${id}" style="margin-top:8px;font-size:12.5px;color:var(--muted);">Ready to upload</div>
    `;
    document.getElementById('fileQueue').appendChild(div);
    setStep(3);
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
    fd.append('collection_notes',document.getElementById('collectionNotes')?.value||'');
    fd.append('chain_of_custody_notes',document.getElementById('cocNotes')?.value||'');
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
                    <div class="hash-row"><span class="hash-label">MD5</span><span class="hash-val" id="md5_${id}">${esc(d.md5)}</span><button class="copy-hash" onclick="copyHash('md5_${id}')"><i class="fas fa-copy"></i></button></div>
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
    html+=`<div style="background:rgba(201,168,76,0.05);border:1px solid rgba(201,168,76,0.15);border-radius:var(--radius);padding:14px 16px;margin-bottom:18px;">
        <p style="font-size:11.5px;font-weight:600;color:var(--gold);text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px;"><i class="fas fa-shield-halved" style="margin-right:5px"></i>Chain of Custody Record</p>
        <table class="summary-table">
            <tr><td>Collected by</td><td>${esc(document.getElementById('collectedByName')?.value||'—')}</td></tr>
            <tr><td>Badge / ID</td><td>${esc(document.getElementById('collectorBadge')?.value||'—')}</td></tr>
            <tr><td>Unit</td><td>${esc(document.getElementById('collectorUnit')?.value||'—')}</td></tr>
            <tr><td>Collection date/time</td><td>${esc(document.getElementById('collDate')?.value||'')} ${esc(document.getElementById('collTime')?.value||'')}</td></tr>
            <tr><td>Location</td><td>${esc(document.getElementById('collLocation')?.value||'—')}</td></tr>
            <tr><td>Condition on receipt</td><td>${esc(document.getElementById('conditionOnReceipt')?.value||'—')}</td></tr>
            <tr><td>Acquisition method</td><td>${esc(document.getElementById('acquisitionMethod')?.value||'—')}</td></tr>
            <tr><td>Tools used</td><td>${esc(document.getElementById('toolsUsed')?.value||'—')}</td></tr>
            <tr><td>Write blocker</td><td>${document.getElementById('writeBlockerUsed')?.checked?'Yes':'No'}</td></tr>
            <tr><td>Witness</td><td>${esc(document.getElementById('witnessName')?.value||'—')}</td></tr>
        </table>
    </div>`;
    html+=`<table class="dc-table"><thead><tr><th>Evidence Number</th><th>Title</th><th>SHA-256</th><th>MD5</th><th>Size</th><th>Status</th></tr></thead><tbody>`;
    uploadResults.forEach(r=>{
        html+=r.success
            ?`<tr><td style="color:var(--gold);font-weight:700">${esc(r.evidence_number)}</td><td>${esc(r.title)}</td><td class="mono">${esc(r.sha256?.substring(0,16))}...</td><td class="mono">${esc(r.md5?.substring(0,12))}...</td><td>${esc(r.file_size)}</td><td><span class="badge badge-green"><i class="fas fa-check"></i> Uploaded</span></td></tr>`
            :`<tr><td>—</td><td>${esc(r.title)}</td><td colspan="3" style="color:var(--danger)">${esc(r.error)}</td><td><span class="badge badge-red"><i class="fas fa-xmark"></i> Failed</span></td></tr>`;
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