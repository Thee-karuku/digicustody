<?php
// ============================================================
// DigiCustody – Helper Functions
// File: config/functions.php
// ============================================================

// ── Core Constants (must be defined before any function uses them) ──
if (!defined('SESSION_TIMEOUT')) define('SESSION_TIMEOUT', 3600);
if (!defined('LOGIN_MAX_ATTEMPTS')) define('LOGIN_MAX_ATTEMPTS', 5);

// ── Password Generation ──────────────────────────────────────
function generate_strong_password($length = 8) {
    $lowercase = 'abcdefghijklmnopqrstuvwxyz';
    $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $numbers = '0123456789';
    $special = '!@#$%^&*()';
    
    $password = '';
    $password .= $lowercase[random_int(0, strlen($lowercase) - 1)];
    $password .= $uppercase[random_int(0, strlen($uppercase) - 1)];
    $password .= $numbers[random_int(0, strlen($numbers) - 1)];
    $password .= $special[random_int(0, strlen($special) - 1)];
    
    $all = $lowercase . $uppercase . $numbers . $special;
    for ($i = 4; $i < $length; $i++) {
        $password .= $all[random_int(0, strlen($all) - 1)];
    }
    
    return str_shuffle($password);
}

// ── Security Headers ─────────────────────────────────────────
function set_security_headers() {
    header('X-Frame-Options: SAMEORIGIN');
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 1; mode=block');
    header('X-Robots-Tag: noindex, nofollow');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: https://cdnjs.cloudflare.com https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:; img-src 'self' data: blob:; connect-src 'self'; worker-src 'self' blob:;");
    header_remove('X-Powered-By');
}

function set_secure_session_config() {
    if (session_status() === PHP_SESSION_NONE) {
        // Secure cookie settings
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', 1);
        ini_set('session.cookie_samesite', 'Strict');
        
        // Session security
        ini_set('session.use_strict_mode', 1);
        ini_set('session.use_only_cookies', 1);
        ini_set('session.use_trans_sid', 0);
        ini_set('session.regenerate_id', 0);
        
        // Session timeout
        ini_set('session.gc_maxlifetime', SESSION_TIMEOUT);
        ini_set('session.cookie_lifetime', 0);
        
        // Session save path
        $save_path = __DIR__ . '/../sessions';
        if (!is_dir($save_path)) {
            mkdir($save_path, 0700, true);
        }
        ini_set('session.save_path', $save_path);
        
        // Session garbage collection
        ini_set('session.gc_probability', 1);
        ini_set('session.gc_divisor', 100);
    }
}

function secure_session_regenerate() {
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_regenerate_id(true);
    }
}

// ── Input Validation & Sanitization ──────────────────────────
function sanitize_input($input, $type = 'string') {
    if ($input === null) return '';
    
    switch ($type) {
        case 'int':
            return filter_var(trim($input), FILTER_VALIDATE_INT) !== false ? (int)trim($input) : 0;
        
        case 'email':
            return filter_var(trim($input), FILTER_VALIDATE_EMAIL) ? strtolower(trim($input)) : '';
        
        case 'url':
            return filter_var(trim($input), FILTER_VALIDATE_URL) ? trim($input) : '';
        
        case 'phone':
            return preg_replace('/[^0-9+\-\s]/', '', trim($input));
        
        case 'alphanumeric':
            return preg_replace('/[^a-zA-Z0-9]/', '', trim($input));
        
        case 'filename':
            return preg_replace('/[^a-zA-Z0-9_\-\.]/', '', basename(trim($input)));
        
        case 'html':
            return strip_tags(trim($input));
        
        case 'sql':
            return preg_replace('/[^a-zA-Z0-9_\-\s\.\,\(\)\=\'\"\%\$\@\!]/', '', trim($input));
        
        case 'text':
        default:
            return trim($input);
    }
}

function validate_required($input, $field_name = 'Field') {
    if (empty(trim($input)) && $input !== '0') {
        return ["valid" => false, "message" => "$field_name is required."];
    }
    return ["valid" => true];
}

function validate_min_length($input, $min, $field_name = 'Field') {
    if (strlen(trim($input)) < $min) {
        return ["valid" => false, "message" => "$field_name must be at least $min characters."];
    }
    return ["valid" => true];
}

function validate_max_length($input, $max, $field_name = 'Field') {
    if (strlen(trim($input)) > $max) {
        return ["valid" => false, "message" => "$field_name must not exceed $max characters."];
    }
    return ["valid" => true];
}

function validate_email($email) {
    if (!filter_var(trim($email), FILTER_VALIDATE_EMAIL)) {
        return ["valid" => false, "message" => "Please enter a valid email address."];
    }
    return ["valid" => true];
}

function validate_phone($phone) {
    $clean = preg_replace('/[^0-9]/', '', $phone);
    if (strlen($clean) < 9 || strlen($clean) > 15) {
        return ["valid" => false, "message" => "Please enter a valid phone number."];
    }
    return ["valid" => true];
}

function validate_badge($badge) {
    if (!preg_match('/^[a-zA-Z0-9\-\/]+$/', trim($badge))) {
        return ["valid" => false, "message" => "Badge number contains invalid characters."];
    }
    return ["valid" => true];
}

function validate_file_extension($filename, $allowed = ['pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx', 'zip', 'rar', 'txt']) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    if (!in_array($ext, $allowed)) {
        return ["valid" => false, "message" => "File type not allowed. Allowed: " . implode(', ', $allowed)];
    }
    return ["valid" => true];
}

function validate_mime_type($filepath, $allowed = []) {
    if (!file_exists($filepath)) return ["valid" => false, "message" => "File not found."];
    
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $filepath);
    finfo_close($finfo);
    
    if (!empty($allowed) && !in_array($mime, $allowed)) {
        return ["valid" => false, "message" => "Invalid file content type."];
    }
    return ["valid" => true, "mime" => $mime];
}

function validate_upload_size($filepath, $max_mb = 100) {
    $size = filesize($filepath);
    $max_bytes = $max_mb * 1024 * 1024;
    if ($size > $max_bytes) {
        return ["valid" => false, "message" => "File size exceeds maximum allowed ({$max_mb}MB)."];
    }
    return ["valid" => true, "size" => $size];
}

function validate_ip_address($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return ["valid" => false, "message" => "Invalid IP address."];
    }
    return ["valid" => true];
}

function is_ajax_request() {
    return isset($_SERVER['HTTP_X_REQUESTED_WITH']) && 
           strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}

function require_ajax() {
    if (!is_ajax_request()) {
        http_response_code(403);
        die(json_encode(["error" => "AJAX request required."]));
    }
}

// ── Rate Limiting ─────────────────────────────────────────────
if (!defined('LOGIN_MAX_ATTEMPTS')) define('LOGIN_MAX_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_SECS', 300);

function record_login_attempt($pdo, $username, $ip, $successful = false) {
    try {
        $stmt = $pdo->prepare("INSERT INTO login_attempts (ip_address, username, successful) VALUES (?, ?, ?)");
        $stmt->execute([$ip, $username, $successful ? 1 : 0]);
    } catch (Exception $e) {
        error_log("Failed to record login attempt: " . $e->getMessage());
    }
}

function cleanup_old_login_attempts($pdo) {
    $pdo->exec("DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)");
}

function get_failed_attempts($pdo, $username, $ip) {
    $since = date('Y-m-d H:i:s', time() - 900);
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND (username = ? OR username IS NULL) AND successful = 0 AND attempted_at > ?");
    $stmt->execute([$ip, $username, $since]);
    return (int)$stmt->fetchColumn();
}

function is_locked_out($pdo, $username, $ip) {
    $attempts = get_failed_attempts($pdo, $username, $ip);
    return $attempts >= LOGIN_MAX_ATTEMPTS;
}

function get_lockout_remaining($pdo, $username, $ip) {
    $since = date('Y-m-d H:i:s', time() - 900);
    $stmt = $pdo->prepare("SELECT MAX(attempted_at) FROM login_attempts WHERE ip_address = ? AND (username = ? OR username IS NULL) AND successful = 0 AND attempted_at > ?");
    $stmt->execute([$ip, $username, $since]);
    $last_attempt = $stmt->fetchColumn();
    if (!$last_attempt) return 0;
    $elapsed = time() - strtotime($last_attempt);
    return max(0, 900 - $elapsed);
}

// ── Session Security ─────────────────────────────────────────
function require_login($pdo = null) {
    static $headers_applied = false;
    if (!$headers_applied) {
        set_security_headers();
        set_secure_session_config();
        $headers_applied = true;
    }
    if (!isset($_SESSION['user_id'])) {
        header('Location: ' . BASE_URL . 'login.php?msg=session_expired');
        exit;
    }
    // Session timeout check
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
        session_unset(); session_destroy();
        header('Location: ' . BASE_URL . 'login.php?msg=timeout');
        exit;
    }
    // 2FA verification check - require 2FA for users with 2FA enabled
    if (!empty($_SESSION['require_2fa']) && empty($_SESSION['2fa_verified'])) {
        header('Location: ' . BASE_URL . 'verify_2fa.php?reason=required');
        exit;
    }
    // Additional check: verify 2FA status from database if session was hijacked
    // This prevents bypassing 2FA by manually setting session variables
    if ($pdo && !empty($_SESSION['user_id']) && empty($_SESSION['2fa_verified'])) {
        $stmt = $pdo->prepare("SELECT two_factor_enabled FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch();
        if ($user && $user['two_factor_enabled'] == 1) {
            header('Location: ' . BASE_URL . 'verify_2fa.php?reason=required');
            exit;
        }
    }
    $_SESSION['last_activity'] = time();
}

function require_role($roles) {
    require_login();
    if (!is_array($roles)) $roles = [$roles];
    if (!in_array($_SESSION['role'], $roles)) {
        header('Location: ' . BASE_URL . 'dashboard.php?error=access_denied');
        exit;
    }
}

function is_admin()        { return isset($_SESSION['role']) && $_SESSION['role'] === 'admin'; }
function is_investigator() { return isset($_SESSION['role']) && $_SESSION['role'] === 'investigator'; }
function is_analyst()      { return isset($_SESSION['role']) && $_SESSION['role'] === 'analyst'; }

// ── Evidence Status Transitions ───────────────────────────────
function can_change_evidence_status($from, $to) {
    // Flagged status can only be exited via clear_flag action, not through this function
    if ($from === 'flagged' || $to === 'flagged') {
        return false;
    }
    
    $valid_transitions = [
        'collected'    => ['in_analysis'],
        'in_analysis' => ['transferred', 'archived'],
        'transferred' => ['in_analysis'],
        'archived'   => ['in_analysis'],
    ];
    
    return isset($valid_transitions[$from]) && in_array($to, $valid_transitions[$from]);
}

// ── Role-based Capability Gates ──────────────────────────────
// Admin & Investigator: full operational access
// Analyst: analysis & read access (scoped to assigned evidence)
// Viewer: read-only, no modifications

function can_upload()   { return in_array($_SESSION['role'] ?? '', ['admin','investigator']); }
function can_transfer() { return in_array($_SESSION['role'] ?? '', ['admin','investigator']); }
function can_verify()   { return in_array($_SESSION['role'] ?? '', ['admin','investigator']); }
function can_download() { return in_array($_SESSION['role'] ?? '', ['admin','investigator','analyst']); }
function can_analyse()  { return in_array($_SESSION['role'] ?? '', ['admin','investigator','analyst']); }
function can_report()   { return in_array($_SESSION['role'] ?? '', ['admin','investigator','analyst']); }
function can_write()    { return in_array($_SESSION['role'] ?? '', ['admin','investigator','analyst']); }

// ── Scoped Visibility (case_access based) ────────────────────
// Admin sees everything. All other roles only see cases/evidence
// they have explicit access to via the case_access table.

function can_see_case($pdo, $case_id, $user_id, $role) {
    if ($role === 'admin') return true;
    $stmt = $pdo->prepare("SELECT 1 FROM case_access WHERE case_id = ? AND user_id = ?");
    $stmt->execute([$case_id, $user_id]);
    return (bool)$stmt->fetchColumn();
}

function user_can_access_case($pdo, $uid, $role, $case_id) {
    $case_id = (int)$case_id;
    if (!$case_id) return false;
    if ($role === 'admin') return true;
    if ($role === 'investigator') {
        $stmt = $pdo->prepare("SELECT 1 FROM cases WHERE id = ? AND created_by = ?");
        $stmt->execute([$case_id, $uid]);
        if ($stmt->fetchColumn()) return true;
        $stmt = $pdo->prepare("SELECT 1 FROM case_access WHERE case_id = ? AND user_id = ?");
        $stmt->execute([$case_id, $uid]);
        return (bool)$stmt->fetchColumn();
    }
    if ($role === 'analyst') {
        $stmt = $pdo->prepare("SELECT 1 FROM case_access WHERE case_id = ? AND user_id = ?");
        $stmt->execute([$case_id, $uid]);
        return (bool)$stmt->fetchColumn();
    }
    return false;
}

function user_can_access_evidence($pdo, $uid, $role, $evidence_id) {
    $evidence_id = (int)$evidence_id;
    if (!$evidence_id) return false;
    if ($role === 'admin') return true;
    $stmt = $pdo->prepare("SELECT case_id FROM evidence WHERE id = ?");
    $stmt->execute([$evidence_id]);
    $case_id = $stmt->fetchColumn();
    if (!$case_id) return false;
    return user_can_access_case($pdo, $uid, $role, $case_id);
}

function case_access_sql($user_id, $role) {
    if ($role === 'admin') return '';
    if ($role === 'investigator') {
        return " AND (c.created_by = $user_id OR c.id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id = $user_id))";
    }
    return " AND c.id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id = $user_id)";
}

function evidence_access_sql($user_id, $role) {
    if ($role === 'admin') return '';
    if ($role === 'investigator') {
        return " AND (e.uploaded_by = $user_id OR e.current_custodian = $user_id OR e.case_id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id = $user_id))";
    }
    return " AND e.case_id IN (SELECT ca.case_id FROM case_access ca WHERE ca.user_id = $user_id)";
}

function grant_case_access($pdo, $case_id, $user_id, $granted_by, $access_role = 'analyst', $notes = null) {
    try {
        $pdo->prepare("
            INSERT INTO case_access (case_id, user_id, granted_by, access_role, notes) 
            VALUES (?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE access_role = VALUES(access_role), notes = VALUES(notes)
        ")->execute([$case_id, $user_id, $granted_by, $access_role, $notes]);
    } catch (Exception $e) {
        error_log("grant_case_access failed: " . $e->getMessage());
    }
}

function assign_analyst_to_evidence($pdo, $evidence_id, $analyst_id, $assigned_by, $notes = null) {
    try {
        $stmt = $pdo->prepare("SELECT status FROM evidence WHERE id = ?");
        $stmt->execute([$evidence_id]);
        $current_status = $stmt->fetchColumn();
        if (!$current_status) {
            return ['success' => false, 'error' => 'Evidence not found'];
        }
        if (!can_change_evidence_status($current_status, 'in_analysis')) {
            return ['success' => false, 'error' => 'Cannot change status from ' . $current_status . ' to in_analysis'];
        }
        $pdo->prepare("
            UPDATE evidence 
            SET assigned_analyst = ?, assignment_notes = ?, assigned_at = NOW(), 
                analysis_status = 'assigned', status = 'in_analysis' 
            WHERE id = ?
        ")->execute([$analyst_id, $notes, $evidence_id]);
        return ['success' => true];
    } catch (Exception $e) {
        error_log("assign_analyst_to_evidence failed: " . $e->getMessage());
        return ['success' => false, 'error' => 'Database error'];
    }
}

function revoke_case_access($pdo, $case_id, $user_id) {
    try {
        $pdo->prepare("DELETE FROM case_access WHERE case_id = ? AND user_id = ?")
            ->execute([$case_id, $user_id]);
    } catch (Exception $e) {
        error_log("revoke_case_access failed: " . $e->getMessage());
    }
}

function get_case_collaborators($pdo, $case_id) {
    $stmt = $pdo->prepare("
        SELECT u.id, u.username, u.full_name, u.role, ca.granted_at
        FROM case_access ca
        JOIN users u ON u.id = ca.user_id
        WHERE ca.case_id = ?
        ORDER BY ca.granted_at ASC
    ");
    $stmt->execute([$case_id]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// ── Download History Logging ─────────────────────────────────

function log_download($pdo, $evidence_id, $user_id, $token_id = null, $reason = '') {
    try {
        $pdo->prepare("INSERT INTO download_history (evidence_id, user_id, token_id, ip_address, user_agent, reason)
            VALUES (?, ?, ?, ?, ?, ?)")
            ->execute([
                $evidence_id,
                $user_id,
                $token_id,
                $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                $_SERVER['HTTP_USER_AGENT'] ?? '',
                $reason
            ]);
    } catch (Exception $e) {
        error_log("log_download failed: " . $e->getMessage());
    }
}

function get_user_download_history($pdo, $user_id, $role, $limit = 50) {
    if ($role === 'admin') {
        $sql = "SELECT dh.*, e.evidence_number, e.title, e.file_name, e.file_size,
                       u.full_name AS downloaded_by
                FROM download_history dh
                JOIN evidence e ON e.id = dh.evidence_id
                JOIN users u ON u.id = dh.user_id
                ORDER BY dh.downloaded_at DESC LIMIT ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$limit]);
    } else {
        $sql = "SELECT dh.*, e.evidence_number, e.title, e.file_name, e.file_size,
                       u.full_name AS downloaded_by
                FROM download_history dh
                JOIN evidence e ON e.id = dh.evidence_id
                JOIN users u ON u.id = dh.user_id
                WHERE dh.user_id = ?
                ORDER BY dh.downloaded_at DESC LIMIT ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$user_id, $limit]);
    }
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function count_pending_transfers($pdo, $user_id) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM evidence_transfers WHERE to_user = ? AND status = 'pending'");
    $stmt->execute([$user_id]);
    return (int)$stmt->fetchColumn();
}

function count_outstanding_transfers($pdo, $user_id) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM evidence_transfers WHERE from_user = ? AND status = 'pending'");
    $stmt->execute([$user_id]);
    return (int)$stmt->fetchColumn();
}

// ── Audit Logging ────────────────────────────────────────────
function audit_log($pdo, $user_id, $username, $role, $action_type,
                   $target_type=null, $target_id=null, $target_label=null,
                   $description='', $ip=null, $ua=null, $extra=null) {
    try {
        $last_chain_hash = null;
        
        $last_row = $pdo->query("SELECT chain_hash FROM audit_logs ORDER BY id DESC LIMIT 1")->fetch();
        if ($last_row) {
            $last_chain_hash = $last_row['chain_hash'];
        }
        
        $stmt = $pdo->prepare("INSERT INTO audit_logs
            (user_id, username, user_role, action_type, target_type, target_id, target_label,
             description, ip_address, user_agent, session_id, extra_data)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)");
        $stmt->execute([
            $user_id, $username, $role, $action_type,
            $target_type, $target_id, $target_label,
            $description,
            $ip ?? ($_SERVER['REMOTE_ADDR'] ?? 'unknown'),
            $ua  ?? ($_SERVER['HTTP_USER_AGENT'] ?? ''),
            session_id(),
            $extra ? json_encode($extra) : null
        ]);
        
        $new_id = $pdo->lastInsertId();
        
        $row_data = $pdo->query("SELECT * FROM audit_logs WHERE id = $new_id")->fetch();
        $chain_data = 
            $row_data['id'] . 
            $row_data['user_id'] . 
            $row_data['username'] . 
            $row_data['user_role'] . 
            $row_data['action_type'] . 
            ($row_data['target_type'] ?? '') . 
            ($row_data['target_id'] ?? '') . 
            ($row_data['target_label'] ?? '') . 
            $row_data['description'] . 
            $row_data['ip_address'] . 
            $row_data['created_at'];
        
        $new_chain_hash = hash('sha256', $chain_data . ($last_chain_hash ?? ''));
        
        $pdo->prepare("UPDATE audit_logs SET chain_hash = ? WHERE id = ?")->execute([$new_chain_hash, $new_id]);
        
    } catch (Exception $e) {
        error_log("Audit log failed: " . $e->getMessage());
    }
}

function verify_audit_chain($pdo) {
    $results = ['valid' => true, 'total' => 0, 'errors' => []];
    
    $rows = $pdo->query("SELECT * FROM audit_logs ORDER BY id ASC")->fetchAll(PDO::FETCH_ASSOC);
    $results['total'] = count($rows);
    
    $previous_hash = null;
    
    foreach ($rows as $row) {
        $chain_data = 
            $row['id'] . 
            $row['user_id'] . 
            $row['username'] . 
            $row['user_role'] . 
            $row['action_type'] . 
            ($row['target_type'] ?? '') . 
            ($row['target_id'] ?? '') . 
            ($row['target_label'] ?? '') . 
            $row['description'] . 
            $row['ip_address'] . 
            $row['created_at'];
        
        $expected_hash = hash('sha256', $chain_data . ($previous_hash ?? ''));
        $stored_hash = $row['chain_hash'] ?? '';
        
        if ($expected_hash !== $stored_hash) {
            $results['valid'] = false;
            $results['errors'][] = "Chain broken at row ID {$row['id']}: expected $expected_hash, got $stored_hash";
        }
        
        $previous_hash = $stored_hash;
    }
    
    return $results;
}

// ── Hash Generation ──────────────────────────────────────────
function generate_file_hashes($filepath) {
    if (!file_exists($filepath)) return null;
    return [
        'sha256'    => hash_file('sha256', $filepath),
        'sha3_256'  => hash_file('sha3-256', $filepath),
        'file_size' => filesize($filepath),
        'timestamp' => date('Y-m-d H:i:s'),
    ];
}

function verify_file_integrity($filepath, $original_sha256, $original_sha3_256) {
    if (!file_exists($filepath)) return 'file_missing';
    $current_sha256 = hash_file('sha256', $filepath);
    $current_sha3_256 = hash_file('sha3-256', $filepath);
    if ($current_sha256 === $original_sha256 && $current_sha3_256 === $original_sha3_256) return 'intact';
    return 'tampered';
}

// ── File Streaming Helper ────────────────────────────────────────
function stream_evidence_file($file_path, $file_name, $mime_type = null) {
    if (!file_exists($file_path) || !is_readable($file_path)) {
        http_response_code(404);
        die('File not found on server.');
    }
    
    while (ob_get_level()) { ob_end_clean(); }
    
    $file_size = filesize($file_path);
    $mime = $mime_type ?? (new finfo(FILEINFO_MIME_TYPE))->file($file_path);
    
    header('X-Content-Type-Options: nosniff');
    header('Content-Type: ' . $mime);
    header('Content-Disposition: attachment; filename="' . addslashes($file_name) . '"');
    header('Content-Length: ' . $file_size);
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    readfile($file_path);
    exit;
}

// ── Evidence Number Generator ────────────────────────────────
function generate_evidence_number($pdo) {
    $year = date('Y');
    $pdo->beginTransaction();
    try {
        // Lock the last evidence record for this year
        $stmt = $pdo->prepare("
            SELECT evidence_number FROM evidence 
            WHERE YEAR(uploaded_at) = ? 
            ORDER BY id DESC LIMIT 1 
            FOR UPDATE
        ");
        $stmt->execute([$year]);
        $last = $stmt->fetch();
        
        if ($last && preg_match('/EV-' . $year . '-(\d+)/', $last['evidence_number'], $m)) {
            $count = (int)$m[1] + 1;
        } else {
            $count = 1;
        }
        
        $number = 'EV-' . $year . '-' . str_pad($count, 5, '0', STR_PAD_LEFT);
        $pdo->commit();
        return $number;
    } catch (Exception $e) {
        $pdo->rollBack();
        throw $e;
    }
}

function generate_case_number($pdo) {
    $year = date('Y');
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare("
            SELECT case_number FROM cases 
            WHERE YEAR(created_at) = ? 
            ORDER BY id DESC LIMIT 1 
            FOR UPDATE
        ");
        $stmt->execute([$year]);
        $last = $stmt->fetch();
        
        if ($last && preg_match('/CASE-' . $year . '-(\d+)/', $last['case_number'], $m)) {
            $count = (int)$m[1] + 1;
        } else {
            $count = 1;
        }
        
        $number = 'CASE-' . $year . '-' . str_pad($count, 4, '0', STR_PAD_LEFT);
        $pdo->commit();
        return $number;
    } catch (Exception $e) {
        $pdo->rollBack();
        throw $e;
    }
}

function generate_report_number($pdo) {
    $year = date('Y');
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare("
            SELECT report_number FROM analysis_reports 
            WHERE YEAR(created_at) = ? 
            ORDER BY id DESC LIMIT 1 
            FOR UPDATE
        ");
        $stmt->execute([$year]);
        $last = $stmt->fetch();
        
        if ($last && preg_match('/RPT-' . $year . '-(\d+)/', $last['report_number'], $m)) {
            $count = (int)$m[1] + 1;
        } else {
            $count = 1;
        }
        
        $number = 'RPT-' . $year . '-' . str_pad($count, 4, '0', STR_PAD_LEFT);
        $pdo->commit();
        return $number;
    } catch (Exception $e) {
        $pdo->rollBack();
        throw $e;
    }
}

// ── Download Token ────────────────────────────────────────────
function create_download_token($pdo, $evidence_id, $user_id, $reason = '', $hours = null) {
    if ($hours === null) $hours = DOWNLOAD_TOKEN_EXPIRY;
    $token = bin2hex(random_bytes(32));
    $expires = date('Y-m-d H:i:s', strtotime("+{$hours} hours"));
    
    // Get evidence details for the token
    $ev = $pdo->prepare("SELECT file_path, file_name, evidence_number, sha256_hash, sha3_256_hash FROM evidence WHERE id=?");
    $ev->execute([$evidence_id]);
    $ev = $ev->fetch();
    
    $stmt = $pdo->prepare("INSERT INTO download_tokens (token, evidence_id, file_path, file_name, evidence_number, sha256_hash, sha3_256_hash, created_by, intended_user_id, expires_at, download_reason) VALUES (?,?,?,?,?,?,?,?,?,?,?)");
    $stmt->execute([$token, $evidence_id, $ev['file_path'] ?? '', $ev['file_name'] ?? '', $ev['evidence_number'] ?? '', $ev['sha256_hash'] ?? '', $ev['sha3_256_hash'] ?? '', $user_id, $user_id, $expires, $reason]);
    return $token;
}

function validate_download_token($pdo, $token, $user_id = null) {
    $stmt = $pdo->prepare("
        SELECT dt.*, u.full_name AS creator_name
        FROM download_tokens dt
        JOIN users u ON u.id = dt.created_by
        WHERE dt.token = ? AND dt.is_used = 0 AND dt.expires_at > NOW()
    ");
    $stmt->execute([$token]);
    $token_data = $stmt->fetch();
    
    if (!$token_data) return false;
    
    // Verify user is authorized to use this token
    if ($user_id !== null) {
        $is_creator = (int)$token_data['created_by'] === (int)$user_id;
        $is_intended = !empty($token_data['intended_user_id']) && (int)$token_data['intended_user_id'] === (int)$user_id;
        if (!$is_creator && !$is_intended) {
            return false;
        }
    }
    
    return $token_data;
}

// ── Notifications ────────────────────────────────────────────
function send_notification($pdo, $user_id, $title, $message, $type = 'info', $related_type = null, $related_id = null) {
    try {
        $stmt = $pdo->prepare("INSERT INTO notifications (user_id, title, message, type, related_type, related_id) VALUES (?,?,?,?,?,?)");
        $stmt->execute([$user_id, $title, $message, $type, $related_type, $related_id]);
    } catch (Exception $e) {
        error_log("Notification failed: " . $e->getMessage());
    }
}

function get_unread_notifications($pdo, $user_id, $limit = 10) {
    $stmt = $pdo->prepare("SELECT * FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY created_at DESC LIMIT ?");
    $stmt->execute([$user_id, $limit]);
    return $stmt->fetchAll();
}

function count_unread_notifications($pdo, $user_id) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0");
    $stmt->execute([$user_id]);
    return (int)$stmt->fetchColumn();
}

// ── File Upload ───────────────────────────────────────────────
function handle_evidence_upload($file, $evidence_number, $pdo = null, $user_id = null, $username = null, $role = null, $collection_date = null, $collection_location = null, $collection_notes = null) {
    // Validate file size before any processing
    $size_check = validate_upload_size($file['tmp_name'], 500);
    if (!$size_check['valid']) {
        return ['success' => false, 'error' => $size_check['message'] ?? 'File size validation failed'];
    }

    $allowed_types = [
        'image/jpeg','image/png','image/gif','image/bmp','image/tiff','image/webp',
        'video/mp4','video/avi','video/mkv','video/mov','video/wmv','video/webm',
        'application/pdf','application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'text/plain','text/csv','text/html','text/x-python','text/x-shellscript',
        'application/zip','application/x-zip-compressed',
        'application/x-7z-compressed','application/gzip',
        'application/sql','application/x-sqlite3',
        'application/javascript','application/json','application/xml',
        'application/x-msdownload','application/x-executable',
        'application/vnd.android.package-archive',
    ];

    if ($file['error'] !== UPLOAD_ERR_OK) {
        return ['success' => false, 'error' => 'Upload error: ' . $file['error']];
    }

    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->file($file['tmp_name']);

    if (!in_array($mime, $allowed_types)) {
        @unlink($file['tmp_name']);
        return ['success' => false, 'error' => 'File type not permitted.'];
    }

    // MIME-to-extension map for validation
    $mime_to_exts = [
        'image/jpeg' => ['jpg', 'jpeg'],
        'image/png' => ['png'],
        'image/gif' => ['gif'],
        'image/bmp' => ['bmp'],
        'image/tiff' => ['tif', 'tiff'],
        'image/webp' => ['webp'],
        'video/mp4' => ['mp4'],
        'video/avi' => ['avi'],
        'video/mkv' => ['mkv'],
        'video/mov' => ['mov'],
        'video/wmv' => ['wmv'],
        'video/webm' => ['webm'],
        'application/pdf' => ['pdf'],
        'application/msword' => ['doc'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => ['docx'],
        'application/vnd.ms-excel' => ['xls'],
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => ['xlsx'],
        'text/plain' => ['txt', 'log', 'py', 'js', 'sh', 'bat', 'ps1', 'conf', 'cfg', 'ini', 'env'],
        'text/csv' => ['csv'],
        'text/html' => ['html', 'htm'],
        'text/x-python' => ['py', 'pyw'],
        'text/x-shellscript' => ['sh', 'bash', 'zsh', 'ksh', 'csh'],
        'application/zip' => ['zip'],
        'application/x-zip-compressed' => ['zip'],
        'application/x-7z-compressed' => ['7z'],
        'application/gzip' => ['gz', 'tar.gz'],
        'application/sql' => ['sql'],
        'application/x-sqlite3' => ['db', 'sqlite', 'sqlite3'],
        'application/javascript' => ['js'],
        'application/json' => ['json'],
        'application/xml' => ['xml'],
        'application/x-msdownload' => ['exe', 'dll', 'msi'],
        'application/x-executable' => ['exe', 'bin'],
        'application/vnd.android.package-archive' => ['apk'],
    ];

    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    
    // Validate extension matches MIME type
    if (!isset($mime_to_exts[$mime]) || !in_array($ext, $mime_to_exts[$mime])) {
        @unlink($file['tmp_name']);
        return ['success' => false, 'error' => 'File extension does not match detected file type.'];
    }
    $safe_name = preg_replace('/[^a-zA-Z0-9_\-]/', '_', pathinfo($file['name'], PATHINFO_FILENAME));
    $filename = $evidence_number . '_' . $safe_name . '_' . time() . '.' . $ext;
    $dest = UPLOAD_DIR . $filename;

    if (!is_dir(UPLOAD_DIR)) mkdir(UPLOAD_DIR, 0750, true);

    if (!move_uploaded_file($file['tmp_name'], $dest)) {
        return ['success' => false, 'error' => 'Failed to move uploaded file.'];
    }

    $hashes = generate_file_hashes($dest);
    
    $signature = null;
    $private_key_path = '/etc/digicustody/private.key';
    if (file_exists($private_key_path)) {
        $private_key = openssl_pkey_get_private(file_get_contents($private_key_path));
        if ($private_key) {
            $signature_binary = '';
            if (openssl_sign($hashes['sha256'], $signature_binary, $private_key, OPENSSL_ALGO_SHA256)) {
                $signature = base64_encode($signature_binary);
            }
        }
    }
    
    if ($pdo && $user_id) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        audit_log($pdo, $user_id, $username, $role, 'evidence_uploaded', 'evidence', 0, $evidence_number,
            "File uploaded: $filename | Size: " . format_filesize($hashes['file_size']) . " | SHA256: " . substr($hashes['sha256'], 0, 16) . "...", $ip, $user_agent);
    }
    
    return [
        'success'   => true,
        'filename'  => $filename,
        'filepath'  => $dest,
        'file_size' => $hashes['file_size'],
        'sha256'    => $hashes['sha256'],
        'sha3_256'  => $hashes['sha3_256'],
        'mime_type' => $mime,
        'collection_date' => $collection_date,
        'collection_location' => $collection_location,
        'collection_notes' => $collection_notes,
    ];
}

// ── Formatting Helpers ────────────────────────────────────────
function format_filesize($bytes) {
    if ($bytes >= 1073741824) return round($bytes / 1073741824, 2) . ' GB';
    if ($bytes >= 1048576)    return round($bytes / 1048576, 2) . ' MB';
    if ($bytes >= 1024)       return round($bytes / 1024, 2) . ' KB';
    return $bytes . ' B';
}

function time_ago($datetime) {
    $now  = new DateTime();
    $ago  = new DateTime($datetime);
    $diff = $now->diff($ago);
    if ($diff->y > 0) return $diff->y . ' year' . ($diff->y > 1 ? 's' : '') . ' ago';
    if ($diff->m > 0) return $diff->m . ' month' . ($diff->m > 1 ? 's' : '') . ' ago';
    if ($diff->d > 0) return $diff->d . ' day' . ($diff->d > 1 ? 's' : '') . ' ago';
    if ($diff->h > 0) return $diff->h . ' hour' . ($diff->h > 1 ? 's' : '') . ' ago';
    if ($diff->i > 0) return $diff->i . ' minute' . ($diff->i > 1 ? 's' : '') . ' ago';
    return 'Just now';
}

function role_badge($role) {
    $map = [
        'admin'        => ['label' => 'Admin',        'color' => '#c9a84c', 'bg' => 'rgba(201,168,76,0.15)'],
        'investigator' => ['label' => 'Investigator',  'color' => '#4a9eff', 'bg' => 'rgba(74,158,255,0.15)'],
        'analyst'      => ['label' => 'Analyst',       'color' => '#3ecf8e', 'bg' => 'rgba(62,207,142,0.15)'],
    ];
    $r = $map[$role] ?? ['label' => ucfirst($role), 'color' => '#888', 'bg' => '#eee'];
    return "<span style=\"display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600;color:{$r['color']};background:{$r['bg']};\">{$r['label']}</span>";
}

function status_badge($status) {
    $map = [
        'collected'          => ['#4a9eff', 'rgba(74,158,255,0.15)'],
        'in_analysis'        => ['#f59e0b', 'rgba(245,158,11,0.15)'],
        'transferred'        => ['#8b5cf6', 'rgba(139,92,246,0.15)'],
        'archived'           => ['#6b7280', 'rgba(107,114,128,0.15)'],
        'flagged'            => ['#ef4444', 'rgba(239,68,68,0.15)'],
        'open'               => ['#3ecf8e', 'rgba(62,207,142,0.15)'],
        'under_investigation'=> ['#4a9eff', 'rgba(74,158,255,0.15)'],
        'closed'             => ['#6b7280', 'rgba(107,114,128,0.15)'],
        'active'             => ['#3ecf8e', 'rgba(62,207,142,0.15)'],
        'pending'            => ['#f59e0b', 'rgba(245,158,11,0.15)'],
        'approved'           => ['#3ecf8e', 'rgba(62,207,142,0.15)'],
        'rejected'           => ['#ef4444', 'rgba(239,68,68,0.15)'],
        'intact'             => ['#3ecf8e', 'rgba(62,207,142,0.15)'],
        'tampered'           => ['#ef4444', 'rgba(239,68,68,0.15)'],
    ];
    $label = ucwords(str_replace('_', ' ', $status));
    [$color, $bg] = $map[$status] ?? ['#888', '#eee'];
    return "<span style=\"display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600;color:{$color};background:{$bg};\">{$label}</span>";
}

function e($str) { return htmlspecialchars($str ?? '', ENT_QUOTES, 'UTF-8'); }

function csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// ── Password Reset ────────────────────────────────────────────
define('PASSWORD_RESET_EXPIRY', 3600);

function generate_password_reset_token($pdo, $email) {
    $email = trim($email);
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND status = 'active' ORDER BY created_at DESC LIMIT 10");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if (!$user) {
        return ['success' => false, 'message' => 'If an account exists with this email, a reset link has been sent.'];
    }

    $token = bin2hex(random_bytes(32));
    $expires_at = date('Y-m-d H:i:s', time() + PASSWORD_RESET_EXPIRY);

    $pdo->prepare("DELETE FROM password_resets WHERE email = ?")->execute([$email]);

    $pdo->prepare("INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)")
        ->execute([$email, password_hash($token, PASSWORD_DEFAULT), $expires_at]);

    return [
        'success' => true,
        'token' => $token,
        'email' => $email,
        'expires_at' => $expires_at
    ];
}

function verify_password_reset_token($pdo, $token) {
    $stmt = $pdo->prepare("SELECT * FROM password_resets WHERE used = 0 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 10");
    $stmt->execute();
    $records = $stmt->fetchAll();

    foreach ($records as $record) {
        if (password_verify($token, $record['token'])) {
            return [
                'success' => true,
                'email' => $record['email'],
                'expires_at' => $record['expires_at']
            ];
        }
    }
    return ['success' => false, 'message' => 'Invalid or expired reset token.'];
}

function reset_password($pdo, $token, $new_password) {
    $result = verify_password_reset_token($pdo, $token);
    if (!$result['success']) {
        return $result;
    }

    $email = $result['email'];
    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

    $pdo->prepare("UPDATE users SET password = ?, updated_at = NOW() WHERE email = ?")
        ->execute([$hashed_password, $email]);

    $pdo->prepare("UPDATE password_resets SET used = 1 WHERE email = ?")->execute([$email]);

    $pdo->prepare("DELETE FROM password_resets WHERE email = ? AND used = 1")->execute([$email]);

    return ['success' => true, 'message' => 'Password has been reset successfully.'];
}

function send_password_reset_email($email, $token) {
    $reset_link = (defined('BASE_URL') ? BASE_URL : 'http://localhost:8000/') . "reset_password.php?token=" . urlencode($token);

    $subject = "DigiCustody - Password Reset Request";
    $message = "
    <html>
    <body style='font-family: Arial, sans-serif; background: #060d1a; color: #f0f4fa; padding: 20px;'>
        <div style='max-width: 500px; margin: 0 auto; background: #0c1526; border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 32px;'>
            <h2 style='color: #c9a84c; margin-bottom: 20px;'>DigiCustody Password Reset</h2>
            <p>You requested a password reset for your DigiCustody account.</p>
            <p>Click the button below to reset your password:</p>
            <a href='{$reset_link}' style='display: inline-block; background: #c9a84c; color: #060d1a; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; margin: 20px 0;'>Reset Password</a>
            <p>Or copy this link: <a href='{$reset_link}' style='color: #c9a84c;'>{$reset_link}</a></p>
            <p style='color: #6b82a0; font-size: 13px; margin-top: 20px;'>This link expires in 1 hour. If you didn't request this, please ignore this email.</p>
        </div>
    </body>
    </html>";

    $headers = "MIME-Version: 1.0\r\n";
    $headers .= "Content-type: text/html; charset=UTF-8\r\n";
    $headers .= "From: noreply@digicustody.go.ke\r\n";

    return send_email($email, $subject, $message);
}

function send_email($to, $subject, $html) {
    require_once __DIR__ . '/../vendor/autoload.php';
    
    $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
    
    try {
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com';
        $mail->SMTPAuth = true;
        $mail->Username = GMAIL_USER;
        $mail->Password = GMAIL_APP_PASSWORD;
        $mail->SMTPSecure = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = 587;
        
        $mail->setFrom(GMAIL_USER, 'DigiCustody');
        $mail->addAddress($to);
        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body = $html;
        
        $mail->send();
        return true;
    } catch (\Exception $e) {
        error_log("PHPMailer Error: " . $e->getMessage());
        return false;
    }
}

function send_account_approval_email($email, $full_name, $username, $password, $role) {
    $login_url = (defined('BASE_URL') ? BASE_URL : 'http://localhost:8000/') . "login.php";

    $subject = "DigiCustody - Your Account Has Been Approved";
    $html = "
    <html>
    <body style='font-family: Arial, sans-serif; background: #060d1a; color: #f0f4fa; padding: 20px;'>
        <div style='max-width: 500px; margin: 0 auto; background: #0c1526; border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 32px;'>
            <div style='text-align: center; margin-bottom: 24px;'>
                <h1 style='color: #c9a84c; font-size: 28px; margin: 0;'>DigiCustody</h1>
                <p style='color: #6b82a0; margin: 8px 0 0;'>Evidence Management Platform</p>
            </div>
            <h2 style='color: #3ecf8e; margin-bottom: 20px;'>✓ Account Approved!</h2>
            <p>Hello <strong>{$full_name}</strong>,</p>
            <p>Great news! Your account request has been approved. You now have access to the DigiCustody platform as a <strong>" . ucfirst($role) . "</strong>.</p>
            <div style='background: rgba(201,168,76,0.1); border: 1px solid rgba(201,168,76,0.2); border-radius: 12px; padding: 20px; margin: 20px 0;'>
                <h3 style='color: #c9a84c; margin: 0 0 16px; font-size: 14px; text-transform: uppercase; letter-spacing: 1px;'>Your Login Credentials</h3>
                <p style='margin: 8px 0;'><strong style='color: #8899aa;'>Username:</strong> <code style='background: rgba(255,255,255,0.05); padding: 4px 10px; border-radius: 6px; color: #f0f4fa;'>{$username}</code></p>
                <p style='margin: 8px 0;'><strong style='color: #8899aa;'>Password:</strong> <code style='background: rgba(255,255,255,0.05); padding: 4px 10px; border-radius: 6px; color: #f0f4fa;'>{$password}</code></p>
            </div>
            <p style='color: #ef4444; font-size: 13px; margin-bottom: 20px;'>⚠️ Please change your password after your first login.</p>
            <a href='{$login_url}' style='display: inline-block; background: #c9a84c; color: #060d1a; padding: 14px 28px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 16px;'>Login to DigiCustody</a>
            <p style='color: #6b82a0; font-size: 12px; margin-top: 24px;'>If the button doesn't work, copy this link to your browser:<br><a href='{$login_url}' style='color: #c9a84c;'>{$login_url}</a></p>
        </div>
    </body>
    </html>";

    return send_email($email, $subject, $html);
}

// ── Two-Factor Authentication ─────────────────────────────────
function generate_2fa_secret() {
    $base32_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    for ($i = 0; $i < 16; $i++) {
        $secret .= $base32_chars[random_int(0, 31)];
    }
    return $secret;
}

function get_2fa_qrcode_url($email, $secret, $issuer = 'DigiCustody') {
    require_once __DIR__ . '/../vendor/autoload.php';
    $otpauth = 'otpauth://totp/' . rawurlencode($issuer . ':' . $email) . '?secret=' . $secret . '&issuer=' . rawurlencode($issuer) . '&algorithm=SHA1&digits=6&period=30';
    
    $qrcode = new \chillerlan\QRCode\QRCode(new \chillerlan\QRCode\QROptions([
        'outputInterface' => \chillerlan\QRCode\Output\QRGdImagePNG::class,
        'scale' => 5,
        'imageBase64' => true,
    ]));
    
    return $qrcode->render($otpauth);
}

function verify_2fa_code($secret, $code) {
    $timeSlice = floor(time() / 30);
    for ($i = -1; $i <= 1; $i++) {
        $time = $timeSlice + $i;
        $expectedCode = generate_6digit_code($secret, $time);
        if ($expectedCode === str_pad($code, 6, '0', STR_PAD_LEFT)) {
            return true;
        }
    }
    return false;
}

function generate_6digit_code($secret, $timeSlice) {
    $secretKey = base32_decode($secret);
    $time = pack('N*', 0) . pack('N*', $timeSlice);
    $hash = hash_hmac('sha1', $time, $secretKey, true);
    $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
    $binary = substr($hash, $offset, 4);
    $value = unpack('N', $binary)[1];
    $value = $value & 0x7FFFFFFF;
    $otp = $value % 1000000;
    return str_pad($otp, 6, '0', STR_PAD_LEFT);
}

function base32_decode($input) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $input = strtoupper(trim($input));
    $output = '';
    $bits = '';
    foreach (str_split($input) as $char) {
        if ($char === '=') break;
        $val = strpos($alphabet, $char);
        if ($val === false) continue;
        $bits .= str_pad(decbin($val), 5, '0', STR_PAD_LEFT);
    }
    for ($i = 0; $i + 8 <= strlen($bits); $i += 8) {
        $output .= chr(bindec(substr($bits, $i, 8)));
    }
    return $output;
}

function generate_backup_codes($count = 8) {
    $codes = [];
    for ($i = 0; $i < $count; $i++) {
        $codes[] = strtoupper(substr(bin2hex(random_bytes(4)), 0, 4) . '-' . substr(bin2hex(random_bytes(4)), 0, 4));
    }
    return $codes;
}

function verify_backup_code($stored_codes, $entered_code) {
    $entered_code = strtoupper(trim($entered_code));
    $codes = json_decode($stored_codes, true) ?? [];
    $key = array_search($entered_code, $codes);
    if ($key !== false) {
        unset($codes[$key]);
        return ['valid' => true, 'remaining_codes' => array_values($codes)];
    }
    return ['valid' => false, 'remaining_codes' => $codes];
}

function enable_2fa($pdo, $user_id, $secret) {
    $stmt = $pdo->prepare("UPDATE users SET two_factor_enabled = 1, two_factor_secret = ?, two_factor_verified = 1 WHERE id = ?");
    $stmt->execute([$secret, $user_id]);
}

function disable_2fa($pdo, $user_id) {
    $stmt = $pdo->prepare("UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL, two_factor_verified = 0, backup_codes = NULL WHERE id = ?");
    $stmt->execute([$user_id]);
}

function is_2fa_enabled($pdo, $user_id) {
    $stmt = $pdo->prepare("SELECT two_factor_enabled FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $result = $stmt->fetch();
    return $result && $result['two_factor_enabled'] == 1;
}


function get_user_email($pdo, $user_id) {
    $stmt = $pdo->prepare("SELECT email FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $result = $stmt->fetch();
    return $result ? $result['email'] : '';
}

function get_user_2fa_secret($pdo, $user_id) {
    $stmt = $pdo->prepare("SELECT two_factor_secret FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $result = $stmt->fetch();
    return $result ? $result['two_factor_secret'] : null;
}

// ── Trusted Devices (Remember Me) ─────────────────────────────
function generate_device_token() {
    return bin2hex(random_bytes(32));
}

function hash_token($token) {
    return hash('sha256', $token);
}

function create_trusted_device($pdo, $user_id, $days = 30) {
    $token = generate_device_token();
    $token_hash = hash_token($token);
    $expires_at = date('Y-m-d H:i:s', strtotime("+{$days} days"));
    $device_name = parse_user_agent($_SERVER['HTTP_USER_AGENT'] ?? '');
    $ip = $_SERVER['REMOTE_ADDR'] ?? null;
    $user_agent = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500);
    
    $stmt = $pdo->prepare("INSERT INTO trusted_devices (user_id, token_hash, device_name, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->execute([$user_id, $token_hash, $device_name, $ip, $user_agent, $expires_at]);
    
    return $token;
}

function validate_trusted_device($pdo, $user_id, $token) {
    $token_hash = hash_token($token);
    
    $stmt = $pdo->prepare("SELECT * FROM trusted_devices WHERE user_id = ? AND token_hash = ? AND expires_at > NOW()");
    $stmt->execute([$user_id, $token_hash]);
    $device = $stmt->fetch();
    
    if ($device) {
        $pdo->prepare("UPDATE trusted_devices SET last_used_at = NOW() WHERE id = ?")->execute([$device['id']]);
        return true;
    }
    return false;
}

function get_user_trusted_devices($pdo, $user_id) {
    $stmt = $pdo->prepare("SELECT id, device_name, ip_address, created_at, last_used_at, expires_at FROM trusted_devices WHERE user_id = ? ORDER BY last_used_at DESC");
    $stmt->execute([$user_id]);
    return $stmt->fetchAll();
}

function revoke_trusted_device($pdo, $device_id, $user_id) {
    $stmt = $pdo->prepare("DELETE FROM trusted_devices WHERE id = ? AND user_id = ?");
    $stmt->execute([$device_id, $user_id]);
    return $stmt->rowCount() > 0;
}

function revoke_all_trusted_devices($pdo, $user_id) {
    $stmt = $pdo->prepare("DELETE FROM trusted_devices WHERE user_id = ?");
    $stmt->execute([$user_id]);
}

function parse_user_agent($ua) {
    if (empty($ua)) return 'Unknown Device';
    
    $device = 'Unknown Device';
    if (strpos($ua, 'Windows') !== false) $device = 'Windows PC';
    elseif (strpos($ua, 'Macintosh') !== false) $device = 'Mac';
    elseif (strpos($ua, 'Linux') !== false) $device = 'Linux PC';
    elseif (strpos($ua, 'Android') !== false) {
        preg_match('/Android\s([0-9.]+)/', $ua, $m);
        $device = 'Android' . ($m ? ' (' . $m[1] . ')' : '');
    }
    elseif (strpos($ua, 'iPhone') !== false || strpos($ua, 'iPad') !== false) $device = 'iOS Device';
    
    if (strpos($ua, 'Chrome') !== false) $device .= ' - Chrome';
    elseif (strpos($ua, 'Firefox') !== false) $device .= ' - Firefox';
    elseif (strpos($ua, 'Safari') !== false && strpos($ua, 'Chrome') === false) $device .= ' - Safari';
    elseif (strpos($ua, 'Edge') !== false) $device .= ' - Edge';
    
    return $device;
}

function set_trusted_device_cookie($token, $days = 30) {
    setcookie('trusted_device', $token, [
        'expires' => time() + ($days * 86400),
        'path' => '/',
        'domain' => '',
        'secure' => false,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
}

function get_trusted_device_token() {
    return $_COOKIE['trusted_device'] ?? null;
}

function clear_trusted_device_cookie() {
    setcookie('trusted_device', '', [
        'expires' => time() - 3600,
        'path' => '/'
    ]);
}

function is_trusted_device_valid($pdo, $user_id) {
    $token = get_trusted_device_token();
    if (!$token) return false;
    return validate_trusted_device($pdo, $user_id, $token);
}

// ── Security Hardening ────────────────────────────────────────
function validate_integer($value, $min = null, $max = null) {
    if (!is_numeric($value) || (int)$value != $value) return false;
    $val = (int)$value;
    if ($min !== null && $val < $min) return false;
    if ($max !== null && $val > $max) return false;
    return true;
}

function validate_enum($value, $allowed) {
    return in_array($value, $allowed, true);
}

function sanitize_filename($filename) {
    $filename = preg_replace('/[^\p{L}\p{N}_\-.]/u', '_', $filename);
    $filename = preg_replace('/_{2,}/', '_', $filename);
    return trim($filename, '_.');
}

function rate_limit_check($pdo, $action, $identifier, $max_attempts = 10, $window_seconds = 60) {
    try {
        $pdo->prepare("DELETE FROM rate_limits WHERE action = ? AND created_at < ?")
            ->execute([$action, date('Y-m-d H:i:s', time() - $window_seconds)]);
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM rate_limits WHERE action = ? AND identifier = ?");
        $stmt->execute([$action, $identifier]);
        $count = (int)$stmt->fetchColumn();
        if ($count >= $max_attempts) return false;
        $pdo->prepare("INSERT INTO rate_limits (action, identifier) VALUES (?, ?)")
            ->execute([$action, $identifier]);
        return true;
    } catch (Exception $e) {
        return true;
    }
}

function generate_csrf_input($name = 'csrf_token') {
    $token = csrf_token();
    return '<input type="hidden" name="'.htmlspecialchars($name, ENT_QUOTES, 'UTF-8').'" value="'.htmlspecialchars($token, ENT_QUOTES, 'UTF-8').'">';
}

function require_csrf($method = 'POST') {
    if ($_SERVER['REQUEST_METHOD'] !== $method) {
        http_response_code(405);
        die(json_encode(['error' => 'Method not allowed.']));
    }
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        http_response_code(403);
        die(json_encode(['error' => 'Invalid or expired security token. Please refresh and try again.']));
    }
}

function log_security_event($pdo, $event_type, $details = []) {
    try {
        $pdo->prepare("INSERT INTO security_events (event_type, ip_address, user_agent, user_id, details, created_at) VALUES (?, ?, ?, ?, ?, NOW())")
            ->execute([
                $event_type,
                $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                $_SERVER['HTTP_USER_AGENT'] ?? '',
                $_SESSION['user_id'] ?? null,
                json_encode($details)
            ]);
    } catch (Exception $e) {
        error_log("Security event logging failed: " . $e->getMessage());
    }
}

function validate_evidence_access($pdo, $evidence_id, $user_id, $role) {
    $stmt = $pdo->prepare("SELECT id, case_id, current_custodian, uploaded_by, status FROM evidence WHERE id = ?");
    $stmt->execute([$evidence_id]);
    $evidence = $stmt->fetch();
    if (!$evidence) return ['allowed' => false, 'reason' => 'Evidence not found.'];
    if ($role === 'admin') return ['allowed' => true, 'evidence' => $evidence];
    if ($role === 'investigator') return ['allowed' => true, 'evidence' => $evidence];
    if ($role === 'analyst') {
        $stmt2 = $pdo->prepare("SELECT 1 FROM case_access WHERE case_id = ? AND user_id = ?");
        $stmt2->execute([$evidence['case_id'], $user_id]);
        if ($stmt2->fetchColumn()) return ['allowed' => true, 'evidence' => $evidence];
        return ['allowed' => false, 'reason' => 'Access denied.'];
    }
    return ['allowed' => false, 'reason' => 'Access denied.'];
}
// ── System Settings ─────────────────────────────────────────
function get_system_setting($pdo, $key, $default = null) {
    $stmt = $pdo->prepare("SELECT setting_value FROM system_settings WHERE setting_key = ?");
    $stmt->execute([$key]);
    $result = $stmt->fetch();
    return $result ? $result['setting_value'] : $default;
}

function set_system_setting($pdo, $key, $value) {
    $stmt = $pdo->prepare("INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?) 
                           ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)");
    return $stmt->execute([$key, $value]);
}

function is_mandatory_2fa_enabled($pdo) {
    return get_system_setting($pdo, 'mandatory_2fa', '0') === '1';
}

// ── Password Strength Validation ─────────────────────────────
function validate_password_strength($password) {
    $errors = array();
    
    if (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters long";
    }
    if (strlen($password) > 128) {
        $errors[] = "Password must not exceed 128 characters";
    }
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Password must contain at least one lowercase letter";
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Password must contain at least one uppercase letter";
    }
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must contain at least one number";
    }
    if (!preg_match('/[!@#$%^&*()]/', $password)) {
        $errors[] = "Password must contain at least one special character";
    }
    $common = array("password", "12345678", "qwerty", "abc123", "password123");
    if (in_array(strtolower($password), $common)) {
        $errors[] = "This is a commonly used password";
    }
    
    return array(
        'valid' => empty($errors),
        'errors' => $errors,
        'score' => calculate_password_score($password)
    );
}

function calculate_password_score($password) {
    $score = 0;
    if (strlen($password) >= 8) $score += 20;
    if (strlen($password) >= 12) $score += 10;
    if (strlen($password) >= 16) $score += 10;
    if (preg_match('/[a-z]/', $password)) $score += 15;
    if (preg_match('/[A-Z]/', $password)) $score += 15;
    if (preg_match('/[0-9]/', $password)) $score += 15;
    if (preg_match('/[!@#$%^&*()]/', $password)) $score += 15;
    return min(100, $score);
}

function get_password_strength_label($score) {
    if ($score < 40) return array('label' => 'Weak', 'color' => '#ef4444');
    if ($score < 60) return array('label' => 'Fair', 'color' => '#f59e0b');
    if ($score < 80) return array('label' => 'Good', 'color' => '#22c55e');
    return array('label' => 'Strong', 'color' => '#10b981');
}

