<?php
// ============================================================
// DigiCustody – Helper Functions
// File: config/functions.php
// ============================================================

// ── Session Security ─────────────────────────────────────────
function require_login() {
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
function is_viewer()       { return isset($_SESSION['role']) && $_SESSION['role'] === 'viewer'; }

// Investigators and Analysts share ALL the same capabilities — only Viewer is read-only
function can_upload()   { return in_array($_SESSION['role'] ?? '', ['admin','investigator','analyst']); }
function can_download() { return in_array($_SESSION['role'] ?? '', ['admin','investigator','analyst']); }
function can_analyse()  { return in_array($_SESSION['role'] ?? '', ['admin','investigator','analyst']); }
function can_verify()   { return in_array($_SESSION['role'] ?? '', ['admin','investigator','analyst']); }
function can_report()   { return in_array($_SESSION['role'] ?? '', ['admin','investigator','analyst']); }
function can_write()    { return in_array($_SESSION['role'] ?? '', ['admin','investigator','analyst']); }

// ── Audit Logging ────────────────────────────────────────────
function audit_log($pdo, $user_id, $username, $role, $action_type,
                   $target_type=null, $target_id=null, $target_label=null,
                   $description='', $ip=null, $ua=null, $extra=null) {
    try {
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
    } catch (Exception $e) {
        error_log("Audit log failed: " . $e->getMessage());
    }
}

// ── Hash Generation ──────────────────────────────────────────
function generate_file_hashes($filepath) {
    if (!file_exists($filepath)) return null;
    return [
        'sha256'    => hash_file('sha256', $filepath),
        'md5'       => hash_file('md5', $filepath),
        'file_size' => filesize($filepath),
        'timestamp' => date('Y-m-d H:i:s'),
    ];
}

function verify_file_integrity($filepath, $original_sha256, $original_md5) {
    if (!file_exists($filepath)) return 'file_missing';
    $current_sha256 = hash_file('sha256', $filepath);
    $current_md5    = hash_file('md5', $filepath);
    if ($current_sha256 === $original_sha256 && $current_md5 === $original_md5) return 'intact';
    return 'tampered';
}

// ── Evidence Number Generator ────────────────────────────────
function generate_evidence_number($pdo) {
    $year = date('Y');
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM evidence WHERE YEAR(uploaded_at) = ?");
    $stmt->execute([$year]);
    $count = (int)$stmt->fetchColumn() + 1;
    return 'EV-' . $year . '-' . str_pad($count, 5, '0', STR_PAD_LEFT);
}

function generate_case_number($pdo) {
    $year = date('Y');
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM cases WHERE YEAR(created_at) = ?");
    $stmt->execute([$year]);
    $count = (int)$stmt->fetchColumn() + 1;
    return 'CASE-' . $year . '-' . str_pad($count, 4, '0', STR_PAD_LEFT);
}

function generate_report_number($pdo) {
    $year = date('Y');
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM analysis_reports WHERE YEAR(created_at) = ?");
    $stmt->execute([$year]);
    $count = (int)$stmt->fetchColumn() + 1;
    return 'RPT-' . $year . '-' . str_pad($count, 4, '0', STR_PAD_LEFT);
}

// ── Download Token ────────────────────────────────────────────
function create_download_token($pdo, $evidence_id, $user_id, $reason = '', $hours = null) {
    if ($hours === null) $hours = DOWNLOAD_TOKEN_EXPIRY;
    $token = bin2hex(random_bytes(32));
    $expires = date('Y-m-d H:i:s', strtotime("+{$hours} hours"));
    $stmt = $pdo->prepare("INSERT INTO download_tokens (token, evidence_id, created_by, expires_at, download_reason) VALUES (?,?,?,?,?)");
    $stmt->execute([$token, $evidence_id, $user_id, $expires, $reason]);
    return $token;
}

function validate_download_token($pdo, $token) {
    $stmt = $pdo->prepare("SELECT dt.*, e.file_path, e.file_name, e.title as evidence_title
        FROM download_tokens dt
        JOIN evidence e ON e.id = dt.evidence_id
        WHERE dt.token = ? AND dt.is_used = 0 AND dt.expires_at > NOW()");
    $stmt->execute([$token]);
    return $stmt->fetch();
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
function handle_evidence_upload($file, $evidence_number) {
    $allowed_types = [
        'image/jpeg','image/png','image/gif','image/bmp','image/tiff',
        'video/mp4','video/avi','video/mkv','video/mov','video/wmv',
        'application/pdf','application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'text/plain','text/csv','text/html',
        'application/zip','application/x-zip-compressed',
        'application/x-7z-compressed','application/gzip',
        'application/octet-stream',
    ];

    if ($file['error'] !== UPLOAD_ERR_OK) {
        return ['success' => false, 'error' => 'Upload error: ' . $file['error']];
    }

    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->file($file['tmp_name']);

    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $safe_name = preg_replace('/[^a-zA-Z0-9_\-]/', '_', pathinfo($file['name'], PATHINFO_FILENAME));
    $filename = $evidence_number . '_' . $safe_name . '_' . time() . '.' . $ext;
    $dest = UPLOAD_DIR . $filename;

    if (!is_dir(UPLOAD_DIR)) mkdir(UPLOAD_DIR, 0755, true);

    if (!move_uploaded_file($file['tmp_name'], $dest)) {
        return ['success' => false, 'error' => 'Failed to move uploaded file.'];
    }

    $hashes = generate_file_hashes($dest);
    return [
        'success'   => true,
        'filename'  => $filename,
        'filepath'  => $dest,
        'file_size' => $hashes['file_size'],
        'sha256'    => $hashes['sha256'],
        'md5'       => $hashes['md5'],
        'mime_type' => $mime,
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
        'viewer'       => ['label' => 'Viewer',        'color' => '#8899aa', 'bg' => 'rgba(136,153,170,0.15)'],
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