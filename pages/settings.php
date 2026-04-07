<?php
/**
 * DigiCustody – Settings Page
 * Save to: /var/www/html/digicustody/pages/settings.php
 */
require_once __DIR__."/../config/functions.php";
set_secure_session_config();
session_start();
require_once __DIR__.'/../config/db.php';
require_login();
require_role('admin');

$page_title = 'Settings';
$uid = $_SESSION['user_id'];
$msg = ''; $err = '';

// ── Handle settings update ────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $err = 'Security token mismatch.';
    } else {
        $settings = [
            'site_name'                   => trim($_POST['site_name'] ?? ''),
            'site_tagline'                => trim($_POST['site_tagline'] ?? ''),
            'institution_name'            => trim($_POST['institution_name'] ?? ''),
            'download_token_expiry_hours' => max(1, (int)($_POST['download_token_expiry_hours'] ?? 24)),
            'max_upload_size_mb'          => max(1, (int)($_POST['max_upload_size_mb'] ?? 500)),
            'session_timeout_minutes'     => max(5, (int)($_POST['session_timeout_minutes'] ?? 60)),
            'allow_viewer_download'       => isset($_POST['allow_viewer_download']) ? '1' : '0',
        ];

        foreach ($settings as $key => $value) {
            $pdo->prepare("INSERT INTO system_settings (setting_key, setting_value, updated_by)
                VALUES (?,?,?)
                ON DUPLICATE KEY UPDATE setting_value=?, updated_by=?, updated_at=NOW()")
                ->execute([$key, $value, $uid, $value, $uid]);
        }

        audit_log($pdo, $uid, $_SESSION['username'], 'admin', 'admin_action',
            null, null, null, 'System settings updated by admin');
        $msg = 'Settings saved successfully.';
    }
}

// ── Fetch current settings ────────────────────────────────
$rows = $pdo->query("SELECT setting_key, setting_value FROM system_settings")->fetchAll(PDO::FETCH_ASSOC);
$settings = array_column($rows, 'setting_value', 'setting_key');

// ── System info ───────────────────────────────────────────
$total_users    = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
$total_evidence = (int)$pdo->query("SELECT COUNT(*) FROM evidence")->fetchColumn();
$total_cases    = (int)$pdo->query("SELECT COUNT(*) FROM cases")->fetchColumn();
$total_logs     = (int)$pdo->query("SELECT COUNT(*) FROM audit_logs")->fetchColumn();
$storage_bytes  = (int)$pdo->query("SELECT COALESCE(SUM(file_size),0) FROM evidence")->fetchColumn();
$db_version     = $pdo->query("SELECT VERSION()")->fetchColumn();

$csrf = csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Settings — DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="<?= BASE_URL ?>assets/css/font-awesome.min.css">
<link rel="stylesheet" href="../assets/css/global.css">
<style>
.field{margin-bottom:18px;}
.field label{display:block;font-size:11.5px;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:7px;}
.field input,.field select{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:11px 14px;font-size:14px;color:var(--text);outline:none;font-family:'Inter',sans-serif;transition:border-color .2s;}
.field input:focus,.field select:focus{border-color:rgba(201,168,76,0.5);box-shadow:0 0 0 3px rgba(201,168,76,0.06);}
.field select option{background:var(--surface2);}
.field .hint{font-size:12px;color:var(--dim);margin-top:5px;}
.toggle-row{display:flex;align-items:center;justify-content:space-between;padding:14px 0;border-bottom:1px solid var(--border);}
.toggle-row:last-child{border-bottom:none;}
.toggle-label{font-size:13.5px;color:var(--text);font-weight:500;}
.toggle-desc{font-size:12px;color:var(--muted);margin-top:3px;}
.toggle-switch{position:relative;width:46px;height:24px;flex-shrink:0;}
.toggle-switch input{opacity:0;width:0;height:0;}
.toggle-slider{position:absolute;cursor:pointer;inset:0;background:var(--dim);border-radius:24px;transition:.3s;}
.toggle-slider:before{content:'';position:absolute;height:18px;width:18px;left:3px;bottom:3px;background:white;border-radius:50%;transition:.3s;}
.toggle-switch input:checked+.toggle-slider{background:var(--gold);}
.toggle-switch input:checked+.toggle-slider:before{transform:translateX(22px);}
.info-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border);}
.info-row:last-child{border-bottom:none;}
.info-label{font-size:13px;color:var(--muted);}
.info-value{font-size:13.5px;font-weight:500;color:var(--text);}
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
        <h1 style="margin-top:8px;">Settings</h1>
        <p>System configuration and administration</p>
    </div>
</div>

<?php if ($msg): ?><div class="alert alert-success"><i class="fas fa-circle-check"></i> <?= e($msg) ?></div><?php endif; ?>
<?php if ($err): ?><div class="alert alert-danger"><i class="fas fa-circle-exclamation"></i> <?= e($err) ?></div><?php endif; ?>

<div class="grid-2" style="gap:24px;">

    <!-- General Settings -->
    <div>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">

            <div class="section-card" style="margin-bottom:20px;">
                <div class="section-head"><h2><i class="fas fa-sliders"></i> General Settings</h2></div>
                <div class="section-body padded">
                    <div class="field">
                        <label>System Name</label>
                        <input type="text" name="site_name" value="<?= e($settings['site_name'] ?? 'DigiCustody') ?>">
                    </div>
                    <div class="field">
                        <label>System Tagline</label>
                        <input type="text" name="site_tagline" value="<?= e($settings['site_tagline'] ?? 'Secure Evidence Management Platform') ?>">
                    </div>
                    <div class="field">
                        <label>Institution Name</label>
                        <input type="text" name="institution_name" value="<?= e($settings['institution_name'] ?? '') ?>" placeholder="e.g. Digital Forensics Unit, DCI Kenya">
                        <p class="hint">Appears on generated reports and audit logs.</p>
                    </div>
                </div>
            </div>

            <div class="section-card" style="margin-bottom:20px;">
                <div class="section-head"><h2><i class="fas fa-shield-halved"></i> Security Settings</h2></div>
                <div class="section-body padded">
                    <div class="field">
                        <label>Session Timeout (minutes)</label>
                        <input type="number" name="session_timeout_minutes" min="5" max="480"
                            value="<?= e($settings['session_timeout_minutes'] ?? 60) ?>">
                        <p class="hint">Users will be automatically logged out after this period of inactivity.</p>
                    </div>
                    <div class="field">
                        <label>Default Download Token Expiry (hours)</label>
                        <input type="number" name="download_token_expiry_hours" min="1" max="72"
                            value="<?= e($settings['download_token_expiry_hours'] ?? 24) ?>">
                        <p class="hint">Default expiry time for secure evidence download links.</p>
                    </div>
                    <div class="field">
                        <label>Maximum Upload Size (MB)</label>
                        <input type="number" name="max_upload_size_mb" min="1" max="2048"
                            value="<?= e($settings['max_upload_size_mb'] ?? 500) ?>">
                        <p class="hint">Maximum allowed size for evidence file uploads.</p>
                    </div>
                    <div class="toggle-row">
                        <div>
                            <p class="toggle-label">Allow Viewers to Download Evidence</p>
                            <p class="toggle-desc">If enabled, users with Viewer role can download evidence files.</p>
                        </div>
                        <label class="toggle-switch">
                            <input type="checkbox" name="allow_viewer_download" value="1"
                                <?= ($settings['allow_viewer_download'] ?? '0') === '1' ? 'checked' : '' ?>>
                            <span class="toggle-slider"></span>
                        </label>
                    </div>
                </div>
            </div>

            <button type="submit" class="btn btn-gold" style="width:100%;padding:13px;font-size:15px;">
                <i class="fas fa-save"></i> Save Settings
            </button>
        </form>
    </div>

    <!-- System Info -->
    <div>
        <div class="section-card" style="margin-bottom:20px;">
            <div class="section-head"><h2><i class="fas fa-circle-info"></i> System Information</h2></div>
            <div class="section-body padded">
                <div class="info-row"><span class="info-label">PHP Version</span><span class="info-value"><?= PHP_VERSION ?></span></div>
                <div class="info-row"><span class="info-label">Database Version</span><span class="info-value"><?= e($db_version) ?></span></div>
                <div class="info-row"><span class="info-label">Server Software</span><span class="info-value"><?= e($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown') ?></span></div>
                <div class="info-row"><span class="info-label">Upload Directory</span><span class="info-value" style="font-family:'Courier New',monospace;font-size:12px">/var/www/html/digicustody/uploads/</span></div>
                <div class="info-row"><span class="info-label">Max Upload Size (PHP)</span><span class="info-value"><?= ini_get('upload_max_filesize') ?></span></div>
                <div class="info-row"><span class="info-label">Memory Limit</span><span class="info-value"><?= ini_get('memory_limit') ?></span></div>
            </div>
        </div>

        <div class="section-card" style="margin-bottom:20px;">
            <div class="section-head"><h2><i class="fas fa-chart-pie"></i> Database Statistics</h2></div>
            <div class="section-body padded">
                <div class="info-row"><span class="info-label">Total Users</span><span class="info-value"><?= number_format($total_users) ?></span></div>
                <div class="info-row"><span class="info-label">Total Evidence Files</span><span class="info-value"><?= number_format($total_evidence) ?></span></div>
                <div class="info-row"><span class="info-label">Total Cases</span><span class="info-value"><?= number_format($total_cases) ?></span></div>
                <div class="info-row"><span class="info-label">Total Audit Log Entries</span><span class="info-value"><?= number_format($total_logs) ?></span></div>
                <div class="info-row"><span class="info-label">Total Storage Used</span><span class="info-value"><?= format_filesize($storage_bytes) ?></span></div>
            </div>
        </div>

        <div class="section-card">
            <div class="section-head"><h2><i class="fas fa-wrench"></i> Maintenance</h2></div>
            <div class="section-body padded">
                <p style="font-size:13px;color:var(--muted);margin-bottom:16px;">Administrative maintenance actions. Use with caution.</p>
                <div style="display:flex;flex-direction:column;gap:10px;">
                    <a href="audit.php" class="btn btn-outline" style="justify-content:flex-start;">
                        <i class="fas fa-scroll"></i> View Full Audit Log
                    </a>
                    <a href="users.php" class="btn btn-outline" style="justify-content:flex-start;">
                        <i class="fas fa-users"></i> Manage User Accounts
                    </a>
                    <a href="requests.php" class="btn btn-outline" style="justify-content:flex-start;">
                        <i class="fas fa-user-clock"></i> Review Access Requests
                    </a>
                    <button class="btn btn-outline" style="justify-content:flex-start;"
                        onclick="if(confirm('Clear expired download tokens?')) clearTokens()">
                        <i class="fas fa-key"></i> Clear Expired Download Tokens
                    </button>
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
function clearTokens(){
    fetch('settings.php?action=clear_tokens').then(()=>location.reload());
}
</script>
<script src="../assets/js/main.js"></script>
</body>
</html>
