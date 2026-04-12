<?php
/**
 * DigiCustody – Evidence Integrity Verification Cron Job
 * 
 * This script verifies the integrity of all evidence files by comparing
 * stored hash values against current file hashes. Any discrepancies are
 * logged and the evidence is flagged.
 * 
 * ============================================================================
 * CRON JOB SETUP INSTRUCTIONS
 * ============================================================================
 * 
 * Option 1: System cron (run as root or www-data)
 * --------------------------------------------------------------------
 * Edit crontab:
 *   sudo crontab -e
 * 
 * Add this line to run daily at 2 AM:
 *   0 2 * * * /usr/bin/php /var/www/html/digicustody/cron/verify_integrity.php >> /var/log/digicustody_integrity.log 2>&1
 * 
 * Option 2: User crontab (www-data)
 * --------------------------------------------------------------------
 *   sudo crontab -u www-data -e
 *   0 2 * * * /usr/bin/php /var/www/html/digicustody/cron/verify_integrity.php >> /var/log/digicustody_integrity.log 2>&1
 * 
 * Option 3: Run manually (for testing)
 * --------------------------------------------------------------------
 *   php /var/www/html/digicustody/cron/verify_integrity.php
 * 
 * RECOMMENDED SCHEDULE:
 *   - Daily (midnight or early morning): Catch tampering as soon as possible
 *   - After any security incident: Run immediately
 *   - Before audits: Run and review results
 * 
 * LOG ROTATION (add to /etc/logrotate.d/digicustody):
 * --------------------------------------------------------------------
 *   /var/log/digicustody_integrity.log {
 *       weekly
 *       rotate 12
 *       compress
 *       missingok
 *       notifempty
 *   }
 * 
 * ============================================================================
 */

define('BASE_PATH', dirname(__DIR__));

require_once BASE_PATH . '/config/db.php';
require_once BASE_PATH . '/config/functions.php';
require_once BASE_PATH . '/config/logger.php';

echo "[" . date('Y-m-d H:i:s') . "] Starting evidence integrity verification...\n";

$start_time = microtime(true);

// Query all evidence with file paths
$stmt = $pdo->query("
    SELECT id, evidence_number, file_path, sha256_hash, sha3_256_hash, file_name, status
    FROM evidence
    WHERE file_path IS NOT NULL AND file_path != ''
");
$evidence_records = $stmt->fetchAll(PDO::FETCH_ASSOC);

$total = count($evidence_records);
$verified = 0;
$intact = 0;
$tampered = 0;
$missing = 0;
$errors = 0;

echo "Found $total evidence records to verify.\n";

foreach ($evidence_records as $evidence) {
    $verified++;
    $ev_id = $evidence['id'];
    $ev_number = $evidence['evidence_number'];
    $file_path = $evidence['file_path'];
    
    echo "Verifying: $ev_number ({$evidence['file_name']})... ";
    
    // Verify file integrity
    $result = verify_file_integrity($file_path, $evidence['sha256_hash'], $evidence['sha3_256_hash']);
    
    if ($result === 'intact') {
        echo "INTACT\n";
        $intact++;
        
    } elseif ($result === 'file_missing') {
        echo "MISSING\n";
        $missing++;
        
        // Log the violation
        audit_log(
            $pdo,
            0,
            'SYSTEM',
            'system',
            'integrity_violation',
            'evidence',
            $ev_id,
            $ev_number,
            "File missing: {$evidence['file_name']} | Expected path: $file_path",
            '127.0.0.1',
            'Integrity Cron Job'
        );
        
        // Flag the evidence
        flag_evidence($pdo, $ev_id, 'integrity_violation', "File missing from storage");
        
        echo "  -> FLAGGED: File missing\n";
        
    } elseif ($result === 'tampered') {
        echo "TAMPERED\n";
        $tampered++;
        
        // Get current hashes for audit log
        $current_sha256 = file_exists($file_path) ? hash_file('sha256', $file_path) : 'N/A';
        $current_md5 = file_exists($file_path) ? hash_file('md5', $file_path) : 'N/A';
        
        // Log the violation
        audit_log(
            $pdo,
            0,
            'SYSTEM',
            'system',
            'integrity_violation',
            'evidence',
            $ev_id,
            $ev_number,
            "Hash mismatch: {$evidence['file_name']} | Stored SHA256: " . substr($evidence['sha256_hash'], 0, 16) . "... | Current: " . substr($current_sha256, 0, 16) . "...",
            '127.0.0.1',
            'Integrity Cron Job'
        );
        
        // Flag the evidence
        flag_evidence($pdo, $ev_id, 'integrity_violation', "Hash mismatch detected - file may have been modified");
        
        echo "  -> FLAGGED: Hash mismatch\n";
        
    } else {
        echo "ERROR: Unknown result\n";
        $errors++;
    }
}

$end_time = microtime(true);
$duration = round($end_time - $start_time, 2);

echo "\n============================================\n";
echo "Integrity Verification Complete\n";
echo "============================================\n";
echo "Total records:     $total\n";
echo "Verified:           $verified\n";
echo "Intact:             $intact\n";
echo "Missing:            $missing\n";
echo "Tampered:           $tampered\n";
echo "Errors:             $errors\n";
echo "Duration:           {$duration}s\n";
echo "============================================\n";

if ($tampered > 0 || $missing > 0) {
    echo "\n⚠️  ALERT: $tampered tampered, $missing missing - Review flagged evidence immediately!\n";
    
    // Notify admins via in-app notification and email
    $admins = $pdo->query("SELECT id, email, full_name FROM users WHERE role='admin' AND status='active'")->fetchAll();
    $alert_message = "Integrity check found $tampered tampered and $missing missing evidence files. Review flagged records immediately.";
    
    foreach ($admins as $admin) {
        // Send in-app notification
        send_notification(
            $pdo,
            $admin['id'],
            'Evidence Integrity Alert',
            $alert_message,
            'danger',
            'system',
            0
        );
        
        // Send email to admin
        $email_subject = "⚠️ DigiCustody Evidence Integrity Alert";
        $email_html = "
        <html>
        <body style='font-family: Arial, sans-serif; background: #060d1a; color: #f0f4fa; padding: 20px;'>
            <div style='max-width: 600px; margin: 0 auto; background: #0c1526; border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 32px;'>
                <h2 style='color: #ef4444; margin-bottom: 20px;'>⚠️ Evidence Integrity Alert</h2>
                <p>Hello <strong>{$admin['full_name']}</strong>,</p>
                <p>The automated integrity verification has detected issues that require your immediate attention:</p>
                <div style='background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); border-radius: 12px; padding: 20px; margin: 20px 0;'>
                    <p style='margin: 8px 0;'><strong style='color: #ef4444;'>Tampered Files:</strong> <span style='font-size: 24px; font-weight: bold;'>{$tampered}</span></p>
                    <p style='margin: 8px 0;'><strong style='color: #fbbf24;'>Missing Files:</strong> <span style='font-size: 24px; font-weight: bold;'>{$missing}</span></p>
                </div>
                <p style='color: #ef4444; font-weight: 600;'>Please review the flagged evidence records in the DigiCustody dashboard immediately.</p>
                <p style='color: #6b82a0; font-size: 12px; margin-top: 20px;'>This is an automated alert from the DigiCustody Evidence Management System. Run time: " . date('Y-m-d H:i:s') . "</p>
            </div>
        </body>
        </html>";
        
        send_email($admin['email'], $email_subject, $email_html);
    }
    
    echo "  -> Admin notifications sent to " . count($admins) . " admin(s)\n";
}

// Record integrity check run in database
$pdo->prepare("
    INSERT INTO integrity_checks 
    (run_at, total_records, verified, intact, tampered, missing, errors, duration_seconds) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
")->execute([
    date('Y-m-d H:i:s'),
    $total,
    $verified,
    $intact,
    $tampered,
    $missing,
    $errors,
    $duration
]);

echo "[" . date('Y-m-d H:i:s') . "] Integrity verification finished.\n";

/**
 * Flag an evidence record for integrity violation
 */
function flag_evidence($pdo, $evidence_id, $reason, $details) {
    try {
        $stmt = $pdo->prepare("
            UPDATE evidence 
            SET status = 'flagged', 
                pre_flag_status = COALESCE(pre_flag_status, status),
                flagged_reason = CONCAT(IFNULL(flagged_reason, ''), NOW(), ' | ', ?, ' | ', ?, ' | INTEGRITY CHECK\n')
            WHERE id = ?
        ");
        $stmt->execute([$reason, $details, $evidence_id]);
        return true;
    } catch (Exception $e) {
        log_error("Failed to flag evidence", ['evidence_id' => $evidence_id, 'error' => $e->getMessage()]);
        return false;
    }
}
