-- DigiCustody - Access Control & Download History Migration
-- Run: mysql -u root -p'DigiCustody@2025' digicustody < migrate_access_control.sql

-- 1. case_access junction table (explicit per-user case permissions)
CREATE TABLE IF NOT EXISTS case_access (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    case_id     INT NOT NULL,
    user_id     INT NOT NULL,
    granted_by  INT DEFAULT NULL,
    granted_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_case_user (case_id, user_id),
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_case (user_id, case_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. download_history table (dedicated download audit trail)
CREATE TABLE IF NOT EXISTS download_history (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id     INT NOT NULL,
    user_id         INT NOT NULL,
    token_id        INT DEFAULT NULL,
    ip_address      VARCHAR(45) NOT NULL,
    user_agent      TEXT,
    reason          VARCHAR(500),
    downloaded_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (token_id) REFERENCES download_tokens(id) ON DELETE SET NULL,
    INDEX idx_evidence (evidence_id),
    INDEX idx_user (user_id),
    INDEX idx_downloaded_at (downloaded_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Auto-grant case_access for existing relationships
-- Grant access to case creators
INSERT IGNORE INTO case_access (case_id, user_id, granted_by)
SELECT id, created_by, created_by FROM cases;

-- Grant access to case assignees (assigned_to)
INSERT IGNORE INTO case_access (case_id, user_id, granted_by)
SELECT id, assigned_to, created_by FROM cases WHERE assigned_to IS NOT NULL;

-- Grant access to evidence uploaders
INSERT IGNORE INTO case_access (case_id, user_id, granted_by)
SELECT DISTINCT e.case_id, e.uploaded_by, e.uploaded_by
FROM evidence e;

-- Grant access to evidence custodians
INSERT IGNORE INTO case_access (case_id, user_id, granted_by)
SELECT DISTINCT e.case_id, e.current_custodian, e.uploaded_by
FROM evidence e;

-- 4. Auto-grant admin full access to all cases
INSERT IGNORE INTO case_access (case_id, user_id, granted_by)
SELECT c.id, u.id, 1
FROM cases c
CROSS JOIN users u
WHERE u.role = 'admin';
