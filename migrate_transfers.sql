-- DigiCustody - Evidence Transfer System Migration
-- Run this to ensure all tables and columns exist for the transfer workflow

-- 1. evidence_transfers table (create if not exists)
CREATE TABLE IF NOT EXISTS evidence_transfers (
    id                    INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id           INT NOT NULL,
    from_user             INT NOT NULL,
    to_user               INT NOT NULL,
    transfer_reason       VARCHAR(500) NOT NULL,
    transfer_notes        TEXT,
    hash_verified         TINYINT DEFAULT 0,
    hash_at_transfer      VARCHAR(255),
    status                ENUM('pending','accepted','rejected') DEFAULT 'pending',
    transferred_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    accepted_at           DATETIME DEFAULT NULL,
    accepted_by           INT DEFAULT NULL,
    rejection_reason      TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE,
    FOREIGN KEY (from_user) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (to_user) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (accepted_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_to_user_status (to_user, status),
    INDEX idx_from_user_status (from_user, status),
    INDEX idx_evidence_status (evidence_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Add accepted_at and accepted_by columns if they don't exist
SET @dbname = DATABASE();
SET @tablename = 'evidence_transfers';
SET @columnname = 'accepted_at';
SET @preparedStatement = (SELECT IF(
  (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = @dbname
    AND TABLE_NAME = @tablename
    AND COLUMN_NAME = @columnname) > 0,
  'SELECT 1',
  CONCAT('ALTER TABLE ', @tablename, ' ADD COLUMN ', @columnname, ' DATETIME DEFAULT NULL AFTER transferred_at')
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

SET @columnname = 'accepted_by';
SET @preparedStatement = (SELECT IF(
  (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = @dbname
    AND TABLE_NAME = @tablename
    AND COLUMN_NAME = @columnname) > 0,
  'SELECT 1',
  CONCAT('ALTER TABLE ', @tablename, ' ADD COLUMN ', @columnname, ' INT DEFAULT NULL AFTER accepted_at')
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

SET @columnname = 'rejection_reason';
SET @preparedStatement = (SELECT IF(
  (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = @dbname
    AND TABLE_NAME = @tablename
    AND COLUMN_NAME = @columnname) > 0,
  'SELECT 1',
  CONCAT('ALTER TABLE ', @tablename, ' ADD COLUMN ', @columnname, ' TEXT AFTER accepted_by')
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- 3. Add foreign key for accepted_by if it doesn't exist
SET @fk_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
  WHERE TABLE_SCHEMA = @dbname
  AND TABLE_NAME = @tablename
  AND CONSTRAINT_NAME = 'evidence_transfers_ibfk_accepted_by');
SET @preparedStatement = (SELECT IF(@fk_exists > 0,
  'SELECT 1',
  'ALTER TABLE evidence_transfers ADD CONSTRAINT evidence_transfers_ibfk_accepted_by FOREIGN KEY (accepted_by) REFERENCES users(id) ON DELETE SET NULL'
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- 4. Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_transfers_to_user_status ON evidence_transfers(to_user, status);
CREATE INDEX IF NOT EXISTS idx_transfers_from_user_status ON evidence_transfers(from_user, status);
CREATE INDEX IF NOT EXISTS idx_transfers_evidence_status ON evidence_transfers(evidence_id, status);

-- 5. rate_limits table (for security hardening)
CREATE TABLE IF NOT EXISTS rate_limits (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    action      VARCHAR(100) NOT NULL,
    identifier  VARCHAR(255) NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_action_identifier (action, identifier, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. security_events table (for security event logging)
CREATE TABLE IF NOT EXISTS security_events (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    event_type  VARCHAR(100) NOT NULL,
    ip_address  VARCHAR(45) NOT NULL,
    user_agent  TEXT,
    user_id     INT DEFAULT NULL,
    details     JSON,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_event_type (event_type, created_at),
    INDEX idx_user_id (user_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. account_requests table (create if not exists)
CREATE TABLE IF NOT EXISTS account_requests (
    id                INT AUTO_INCREMENT PRIMARY KEY,
    full_name         VARCHAR(255) NOT NULL,
    email             VARCHAR(255) NOT NULL,
    phone             VARCHAR(50),
    department        VARCHAR(255),
    badge_number      VARCHAR(50),
    requested_role    ENUM('admin','investigator','analyst','viewer') DEFAULT 'viewer',
    reason            TEXT,
    status            ENUM('pending','approved','rejected') DEFAULT 'pending',
    admin_notes       TEXT,
    reviewed_by       INT DEFAULT NULL,
    reviewed_at       DATETIME DEFAULT NULL,
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_email_status (email, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. Ensure evidence table has current_custodian column
SET @tablename = 'evidence';
SET @columnname = 'current_custodian';
SET @preparedStatement = (SELECT IF(
  (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = @dbname
    AND TABLE_NAME = @tablename
    AND COLUMN_NAME = @columnname) > 0,
  'SELECT 1',
  CONCAT('ALTER TABLE ', @tablename, ' ADD COLUMN ', @columnname, ' INT NOT NULL DEFAULT 1 AFTER collection_notes')
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;
