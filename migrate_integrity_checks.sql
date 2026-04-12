-- Migration: Create integrity_checks table for tracking integrity verification runs
-- Run this SQL to create the table for storing integrity check results

CREATE TABLE IF NOT EXISTS integrity_checks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    run_at DATETIME NOT NULL,
    total_records INT NOT NULL DEFAULT 0,
    verified INT NOT NULL DEFAULT 0,
    intact INT NOT NULL DEFAULT 0,
    tampered INT NOT NULL DEFAULT 0,
    missing INT NOT NULL DEFAULT 0,
    errors INT NOT NULL DEFAULT 0,
    duration_seconds DECIMAL(10,2) DEFAULT 0.00,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_run_at (run_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
