-- Migration: Add chain_hash column for audit log integrity
-- Run this SQL to add the chain_hash column for tamper-evident audit log

ALTER TABLE audit_logs ADD COLUMN chain_hash VARCHAR(64) DEFAULT NULL AFTER created_at;
ALTER TABLE audit_logs ADD INDEX idx_chain_hash (chain_hash);
