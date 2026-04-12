-- Migration: Replace MD5 with SHA3-256 for evidence integrity
-- Run this SQL to update the database schema
-- IMPORTANT: Backup your database before running this migration

-- Add new sha3_256_hash column to evidence table
ALTER TABLE evidence ADD COLUMN sha3_256_hash VARCHAR(64) DEFAULT NULL AFTER sha256_hash;

-- Add new sha3_256_hash column to download_tokens table  
ALTER TABLE download_tokens ADD COLUMN sha3_256_hash VARCHAR(64) DEFAULT NULL AFTER sha256_hash;

-- Add new sha3_256_hash column to hash_verifications table
ALTER TABLE hash_verifications ADD COLUMN sha3_256_at_verification VARCHAR(64) DEFAULT NULL AFTER sha256_at_verification;
ALTER TABLE hash_verifications ADD COLUMN original_sha3_256 VARCHAR(64) DEFAULT NULL AFTER original_sha256;

-- Copy existing md5_hash values to sha3_256_hash (if you have existing data)
-- UPDATE evidence SET sha3_256_hash = md5_hash WHERE sha3_256_hash IS NULL;

-- Drop the old md5_hash columns (after copying data if needed)
-- ALTER TABLE evidence DROP COLUMN md5_hash;
-- ALTER TABLE download_tokens DROP COLUMN md5_hash;
-- ALTER TABLE hash_verifications DROP COLUMN md5_at_verification;
-- ALTER TABLE hash_verifications DROP COLUMN original_md5;
