-- Migration: Add digital_signature column to evidence table
-- Run this SQL to add the digital signature column

ALTER TABLE evidence ADD COLUMN digital_signature TEXT DEFAULT NULL AFTER sha3_256_hash;
