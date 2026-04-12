-- Migration: Create limited database user for DigiCustody application
-- Run this SQL to create the digicustody_app user with restricted privileges
-- IMPORTANT: Run as MySQL root/admin user

-- Create the dedicated application user with a strong password
CREATE USER IF NOT EXISTS 'digicustody_app'@'localhost' IDENTIFIED BY 'DigiCust0dy_App_2025_Secure';

-- Grant only the necessary privileges on the digicustody database
GRANT SELECT, INSERT, UPDATE, DELETE ON digicustody.* TO 'digicustody_app'@'localhost';

-- Apply the changes
FLUSH PRIVILEGES;

-- Verify the privileges (optional, for confirmation)
-- SHOW GRANTS FOR 'digicustody_app'@'localhost';
