# DigiCustody - Digital Evidence Management System

A secure web-based digital evidence management system for forensic investigators and law enforcement agencies.

## 🔒 Features

- **Evidence Management**: Upload, view, verify, and manage digital evidence
- **Chain of Custody**: Complete audit trail for every evidence item
- **User Management**: Role-based access control (Admin, Investigator, Analyst)
- **Two-Factor Authentication**: Optional 2FA with TOTP support
- **Download Tokens**: Secure, time-limited download links
- **Audit Logging**: Comprehensive activity tracking
- **Search & Filtering**: Advanced search across evidence, cases, and reports

## 📋 Requirements

### Server Requirements

- **PHP**: 8.0 or higher
- **Database**: MySQL 5.7+ or MariaDB 10.3+
- **Web Server**: Apache2 with mod_rewrite or Nginx
- **SSL**: HTTPS required for production

### Required PHP Extensions

```bash
# Core extensions
pdo
pdo_mysql
gd
mbstring
zip
json
openssl
session
ctype
filter
```

### Optional (Recommended)

```bash
# For PDF generation
dompdf  # or tcpdf

# For email notifications
sendmail or SMTP server
```

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone <repository-url> digicustody
cd digicustody
```

### 2. Configure Web Server

#### Apache (Recommended)

Create `.htaccess` in project root:

```apache
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php [QSA,L]
```

Enable mod_rewrite:

```bash
sudo a2enmod rewrite
sudo systemctl restart apache2
```

#### Nginx

```nginx
server {
    listen 80;
    server_name your-domain.com;
    root /var/www/digicustody;
    index index.php;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\.ht {
        deny all;
    }
}
```

### 3. Set Folder Permissions

```bash
# Set ownership
sudo chown -R www-data:www-data /var/www/digicustody

# Create and set permissions for writable directories
mkdir -p /var/www/digicustody/sessions
mkdir -p /var/www/digicustody/uploads/evidence
mkdir -p /var/www/digicustody/uploads/temp

# Set permissions
chmod 755 /var/www/digicustody
chmod 775 /var/www/digicustody/sessions
chmod 775 /var/www/digicustody/uploads
chmod 775 /var/www/digicustody/uploads/evidence
chmod 775 /var/www/digicustody/uploads/temp

# Optional: Lock config files
chmod 640 /var/www/digicustody/config/db.php
```

### 4. Create Database

```sql
-- Login to MySQL
mysql -u root -p

-- Create database
CREATE DATABASE digicustody CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user (recommended)
CREATE USER 'digicustody'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON digicustody.* TO 'digicustody'@'localhost';
FLUSH PRIVILEGES;

USE digicustody;
```

### 5. Import Database Schema

The system uses the following tables (automatically created on first run or manually via SQL):

```sql
-- Core tables
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    role ENUM('admin','investigator','analyst') NOT NULL,
    status ENUM('active','suspended','pending') DEFAULT 'pending',
    two_factor_enabled TINYINT(1) DEFAULT 0,
    two_factor_secret VARCHAR(255),
    backup_codes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    UNIQUE KEY email_unique (email)
);

CREATE TABLE cases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_number VARCHAR(50) UNIQUE NOT NULL,
    case_title VARCHAR(255) NOT NULL,
    case_type VARCHAR(100),
    description TEXT,
    status ENUM('open','under_investigation','closed','archived') DEFAULT 'open',
    priority ENUM('low','medium','high','critical') DEFAULT 'medium',
    created_by INT,
    assigned_to INT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    closed_at DATETIME,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (assigned_to) REFERENCES users(id)
);

CREATE TABLE evidence (
    id INT AUTO_INCREMENT PRIMARY KEY,
    evidence_number VARCHAR(100) UNIQUE NOT NULL,
    case_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    evidence_type ENUM('image','video','document','log_file','email','database','network_capture','mobile_data','other'),
    file_name VARCHAR(255),
    file_path VARCHAR(500),
    file_size BIGINT,
    mime_type VARCHAR(100),
    sha256_hash VARCHAR(64),
    md5_hash VARCHAR(32),
    collection_date DATETIME,
    collection_location VARCHAR(255),
    collection_notes TEXT,
    current_custodian INT,
    status ENUM('collected','in_analysis','transferred','archived','flagged') DEFAULT 'collected',
    is_verified TINYINT(1) DEFAULT 0,
    uploaded_by INT,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id),
    FOREIGN KEY (current_custodian) REFERENCES users(id),
    FOREIGN KEY (uploaded_by) REFERENCES users(id)
);

-- Supporting tables
CREATE TABLE cases (
    -- See above
);

CREATE TABLE audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    username VARCHAR(80),
    user_role VARCHAR(30),
    action_type ENUM('login','logout','login_failed','evidence_uploaded','evidence_viewed',
                    'evidence_downloaded','evidence_transferred','hash_verified', ...),
    target_type VARCHAR(50),
    target_id INT,
    target_label VARCHAR(255),
    description TEXT,
    ip_address VARCHAR(45),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE evidence_transfers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id INT NOT NULL,
    from_user INT NOT NULL,
    to_user INT NOT NULL,
    transfer_reason TEXT,
    hash_verified TINYINT(1) DEFAULT 0,
    hash_at_transfer VARCHAR(64),
    status ENUM('pending','accepted','rejected'),
    transferred_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id),
    FOREIGN KEY (from_user) REFERENCES users(id),
    FOREIGN KEY (to_user) REFERENCES users(id)
);

CREATE TABLE trusted_devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    ip_address VARCHAR(45),
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE download_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    evidence_id INT NOT NULL,
    created_by INT,
    expires_at DATETIME,
    is_used TINYINT(1) DEFAULT 0,
    used_at DATETIME,
    download_reason TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    username VARCHAR(150),
    successful TINYINT(1) DEFAULT 0,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_time (ip_address, attempted_at)
);
```

### 6. Configure Database Connection

Copy the example config and edit:

```bash
cp config/db.example.php config/db.php
nano config/db.php
```

Update with your settings:

```php
define('DB_HOST', 'localhost');
define('DB_NAME', 'digicustody');
define('DB_USER', 'digicustody');
define('DB_PASS', 'your_secure_password');
define('DB_CHARSET', 'utf8mb4');
```

### 7. Create Admin Account

After first login, you can create an admin user through the web interface, or directly via SQL:

```sql
-- Hash password using PHP: echo password_hash('your-password', PASSWORD_DEFAULT);
INSERT INTO users (username, email, password, full_name, role, status)
VALUES ('admin', 'admin@your-domain.com', '$2y$10$...', 'System Administrator', 'admin', 'active');
```

## 🔒 Security Checklist

Before going live, ensure:

- [ ] HTTPS enabled with valid SSL certificate
- [ ] `config/db.php` file protected (chmod 640)
- [ ] Uploads directory not publicly accessible
- [ ] Sessions directory not publicly accessible
- [ ] Debug mode disabled
- [ ] Error logging enabled (not displayed to users)
- [ ] Strong passwords enforced (min 8 chars, mixed case, numbers, special chars)
- [ ] Two-Factor Authentication enabled for all users
- [ ] Regular backups configured

## 📁 Folder Structure

```
digicustody/
├── config/
│   ├── db.php              # Database configuration (PRIVATE)
│   └── functions.php       # Core functions
├── pages/                  # Application pages
│   ├── dashboard_admin.php
│   ├── evidence_view.php
│   ├── audit.php
│   └── ...
├── includes/
│   ├── sidebar.php
│   └── navbar.php
├── assets/
│   ├── css/
│   ├── js/
│   └── img/
├── uploads/
│   ├── evidence/          # Evidence files (NOT public)
│   └── temp/              # Temporary uploads
├── sessions/              # PHP sessions (NOT public)
├── login.php             # Login page
├── dashboard.php          # Dashboard router
└── README.md
```

## 🛠️ Troubleshooting

### Login not working
```bash
# Check sessions directory
ls -la sessions/
# Should be writable by web server
chmod 775 sessions
```

### Database connection failed
```bash
# Verify credentials
mysql -u digicustody -p -e "USE digicustody; SHOW TABLES;"
```

### Upload failing
```bash
# Check upload limits
php -i | grep upload
# Verify directory permissions
chmod 775 uploads/evidence
```

### 2FA not working
- Ensure server time is synchronized: `sudo timedatectl set-timezone Africa/Nairobi`
- Check NTP: `sudo systemctl status ntp`

## 📞 Support

For issues or questions, please contact your system administrator.

## 📄 License

Proprietary - All rights reserved.
