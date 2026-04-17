<?php
/**
 * Migration: Case Collaborator Invites
 * Run this once to create the table
 */
require_once __DIR__."/config/db.php";

$pdo->exec("
CREATE TABLE IF NOT EXISTS case_collab_invites (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT NOT NULL,
    invited_by INT NOT NULL,
    invited_user_id INT NOT NULL,
    status ENUM('pending','accepted','rejected') DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    responded_at DATETIME,
    UNIQUE KEY unique_invite (case_id, invited_user_id),
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (invited_by) REFERENCES users(id),
    FOREIGN KEY (invited_user_id) REFERENCES users(id)
)");

echo "Table case_collab_invites created successfully.\n";
