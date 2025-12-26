<?php
// ============================================================================
// ONE-TIME PASSWORD UPDATE SCRIPT
// Run this ONCE, then DELETE it immediately!
// ============================================================================

// Include config (temporary connection without full security for this script)
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'task_manager');

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Function to hash password with bcrypt
function hash_password_bcrypt($password) {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

echo "<h2>🔐 Updating Passwords to Bcrypt Hashes</h2>";
echo "<p>This script will update all plaintext passwords to secure bcrypt hashes.</p>";
echo "<hr>";

// Array of users to update (ID, username, current plain password)
$users_to_update = [
    ['id' => 1, 'username' => 'admin', 'current_password' => 'admin123'],
    ['id' => 4, 'username' => 'testuser', 'current_password' => 'testpass123'],
    ['id' => 5, 'username' => 'czarritzman', 'current_password' => 'czar123'],
    ['id' => 6, 'username' => 'iman', 'current_password' => 'iman123']
];

foreach ($users_to_update as $user) {
    $hashed_password = hash_password_bcrypt($user['current_password']);
    
    // Use prepared statement to prevent SQL injection
    $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
    $stmt->bind_param("si", $hashed_password, $user['id']);
    
    if ($stmt->execute()) {
        echo "✅ Updated: <strong>{$user['username']}</strong> (ID: {$user['id']})<br>";
        echo "&nbsp;&nbsp;&nbsp;Old password: {$user['current_password']}<br>";
        echo "&nbsp;&nbsp;&nbsp;New hash: " . substr($hashed_password, 0, 30) . "...<br><br>";
    } else {
        echo "❌ Failed: {$user['username']} - " . $stmt->error . "<br><br>";
    }
    
    $stmt->close();
}

echo "<hr><h3>🔧 Adding Security Columns to Users Table</h3>";

// Check and add failed_attempts column
$check_column = $conn->query("SHOW COLUMNS FROM users LIKE 'failed_attempts'");
if ($check_column->num_rows == 0) {
    $conn->query("ALTER TABLE users ADD COLUMN failed_attempts INT DEFAULT 0");
    echo "✅ Added 'failed_attempts' column<br>";
} else {
    echo "✓ 'failed_attempts' column already exists<br>";
}

// Check and add locked_until column
$check_column = $conn->query("SHOW COLUMNS FROM users LIKE 'locked_until'");
if ($check_column->num_rows == 0) {
    $conn->query("ALTER TABLE users ADD COLUMN locked_until DATETIME DEFAULT NULL");
    echo "✅ Added 'locked_until' column<br>";
} else {
    echo "✓ 'locked_until' column already exists<br>";
}

// Check and add audit_logs table if not exists
$check_table = $conn->query("SHOW TABLES LIKE 'audit_logs'");
if ($check_table->num_rows == 0) {
    $create_audit_logs = "CREATE TABLE audit_logs (
        id INT(11) NOT NULL AUTO_INCREMENT,
        user_id INT(11) DEFAULT NULL,
        username VARCHAR(50) DEFAULT NULL,
        action VARCHAR(100) NOT NULL,
        ip_address VARCHAR(45) DEFAULT NULL,
        user_agent TEXT DEFAULT NULL,
        details TEXT DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY user_id (user_id),
        KEY created_at (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
    
    if ($conn->query($create_audit_logs)) {
        echo "✅ Created 'audit_logs' table<br>";
    } else {
        echo "❌ Failed to create audit_logs: " . $conn->error . "<br>";
    }
} else {
    echo "✓ 'audit_logs' table already exists<br>";
}

// Check and add system_logs table if not exists
$check_table = $conn->query("SHOW TABLES LIKE 'system_logs'");
if ($check_table->num_rows == 0) {
    $create_system_logs = "CREATE TABLE system_logs (
        id INT(11) NOT NULL AUTO_INCREMENT,
        level ENUM('INFO','WARNING','ERROR','SECURITY') DEFAULT 'INFO',
        message TEXT NOT NULL,
        context TEXT DEFAULT NULL,
        ip_address VARCHAR(45) DEFAULT NULL,
        user_id INT(11) DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY level (level),
        KEY created_at (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
    
    if ($conn->query($create_system_logs)) {
        echo "✅ Created 'system_logs' table<br>";
    } else {
        echo "❌ Failed to create system_logs: " . $conn->error . "<br>";
    }
} else {
    echo "✓ 'system_logs' table already exists<br>";
}

echo "<hr><h3>📋 Generated SQL for Reference:</h3>";
echo "<pre>";
foreach ($users_to_update as $user) {
    $hashed_password = hash_password_bcrypt($user['current_password']);
    echo "UPDATE users SET password = '$hashed_password' WHERE id = {$user['id']};\n";
}
echo "</pre>";

echo "<hr><h3>🎉 Update Complete!</h3>";
echo "<div style='background: #ffebee; padding: 15px; border-radius: 5px; border-left: 4px solid #f44336;'>";
echo "<strong>⚠️ IMPORTANT SECURITY NOTICE:</strong><br>";
echo "1. DELETE this file immediately after running!<br>";
echo "2. Test login with the updated passwords<br>";
echo "3. All passwords are now securely hashed with bcrypt<br>";
echo "4. New users will automatically get hashed passwords<br>";
echo "</div>";

$conn->close();
?>