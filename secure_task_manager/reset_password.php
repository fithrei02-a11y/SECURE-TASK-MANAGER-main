<?php
require_once __DIR__ . '/../includes/config.php';

echo "<h2>⚠️ SECURITY WARNING: This script stores passwords in plain text!</h2>";
echo "<p>For testing/educational purposes ONLY. Delete this file after use!</p>";

if (isset($_POST['reset_all'])) {
    // List of plain text passwords to assign (for testing)
    $test_passwords = [
        'admin' => 'AdminPassword123!',
        'john' => 'JohnPassword123!',
        'jane' => 'JanePassword123!',
        'test' => 'TestPassword123!',
        'user1' => 'Password123!',
        'user2' => 'Password456!'
    ];
    
    echo "<h3>Updating passwords to plain text:</h3>";
    
    $updated = 0;
    foreach ($test_passwords as $username => $plain_password) {
        $stmt = $conn->prepare("UPDATE users SET password = ? WHERE username = ?");
        $stmt->bind_param("ss", $plain_password, $username);
        
        if ($stmt->execute()) {
            if ($stmt->affected_rows > 0) {
                echo "Updated $username: $plain_password<br>";
                $updated++;
            } else {
                echo "User $username not found<br>";
            }
        }
        $stmt->close();
    }
    
    echo "<br><strong>Updated $updated users. Their passwords are now in plain text.</strong>";
    echo "<br><strong style='color: red;'>DELETE THIS FILE NOW!</strong>";
    
} elseif (isset($_POST['reset_specific'])) {
    $username = $_POST['username'];
    $new_password = $_POST['new_password'];
    
    $stmt = $conn->prepare("UPDATE users SET password = ? WHERE username = ?");
    $stmt->bind_param("ss", $new_password, $username);
    
    if ($stmt->execute() && $stmt->affected_rows > 0) {
        echo "Updated password for $username to: $new_password";
    } else {
        echo "User not found or update failed";
    }
    $stmt->close();
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>⚠️ Password Reset Tool</title>
    <style>
        body { font-family: Arial; padding: 20px; background: #ffebee; }
        .warning { 
            background: #ffcdd2; 
            border: 3px solid #f44336; 
            padding: 15px; 
            margin: 20px 0;
            border-radius: 5px;
        }
        .form-box { 
            background: white; 
            padding: 20px; 
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="warning">
        <h2>⚠️ SECURITY ALERT ⚠️</h2>
        <p><strong>NEVER store passwords in plain text in a real application!</strong></p>
        <p>This is for EDUCATIONAL/TESTING purposes ONLY in a LOCAL environment.</p>
        <p>In production, always use proper password hashing with bcrypt/Argon2.</p>
    </div>
    
    <div class="form-box">
        <h3>Reset All Test Users</h3>
        <p>This will update common test usernames to known plain text passwords:</p>
        <form method="POST">
            <input type="hidden" name="reset_all" value="1">
            <button type="submit" style="background: #f44336; color: white; padding: 10px 20px; border: none; border-radius: 4px;">
                ⚠️ Reset All Test Passwords to Plain Text
            </button>
        </form>
    </div>
    
    <div class="form-box">
        <h3>Reset Specific User</h3>
        <form method="POST">
            <input type="hidden" name="reset_specific" value="1">
            <input type="text" name="username" placeholder="Username" required style="padding: 8px; margin: 5px 0; width: 200px;"><br>
            <input type="text" name="new_password" placeholder="New Password (plain text)" required style="padding: 8px; margin: 5px 0; width: 200px;"><br>
            <button type="submit" style="background: #ff9800; color: white; padding: 8px 15px; border: none; border-radius: 4px;">
                Update This User
            </button>
        </form>
    </div>
    
    <div class="form-box">
        <h3>View Current Users</h3>
        <?php
        $result = $conn->query("SELECT id, username, password, LENGTH(password) as length FROM users LIMIT 20");
        echo "<table border='1' cellpadding='8' cellspacing='0'>";
        echo "<tr><th>ID</th><th>Username</th><th>Password/Current Hash</th><th>Length</th></tr>";
        while ($row = $result->fetch_assoc()) {
            $is_hash = (strpos($row['password'], '$2y$') === 0 || strlen($row['password']) > 32);
            $password_display = $is_hash ? '[HASHED] ' . substr($row['password'], 0, 30) . '...' : $row['password'];
            echo "<tr>";
            echo "<td>{$row['id']}</td>";
            echo "<td>{$row['username']}</td>";
            echo "<td>{$password_display}</td>";
            echo "<td>{$row['length']}</td>";
            echo "</tr>";
        }
        echo "</table>";
        ?>
    </div>
</body>
</html>