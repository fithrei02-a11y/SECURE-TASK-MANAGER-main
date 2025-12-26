<?php
session_start();
require_once __DIR__ . '/../includes/config.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if (empty($username) || empty($password)) {
        $error = "Please enter username and password";
    } else {
        $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            
            // Compare passwords directly (plain text comparison)
            if ($password === $user['password']) {
                // Login successful
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['last_activity'] = time();
                
                header('Location: dashboard.php');
                exit;
            } else {
                $error = "Invalid password. Stored password is: '" . htmlspecialchars($user['password']) . "'";
            }
        } else {
            $error = "User not found";
        }
        $stmt->close();
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>⚠️ Plain Text Login (TESTING)</title>
    <style>
        body { font-family: Arial; padding: 20px; }
        .warning { background: #ffebee; border: 2px solid #f44336; padding: 15px; margin: 20px 0; }
        input { padding: 8px; margin: 5px 0; width: 300px; }
        button { padding: 10px 20px; background: #2196F3; color: white; border: none; }
    </style>
</head>
<body>
    <div class="warning">
        <h3>⚠️ WARNING: This compares passwords in plain text!</h3>
        <p>For testing purposes only. Never use in production.</p>
    </div>
    
    <h2>Plain Text Login (Testing)</h2>
    
    <?php if ($error): ?>
        <div style="color: red; padding: 10px; background: #ffebee;"><?php echo $error; ?></div>
    <?php endif; ?>
    
    <form method="POST">
        <div>
            <label>Username:</label><br>
            <input type="text" name="username" required>
        </div>
        
        <div>
            <label>Password (compared in plain text):</label><br>
            <input type="text" name="password" required>
        </div>
        
        <br>
        <button type="submit">Login (Plain Text Check)</button>
    </form>
    
    <p><a href="register_plain.php">Register New User (Plain Text)</a></p>
    <p><a href="view_users.php">View All Users (See Plain Passwords)</a></p>
</body>
</html>