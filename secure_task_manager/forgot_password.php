<?php
// Use your existing config file
require_once 'includes/config.php';

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        $error = "Security token invalid. Please try again.";
        log_security_event('CSRF attempt in forgot_password', [
            'email' => $email,
            'ip' => $_SERVER['REMOTE_ADDR']
        ]);
    } elseif (!validate_email($email)) {
        $error = "Please enter a valid email address.";
    } else {
        try {
            // Check if user exists
            $stmt = $conn->prepare("SELECT id, username FROM users WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            $user = $result->fetch_assoc();
            
            if ($user) {
                // Generate secure reset token
                $token = bin2hex(random_bytes(32));
                $expires = date('Y-m-d H:i:s', strtotime('+1 hour'));
                
                // Store token in database
                $stmt = $conn->prepare("UPDATE users SET reset_token = ?, token_expires = ? WHERE id = ?");
                $stmt->bind_param("ssi", $token, $expires, $user['id']);
                
                if ($stmt->execute()) {
                    // Create reset link
                    $reset_link = "http://localhost/secure-task-manager-py-main/secure_task_manager/reset_password.php?token=" . urlencode($token);
                    
                    // In production, you would email this link
                    // For demo purposes, show it on screen
                    $success = "Password reset link generated!<br><br>";
                    $success .= "For demo: <a href='$reset_link'>Click here to reset password</a><br><br>";
                    $success .= "In production, this link would be sent to your email.";
                    
                    // Log the reset request
                    log_system_event('INFO', 'Password reset requested', [
                        'user_id' => $user['id'],
                        'username' => $user['username'],
                        'email' => $email
                    ]);
                } else {
                    $error = "Failed to generate reset token. Please try again.";
                }
            } else {
                // Don't reveal if email exists or not (security best practice)
                $success = "If your email exists in our system, you will receive a reset link shortly.";
                
                // Still log the attempt
                log_system_event('INFO', 'Password reset attempt for non-existent email', [
                    'email' => $email
                ]);
            }
            
            $stmt->close();
        } catch (Exception $e) {
            $error = "An error occurred. Please try again later.";
            log_system_event('ERROR', 'Password reset error', [
                'error' => $e->getMessage(),
                'email' => $email
            ]);
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password - Secure Task Manager</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .auth-container {
            max-width: 400px;
            margin: 50px auto;
            padding: 20px;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .auth-form h2 {
            text-align: center;
            margin-bottom: 20px;
            color: #333;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #555;
        }
        
        .form-group input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        
        .btn {
            display: block;
            width: 100%;
            padding: 10px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        
        .btn:hover {
            background: #0056b3;
        }
        
        .alert {
            padding: 10px;
            margin-bottom: 15px;
            border-radius: 4px;
        }
        
        .alert-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .text-center {
            text-align: center;
        }
        
        .mt-3 {
            margin-top: 15px;
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <div class="auth-form">
            <h2>Forgot Password</h2>
            
            <?php if ($error): ?>
                <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="alert alert-success"><?php echo $success; ?></div>
            <?php endif; ?>
            
            <form method="POST" action="">
                <!-- CSRF Protection -->
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" required 
                           placeholder="Enter your registered email"
                           value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>">
                </div>
                
                <button type="submit" class="btn btn-primary">Send Reset Link</button>
                <p class="text-center mt-3">
                    <a href="login.php">Back to Login</a>
                </p>
            </form>
        </div>
    </div>
</body>
</html>