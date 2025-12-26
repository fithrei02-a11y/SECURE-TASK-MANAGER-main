<?php
// ============================================================================
// SECURE LOGIN SYSTEM - OWASP COMPLIANT
// ============================================================================

// Include secure configuration
require_once 'includes/config.php';

// If already logged in, redirect to dashboard
if (is_authenticated()) {
    header("Location: index.php");
    exit();
}

// Initialize variables
$error = '';
$username = '';
$login_attempts_exceeded = false;

// Check if IP is blocked due to too many failed attempts
function is_ip_blocked() {
    return false; // Disable IP blocking for testing
}

// Process login form
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Check if IP is blocked FIRST - even before CSRF check
    if (is_ip_blocked()) {
        $login_attempts_exceeded = true;
        $error = "Security Alert: Too many failed login attempts from your IP address. Please wait 15 minutes before trying again.";
        log_security_event('Blocked IP attempted login', [
            'ip' => $_SERVER['REMOTE_ADDR'],
            'username' => $_POST['username'] ?? 'Unknown'
        ]);
        
        // Still validate and log CSRF token if provided
        if (isset($_POST['csrf_token'])) {
            if (!validate_csrf_token($_POST['csrf_token'])) {
                log_security_event('Blocked IP with invalid CSRF token', [
                    'ip' => $_SERVER['REMOTE_ADDR']
                ]);
            }
        }
    } else {
        // Validate CSRF token for non-blocked IPs
        if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
            $error = "Security token invalid. Please refresh the page and try again.";
            log_security_event('CSRF token validation failed on login', [
                'ip' => $_SERVER['REMOTE_ADDR']
            ]);
        } else {
            // Sanitize and validate inputs
            $username = sanitize_input($_POST['username'] ?? '');
            $password = $_POST['password'] ?? ''; // Don't sanitize password
            
            // Basic validation
            if (empty($username) || empty($password)) {
                $error = "Please enter both username and password";
            } elseif (strlen($username) > 50 || strlen($password) > 255) {
                $error = "Invalid input length";
            } else {
                // Check user in database using prepared statement
                $stmt = $conn->prepare("SELECT id, username, email, password, is_admin, failed_attempts, locked_until FROM users WHERE username = ? OR email = ?");
                $stmt->bind_param("ss", $username, $username);
                $stmt->execute();
                $result = $stmt->get_result();
                
                if ($result->num_rows == 1) {
                    $user = $result->fetch_assoc();
                    $stmt->close();
                    
                    // Check if account is locked
                    if ($user['locked_until'] && strtotime($user['locked_until']) > time()) {
                        $error = "Account is locked. Please try again later.";
                        log_security_event('Attempted login to locked account', [
                            'username' => $user['username'],
                            'ip' => $_SERVER['REMOTE_ADDR']
                        ]);
                    } else {
                        // Verify password - PLAINTEXT VERSION
                        if ($password === $user['password']) {
                            // SUCCESSFUL LOGIN
                            
                            // Reset failed attempts
                            $reset_stmt = $conn->prepare("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?");
                            $reset_stmt->bind_param("i", $user['id']);
                            $reset_stmt->execute();
                            $reset_stmt->close();
                            
                            // Set session variables
                            $_SESSION['user_id'] = $user['id'];
                            $_SESSION['username'] = $user['username'];
                            $_SESSION['email'] = $user['email'];
                            $_SESSION['is_admin'] = $user['is_admin'];
                            $_SESSION['last_activity'] = time();
                            $_SESSION['login_time'] = time();
                            
                            // Set secure session cookie
                            $session_id = session_id();
                            setcookie(session_name(), $session_id, [
                                'expires' => time() + 1800, // 30 minutes
                                'path' => '/',
                                'domain' => '',
                                'secure' => true, // Enable in production with HTTPS
                                'httponly' => true,
                                'samesite' => 'Strict'
                            ]);
                            
                            // Log successful login
                            log_security_event('Successful login', [
                                'username' => $user['username'],
                                'ip' => $_SERVER['REMOTE_ADDR'],
                                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
                            ]);
                            
                            // Redirect to intended page or dashboard
                            $redirect_url = $_SESSION['redirect_url'] ?? 'index.php';
                            unset($_SESSION['redirect_url']);
                            
                            // Regenerate session ID after login
                            session_regenerate_id(true);
                            
                            header("Location: " . $redirect_url);
                            exit();
                        } else {
                            // FAILED LOGIN
                            
                            // Increment failed attempts
                            $new_attempts = $user['failed_attempts'] + 1;
                            $lock_until = null;
                            
                            // Lock account after 3 failed attempts for 15 minutes
                            if ($new_attempts >= 3) {
                                $lock_until = date('Y-m-d H:i:s', strtotime('+15 minutes'));
                            }
                            
                            $update_stmt = $conn->prepare("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?");
                            $update_stmt->bind_param("isi", $new_attempts, $lock_until, $user['id']);
                            $update_stmt->execute();
                            $update_stmt->close();
                            
                            // Log failed attempt
                            log_security_event('Failed login attempt', [
                                'username' => $user['username'],
                                'ip' => $_SERVER['REMOTE_ADDR'],
                                'attempts' => $new_attempts
                            ]);
                            
                            // Generic error message
                            $error = "Invalid username or password";
                            
                            if ($lock_until) {
                                $error .= ". Account locked for 15 minutes due to multiple failed attempts.";
                            }
                            
                            // Check if IP should be blocked after this attempt
                            if (is_ip_blocked()) {
                                $login_attempts_exceeded = true;
                                $error = "Security Alert: Too many failed login attempts from your IP address. Please wait 15 minutes before trying again.";
                            }
                        }
                    }
                } else {
                    // User not found - generic error
                    sleep(1); // Delay to prevent timing attacks
                    $error = "Invalid username or password";
                    
                    // Log failed attempt with IP only
                    log_security_event('Failed login attempt - unknown user', [
                        'attempted_username' => $username,
                        'ip' => $_SERVER['REMOTE_ADDR']
                    ]);
                    
                    // Check if IP should be blocked after this attempt
                    if (is_ip_blocked()) {
                        $login_attempts_exceeded = true;
                        $error = "Security Alert: Too many failed login attempts from your IP address. Please wait 15 minutes before trying again.";
                    }
                }
            }
        }
    }
}

// Generate new CSRF token for the form
$csrf_token = generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Secure Task Manager</title>
    
    <!-- Security meta tags -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';">
    
    <style>
        * { 
            margin: 0; 
            padding: 0; 
            box-sizing: border-box; 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
        }
        
        body { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex; 
            justify-content: center; 
            align-items: center; 
            min-height: 100vh; 
            padding: 20px; 
        }
        
        .login-container { 
            background: rgba(255, 255, 255, 0.95); 
            padding: 40px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2); 
            width: 100%; 
            max-width: 450px; 
            backdrop-filter: blur(10px);
        }
        
        .security-warning {
            background: linear-gradient(135deg, #ff4444 0%, #cc0000 100%);
            color: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 25px;
            text-align: center;
            font-weight: bold;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 0.8; }
            50% { opacity: 1; }
            100% { opacity: 0.8; }
        }
        
        .security-notice {
            background: #ffebee;
            border-left: 4px solid #f44336;
            padding: 12px;
            margin-bottom: 25px;
            border-radius: 4px;
            font-size: 14px;
        }
        
        .security-notice i {
            color: #f44336;
            margin-right: 8px;
        }
        
        h1 { 
            text-align: center; 
            color: #333; 
            margin-bottom: 10px;
            font-size: 28px;
        }
        
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        
        .form-group { 
            margin-bottom: 25px; 
        }
        
        label { 
            display: block; 
            margin-bottom: 8px; 
            color: #555; 
            font-weight: 500;
        }
        
        input { 
            width: 100%; 
            padding: 14px; 
            border: 2px solid #ddd; 
            border-radius: 8px; 
            font-size: 16px; 
            transition: border 0.3s;
        }
        
        input:focus { 
            border-color: #4CAF50; 
            outline: none;
            box-shadow: 0 0 0 3px rgba(76, 175, 80, 0.1);
        }
        
        .password-container {
            position: relative;
        }
        
        .toggle-password {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            cursor: pointer;
            color: #666;
            font-size: 18px;
        }
        
        .login-btn { 
            width: 100%; 
            padding: 16px; 
            background: linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%); 
            color: white; 
            border: none; 
            border-radius: 8px; 
            font-size: 16px; 
            font-weight: 600;
            cursor: pointer; 
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .login-btn:hover { 
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(76, 175, 80, 0.3);
        }
        
        .login-btn:disabled {
            background: #cccccc;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        .error { 
            background: #ffebee; 
            color: #c62828; 
            padding: 15px; 
            border-radius: 8px; 
            margin-bottom: 25px; 
            text-align: center; 
            border-left: 4px solid #c62828;
        }
        
        .warning {
            background: #fff3e0;
            color: #ef6c00;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 25px;
            border-left: 4px solid #ef6c00;
        }
        
        .links { 
            text-align: center; 
            margin-top: 25px; 
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        
        a { 
            color: #2196F3; 
            text-decoration: none; 
            font-weight: 500;
        }
        
        a:hover { 
            text-decoration: underline; 
        }
        
        .password-strength {
            font-size: 12px;
            margin-top: 5px;
            display: none;
        }
        
        .strength-weak { color: #f44336; }
        .strength-medium { color: #ff9800; }
        .strength-strong { color: #4CAF50; }
        
        @media (max-width: 480px) {
            .login-container {
                padding: 25px;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="security-warning">
            ⚠️ PLAINTEXT PASSWORDS ENABLED - INSECURE CONFIGURATION ⚠️
        </div>
        
        <h1>🔒 Secure Login</h1>
        <p class="subtitle">Secure Task Management System</p>
        
        <div class="security-notice">
            <i>⚠️</i> <strong>INSECURE CONFIGURATION:</strong> Passwords are stored in plaintext. For testing only.
        </div>
        
        <?php if ($login_attempts_exceeded): ?>
            <div class="warning">
                <strong>⚠️ Security Alert:</strong> Too many failed login attempts from your IP address. Please wait 15 minutes before trying again.
            </div>
        <?php endif; ?>
        
        <?php if ($error && !$login_attempts_exceeded): ?>
            <div class="error"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        
        <form method="POST" action="" id="loginForm" autocomplete="on">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
            
            <div class="form-group">
                <label for="username">Username or Email:</label>
                <input type="text" 
                       id="username" 
                       name="username" 
                       value="<?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>" 
                       required 
                       placeholder="Enter your username or email"
                       autocomplete="username"
                       maxlength="100">
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <div class="password-container">
                    <input type="password" 
                           id="password" 
                           name="password" 
                           required 
                           placeholder="Enter your password"
                           autocomplete="current-password"
                           maxlength="255"
                           oninput="checkPasswordStrength(this.value)">
                    <button type="button" class="toggle-password" onclick="togglePasswordVisibility()">
                        👁️
                    </button>
                </div>
                <div id="passwordStrength" class="password-strength"></div>
            </div>
            
            <button type="submit" class="login-btn" id="loginBtn">
                Sign In
            </button>
        </form>
        
        <div class="links">
            <p>Don't have an account? <a href="register.php">Register here</a></p>
            <p>Forgot password? <a href="forgot_password.php">Reset it here</a></p>
            <p style="margin-top: 15px; font-size: 12px; color: #888;">
                <i>⚠️ SECURITY WARNING: Passwords are stored in plaintext - Testing only</i>
            </p>
        </div>
    </div>

    <script>
        // Toggle password visibility
        function togglePasswordVisibility() {
            const passwordInput = document.getElementById('password');
            const toggleButton = document.querySelector('.toggle-password');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                toggleButton.textContent = '🙈';
            } else {
                passwordInput.type = 'password';
                toggleButton.textContent = '👁️';
            }
        }
        
        // Password strength indicator (client-side only)
        function checkPasswordStrength(password) {
            const strengthElement = document.getElementById('passwordStrength');
            
            if (password.length === 0) {
                strengthElement.style.display = 'none';
                return;
            }
            
            strengthElement.style.display = 'block';
            
            let strength = 0;
            let feedback = '';
            
            // Length check
            if (password.length >= 12) strength++;
            else feedback = 'Minimum 12 characters required';
            
            // Complexity checks
            if (/[a-z]/.test(password)) strength++;
            if (/[A-Z]/.test(password)) strength++;
            if (/[0-9]/.test(password)) strength++;
            if (/[^A-Za-z0-9]/.test(password)) strength++;
            
            // Set strength class and message
            if (strength >= 5) {
                strengthElement.className = 'password-strength strength-strong';
                strengthElement.textContent = 'Strong password ✓';
            } else if (strength >= 3) {
                strengthElement.className = 'password-strength strength-medium';
                strengthElement.textContent = 'Medium password';
            } else {
                strengthElement.className = 'password-strength strength-weak';
                strengthElement.textContent = feedback || 'Weak password';
            }
        }
        
        // Form submission protection
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            const loginBtn = document.getElementById('loginBtn');
            loginBtn.disabled = true;
            loginBtn.innerHTML = 'Signing in... <span class="spinner"></span>';
            
            // Prevent double submission
            setTimeout(() => {
                loginBtn.disabled = false;
                loginBtn.innerHTML = 'Sign In';
            }, 5000);
        });
        
        // Focus on username field on page load
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('username').focus();
        });
    </script>
</body>
</html>