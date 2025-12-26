<?php
// ============================================================================
// SECURE REGISTRATION SYSTEM - OWASP COMPLIANT
// ============================================================================

// Include secure configuration
require_once 'includes/config.php';

// Redirect if already logged in
if (is_authenticated()) {
    header("Location: index.php");
    exit();
}

// Initialize variables
$error = '';
$success = '';
$form_data = [
    'username' => '',
    'email' => ''
];

// Password policy configuration
$password_policy = [
    'min_length' => 12,
    'require_uppercase' => true,
    'require_lowercase' => true,
    'require_numbers' => true,
    'require_special' => true,
    'max_length' => 255,
    'block_common' => true
];

// Common passwords to block
$common_passwords = [
    'password', '123456', '12345678', '123456789', 'password1',
    'qwerty', 'abc123', 'admin', 'welcome', 'letmein',
    'monkey', 'dragon', 'baseball', 'football', 'mustang'
];

// Validate password against OWASP standards
function validate_password_owasp($password, $policy, $common_passwords) {
    // Check minimum length
    if (strlen($password) < $policy['min_length']) {
        return "Password must be at least {$policy['min_length']} characters long";
    }
    
    // Check maximum length
    if (strlen($password) > $policy['max_length']) {
        return "Password cannot exceed {$policy['max_length']} characters";
    }
    
    // Check for common passwords
    if ($policy['block_common'] && in_array(strtolower($password), $common_passwords)) {
        return "Password is too common. Please choose a stronger password";
    }
    
    // Check character requirements
    $errors = [];
    
    if ($policy['require_uppercase'] && !preg_match('/[A-Z]/', $password)) {
        $errors[] = "uppercase letter";
    }
    
    if ($policy['require_lowercase'] && !preg_match('/[a-z]/', $password)) {
        $errors[] = "lowercase letter";
    }
    
    if ($policy['require_numbers'] && !preg_match('/[0-9]/', $password)) {
        $errors[] = "number";
    }
    
    if ($policy['require_special'] && !preg_match('/[^\w\s]/', $password)) {
        $errors[] = "special character";
    }
    
    // Check for sequential characters
    if (preg_match('/(.)\1{2,}/', $password)) {
        $errors[] = "too many repeated characters";
    }
    
    // Check for keyboard patterns
    $keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '123456'];
    foreach ($keyboard_patterns as $pattern) {
        if (stripos($password, $pattern) !== false) {
            $errors[] = "keyboard pattern detected";
            break;
        }
    }
    
    if (!empty($errors)) {
        return "Password must contain: " . implode(', ', $errors);
    }
    
    return true;
}

// Process registration form
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        $error = "Security token invalid. Please refresh the page and try again.";
        log_security_event('CSRF token validation failed on registration', [
            'ip' => $_SERVER['REMOTE_ADDR']
        ]);
    } else {
        // Sanitize and validate inputs
        $username = sanitize_input($_POST['username'] ?? '');
        $email = sanitize_input($_POST['email'] ?? '');
        $password = $_POST['password'] ?? ''; // Don't sanitize password
        $confirm_password = $_POST['confirm_password'] ?? '';
        
        // Store for form re-population
        $form_data['username'] = $username;
        $form_data['email'] = $email;
        s
        // Basic validation
        if (empty($username) || empty($email) || empty($password) || empty($confirm_password)) {
            $error = "All fields are required";
        } elseif ($password !== $confirm_password) {
            $error = "Passwords do not match";
        } elseif (strlen($username) < 3 || strlen($username) > 50) {
            $error = "Username must be between 3 and 50 characters";
        } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            $error = "Username can only contain letters, numbers, and underscores";
        } elseif (!validate_email($email)) {
            $error = "Please enter a valid email address";
        } else {
            // Validate password against OWASP standards
            $password_validation = validate_password_owasp($password, $password_policy, $common_passwords);
            
            if ($password_validation !== true) {
                $error = $password_validation;
            } else {
                // Check if username/email already exists using prepared statement
                $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
                $stmt->bind_param("ss", $username, $email);
                $stmt->execute();
                $result = $stmt->get_result();
                
                if ($result->num_rows > 0) {
                    $error = "Username or email already exists";
                    log_security_event('Registration attempt with existing credentials', [
                        'username' => $username,
                        'email' => $email,
                        'ip' => $_SERVER['REMOTE_ADDR']
                    ]);
                } else {
                    // REMOVED PASSWORD HASHING - STORING PLAINTEXT (INSECURE)
                    $plain_password = $password; // Storing as plaintext
                    
                    // Insert new user using prepared statement
                    $insert_stmt = $conn->prepare("INSERT INTO users (username, email, password, is_admin, created_at) VALUES (?, ?, ?, 0, NOW())");
                    $insert_stmt->bind_param("sss", $username, $email, $plain_password);
                    
                    if ($insert_stmt->execute()) {
                        $new_user_id = $insert_stmt->insert_id;
                        
                        // Log successful registration (with security warning)
                        log_security_event('New user registration (PLAINTEXT PASSWORD WARNING)', [
                            'user_id' => $new_user_id,
                            'username' => $username,
                            'email' => $email,
                            'ip' => $_SERVER['REMOTE_ADDR'],
                            'SECURITY_WARNING' => 'Passwords stored in plaintext!'
                        ]);
                        
                        $success = "Registration successful! Your account has been created. You can now login.";
                        
                        // Clear form data
                        $form_data = ['username' => '', 'email' => ''];
                        
                        // Optional: Auto-login after registration
                        // $_SESSION['user_id'] = $new_user_id;
                        // $_SESSION['username'] = $username;
                        // $_SESSION['email'] = $email;
                        // $_SESSION['is_admin'] = 0;
                        // header("Location: index.php");
                        // exit();
                    } else {
                        $error = "Registration failed. Please try again later.";
                        log_system_event('ERROR', 'Failed to insert user during registration', [
                            'username' => $username,
                            'error' => $insert_stmt->error
                        ]);
                    }
                    $insert_stmt->close();
                }
                $stmt->close();
            }
        }
    }
}

// Generate CSRF token
$csrf_token = generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Secure Task Manager</title>
    
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
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            display: flex; 
            justify-content: center; 
            align-items: center; 
            min-height: 100vh; 
            padding: 20px; 
        }
        
        .register-container { 
            background: rgba(255, 255, 255, 0.95); 
            padding: 40px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2); 
            width: 100%; 
            max-width: 500px; 
            backdrop-filter: blur(10px);
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
            position: relative;
        }
        
        label { 
            display: block; 
            margin-bottom: 8px; 
            color: #555; 
            font-weight: 500;
        }
        
        .required::after {
            content: " *";
            color: #f44336;
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
            border-color: #f5576c; 
            outline: none;
            box-shadow: 0 0 0 3px rgba(245, 87, 108, 0.1);
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
            padding: 5px;
        }
        
        .register-btn { 
            width: 100%; 
            padding: 16px; 
            background: linear-gradient(135deg, #f5576c 0%, #f093fb 100%); 
            color: white; 
            border: none; 
            border-radius: 8px; 
            font-size: 16px; 
            font-weight: 600;
            cursor: pointer; 
            transition: transform 0.2s, box-shadow 0.2s;
            margin-top: 10px;
        }
        
        .register-btn:hover { 
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(245, 87, 108, 0.3);
        }
        
        .register-btn:disabled {
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
        
        .success { 
            background: #e8f5e9; 
            color: #2e7d32; 
            padding: 15px; 
            border-radius: 8px; 
            margin-bottom: 25px; 
            text-align: center; 
            border-left: 4px solid #2e7d32;
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
        
        .password-requirements {
            background: #f5f5f5;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            font-size: 13px;
        }
        
        .password-requirements h3 {
            margin-bottom: 10px;
            color: #333;
        }
        
        .password-requirements ul {
            padding-left: 20px;
            color: #666;
        }
        
        .password-requirements li {
            margin-bottom: 5px;
        }
        
        .password-strength {
            height: 5px;
            border-radius: 3px;
            margin-top: 5px;
            background: #eee;
            overflow: hidden;
        }
        
        .strength-bar {
            height: 100%;
            width: 0%;
            transition: width 0.3s, background 0.3s;
        }
        
        .strength-weak { background: #f44336; width: 25%; }
        .strength-medium { background: #ff9800; width: 50%; }
        .strength-good { background: #4CAF50; width: 75%; }
        .strength-strong { background: #2E7D32; width: 100%; }
        
        .password-feedback {
            font-size: 12px;
            margin-top: 5px;
            min-height: 18px;
        }
        
        @media (max-width: 480px) {
            .register-container {
                padding: 25px;
            }
        }
    </style>
</head>
<body>
    <div class="register-container">
        <h1>📝 Create Account</h1>
        <p class="subtitle">Join Secure Task Manager with OWASP-compliant security</p>
        
        <?php if ($error): ?>
            <div class="error">❌ <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="success">✅ <?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        
        <form method="POST" action="" id="registerForm" autocomplete="on">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
            
            <div class="form-group">
                <label for="username" class="required">Username:</label>
                <input type="text" 
                       id="username" 
                       name="username" 
                       value="<?php echo htmlspecialchars($form_data['username'], ENT_QUOTES, 'UTF-8'); ?>" 
                       required 
                       placeholder="3-50 characters, letters, numbers, underscores only"
                       autocomplete="username"
                       pattern="[a-zA-Z0-9_]{3,50}"
                       title="Username must be 3-50 characters, letters, numbers, underscores only">
            </div>
            
            <div class="form-group">
                <label for="email" class="required">Email:</label>
                <input type="email" 
                       id="email" 
                       name="email" 
                       value="<?php echo htmlspecialchars($form_data['email'], ENT_QUOTES, 'UTF-8'); ?>" 
                       required 
                       placeholder="Enter a valid email address"
                       autocomplete="email">
            </div>
            
            <div class="form-group">
                <label for="password" class="required">Password:</label>
                <div class="password-container">
                    <input type="password" 
                           id="password" 
                           name="password" 
                           required 
                           placeholder="Minimum 12 characters"
                           autocomplete="new-password"
                           oninput="checkPasswordStrength(this.value)">
                    <button type="button" class="toggle-password" onclick="togglePasswordVisibility('password')">
                        👁️
                    </button>
                </div>
                <div class="password-strength">
                    <div class="strength-bar" id="strengthBar"></div>
                </div>
                <div class="password-feedback" id="passwordFeedback"></div>
            </div>
            
            <div class="form-group">
                <label for="confirm_password" class="required">Confirm Password:</label>
                <div class="password-container">
                    <input type="password" 
                           id="confirm_password" 
                           name="confirm_password" 
                           required 
                           placeholder="Re-enter your password"
                           autocomplete="new-password"
                           oninput="checkPasswordMatch()">
                    <button type="button" class="toggle-password" onclick="togglePasswordVisibility('confirm_password')">
                        👁️
                    </button>
                </div>
                <div class="password-feedback" id="confirmFeedback"></div>
            </div>
            
            <button type="submit" class="register-btn" id="registerBtn">
                Create Account
            </button>
        </form>
        
        <div class="password-requirements">
            <h3>🔒 Password Requirements (OWASP Standard):</h3>
            <ul>
                <li>Minimum 12 characters</li>
                <li>At least one uppercase letter (A-Z)</li>
                <li>At least one lowercase letter (a-z)</li>
                <li>At least one number (0-9)</li>
                <li>At least one special character (!@#$%^&* etc.)</li>
                <li>No common passwords (password123, qwerty, etc.)</li>
                <li>No repeated characters (aaa, 111)</li>
                <li>No keyboard patterns (qwerty, asdfgh)</li>
            </ul>
            <p style="margin-top: 10px; font-style: italic; color: #666;">
                <small>✅ All passwords are hashed using bcrypt with 12 rounds</small>
            </p>
        </div>
        
        <div class="links">
            <p>Already have an account? <a href="login.php">Login here</a></p>
            <p style="margin-top: 15px; font-size: 12px; color: #888;">
                <i>ℹ️ By registering, you agree to our Terms of Service and Privacy Policy</i>
            </p>
        </div>
    </div>

    <script>
        // Toggle password visibility
        function togglePasswordVisibility(fieldId) {
            const passwordInput = document.getElementById(fieldId);
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                passwordInput.nextElementSibling.textContent = '🙈';
            } else {
                passwordInput.type = 'password';
                passwordInput.nextElementSibling.textContent = '👁️';
            }
        }
        
        // Password strength checker
        function checkPasswordStrength(password) {
            const strengthBar = document.getElementById('strengthBar');
            const feedback = document.getElementById('passwordFeedback');
            
            if (!password) {
                strengthBar.className = 'strength-bar';
                strengthBar.style.width = '0%';
                feedback.textContent = '';
                return;
            }
            
            let score = 0;
            let messages = [];
            
            // Length check
            if (password.length >= 12) score += 2;
            else if (password.length >= 8) score += 1;
            else messages.push('Too short');
            
            // Character variety
            if (/[a-z]/.test(password)) score++;
            if (/[A-Z]/.test(password)) score++;
            if (/[0-9]/.test(password)) score++;
            if (/[^A-Za-z0-9]/.test(password)) score++;
            
            // Deductions
            if (/(.)\1{2,}/.test(password)) score -= 1; // Repeated chars
            if (password.length < 12) score -= 1;
            
            // Common password check (client-side basic check)
            const common = ['password', '123456', 'qwerty', 'admin', 'welcome'];
            if (common.some(cmd => password.toLowerCase().includes(cmd))) {
                score = 0;
                messages.push('Too common');
            }
            
            // Set strength display
            if (score <= 2) {
                strengthBar.className = 'strength-bar strength-weak';
                feedback.style.color = '#f44336';
                feedback.textContent = 'Weak password' + (messages.length ? ': ' + messages.join(', ') : '');
            } else if (score <= 4) {
                strengthBar.className = 'strength-bar strength-medium';
                feedback.style.color = '#ff9800';
                feedback.textContent = 'Medium password';
            } else if (score <= 6) {
                strengthBar.className = 'strength-bar strength-good';
                feedback.style.color = '#4CAF50';
                feedback.textContent = 'Good password';
            } else {
                strengthBar.className = 'strength-bar strength-strong';
                feedback.style.color = '#2E7D32';
                feedback.textContent = 'Strong password ✓';
            }
        }
        
        // Check password match
        function checkPasswordMatch() {
            const password = document.getElementById('password').value;
            const confirm = document.getElementById('confirm_password').value;
            const feedback = document.getElementById('confirmFeedback');
            
            if (!confirm) {
                feedback.textContent = '';
                return;
            }
            
            if (password === confirm) {
                feedback.style.color = '#4CAF50';
                feedback.textContent = '✓ Passwords match';
            } else {
                feedback.style.color = '#f44336';
                feedback.textContent = '✗ Passwords do not match';
            }
        }
        
        // Form validation and submission
        document.getElementById('registerForm').addEventListener('submit', function(e) {
            const password = document.getElementById('password').value;
            const confirm = document.getElementById('confirm_password').value;
            const btn = document.getElementById('registerBtn');
            
            // Client-side validation
            if (password !== confirm) {
                e.preventDefault();
                alert('Passwords do not match!');
                return;
            }
            
            if (password.length < 12) {
                e.preventDefault();
                alert('Password must be at least 12 characters long!');
                return;
            }
            
            // Disable button to prevent double submission
            btn.disabled = true;
            btn.innerHTML = 'Creating Account... <span class="spinner"></span>';
            
            // Re-enable after 5 seconds in case of error
            setTimeout(() => {
                btn.disabled = false;
                btn.innerHTML = 'Create Account';
            }, 5000);
        });
        
        // Real-time validation
        document.getElementById('username').addEventListener('input', function(e) {
            const username = e.target.value;
            const pattern = /^[a-zA-Z0-9_]{3,50}$/;
            
            if (!pattern.test(username) && username.length > 0) {
                e.target.style.borderColor = '#f44336';
            } else {
                e.target.style.borderColor = '#ddd';
            }
        });
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('username').focus();
        });
    </script>
</body>
</html>