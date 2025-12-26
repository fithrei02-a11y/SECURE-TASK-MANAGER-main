<?php
// ============================================================================
// SECURE USER PROFILE - OWASP COMPLIANT
// ============================================================================

// Include secure configuration
require_once 'includes/config.php';

// Require authentication
require_auth();

// Get user information
$user_id = $_SESSION['user_id'];
$username = $_SESSION['username'];
$is_admin = $_SESSION['is_admin'];

// Initialize variables
$error = '';
$success = '';
$user = [];
$form_data = [];
$tasks_count = 0;
$tasks_todo = 0;
$tasks_in_progress = 0;
$tasks_completed = 0;
$recent_tasks = [];

try {
    // Get user details using prepared statement
    $stmt = $conn->prepare("SELECT id, username, email, created_at FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();
    
    if (!$user) {
        throw new Exception("User not found");
    }
    
    // Get user statistics using prepared statements
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM tasks WHERE user_id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $tasks_count = $stmt->get_result()->fetch_assoc()['count'];
    $stmt->close();
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM tasks WHERE user_id = ? AND status = 'todo'");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $tasks_todo = $stmt->get_result()->fetch_assoc()['count'];
    $stmt->close();
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM tasks WHERE user_id = ? AND status = 'in progress'");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $tasks_in_progress = $stmt->get_result()->fetch_assoc()['count'];
    $stmt->close();
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM tasks WHERE user_id = ? AND status = 'completed'");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $tasks_completed = $stmt->get_result()->fetch_assoc()['count'];
    $stmt->close();
    
    // Get recent activity
    $stmt = $conn->prepare("SELECT id, title, description, status, created_at, updated_at FROM tasks WHERE user_id = ? ORDER BY updated_at DESC LIMIT 5");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $recent_tasks_result = $stmt->get_result();
    $recent_tasks = $recent_tasks_result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    
} catch (Exception $e) {
    log_system_event('ERROR', 'Failed to load profile data', [
        'user_id' => $user_id,
        'error' => $e->getMessage()
    ]);
    $error = "Unable to load profile data. Please try again.";
}

// Handle profile update
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        $error = "Security token invalid. Please refresh the page and try again.";
        log_security_event('CSRF attempt on profile update', [
            'user_id' => $user_id,
            'username' => $username,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
        ]);
    } else {
        // Sanitize and validate inputs
        $email = sanitize_input($_POST['email'] ?? '');
        $current_password = $_POST['current_password'] ?? '';
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        
        // Store for form re-population
        $form_data = compact('email');
        
        // Validate email
        $validated_email = validate_email($email);
        if (!$validated_email) {
            $error = "Please enter a valid email address.";
        } elseif (empty($email)) {
            $error = "Email is required!";
        } else {
            try {
                // Check if email already exists (excluding current user)
                $stmt = $conn->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
                $stmt->bind_param("si", $email, $user_id);
                $stmt->execute();
                $check_result = $stmt->get_result();
                
                if ($check_result->num_rows > 0) {
                    $error = "Email already registered by another user!";
                    log_security_event('Email change attempt with existing email', [
                        'user_id' => $user_id,
                        'attempted_email' => $email
                    ]);
                } else {
                    $update_success = false;
                    $password_changed = false;
                    
                    // Handle password change if provided
                    if (!empty($new_password)) {
                        if ($new_password !== $confirm_password) {
                            $error = "New passwords do not match!";
                        } else {
                            // Validate new password against OWASP standards
                            $password_validation = validate_password($new_password);
                            if ($password_validation !== true) {
                                $error = $password_validation;
                            } elseif (empty($current_password)) {
                                $error = "Current password is required to change password.";
                            } else {
                                // Verify current password
                                $stmt = $conn->prepare("SELECT password FROM users WHERE id = ?");
                                $stmt->bind_param("i", $user_id);
                                $stmt->execute();
                                $result = $stmt->get_result();
                                $db_user = $result->fetch_assoc();
                                $stmt->close();
                                
                                if ($db_user && verify_password($current_password, $db_user['password'])) {
                                    // Update password with bcrypt hashing
                                    $hashed_password = hash_password($new_password);
                                    $stmt = $conn->prepare("UPDATE users SET password = ?, email = ? WHERE id = ?");
                                    $stmt->bind_param("ssi", $hashed_password, $email, $user_id);
                                    
                                    if ($stmt->execute()) {
                                        $update_success = true;
                                        $password_changed = true;
                                        $success = "Profile and password updated successfully!";
                                        
                                        // Log password change
                                        log_security_event('Password changed', [
                                            'user_id' => $user_id,
                                            'username' => $username,
                                            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
                                        ]);
                                    }
                                    $stmt->close();
                                } else {
                                    $error = "Current password is incorrect.";
                                    log_security_event('Failed password change - incorrect current password', [
                                        'user_id' => $user_id,
                                        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
                                    ]);
                                }
                            }
                        }
                    } else {
                        // Only update email
                        $stmt = $conn->prepare("UPDATE users SET email = ? WHERE id = ?");
                        $stmt->bind_param("si", $email, $user_id);
                        
                        if ($stmt->execute()) {
                            $update_success = true;
                            $success = "Profile updated successfully!";
                        }
                        $stmt->close();
                    }
                    
                    if ($update_success) {
                        // Update session email if changed
                        if ($email !== $_SESSION['email']) {
                            $_SESSION['email'] = $email;
                            log_security_event('Email updated', [
                                'user_id' => $user_id,
                                'username' => $username,
                                'old_email' => $user['email'],
                                'new_email' => $email
                            ]);
                        }
                        
                        // Update user data
                        $user['email'] = $email;
                        
                        // Log system event
                        log_system_event('INFO', 'Profile updated' . ($password_changed ? ' with password change' : ''), [
                            'user_id' => $user_id,
                            'username' => $username
                        ]);
                        
                        // Clear password fields
                        $form_data['email'] = $email;
                    } else if (empty($error)) {
                        $error = "Failed to update profile. Please try again.";
                    }
                }
                
            } catch (Exception $e) {
                $error = "Database error. Please try again.";
                log_system_event('ERROR', 'Profile update failed', [
                    'user_id' => $user_id,
                    'error' => $e->getMessage()
                ]);
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
    <title>My Profile - Secure Task Manager</title>
    
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
            min-height: 100vh;
        }
        
        .header { 
            background: rgba(0, 0, 0, 0.85); 
            color: white; 
            padding: 20px; 
            backdrop-filter: blur(10px);
            border-bottom: 3px solid rgba(255, 255, 255, 0.1);
        }
        
        .header-content { 
            max-width: 1200px; 
            margin: 0 auto; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
        }
        
        .container { 
            max-width: 1200px; 
            margin: 30px auto; 
            padding: 0 20px; 
        }
        
        .card { 
            background: rgba(255, 255, 255, 0.95); 
            padding: 40px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2); 
            margin-bottom: 20px; 
            backdrop-filter: blur(10px);
        }
        
        .profile-header { 
            text-align: center; 
            margin-bottom: 40px; 
        }
        
        .avatar { 
            width: 140px; 
            height: 140px; 
            border-radius: 50%; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            font-size: 60px; 
            margin: 0 auto 25px; 
            font-weight: bold;
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
        }
        
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 40px; 
        }
        
        .stat-card { 
            background: rgba(255, 255, 255, 0.9); 
            padding: 25px; 
            border-radius: 15px; 
            text-align: center; 
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
            cursor: pointer;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card.total { 
            border-top: 5px solid #667eea; 
        }
        
        .stat-card.todo { 
            border-top: 5px solid #ff9800; 
        }
        
        .stat-card.in-progress { 
            border-top: 5px solid #2196F3; 
        }
        
        .stat-card.completed { 
            border-top: 5px solid #4CAF50; 
        }
        
        .stat-number { 
            font-size: 36px; 
            font-weight: bold; 
            margin: 15px 0; 
        }
        
        .stat-card.total .stat-number { color: #667eea; }
        .stat-card.todo .stat-number { color: #ff9800; }
        .stat-card.in-progress .stat-number { color: #2196F3; }
        .stat-card.completed .stat-number { color: #4CAF50; }
        
        .btn { 
            display: inline-block; 
            padding: 14px 28px; 
            color: white; 
            text-decoration: none; 
            border-radius: 8px; 
            font-size: 16px; 
            font-weight: 600;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            text-align: center;
        }
        
        .btn:hover { 
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }
        
        .btn-primary { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
        }
        
        .btn-primary:hover { 
            background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
        }
        
        .btn-success { 
            background: linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%); 
        }
        
        .btn-success:hover { 
            background: linear-gradient(135deg, #2E7D32 0%, #4CAF50 100%);
        }
        
        .btn-secondary { 
            background: linear-gradient(135deg, #6c757d 0%, #495057 100%); 
        }
        
        .btn-secondary:hover { 
            background: linear-gradient(135deg, #495057 0%, #6c757d 100%);
        }
        
        .btn-danger { 
            background: linear-gradient(135deg, #f44336 0%, #d32f2f 100%); 
        }
        
        .btn-danger:hover { 
            background: linear-gradient(135deg, #d32f2f 0%, #f44336 100%);
        }
        
        .form-group { 
            margin-bottom: 25px; 
        }
        
        label { 
            display: block; 
            margin-bottom: 10px; 
            color: #333; 
            font-weight: 600;
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
            background: rgba(255, 255, 255, 0.9);
        }
        
        input:focus { 
            border-color: #667eea; 
            outline: none;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .form-row { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 25px; 
        }
        
        .error { 
            background: rgba(244, 67, 54, 0.1); 
            color: #c62828; 
            padding: 15px; 
            border-radius: 8px; 
            margin-bottom: 25px; 
            border-left: 4px solid #c62828;
        }
        
        .success { 
            background: rgba(46, 125, 50, 0.1); 
            color: #2e7d32; 
            padding: 15px; 
            border-radius: 8px; 
            margin-bottom: 25px; 
            border-left: 4px solid #2e7d32;
        }
        
        .info-box { 
            background: rgba(33, 150, 243, 0.1); 
            padding: 20px; 
            border-radius: 10px; 
            margin: 25px 0; 
            border-left: 4px solid #2196F3; 
        }
        
        .activity-list { 
            margin-top: 25px; 
        }
        
        .activity-item { 
            border-left: 4px solid #667eea; 
            padding: 20px; 
            margin: 15px 0; 
            background: rgba(248, 249, 250, 0.9); 
            border-radius: 0 10px 10px 0; 
            transition: all 0.3s ease;
        }
        
        .activity-item:hover {
            transform: translateX(5px);
            background: rgba(255, 255, 255, 0.95);
        }
        
        .badge { 
            display: inline-block; 
            padding: 6px 16px; 
            border-radius: 20px; 
            font-size: 14px; 
            font-weight: 600; 
            margin-left: 10px; 
        }
        
        .badge-admin { 
            background: linear-gradient(135deg, #ff9800 0%, #f57c00 100%); 
            color: white; 
        }
        
        .badge-user { 
            background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%); 
            color: white; 
        }
        
        .password-note { 
            font-size: 13px; 
            color: #666; 
            margin-top: 8px; 
        }
        
        .password-strength {
            height: 5px;
            border-radius: 3px;
            margin-top: 8px;
            background: #eee;
            overflow: hidden;
        }
        
        .strength-bar {
            height: 100%;
            width: 0%;
            transition: width 0.3s, background 0.3s;
        }
        
        .security-notice {
            background: rgba(255, 152, 0, 0.1);
            border-left: 4px solid #ff9800;
            padding: 20px;
            border-radius: 10px;
            margin: 25px 0;
        }
        
        .quick-actions-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        @media (max-width: 768px) {
            .stats-grid { 
                grid-template-columns: repeat(2, 1fr); 
            }
            
            .form-row { 
                grid-template-columns: 1fr; 
            }
            
            .header-content {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }
            
            .container {
                padding: 10px;
            }
            
            .card {
                padding: 25px;
            }
            
            .btn {
                width: 100%;
                margin: 5px 0;
            }
            
            .quick-actions-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div>
                <h1>👤 My Profile</h1>
                <p style="opacity: 0.8; font-size: 14px;">Secure Profile Management | OWASP-Compliant</p>
            </div>
            <div>
                <a href="index.php" class="btn btn-secondary">← Dashboard</a>
                <a href="logout.php?csrf=<?php echo urlencode($csrf_token); ?>" class="btn btn-danger" style="margin-left: 10px;">🚪 Logout</a>
            </div>
        </div>
    </div>
    
    <div class="container">
        <!-- Profile Header -->
        <div class="card">
            <div class="profile-header">
                <div class="avatar">
                    <?php echo htmlspecialchars(strtoupper(substr($username, 0, 1)), ENT_QUOTES, 'UTF-8'); ?>
                </div>
                <h2><?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></h2>
                <p>
                    <?php if ($is_admin): ?>
                        <span class="badge badge-admin">👑 Administrator</span>
                    <?php else: ?>
                        <span class="badge badge-user">👤 Regular User</span>
                    <?php endif; ?>
                </p>
                <p style="color: #666; margin-top: 5px;">Member since: <?php echo htmlspecialchars(date('F d, Y', strtotime($user['created_at'])), ENT_QUOTES, 'UTF-8'); ?></p>
            </div>
            
            <?php if ($error): ?>
                <div class="error">❌ <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="success">✅ <?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></div>
            <?php endif; ?>
        </div>
        
        <!-- Task Statistics -->
        <div class="stats-grid">
            <div class="stat-card total" onclick="window.location.href='my_tasks.php'">
                <h3>📋 Total Tasks</h3>
                <div class="stat-number"><?php echo (int)$tasks_count; ?></div>
                <p>All your tasks</p>
            </div>
            <div class="stat-card todo" onclick="window.location.href='my_tasks.php?status=todo'">
                <h3>📝 To Do</h3>
                <div class="stat-number"><?php echo (int)$tasks_todo; ?></div>
                <p>Pending tasks</p>
            </div>
            <div class="stat-card in-progress" onclick="window.location.href='my_tasks.php?status=in%20progress'">
                <h3>🔄 In Progress</h3>
                <div class="stat-number"><?php echo (int)$tasks_in_progress; ?></div>
                <p>Active tasks</p>
            </div>
            <div class="stat-card completed" onclick="window.location.href='my_tasks.php?status=completed'">
                <h3>✅ Completed</h3>
                <div class="stat-number"><?php echo (int)$tasks_completed; ?></div>
                <p>Finished tasks</p>
            </div>
        </div>
        
        <!-- Profile Information -->
        <div class="card">
            <h2>📋 Profile Information</h2>
            
            <div class="info-box">
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                    <div>
                        <p><strong>🔐 User ID:</strong><br><?php echo (int)$user_id; ?></p>
                    </div>
                    <div>
                        <p><strong>👤 Username:</strong><br><?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?> <em>(cannot be changed)</em></p>
                    </div>
                    <div>
                        <p><strong>🎯 Account Type:</strong><br><?php echo $is_admin ? 'Administrator 👑' : 'Regular User 👤'; ?></p>
                    </div>
                    <div>
                        <p><strong>📅 Registration Date:</strong><br><?php echo htmlspecialchars(date('F d, Y, H:i', strtotime($user['created_at'])), ENT_QUOTES, 'UTF-8'); ?></p>
                    </div>
                </div>
            </div>
            
            <div class="security-notice">
                <h3>🔒 Security Status</h3>
                <p>Your account is protected with:</p>
                <ul style="margin: 10px 0 10px 20px;">
                    <li>✅ Password hashing (bcrypt with 12 rounds)</li>
                    <li>✅ CSRF protection on all forms</li>
                    <li>✅ SQL injection prevention</li>
                    <li>✅ Session timeout (30 minutes)</li>
                    <li>✅ Login attempt limiting</li>
                    <li>🔜 Two-factor authentication (coming soon)</li>
                    <li>🔜 Email verification (coming soon)</li>
                </ul>
            </div>
            
            <h3 style="margin-top: 30px;">✏️ Edit Profile</h3>
            <form method="POST" action="" id="profileForm" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                
                <div class="form-group">
                    <label for="email" class="required">📧 Email Address</label>
                    <input type="email" 
                           id="email" 
                           name="email" 
                           value="<?php echo htmlspecialchars($form_data['email'] ?? $user['email'], ENT_QUOTES, 'UTF-8'); ?>" 
                           placeholder="your.email@example.com" 
                           required
                           autocomplete="email">
                </div>
                
                <h4 style="margin: 30px 0 15px 0; color: #333;">🔐 Change Password (Optional)</h4>
                <p style="color: #666; margin-bottom: 20px;">Leave password fields empty to keep current password.</p>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="current_password">Current Password</label>
                        <input type="password" 
                               id="current_password" 
                               name="current_password" 
                               placeholder="Enter current password"
                               autocomplete="current-password">
                        <div class="password-note">Required only if changing password</div>
                    </div>
                    <div class="form-group">
                        <label for="new_password">New Password</label>
                        <input type="password" 
                               id="new_password" 
                               name="new_password" 
                               placeholder="Enter new password (min 12 chars)"
                               autocomplete="new-password"
                               oninput="checkPasswordStrength(this.value)">
                        <div class="password-strength">
                            <div class="strength-bar" id="strengthBar"></div>
                        </div>
                        <div class="password-note" id="passwordFeedback"></div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">Confirm New Password</label>
                    <input type="password" 
                           id="confirm_password" 
                           name="confirm_password" 
                           placeholder="Re-enter new password"
                           autocomplete="new-password"
                           oninput="checkPasswordMatch()">
                    <div class="password-note" id="confirmFeedback"></div>
                </div>
                
                <div style="display: flex; gap: 15px; margin-top: 30px; flex-wrap: wrap;">
                    <button type="submit" class="btn btn-success" id="submitBtn">
                        💾 Save Changes
                    </button>
                    <a href="index.php" class="btn btn-secondary">← Back to Dashboard</a>
                    <a href="my_tasks.php" class="btn btn-primary">📋 View My Tasks</a>
                </div>
            </form>
        </div>
        
        <!-- Recent Activity -->
        <div class="card">
            <h2>📈 Recent Activity</h2>
            <p>Your latest task updates and activities</p>
            
            <div class="activity-list">
                <?php if (empty($recent_tasks)): ?>
                    <div style="text-align: center; padding: 40px; color: #666;">
                        <h3>No activity yet! 📭</h3>
                        <p>You haven't created or updated any tasks recently.</p>
                        <a href="add_task.php" class="btn btn-primary" style="margin-top: 15px;">➕ Create Your First Task</a>
                    </div>
                <?php else: ?>
                    <?php foreach($recent_tasks as $task): 
                        $status_class = str_replace(' ', '-', $task['status']);
                        $status_colors = [
                            'todo' => ['color' => '#ff9800', 'icon' => '📝'],
                            'in-progress' => ['color' => '#2196F3', 'icon' => '🔄'],
                            'completed' => ['color' => '#4CAF50', 'icon' => '✅']
                        ];
                    ?>
                    <div class="activity-item">
                        <div style="display: flex; justify-content: space-between; align-items: start;">
                            <div>
                                <h4><?php echo htmlspecialchars($task['title'], ENT_QUOTES, 'UTF-8'); ?></h4>
                                <?php if (!empty($task['description'])): ?>
                                    <p style="color: #666; margin: 8px 0;"><?php echo htmlspecialchars(substr($task['description'], 0, 100), ENT_QUOTES, 'UTF-8'); ?><?php echo strlen($task['description']) > 100 ? '...' : ''; ?></p>
                                <?php endif; ?>
                                <small style="color: #888;">
                                    📅 Updated: <?php echo htmlspecialchars(date('M d, Y H:i', strtotime($task['updated_at'])), ENT_QUOTES, 'UTF-8'); ?>
                                    | 🕐 Created: <?php echo htmlspecialchars(date('M d, Y', strtotime($task['created_at'])), ENT_QUOTES, 'UTF-8'); ?>
                                </small>
                            </div>
                            <div>
                                <span style="background: <?php echo $status_colors[$status_class]['color']; ?>; color: white; padding: 6px 12px; border-radius: 15px; font-size: 12px; font-weight: 600;">
                                    <?php echo $status_colors[$status_class]['icon']; ?> 
                                    <?php echo htmlspecialchars(ucwords(str_replace('-', ' ', $status_class)), ENT_QUOTES, 'UTF-8'); ?>
                                </span>
                            </div>
                        </div>
                        <div style="margin-top: 15px;">
                            <a href="edit_task.php?id=<?php echo (int)$task['id']; ?>&csrf=<?php echo urlencode($csrf_token); ?>" 
                               class="btn" 
                               style="padding: 8px 16px; font-size: 14px; background: #e0e0e0; color: #333;">✏️ Edit</a>
                            <a href="my_tasks.php" class="btn" style="padding: 8px 16px; font-size: 14px; background: #667eea; color: white;">📋 View All</a>
                        </div>
                    </div>
                    <?php endforeach; ?>
                    
                    <div style="text-align: center; margin-top: 25px;">
                        <a href="my_tasks.php" class="btn btn-primary">View All Activities</a>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        
        <!-- Quick Actions -->
        <div class="card">
            <h2>⚡ Quick Actions</h2>
            <div class="quick-actions-grid">
                <a href="add_task.php" class="btn btn-primary">➕ Add New Task</a>
                <a href="my_tasks.php" class="btn btn-primary">📋 View My Tasks</a>
                <a href="index.php" class="btn btn-secondary">← Back to Dashboard</a>
                <?php if ($is_admin): ?>
                    <a href="admin/dashboard.php" class="btn btn-success">👑 Admin Panel</a>
                    <a href="admin/audit_log.php" class="btn btn-success">📊 Audit Log</a>
                <?php endif; ?>
            </div>
            
            <div class="security-notice" style="margin-top: 30px;">
                <h3>🔐 Account Security Features</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-top: 15px;">
                    <div style="padding: 15px; background: rgba(255, 255, 255, 0.8); border-radius: 8px;">
                        <h4>✅ Implemented</h4>
                        <ul style="margin: 10px 0 0 20px; font-size: 14px;">
                            <li>Password Hashing (bcrypt)</li>
                            <li>CSRF Protection</li>
                            <li>SQL Injection Prevention</li>
                            <li>Session Management</li>
                            <li>Input Validation</li>
                        </ul>
                    </div>
                    <div style="padding: 15px; background: rgba(255, 255, 255, 0.8); border-radius: 8px;">
                        <h4>🔜 Coming Soon</h4>
                        <ul style="margin: 10px 0 0 20px; font-size: 14px;">
                            <li>Two-Factor Authentication</li>
                            <li>Email Verification</li>
                            <li>Password Expiration</li>
                            <li>Security Questions</li>
                            <li>Account Recovery</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div style="text-align: center; margin: 30px; color: rgba(255, 255, 255, 0.9); padding: 20px;">
        <p>👤 <strong>Secure User Profile</strong> - OWASP-Compliant Task Management System</p>
        <p><small>User ID: <?php echo (int)$user_id; ?> | Account created: <?php echo htmlspecialchars(date('F d, Y', strtotime($user['created_at'])), ENT_QUOTES, 'UTF-8'); ?></small></p>
    </div>

    <script>
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
            else messages.push('Minimum 12 characters');
            
            // Character variety
            if (/[a-z]/.test(password)) score++;
            if (/[A-Z]/.test(password)) score++;
            if (/[0-9]/.test(password)) score++;
            if (/[^A-Za-z0-9]/.test(password)) score++;
            
            // Deductions
            if (/(.)\1{2,}/.test(password)) score -= 1; // Repeated chars
            if (password.length < 12) score -= 1;
            
            // Common password check
            const common = ['password', '123456', 'qwerty', 'admin', 'welcome'];
            if (common.some(cmd => password.toLowerCase().includes(cmd))) {
                score = 0;
                messages.push('Avoid common passwords');
            }
            
            // Set strength display
            if (score <= 2) {
                strengthBar.className = 'strength-bar';
                strengthBar.style.background = '#f44336';
                strengthBar.style.width = '25%';
                feedback.style.color = '#f44336';
                feedback.textContent = 'Weak password' + (messages.length ? ': ' + messages.join(', ') : '');
            } else if (score <= 4) {
                strengthBar.className = 'strength-bar';
                strengthBar.style.background = '#ff9800';
                strengthBar.style.width = '50%';
                feedback.style.color = '#ff9800';
                feedback.textContent = 'Medium password';
            } else if (score <= 6) {
                strengthBar.className = 'strength-bar';
                strengthBar.style.background = '#4CAF50';
                strengthBar.style.width = '75%';
                feedback.style.color = '#4CAF50';
                feedback.textContent = 'Good password';
            } else {
                strengthBar.className = 'strength-bar';
                strengthBar.style.background = '#2E7D32';
                strengthBar.style.width = '100%';
                feedback.style.color = '#2E7D32';
                feedback.textContent = 'Strong password ✓';
            }
        }
        
        // Check password match
        function checkPasswordMatch() {
            const password = document.getElementById('new_password').value;
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
        
        // Form validation
        document.getElementById('profileForm').addEventListener('submit', function(e) {
            const newPassword = document.getElementById('new_password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            const currentPassword = document.getElementById('current_password').value;
            const submitBtn = document.getElementById('submitBtn');
            
            // Check password match
            if (newPassword && newPassword !== confirmPassword) {
                e.preventDefault();
                alert('New passwords do not match!');
                document.getElementById('confirm_password').focus();
                return;
            }
            
            // Check password strength if changing password
            if (newPassword) {
                if (newPassword.length < 12) {
                    e.preventDefault();
                    alert('New password must be at least 12 characters long!');
                    document.getElementById('new_password').focus();
                    return;
                }
                
                if (!currentPassword) {
                    e.preventDefault();
                    alert('Current password is required to change password.');
                    document.getElementById('current_password').focus();
                    return;
                }
            }
            
            // Disable button to prevent double submission
            submitBtn.disabled = true;
            submitBtn.innerHTML = '🔄 Saving Changes...';
            
            // Add form data attribute for beforeunload warning
            this.setAttribute('data-unsaved', 'true');
        });
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Secure profile page loaded.');
            
            // Auto-focus email field
            document.getElementById('email')?.focus();
            
            // Warn before leaving with unsaved changes
            window.addEventListener('beforeunload', function (e) {
                const form = document.getElementById('profileForm');
                if (form && form.hasAttribute('data-unsaved')) {
                    e.preventDefault();
                    e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
                }
            });
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 's') {
                e.preventDefault();
                document.getElementById('submitBtn')?.click();
            }
            if (e.key === 'Escape') {
                window.location.href = 'index.php';
            }
        });
    </script>
</body>
</html>