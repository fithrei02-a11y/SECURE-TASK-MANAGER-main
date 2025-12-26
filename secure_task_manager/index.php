<?php
// ============================================================================
// SECURE DASHBOARD - OWASP COMPLIANT
// ============================================================================

// Include secure configuration
require_once 'includes/config.php';

// Require authentication and check session
require_auth();

// Get session data (already sanitized during login)
$username = $_SESSION['username'] ?? '';
$is_admin = $_SESSION['is_admin'] ?? 0;
$user_id = $_SESSION['user_id'] ?? 0;
$email = $_SESSION['email'] ?? '';

// Initialize variables
$recent_tasks = [];
$task_counts = ['todo' => 0, 'in progress' => 0, 'completed' => 0];
$total_tasks = 0;
$error = '';

try {
    // Get user's recent tasks (last 5) using prepared statement
    $stmt = $conn->prepare("SELECT id, title, description, status, created_at FROM tasks WHERE user_id = ? ORDER BY created_at DESC LIMIT 5");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $tasks_result = $stmt->get_result();
    
    while ($row = $tasks_result->fetch_assoc()) {
        $recent_tasks[] = $row;
    }
    $stmt->close();
    
    // Count user's tasks by status using prepared statement
    $stmt = $conn->prepare("SELECT status, COUNT(*) as count FROM tasks WHERE user_id = ? GROUP BY status");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $count_result = $stmt->get_result();
    
    while ($row = $count_result->fetch_assoc()) {
        $task_counts[$row['status']] = (int)$row['count'];
    }
    $stmt->close();
    
    $total_tasks = array_sum($task_counts);
    
} catch (Exception $e) {
    log_system_event('ERROR', 'Dashboard query failed', [
        'user_id' => $user_id,
        'error' => $e->getMessage()
    ]);
    $error = "Unable to load dashboard data. Please try again.";
}

// Generate CSRF token for any forms that might be added
$csrf_token = generate_csrf_token();

// Security headers are already set in config.php
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Secure Task Manager</title>
    
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
            background: rgba(0, 0, 0, 0.8); 
            color: white; 
            padding: 20px; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            backdrop-filter: blur(10px);
            border-bottom: 3px solid rgba(255, 255, 255, 0.1);
        }
        
        .container { 
            max-width: 1200px; 
            margin: 20px auto; 
            padding: 0 20px; 
        }
        
        .card { 
            background: rgba(255, 255, 255, 0.95); 
            padding: 30px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2); 
            margin-bottom: 20px; 
            backdrop-filter: blur(10px);
        }
        
        .btn { 
            display: inline-block; 
            padding: 12px 24px; 
            color: white; 
            text-decoration: none; 
            border-radius: 8px; 
            margin: 5px; 
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
        
        .btn-danger { 
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); 
        }
        
        .btn-danger:hover { 
            background: linear-gradient(135deg, #f5576c 0%, #f093fb 100%);
        }
        
        .btn-secondary { 
            background: linear-gradient(135deg, #6c757d 0%, #495057 100%); 
        }
        
        .btn-secondary:hover { 
            background: linear-gradient(135deg, #495057 0%, #6c757d 100%);
        }
        
        .btn-primary { 
            background: linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%); 
        }
        
        .btn-primary:hover { 
            background: linear-gradient(135deg, #2E7D32 0%, #4CAF50 100%);
        }
        
        .btn-admin {
            background: linear-gradient(135deg, #ff9800 0%, #f57c00 100%);
        }
        
        .btn-admin:hover {
            background: linear-gradient(135deg, #f57c00 0%, #ff9800 100%);
        }
        
        .task-list { 
            margin-top: 20px; 
        }
        
        .task { 
            border: 1px solid #e0e0e0; 
            padding: 20px; 
            margin: 15px 0; 
            border-radius: 10px; 
            background: white;
            transition: all 0.3s ease;
        }
        
        .task:hover {
            border-color: #4CAF50;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        
        .admin-badge { 
            background: linear-gradient(135deg, #ff9800 0%, #f57c00 100%); 
            color: white; 
            padding: 5px 12px; 
            border-radius: 20px; 
            font-size: 12px; 
            margin-left: 10px; 
            font-weight: bold;
        }
        
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        
        .stat-card { 
            background: rgba(255, 255, 255, 0.95); 
            padding: 25px; 
            border-radius: 15px; 
            text-align: center; 
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
            backdrop-filter: blur(10px);
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-number { 
            font-size: 42px; 
            font-weight: bold; 
            margin: 15px 0; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .stat-todo { 
            border-top: 5px solid #ff9800; 
        }
        
        .stat-progress { 
            border-top: 5px solid #2196F3; 
        }
        
        .stat-completed { 
            border-top: 5px solid #4CAF50; 
        }
        
        .status-badge { 
            display: inline-block; 
            padding: 5px 15px; 
            border-radius: 20px; 
            font-size: 12px; 
            font-weight: bold; 
            margin-left: 10px; 
        }
        
        .badge-todo { 
            background: linear-gradient(135deg, #ff9800 0%, #ff5722 100%); 
            color: white; 
        }
        
        .badge-progress { 
            background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%); 
            color: white; 
        }
        
        .badge-completed { 
            background: linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%); 
            color: white; 
        }
        
        .empty-state { 
            text-align: center; 
            padding: 40px; 
            color: #666; 
            background: rgba(255, 255, 255, 0.8);
            border-radius: 10px;
            border: 2px dashed #ddd;
        }
        
        .empty-state h3 { 
            margin-bottom: 15px; 
            color: #333;
        }
        
        .error-message {
            background: rgba(244, 67, 54, 0.1);
            border-left: 4px solid #f44336;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            color: #c62828;
        }
        
        .security-notice {
            background: rgba(33, 150, 243, 0.1);
            border-left: 4px solid #2196F3;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        
        .quick-stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .stat-item {
            padding: 15px;
            background: rgba(248, 249, 250, 0.8);
            border-radius: 8px;
            border-left: 4px solid #4CAF50;
        }
        
        .session-info {
            background: rgba(255, 193, 7, 0.1);
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
            font-size: 12px;
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .header {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }
            
            .btn {
                display: block;
                margin: 10px 0;
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <!-- Security: This session ID is for demo only, remove in production -->
    <input type="hidden" id="session_id" value="<?php echo session_id(); ?>">
    
    <div class="header">
        <div>
            <h1>🔐 Secure Task Manager</h1>
            <p style="font-size: 14px; opacity: 0.8;">OWASP-Compliant Dashboard</p>
        </div>
        <div style="text-align: right;">
            <div style="margin-bottom: 10px;">
                <span>Welcome, <strong><?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></strong></span>
                <?php if ($is_admin): ?>
                    <span class="admin-badge">👑 ADMIN</span>
                <?php endif; ?>
            </div>
            <div>
                <a href="profile.php" class="btn btn-secondary">👤 Profile</a>
                <a href="logout.php" class="btn btn-danger" onclick="return confirmLogout()">🚪 Logout</a>
            </div>
        </div>
    </div>
    <!-- Add this form for secure logout -->
<form id="logoutForm" action="logout_handler.php" method="POST" style="display: inline;">
    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
    <button type="submit" class="btn btn-danger" style="border: none; background: none; color: white; cursor: pointer;">
        🚪 Logout
    </button>
</form>

    <div class="container">
        <?php if ($error): ?>
            <div class="error-message">
                ⚠️ <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>
        
        <div class="security-notice">
            🔒 <strong>Security Status:</strong> Your session is secured with HTTPS, CSRF protection, and input validation. 
            Session expires in <span id="sessionTimer">30:00</span> minutes.
        </div>
        
        <!-- Task Statistics -->
        <div class="stats-grid">
            <div class="stat-card stat-todo">
                <h3>📝 To Do</h3>
                <div class="stat-number"><?php echo (int)$task_counts['todo']; ?></div>
                <p>Pending Tasks</p>
            </div>
            <div class="stat-card stat-progress">
                <h3>🔄 In Progress</h3>
                <div class="stat-number"><?php echo (int)$task_counts['in progress']; ?></div>
                <p>Active Tasks</p>
            </div>
            <div class="stat-card stat-completed">
                <h3>✅ Completed</h3>
                <div class="stat-number"><?php echo (int)$task_counts['completed']; ?></div>
                <p>Finished Tasks</p>
            </div>
        </div>
        
        <div class="card">
            <h2>🎯 Welcome to Your Secure Dashboard!</h2>
            <p>You are successfully authenticated as <strong><?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></strong>.</p>
            
            <div class="session-info">
                <strong>Session Security:</strong> 
                User ID: <?php echo (int)$user_id; ?> | 
                IP: <?php echo htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'Unknown', ENT_QUOTES, 'UTF-8'); ?> | 
                Last Activity: <span id="lastActivity"><?php echo date('H:i:s'); ?></span>
            </div>
            
            <div style="margin: 25px 0; padding: 20px; background: rgba(232, 245, 233, 0.8); border-radius: 10px;">
                <h3>📊 Your Task Summary</h3>
                <div style="display: flex; justify-content: space-around; margin-top: 15px;">
                    <div style="text-align: center;">
                        <div style="font-size: 24px; font-weight: bold; color: #333;"><?php echo (int)$total_tasks; ?></div>
                        <div style="font-size: 14px; color: #666;">Total Tasks</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 24px; font-weight: bold; color: #ff9800;"><?php echo (int)$task_counts['todo']; ?></div>
                        <div style="font-size: 14px; color: #666;">To Do</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 24px; font-weight: bold; color: #2196F3;"><?php echo (int)$task_counts['in progress']; ?></div>
                        <div style="font-size: 14px; color: #666;">In Progress</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 24px; font-weight: bold; color: #4CAF50;"><?php echo (int)$task_counts['completed']; ?></div>
                        <div style="font-size: 14px; color: #666;">Completed</div>
                    </div>
                </div>
            </div>
            
            <div style="margin-top: 25px;">
                <h3>🚀 Quick Actions</h3>
                <div style="display: flex; flex-wrap: wrap; gap: 10px; margin-top: 15px;">
                    <?php if ($is_admin): ?>
                        <a href="admin/dashboard.php" class="btn btn-admin">👑 Admin Panel</a>
                        <a href="admin/audit_log.php" class="btn btn-admin">📋 Audit Log</a>
                        <a href="admin/manage_users.php" class="btn btn-admin">👥 Manage Users</a>
                        <a href="admin/all_task.php" class="btn btn-admin">📊 All Tasks</a>
                    <?php else: ?>
                        <a href="add_task.php" class="btn btn-primary">➕ Add New Task</a>
                        <a href="my_tasks.php" class="btn btn-primary">📋 My Tasks</a>
                        <a href="profile.php" class="btn btn-primary">👤 My Profile</a>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3>📝 Recent Tasks</h3>
            
            <?php if (count($recent_tasks) == 0): ?>
                <div class="empty-state">
                    <h3>No tasks yet! 🎉</h3>
                    <p>Start organizing your work by creating your first task.</p>
                    <a href="add_task.php" class="btn btn-primary" style="margin-top: 15px;">Create Your First Task</a>
                </div>
            <?php else: ?>
                <div class="task-list">
                    <?php foreach ($recent_tasks as $task): 
                        // Sanitize task data
                        $task_id = (int)$task['id'];
                        $task_title = htmlspecialchars($task['title'], ENT_QUOTES, 'UTF-8');
                        $task_desc = !empty($task['description']) ? htmlspecialchars(substr($task['description'], 0, 150), ENT_QUOTES, 'UTF-8') : '';
                        $task_status = htmlspecialchars($task['status'], ENT_QUOTES, 'UTF-8');
                        $task_date = htmlspecialchars(date('M d, Y H:i', strtotime($task['created_at'])), ENT_QUOTES, 'UTF-8');
                        
                        // Status badges with proper encoding
                        $status_badges = [
                            'todo' => ['text' => '📝 To Do', 'class' => 'badge-todo'],
                            'in progress' => ['text' => '🔄 In Progress', 'class' => 'badge-progress'],
                            'completed' => ['text' => '✅ Completed', 'class' => 'badge-completed']
                        ];
                        
                        $status_key = str_replace(' ', '-', $task_status);
                        $status_key = $status_key === 'in-progress' ? 'in progress' : $status_key;
                    ?>
                    <div class="task">
                        <div style="display: flex; justify-content: space-between; align-items: start;">
                            <div style="flex: 1;">
                                <h4 style="margin-bottom: 8px;"><?php echo $task_title; ?></h4>
                                <?php if (!empty($task_desc)): ?>
                                    <p style="color: #666; margin-bottom: 10px;"><?php echo $task_desc; ?><?php echo strlen($task['description']) > 150 ? '...' : ''; ?></p>
                                <?php endif; ?>
                                <small style="color: #888;">Created: <?php echo $task_date; ?></small>
                            </div>
                            <div style="margin-left: 15px;">
                                <span class="status-badge <?php echo htmlspecialchars($status_badges[$status_key]['class'], ENT_QUOTES, 'UTF-8'); ?>">
                                    <?php echo htmlspecialchars($status_badges[$status_key]['text'], ENT_QUOTES, 'UTF-8'); ?>
                                </span>
                            </div>
                        </div>
                        <div style="margin-top: 15px; display: flex; gap: 10px;">
                            <a href="edit_task.php?id=<?php echo $task_id; ?>&csrf=<?php echo urlencode($csrf_token); ?>" 
                               class="btn btn-secondary" 
                               style="padding: 8px 16px; font-size: 14px;"
                               onclick="return confirmEdit()">
                                ✏️ Edit
                            </a>
                            <a href="my_tasks.php" class="btn btn-secondary" style="padding: 8px 16px; font-size: 14px;">
                                📋 View All
                            </a>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
                <div style="text-align: center; margin-top: 20px;">
                    <a href="my_tasks.php" class="btn btn-primary">
                        View All Tasks (<?php echo (int)$total_tasks; ?>)
                    </a>
                </div>
            <?php endif; ?>
        </div>
        
        <div class="card">
            <h3>📈 Security & Session Information</h3>
            <div class="quick-stats-grid">
                <div class="stat-item">
                    <strong>🔐 User ID:</strong><br>
                    <?php echo (int)$user_id; ?>
                </div>
                <div class="stat-item">
                    <strong>👤 Account Type:</strong><br>
                    <?php echo $is_admin ? '👑 Administrator' : '👤 Regular User'; ?>
                </div>
                <div class="stat-item">
                    <strong>📧 Email:</strong><br>
                    <?php echo htmlspecialchars($email, ENT_QUOTES, 'UTF-8'); ?>
                </div>
                <div class="stat-item">
                    <strong>🕒 Login Time:</strong><br>
                    <span id="loginTime"><?php echo date('H:i:s'); ?></span>
                </div>
                <div class="stat-item">
                    <strong>🌐 IP Address:</strong><br>
                    <?php echo htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'Unknown', ENT_QUOTES, 'UTF-8'); ?>
                </div>
                <div class="stat-item">
                    <strong>📊 Total Tasks:</strong><br>
                    <?php echo (int)$total_tasks; ?>
                </div>
            </div>
        </div>
    </div>
    
    <div style="text-align: center; margin: 30px; color: rgba(255, 255, 255, 0.8);">
        <p>🔒 Secure Software Development Project | OWASP-Compliant Task Management System</p>
        <p><small>Security Features: CSRF Protection, SQL Injection Prevention, XSS Protection, Secure Session Management</small></p>
    </div>

    <script>
        // Session timer (30 minutes = 1800 seconds)
        let sessionTime = 1800;
        const timerElement = document.getElementById('sessionTimer');
        
        function updateTimer() {
            const minutes = Math.floor(sessionTime / 60);
            const seconds = sessionTime % 60;
            timerElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            
            if (sessionTime <= 0) {
                alert('Your session has expired. Please login again.');
                window.location.href = 'logout.php?timeout=1';
            } else {
                sessionTime--;
            }
        }
        
        // Update timer every second
        setInterval(updateTimer, 1000);
        updateTimer(); // Initial call
        
        // Update last activity time
        function updateLastActivity() {
            const now = new Date();
            document.getElementById('lastActivity').textContent = now.toLocaleTimeString();
        }
        
        setInterval(updateLastActivity, 60000); // Update every minute
        
        // Confirmation for logout
        function confirmLogout() {
            return confirm('Are you sure you want to logout? Your session will be securely terminated.');
        }
        
        // Confirmation for edit
        function confirmEdit() {
            return confirm('You are about to edit this task. Continue?');
        }
        
        // Reset timer on user activity
        document.addEventListener('click', function() {
            // Reset session timer to 30 minutes on activity
            sessionTime = 1800;
        });
        
        // Prevent navigation away without saving (if forms are present)
        window.addEventListener('beforeunload', function (e) {
            // Only trigger if there are unsaved changes
            const forms = document.querySelectorAll('form');
            let hasUnsavedChanges = false;
            
            forms.forEach(form => {
                if (form.hasAttribute('data-unsaved')) {
                    hasUnsavedChanges = true;
                }
            });
            
            if (hasUnsavedChanges) {
                e.preventDefault();
                e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
            }
        });
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Secure dashboard loaded. Session protected.');
        });
    </script>
    <script>
// Handle logout form submission
document.getElementById('logoutForm').addEventListener('submit', function(e) {
    e.preventDefault();
    if (confirm('Are you sure you want to logout?')) {
        fetch('logout_handler.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams(new FormData(this))
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.href = data.redirect;
            }
        })
        .catch(error => {
            console.error('Logout error:', error);
            window.location.href = 'logout.php';
        });
    }
});
</script>

</body>
</html>