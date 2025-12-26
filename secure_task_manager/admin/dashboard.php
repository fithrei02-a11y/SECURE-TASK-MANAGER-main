<?php
// ============================================================================
// SECURE ADMIN DASHBOARD - OWASP COMPLIANT
// ============================================================================

// Include secure configuration
require_once '../includes/config.php';

// Require admin authentication
require_admin();

// Get user information
$user_id = $_SESSION['user_id'];
$username = $_SESSION['username'];

// Initialize variables
$users_count = 0;
$tasks_count = 0;
$admins_count = 0;
$recent_tasks = [];
$recent_users = [];

try {
    // Get statistics using prepared statements
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM users");
    $stmt->execute();
    $users_count = $stmt->get_result()->fetch_assoc()['count'];
    $stmt->close();
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM tasks");
    $stmt->execute();
    $tasks_count = $stmt->get_result()->fetch_assoc()['count'];
    $stmt->close();
    
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM users WHERE is_admin = 1");
    $stmt->execute();
    $admins_count = $stmt->get_result()->fetch_assoc()['count'];
    $stmt->close();
    
    // Get recent tasks with user info
    $stmt = $conn->prepare("SELECT t.id, t.title, t.status, t.created_at, u.username, u.id as user_id 
                           FROM tasks t 
                           JOIN users u ON t.user_id = u.id 
                           ORDER BY t.created_at DESC LIMIT 10");
    $stmt->execute();
    $recent_tasks_result = $stmt->get_result();
    $recent_tasks = $recent_tasks_result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    
    // Get recent users
    $stmt = $conn->prepare("SELECT id, username, email, is_admin, created_at FROM users ORDER BY created_at DESC LIMIT 5");
    $stmt->execute();
    $recent_users_result = $stmt->get_result();
    $recent_users = $recent_users_result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    
    // Log admin dashboard access
    log_security_event('Admin accessed dashboard', [
        'admin_id' => $user_id,
        'admin_username' => $username,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
    ]);
    
} catch (Exception $e) {
    log_system_event('ERROR', 'Failed to load admin dashboard data', [
        'admin_id' => $user_id,
        'error' => $e->getMessage()
    ]);
    $error = "Unable to load dashboard data.";
}

// Generate CSRF token for any forms
$csrf_token = generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Secure Task Manager</title>
    
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
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            min-height: 100vh;
        }
        
        .header { 
            background: rgba(0, 0, 0, 0.9); 
            color: white; 
            padding: 20px; 
            backdrop-filter: blur(10px);
            border-bottom: 3px solid rgba(255, 255, 255, 0.1);
        }
        
        .header-content { 
            max-width: 1400px; 
            margin: 0 auto; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
        }
        
        .container { 
            max-width: 1400px; 
            margin: 30px auto; 
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
        
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
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
        
        .stat-card.users { 
            border-top: 5px solid #3498db; 
        }
        
        .stat-card.tasks { 
            border-top: 5px solid #2ecc71; 
        }
        
        .stat-card.admins { 
            border-top: 5px solid #9b59b6; 
        }
        
        .stat-card.activity { 
            border-top: 5px solid #e74c3c; 
        }
        
        .stat-number { 
            font-size: 36px; 
            font-weight: bold; 
            margin: 15px 0; 
        }
        
        .stat-card.users .stat-number { color: #3498db; }
        .stat-card.tasks .stat-number { color: #2ecc71; }
        .stat-card.admins .stat-number { color: #9b59b6; }
        .stat-card.activity .stat-number { color: #e74c3c; }
        
        .btn { 
            display: inline-block; 
            padding: 12px 24px; 
            color: white; 
            text-decoration: none; 
            border-radius: 8px; 
            font-size: 14px; 
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
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); 
        }
        
        .btn-primary:hover { 
            background: linear-gradient(135deg, #2980b9 0%, #3498db 100%);
        }
        
        .btn-success { 
            background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%); 
        }
        
        .btn-success:hover { 
            background: linear-gradient(135deg, #27ae60 0%, #2ecc71 100%);
        }
        
        .btn-danger { 
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); 
        }
        
        .btn-danger:hover { 
            background: linear-gradient(135deg, #c0392b 0%, #e74c3c 100%);
        }
        
        .btn-warning { 
            background: linear-gradient(135deg, #f39c12 0%, #d35400 100%); 
        }
        
        .btn-warning:hover { 
            background: linear-gradient(135deg, #d35400 0%, #f39c12 100%);
        }
        
        .btn-secondary { 
            background: linear-gradient(135deg, #95a5a6 0%, #7f8c8d 100%); 
        }
        
        .btn-secondary:hover { 
            background: linear-gradient(135deg, #7f8c8d 0%, #95a5a6 100%);
        }
        
        .btn-admin {
            background: linear-gradient(135deg, #9b59b6 0%, #8e44ad 100%);
        }
        
        .btn-admin:hover {
            background: linear-gradient(135deg, #8e44ad 0%, #9b59b6 100%);
        }
        
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px; 
        }
        
        th, td { 
            padding: 12px 15px; 
            text-align: left; 
            border-bottom: 1px solid #ddd; 
        }
        
        th { 
            background: rgba(248, 249, 250, 0.9); 
            font-weight: bold; 
            color: #333; 
        }
        
        tr:hover { 
            background: rgba(249, 249, 249, 0.9); 
        }
        
        .admin-nav { 
            background: rgba(52, 73, 94, 0.9); 
            padding: 15px 0; 
            margin-bottom: 20px; 
            backdrop-filter: blur(10px);
        }
        
        .admin-nav ul { 
            list-style: none; 
            display: flex; 
            justify-content: center; 
            gap: 10px; 
            max-width: 1400px; 
            margin: 0 auto; 
            padding: 0 20px; 
            flex-wrap: wrap;
        }
        
        .admin-nav a { 
            color: white; 
            text-decoration: none; 
            padding: 10px 20px; 
            border-radius: 8px; 
            transition: all 0.3s ease;
            font-weight: 500;
        }
        
        .admin-nav a:hover { 
            background: rgba(255, 255, 255, 0.15); 
            transform: translateY(-2px);
        }
        
        .admin-nav a.active { 
            background: #3498db; 
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .admin-badge { 
            background: linear-gradient(135deg, #9b59b6 0%, #8e44ad 100%); 
            color: white; 
            padding: 4px 12px; 
            border-radius: 20px; 
            font-size: 12px; 
            font-weight: bold;
        }
        
        .user-badge { 
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); 
            color: white; 
            padding: 4px 12px; 
            border-radius: 20px; 
            font-size: 12px; 
            font-weight: bold;
        }
        
        .status-badge { 
            display: inline-block; 
            padding: 5px 12px; 
            border-radius: 20px; 
            font-size: 12px; 
            font-weight: bold; 
        }
        
        .badge-todo { 
            background: linear-gradient(135deg, #ff9800 0%, #f57c00 100%); 
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
        
        .two-columns { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 20px; 
        }
        
        .security-notice {
            background: rgba(231, 76, 60, 0.1);
            border-left: 4px solid #e74c3c;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 25px;
            font-size: 14px;
        }
        
        .system-info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .info-item {
            padding: 15px;
            background: rgba(248, 249, 250, 0.9);
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        
        @media (max-width: 1200px) {
            .stats-grid { 
                grid-template-columns: repeat(2, 1fr); 
            }
            
            .two-columns { 
                grid-template-columns: 1fr; 
            }
        }
        
        @media (max-width: 768px) {
            .stats-grid { 
                grid-template-columns: 1fr; 
            }
            
            .header-content {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }
            
            .admin-nav ul {
                flex-direction: column;
                align-items: center;
            }
            
            .admin-nav a {
                width: 100%;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div>
                <h1>👑 Admin Dashboard</h1>
                <p style="opacity: 0.8; font-size: 14px;">Secure Administrative Panel | OWASP-Compliant</p>
            </div>
            <div>
                <span>Welcome, <strong><?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></strong></span>
                <a href="../index.php" class="btn btn-secondary" style="margin-left: 20px;">← User Dashboard</a>
                <a href="../logout.php?csrf=<?php echo urlencode($csrf_token); ?>" class="btn btn-danger" style="margin-left: 10px;">🚪 Logout</a>
            </div>
        </div>
    </div>
    
    <div class="admin-nav">
        <ul>
            <li><a href="dashboard.php" class="active">📊 Dashboard</a></li>
            <li><a href="audit_log.php">📋 Audit Log</a></li>
            <li><a href="manage_users.php">👥 Manage Users</a></li>
            <li><a href="all_tasks.php">📝 All Tasks</a></li>
            <li><a href="system_logs.php">🔧 System Logs</a></li>
        </ul>
    </div>
    
    <div class="container">
        <div class="security-notice">
            🔒 <strong>Admin Security Status:</strong> You are accessing the administrative panel with full system privileges. 
            All actions are logged for audit purposes.
        </div>
        
        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card users" onclick="window.location.href='manage_users.php'">
                <h3>👥 Total Users</h3>
                <div class="stat-number"><?php echo (int)$users_count; ?></div>
                <p>Registered users</p>
                <a href="manage_users.php" class="btn btn-primary" style="margin-top: 15px;">Manage Users</a>
            </div>
            
            <div class="stat-card tasks" onclick="window.location.href='all_tasks.php'">
                <h3>📝 Total Tasks</h3>
                <div class="stat-number"><?php echo (int)$tasks_count; ?></div>
                <p>Created tasks</p>
                <a href="all_tasks.php" class="btn btn-success" style="margin-top: 15px;">View All Tasks</a>
            </div>
            
            <div class="stat-card admins" onclick="window.location.href='manage_users.php?filter=admin'">
                <h3>👑 Administrators</h3>
                <div class="stat-number"><?php echo (int)$admins_count; ?></div>
                <p>Admin accounts</p>
                <a href="manage_users.php?filter=admin" class="btn btn-admin" style="margin-top: 15px;">View Admins</a>
            </div>
            
            <div class="stat-card activity" onclick="window.location.href='audit_log.php'">
                <h3>📈 System Activity</h3>
                <div class="stat-number"><?php echo count($recent_tasks); ?></div>
                <p>Recent tasks</p>
                <a href="audit_log.php" class="btn btn-warning" style="margin-top: 15px;">View Audit Logs</a>
            </div>
        </div>
        
        <!-- Two Columns: Recent Tasks & Recent Users -->
        <div class="two-columns">
            <!-- Recent Tasks -->
            <div class="card">
                <h2>📝 Recent Tasks</h2>
                <p>Latest tasks created by all users</p>
                
                <?php if (empty($recent_tasks)): ?>
                    <p style="text-align: center; padding: 30px; color: #666;">No tasks created yet.</p>
                <?php else: ?>
                    <table>
                        <thead>
                            <tr>
                                <th>Task</th>
                                <th>User</th>
                                <th>Status</th>
                                <th>Created</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach($recent_tasks as $task): 
                                $status_class = str_replace(' ', '-', $task['status']);
                                $is_owner = ($task['user_id'] == $user_id);
                            ?>
                            <tr>
                                <td>
                                    <strong title="<?php echo htmlspecialchars($task['title'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <?php echo htmlspecialchars(substr($task['title'], 0, 30), ENT_QUOTES, 'UTF-8'); ?>
                                        <?php if (strlen($task['title']) > 30): ?>...<?php endif; ?>
                                    </strong>
                                </td>
                                <td>
                                    <span class="user-badge"><?php echo htmlspecialchars($task['username'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    <?php if ($is_owner): ?>
                                        <small style="color: #2e7d32;">(You)</small>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="status-badge badge-<?php echo $status_class; ?>">
                                        <?php 
                                        $status_text = [
                                            'todo' => '📝 To Do',
                                            'in-progress' => '🔄 In Progress',
                                            'completed' => '✅ Completed'
                                        ];
                                        echo $status_text[$status_class];
                                        ?>
                                    </span>
                                </td>
                                <td><?php echo htmlspecialchars(date('M d, Y', strtotime($task['created_at'])), ENT_QUOTES, 'UTF-8'); ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <div style="text-align: center; margin-top: 20px;">
                        <a href="all_tasks.php" class="btn btn-primary">View All Tasks</a>
                    </div>
                <?php endif; ?>
            </div>
            
            <!-- Recent Users -->
            <div class="card">
                <h2>👥 Recent Users</h2>
                <p>Latest registered users</p>
                
                <?php if (empty($recent_users)): ?>
                    <p style="text-align: center; padding: 30px; color: #666;">No users registered yet.</p>
                <?php else: ?>
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>Joined</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach($recent_users as $user_row): 
                                $is_current_user = ($user_row['id'] == $user_id);
                            ?>
                            <tr>
                                <td>
                                    <strong><?php echo htmlspecialchars($user_row['username'], ENT_QUOTES, 'UTF-8'); ?></strong>
                                    <?php if ($is_current_user): ?>
                                        <small style="color: #2e7d32;">(You)</small>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo htmlspecialchars($user_row['email'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>
                                    <?php if ($user_row['is_admin'] == 1): ?>
                                        <span class="admin-badge">👑 Admin</span>
                                    <?php else: ?>
                                        <span class="user-badge">👤 User</span>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo htmlspecialchars(date('M d, Y', strtotime($user_row['created_at'])), ENT_QUOTES, 'UTF-8'); ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <div style="text-align: center; margin-top: 20px;">
                        <a href="manage_users.php" class="btn btn-primary">Manage All Users</a>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        
        <!-- Admin Actions -->
        <div class="card">
            <h2>⚡ Quick Admin Actions</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px;">
                <a href="../register.php" class="btn btn-success">➕ Create New User</a>
                <a href="all_tasks.php" class="btn btn-primary">📋 View All Tasks</a>
                <a href="audit_log.php" class="btn btn-warning">📊 View System Logs</a>
                <a href="manage_users.php" class="btn btn-danger">👥 Manage Users</a>
                <a href="../add_task.php" class="btn btn-success">➕ Create Task</a>
                <a href="../index.php" class="btn btn-secondary">← User View</a>
            </div>
        </div>
        
        <!-- System Info -->
        <div class="card">
            <h2>🔧 System Information</h2>
            <div class="system-info-grid">
                <div class="info-item">
                    <strong>Current Admin:</strong><br>
                    <?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>
                    <span class="admin-badge">Administrator</span>
                </div>
                <div class="info-item">
                    <strong>Admin ID:</strong><br>
                    <?php echo (int)$user_id; ?>
                </div>
                <div class="info-item">
                    <strong>Session Started:</strong><br>
                    <?php echo htmlspecialchars(date('Y-m-d H:i:s'), ENT_QUOTES, 'UTF-8'); ?>
                </div>
                <div class="info-item">
                    <strong>Database Status:</strong><br>
                    <?php echo (int)$tasks_count; ?> tasks, <?php echo (int)$users_count; ?> users
                </div>
                <div class="info-item">
                    <strong>IP Address:</strong><br>
                    <?php echo htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'Unknown', ENT_QUOTES, 'UTF-8'); ?>
                </div>
                <div class="info-item">
                    <strong>User Agent:</strong><br>
                    <?php echo htmlspecialchars(substr($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', 0, 30), ENT_QUOTES, 'UTF-8'); ?>
                </div>
            </div>
        </div>
    </div>
    
    <div style="text-align: center; margin: 30px; color: rgba(255, 255, 255, 0.9); padding: 20px;">
        <p>👑 <strong>Secure Admin Panel</strong> - OWASP-Compliant Task Management System</p>
        <p><small>All administrative actions are logged for security and audit purposes</small></p>
    </div>

    <script>
        // Admin panel security features
        console.log('Secure admin dashboard loaded. All actions are logged.');
        
        // Confirm before performing dangerous actions
        document.addEventListener('click', function(e) {
            if (e.target.classList.contains('btn-danger') || 
                (e.target.parentElement && e.target.parentElement.classList.contains('btn-danger'))) {
                if (!confirm('⚠️ Are you sure you want to perform this administrative action?\n\nThis action will be logged and may affect system security.')) {
                    e.preventDefault();
                    return false;
                }
            }
        });
        
        // Auto-refresh dashboard every 60 seconds
        setInterval(() => {
            console.log('Refreshing admin dashboard data...');
            window.location.reload();
        }, 60000);
        
        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 'a') {
                e.preventDefault();
                window.location.href = 'all_tasks.php';
            }
            if (e.ctrlKey && e.key === 'u') {
                e.preventDefault();
                window.location.href = 'manage_users.php';
            }
            if (e.ctrlKey && e.key === 'l') {
                e.preventDefault();
                window.location.href = 'audit_log.php';
            }
            if (e.key === 'Escape') {
                window.location.href = '../index.php';
            }
        });
    </script>
</body>
</html>