<?php
// ============================================================================
// SECURE USER MANAGEMENT - OWASP COMPLIANT
// ============================================================================

// Include secure configuration
require_once '../includes/config.php';

// Require admin authentication
require_admin();

// Get admin information
$admin_id = $_SESSION['user_id'];
$admin_username = $_SESSION['username'];

// Initialize variables
$error = '';
$success = '';
$users = [];
$filter = $_GET['filter'] ?? 'all';
$search = $_GET['search'] ?? '';
$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$limit = 20;
$offset = ($page - 1) * $limit;

// Allowed filters
$allowed_filters = ['all', 'admin', 'user', 'locked', 'active'];

// Validate filter
if (!in_array($filter, $allowed_filters)) {
    $filter = 'all';
}

// Process user actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        $error = "Security token invalid. Access denied.";
        log_security_event('Invalid CSRF token on user management', [
            'admin_id' => $admin_id,
            'admin_username' => $admin_username,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
        ]);
    } else {
        $action = $_POST['action'] ?? '';
        $target_user_id = isset($_POST['user_id']) ? (int)$_POST['user_id'] : 0;
        
        // Get target user info for logging
        $target_user = null;
        if ($target_user_id > 0) {
            $stmt = $conn->prepare("SELECT username, email, is_admin FROM users WHERE id = ?");
            $stmt->bind_param("i", $target_user_id);
            $stmt->execute();
            $result = $stmt->get_result();
            $target_user = $result->fetch_assoc();
            $stmt->close();
        }
        
        switch ($action) {
            case 'toggle_admin':
                if ($target_user_id > 0 && $target_user) {
                    // Prevent self-demotion (admin cannot remove their own admin rights)
                    if ($target_user_id === $admin_id) {
                        $error = "You cannot modify your own admin privileges.";
                        log_security_event('Admin attempted self-demotion', [
                            'admin_id' => $admin_id,
                            'admin_username' => $admin_username
                        ]);
                    } else {
                        $new_admin_status = $target_user['is_admin'] ? 0 : 1;
                        $stmt = $conn->prepare("UPDATE users SET is_admin = ? WHERE id = ?");
                        $stmt->bind_param("ii", $new_admin_status, $target_user_id);
                        
                        if ($stmt->execute()) {
                            $action_text = $new_admin_status ? 'promoted to admin' : 'demoted from admin';
                            $success = "User '{$target_user['username']}' {$action_text} successfully.";
                            
                            log_security_event('User admin status changed', [
                                'admin_id' => $admin_id,
                                'admin_username' => $admin_username,
                                'target_user_id' => $target_user_id,
                                'target_username' => $target_user['username'],
                                'new_status' => $new_admin_status ? 'admin' : 'user',
                                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
                            ]);
                        }
                        $stmt->close();
                    }
                }
                break;
                
            case 'reset_password':
                if ($target_user_id > 0 && $target_user) {
                    // Generate temporary password
                    $temp_password = bin2hex(random_bytes(8));
                    $hashed_password = hash_password($temp_password);
                    
                    $stmt = $conn->prepare("UPDATE users SET password = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?");
                    $stmt->bind_param("si", $hashed_password, $target_user_id);
                    
                    if ($stmt->execute()) {
                        $success = "Password reset for user '{$target_user['username']}'. Temporary password: <strong>{$temp_password}</strong>";
                        
                        log_security_event('User password reset by admin', [
                            'admin_id' => $admin_id,
                            'admin_username' => $admin_username,
                            'target_user_id' => $target_user_id,
                            'target_username' => $target_user['username'],
                            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
                        ]);
                        
                        // Note: In production, this should be emailed to the user
                        // For now, we show it to admin (this is NOT secure for production!)
                    }
                    $stmt->close();
                }
                break;
                
            case 'unlock_account':
                if ($target_user_id > 0 && $target_user) {
                    $stmt = $conn->prepare("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?");
                    $stmt->bind_param("i", $target_user_id);
                    
                    if ($stmt->execute()) {
                        $success = "Account '{$target_user['username']}' unlocked successfully.";
                        
                        log_security_event('User account unlocked by admin', [
                            'admin_id' => $admin_id,
                            'admin_username' => $admin_username,
                            'target_user_id' => $target_user_id,
                            'target_username' => $target_user['username']
                        ]);
                    }
                    $stmt->close();
                }
                break;
                
            case 'delete_user':
                if ($target_user_id > 0 && $target_user) {
                    // Prevent self-deletion
                    if ($target_user_id === $admin_id) {
                        $error = "You cannot delete your own account.";
                        log_security_event('Admin attempted self-deletion', [
                            'admin_id' => $admin_id,
                            'admin_username' => $admin_username
                        ]);
                    } else {
                        // Start transaction for user deletion
                        $conn->begin_transaction();
                        
                        try {
                            // Delete user's tasks
                            $stmt1 = $conn->prepare("DELETE FROM tasks WHERE user_id = ?");
                            $stmt1->bind_param("i", $target_user_id);
                            $stmt1->execute();
                            $stmt1->close();
                            
                            // Delete user's audit logs
                            $stmt2 = $conn->prepare("DELETE FROM audit_logs WHERE user_id = ?");
                            $stmt2->bind_param("i", $target_user_id);
                            $stmt2->execute();
                            $stmt2->close();
                            
                            // Delete the user
                            $stmt3 = $conn->prepare("DELETE FROM users WHERE id = ?");
                            $stmt3->bind_param("i", $target_user_id);
                            $stmt3->execute();
                            $affected_rows = $stmt3->affected_rows;
                            $stmt3->close();
                            
                            if ($affected_rows > 0) {
                                $conn->commit();
                                $success = "User '{$target_user['username']}' and all associated data deleted successfully.";
                                
                                log_security_event('User deleted by admin', [
                                    'admin_id' => $admin_id,
                                    'admin_username' => $admin_username,
                                    'deleted_user_id' => $target_user_id,
                                    'deleted_username' => $target_user['username'],
                                    'deleted_email' => $target_user['email'],
                                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
                                ]);
                            } else {
                                $conn->rollback();
                                $error = "Failed to delete user.";
                            }
                        } catch (Exception $e) {
                            $conn->rollback();
                            $error = "Database error during user deletion.";
                            log_system_event('ERROR', 'User deletion failed', [
                                'admin_id' => $admin_id,
                                'target_user_id' => $target_user_id,
                                'error' => $e->getMessage()
                            ]);
                        }
                    }
                }
                break;
        }
    }
}

// Build query based on filter and search
try {
    $where_conditions = ["1=1"];
    $params = [];
    $types = "";
    
    if (!empty($search)) {
        $where_conditions[] = "(username LIKE ? OR email LIKE ?)";
        $search_param = "%" . $search . "%";
        $params[] = $search_param;
        $params[] = $search_param;
        $types .= "ss";
    }
    
    if ($filter === 'admin') {
        $where_conditions[] = "is_admin = 1";
    } elseif ($filter === 'user') {
        $where_conditions[] = "is_admin = 0";
    } elseif ($filter === 'locked') {
        $where_conditions[] = "(locked_until IS NOT NULL AND locked_until > NOW())";
    } elseif ($filter === 'active') {
        $where_conditions[] = "(locked_until IS NULL OR locked_until <= NOW())";
    }
    
    $where_clause = implode(" AND ", $where_conditions);
    
    // Get total count for pagination
    $count_sql = "SELECT COUNT(*) as total FROM users WHERE {$where_clause}";
    if (!empty($params)) {
        $stmt = $conn->prepare($count_sql);
        $stmt->bind_param($types, ...$params);
        $stmt->execute();
        $count_result = $stmt->get_result();
    } else {
        $count_result = $conn->query($count_sql);
    }
    $total_users = $count_result->fetch_assoc()['total'];
    $total_pages = ceil($total_users / $limit);
    
    // Get users with pagination
    $sql = "SELECT id, username, email, is_admin, failed_attempts, locked_until, created_at 
            FROM users 
            WHERE {$where_clause} 
            ORDER BY created_at DESC 
            LIMIT ? OFFSET ?";
    
    $params[] = $limit;
    $params[] = $offset;
    $types .= "ii";
    
    $stmt = $conn->prepare($sql);
    if (!empty($params)) {
        $stmt->bind_param($types, ...$params);
    }
    $stmt->execute();
    $result = $stmt->get_result();
    $users = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    
} catch (Exception $e) {
    log_system_event('ERROR', 'Failed to fetch users', [
        'admin_id' => $admin_id,
        'error' => $e->getMessage()
    ]);
    $error = "Unable to load user data. Please try again.";
}

// Generate CSRF token
$csrf_token = generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Users - Admin Panel</title>
    
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
        
        .btn { 
            display: inline-block; 
            padding: 10px 20px; 
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
        
        .btn-sm { 
            padding: 6px 12px; 
            font-size: 12px; 
            margin: 2px;
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
        
        .filter-bar { 
            display: flex; 
            gap: 10px; 
            margin-bottom: 20px; 
            flex-wrap: wrap;
            align-items: center;
        }
        
        .filter-select { 
            padding: 10px 15px; 
            border: 2px solid #ddd; 
            border-radius: 8px; 
            font-size: 14px;
            background: rgba(255, 255, 255, 0.9);
        }
        
        .filter-btn { 
            padding: 10px 20px; 
            background: rgba(224, 224, 224, 0.5); 
            border: 2px solid transparent;
            border-radius: 8px; 
            cursor: pointer; 
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .filter-btn:hover {
            background: rgba(224, 224, 224, 0.8);
        }
        
        .filter-btn.active { 
            background: #3498db; 
            color: white; 
            border-color: #2980b9;
        }
        
        .search-box {
            flex: 1;
            min-width: 200px;
        }
        
        .badge { 
            display: inline-block; 
            padding: 4px 10px; 
            border-radius: 20px; 
            font-size: 12px; 
            font-weight: bold; 
        }
        
        .badge-admin { 
            background: linear-gradient(135deg, #9b59b6 0%, #8e44ad 100%); 
            color: white; 
        }
        
        .badge-user { 
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); 
            color: white; 
        }
        
        .badge-locked { 
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); 
            color: white; 
        }
        
        .badge-active { 
            background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%); 
            color: white; 
        }
        
        .pagination { 
            display: flex; 
            justify-content: center; 
            gap: 5px; 
            margin-top: 20px; 
        }
        
        .page-link { 
            padding: 8px 12px; 
            border: 1px solid #ddd; 
            border-radius: 5px; 
            text-decoration: none; 
            color: #333;
            transition: all 0.3s ease;
        }
        
        .page-link:hover { 
            background: #3498db; 
            color: white; 
            border-color: #3498db;
        }
        
        .page-link.active { 
            background: #3498db; 
            color: white; 
            border-color: #3498db;
        }
        
        .empty-state { 
            text-align: center; 
            padding: 50px 20px; 
            color: #666; 
        }
        
        .empty-state h3 { 
            margin-bottom: 15px; 
        }
        
        .security-notice {
            background: rgba(231, 76, 60, 0.1);
            border-left: 4px solid #e74c3c;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 25px;
            font-size: 14px;
        }
        
        .user-actions {
            display: flex;
            gap: 5px;
            flex-wrap: wrap;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        
        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 15px;
            max-width: 500px;
            width: 90%;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        
        @media (max-width: 768px) {
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
            
            .filter-bar {
                flex-direction: column;
                align-items: stretch;
            }
            
            table {
                display: block;
                overflow-x: auto;
            }
            
            .user-actions {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1>👥 Manage Users</h1>
            <div>
                <a href="dashboard.php" class="btn btn-secondary">← Admin Dashboard</a>
                <a href="../index.php" class="btn btn-secondary" style="margin-left: 10px;">← User View</a>
            </div>
        </div>
    </div>
    
    <div class="admin-nav">
        <ul>
            <li><a href="dashboard.php">📊 Dashboard</a></li>
            <li><a href="audit_log.php">📋 Audit Log</a></li>
            <li><a href="manage_users.php" class="active">👥 Manage Users</a></li>
            <li><a href="all_tasks.php">📝 All Tasks</a></li>
            <li><a href="system_logs.php">🔧 System Logs</a></li>
        </ul>
    </div>
    
    <div class="container">
        <div class="security-notice">
            🔒 <strong>Admin Security Notice:</strong> User management actions are logged for audit purposes. 
            Be cautious when modifying user privileges or deleting accounts.
        </div>
        
        <?php if ($error): ?>
            <div class="error">❌ <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="success">✅ <?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        
        <div class="card">
            <h2>👥 User Management</h2>
            <p>Manage all registered users in the system. Total: <strong><?php echo (int)$total_users; ?></strong> users</p>
            
            <!-- Filter and Search Bar -->
            <div class="filter-bar">
                <strong>Filter:</strong>
                <button class="filter-btn <?php echo $filter === 'all' ? 'active' : ''; ?>" onclick="setFilter('all')">All Users</button>
                <button class="filter-btn <?php echo $filter === 'admin' ? 'active' : ''; ?>" onclick="setFilter('admin')">👑 Admins</button>
                <button class="filter-btn <?php echo $filter === 'user' ? 'active' : ''; ?>" onclick="setFilter('user')">👤 Regular Users</button>
                <button class="filter-btn <?php echo $filter === 'locked' ? 'active' : ''; ?>" onclick="setFilter('locked')">🔒 Locked Accounts</button>
                <button class="filter-btn <?php echo $filter === 'active' ? 'active' : ''; ?>" onclick="setFilter('active')">✅ Active Accounts</button>
                
                <form method="GET" action="" class="search-box" onsubmit="return searchUsers()">
                    <input type="hidden" name="filter" value="<?php echo htmlspecialchars($filter, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="text" 
                           name="search" 
                           class="filter-select" 
                           placeholder="Search by username or email..."
                           value="<?php echo htmlspecialchars($search, ENT_QUOTES, 'UTF-8'); ?>"
                           style="width: 100%;">
                </form>
                
                <a href="../register.php" class="btn btn-success">➕ Create New User</a>
            </div>
            
            <!-- Users Table -->
            <?php if (empty($users)): ?>
                <div class="empty-state">
                    <h3>No users found! 📭</h3>
                    <p>No users match your current filters.</p>
                    <button class="btn btn-primary" onclick="clearFilters()">Clear Filters</button>
                </div>
            <?php else: ?>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): 
                            $is_current_user = ($user['id'] == $admin_id);
                            $is_locked = ($user['locked_until'] && strtotime($user['locked_until']) > time());
                        ?>
                        <tr>
                            <td><?php echo (int)$user['id']; ?></td>
                            <td>
                                <strong><?php echo htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8'); ?></strong>
                                <?php if ($is_current_user): ?>
                                    <span class="badge badge-user">(You)</span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo htmlspecialchars($user['email'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td>
                                <?php if ($user['is_admin']): ?>
                                    <span class="badge badge-admin">👑 Admin</span>
                                <?php else: ?>
                                    <span class="badge badge-user">👤 User</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($is_locked): ?>
                                    <span class="badge badge-locked" title="Locked until: <?php echo htmlspecialchars($user['locked_until'], ENT_QUOTES, 'UTF-8'); ?>">
                                        🔒 Locked
                                    </span>
                                <?php else: ?>
                                    <span class="badge badge-active">✅ Active</span>
                                <?php endif; ?>
                                <?php if ($user['failed_attempts'] > 0): ?>
                                    <br><small style="color: #666;">Failed attempts: <?php echo (int)$user['failed_attempts']; ?></small>
                                <?php endif; ?>
                            </td>
                            <td><?php echo htmlspecialchars(date('M d, Y', strtotime($user['created_at'])), ENT_QUOTES, 'UTF-8'); ?></td>
                            <td>
                                <div class="user-actions">
                                    <!-- Toggle Admin Status -->
                                    <form method="POST" action="" style="display: inline;" onsubmit="return confirmAction(this, 'toggle_admin')">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="action" value="toggle_admin">
                                        <input type="hidden" name="user_id" value="<?php echo (int)$user['id']; ?>">
                                        <button type="submit" class="btn btn-sm btn-warning" <?php echo $is_current_user ? 'disabled title="Cannot modify own admin rights"' : ''; ?>>
                                            <?php echo $user['is_admin'] ? '👤 Demote' : '👑 Promote'; ?>
                                        </button>
                                    </form>
                                    
                                    <!-- Reset Password -->
                                    <form method="POST" action="" style="display: inline;" onsubmit="return confirmAction(this, 'reset_password')">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="action" value="reset_password">
                                        <input type="hidden" name="user_id" value="<?php echo (int)$user['id']; ?>">
                                        <button type="submit" class="btn btn-sm btn-primary">
                                            🔑 Reset PW
                                        </button>
                                    </form>
                                    
                                    <!-- Unlock Account (if locked) -->
                                    <?php if ($is_locked): ?>
                                    <form method="POST" action="" style="display: inline;" onsubmit="return confirmAction(this, 'unlock_account')">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="action" value="unlock_account">
                                        <input type="hidden" name="user_id" value="<?php echo (int)$user['id']; ?>">
                                        <button type="submit" class="btn btn-sm btn-success">
                                            🔓 Unlock
                                        </button>
                                    </form>
                                    <?php endif; ?>
                                    
                                    <!-- Delete User -->
                                    <form method="POST" action="" style="display: inline;" onsubmit="return confirmAction(this, 'delete_user')">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="action" value="delete_user">
                                        <input type="hidden" name="user_id" value="<?php echo (int)$user['id']; ?>">
                                        <button type="submit" class="btn btn-sm btn-danger" <?php echo $is_current_user ? 'disabled title="Cannot delete own account"' : ''; ?>>
                                            🗑️ Delete
                                        </button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                
                <!-- Pagination -->
                <?php if ($total_pages > 1): ?>
                <div class="pagination">
                    <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                        <a href="?filter=<?php echo urlencode($filter); ?>&search=<?php echo urlencode($search); ?>&page=<?php echo $i; ?>" 
                           class="page-link <?php echo $i == $page ? 'active' : ''; ?>">
                            <?php echo $i; ?>
                        </a>
                    <?php endfor; ?>
                </div>
                <?php endif; ?>
            <?php endif; ?>
        </div>
        
        <!-- Quick Stats -->
        <div class="card">
            <h2>📊 User Statistics</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px;">
                <?php
                // Get additional statistics
                $stats_sql = "SELECT 
                    COUNT(*) as total,
                    SUM(is_admin) as admins,
                    SUM(CASE WHEN locked_until IS NOT NULL AND locked_until > NOW() THEN 1 ELSE 0 END) as locked
                    FROM users";
                $stats_result = $conn->query($stats_sql);
                $stats = $stats_result->fetch_assoc();
                ?>
                <div style="text-align: center; padding: 20px; background: rgba(52, 152, 219, 0.1); border-radius: 10px;">
                    <h3>Total Users</h3>
                    <div style="font-size: 32px; font-weight: bold; color: #3498db;"><?php echo (int)$stats['total']; ?></div>
                </div>
                <div style="text-align: center; padding: 20px; background: rgba(155, 89, 182, 0.1); border-radius: 10px;">
                    <h3>Admins</h3>
                    <div style="font-size: 32px; font-weight: bold; color: #9b59b6;"><?php echo (int)$stats['admins']; ?></div>
                </div>
                <div style="text-align: center; padding: 20px; background: rgba(231, 76, 60, 0.1); border-radius: 10px;">
                    <h3>Locked Accounts</h3>
                    <div style="font-size: 32px; font-weight: bold; color: #e74c3c;"><?php echo (int)$stats['locked']; ?></div>
                </div>
                <div style="text-align: center; padding: 20px; background: rgba(46, 204, 113, 0.1); border-radius: 10px;">
                    <h3>Active Accounts</h3>
                    <div style="font-size: 32px; font-weight: bold; color: #2ecc71;"><?php echo (int)($stats['total'] - $stats['locked']); ?></div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Confirmation Modal -->
    <div id="confirmationModal" class="modal">
        <div class="modal-content">
            <h3 id="modalTitle">Confirm Action</h3>
            <p id="modalMessage">Are you sure you want to perform this action?</p>
            <div style="display: flex; gap: 10px; margin-top: 20px;">
                <button id="confirmButton" class="btn btn-danger">Confirm</button>
                <button onclick="closeModal()" class="btn btn-secondary">Cancel</button>
            </div>
        </div>
    </div>

    <script>
        // Filter functions
        function setFilter(filter) {
            const url = new URL(window.location);
            url.searchParams.set('filter', filter);
            url.searchParams.delete('page'); // Reset to page 1
            window.location.href = url.toString();
        }
        
        function searchUsers() {
            const url = new URL(window.location);
            const searchInput = document.querySelector('input[name="search"]');
            url.searchParams.set('search', searchInput.value);
            url.searchParams.delete('page'); // Reset to page 1
            window.location.href = url.toString();
            return false;
        }
        
        function clearFilters() {
            window.location.href = 'manage_users.php';
        }
        
        // Modal functions
        let pendingForm = null;
        let pendingAction = '';
        
        function confirmAction(form, action) {
            pendingForm = form;
            pendingAction = action;
            
            const modal = document.getElementById('confirmationModal');
            const modalTitle = document.getElementById('modalTitle');
            const modalMessage = document.getElementById('modalMessage');
            const confirmButton = document.getElementById('confirmButton');
            
            const username = form.closest('tr').querySelector('td:nth-child(2) strong').textContent;
            
            switch(action) {
                case 'toggle_admin':
                    modalTitle.textContent = 'Toggle Admin Status';
                    modalMessage.textContent = `Are you sure you want to change admin status for user "${username}"?\n\nThis action will be logged for security audit.`;
                    confirmButton.textContent = 'Change Status';
                    break;
                    
                case 'reset_password':
                    modalTitle.textContent = 'Reset Password';
                    modalMessage.innerHTML = `Are you sure you want to reset password for user "${username}"?<br><br>
                                            <strong>⚠️ Security Warning:</strong> A new temporary password will be generated and displayed. 
                                            The user should change it immediately after login.`;
                    confirmButton.textContent = 'Reset Password';
                    break;
                    
                case 'unlock_account':
                    modalTitle.textContent = 'Unlock Account';
                    modalMessage.textContent = `Are you sure you want to unlock account for user "${username}"?\n\nFailed login attempts will be reset.`;
                    confirmButton.textContent = 'Unlock Account';
                    break;
                    
                case 'delete_user':
                    modalTitle.textContent = 'Delete User Account';
                    modalMessage.textContent = `⚠️ DANGER: Are you absolutely sure you want to DELETE user "${username}"?\n\n
                    This will permanently delete:
                    • User account
                    • All tasks created by this user
                    • All audit logs associated with this user
                    \nThis action CANNOT be undone!`;
                    confirmButton.textContent = 'DELETE PERMANENTLY';
                    confirmButton.style.background = 'linear-gradient(135deg, #c0392b 0%, #a93226 100%)';
                    break;
            }
            
            modal.style.display = 'flex';
            return false;
        }
        
        function closeModal() {
            document.getElementById('confirmationModal').style.display = 'none';
            pendingForm = null;
            pendingAction = '';
        }
        
        document.getElementById('confirmButton').addEventListener('click', function() {
            if (pendingForm) {
                // Show loading state
                this.innerHTML = '🔄 Processing...';
                this.disabled = true;
                
                // Submit the form
                pendingForm.submit();
            }
        });
        
        // Close modal on escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeModal();
            }
        });
        
        // Close modal on outside click
        document.getElementById('confirmationModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeModal();
            }
        });
        
        // Initialize
        console.log('Secure user management loaded.');
    </script>
</body>
</html>