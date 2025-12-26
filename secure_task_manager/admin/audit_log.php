<?php
session_start();
require_once '../includes/config.php';

// Redirect to login if not logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: ../login.php");
    exit();
}

// Check if user is admin
if ($_SESSION['is_admin'] != 1) {
    header("Location: ../index.php");
    exit();
}

try {
    // Get filter parameters
    $type_filter = $_GET['type'] ?? 'all';
    $date_filter = $_GET['date'] ?? '';
    $user_filter = $_GET['user'] ?? '';
    $page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
    $limit = 50;
    $offset = ($page - 1) * $limit;
    
    // Build query for audit logs
    $where_conditions = ["1=1"];
    $params = [];
    $types = "";
    
    if ($type_filter !== 'all') {
        if ($type_filter === 'security') {
            $where_conditions[] = "action LIKE ?";
            $params[] = '%security%';
            $types .= "s";
        } elseif ($type_filter === 'login') {
            $where_conditions[] = "(action LIKE ? OR action LIKE ?)";
            $params[] = '%login%';
            $params[] = '%logout%';
            $types .= "ss";
        }
    }
    
    if (!empty($date_filter)) {
        $where_conditions[] = "DATE(created_at) = ?";
        $params[] = $date_filter;
        $types .= "s";
    }
    
    if (!empty($user_filter)) {
        $where_conditions[] = "(username LIKE ? OR user_id = ?)";
        $params[] = "%$user_filter%";
        $params[] = is_numeric($user_filter) ? (int)$user_filter : 0;
        $types .= "si";
    }
    
    $where_clause = implode(" AND ", $where_conditions);
    
    // Get total count
    $count_sql = "SELECT COUNT(*) as total FROM audit_logs WHERE {$where_clause}";
    $stmt = $conn->prepare($count_sql);
    if (!empty($params)) {
        $stmt->bind_param($types, ...$params);
    }
    $stmt->execute();
    $count_result = $stmt->get_result();
    $total_logs = $count_result->fetch_assoc()['total'];
    $total_pages = ceil($total_logs / $limit);
    
    // Get logs with pagination
    $sql = "SELECT * FROM audit_logs WHERE {$where_clause} ORDER BY created_at DESC LIMIT ? OFFSET ?";
    $params[] = $limit;
    $params[] = $offset;
    $types .= "ii";
    
    $stmt = $conn->prepare($sql);
    $stmt->bind_param($types, ...$params);
    $stmt->execute();
    $logs_result = $stmt->get_result();
    $audit_logs = $logs_result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    
} catch (Exception $e) {
    log_system_event('ERROR', 'Failed to fetch audit logs', [
        'admin_id' => $admin_id,
        'error' => $e->getMessage()
    ]);
    $error = "Unable to load audit logs.";
}


$page_title = "Audit Log";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $page_title; ?> - Admin Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: Arial, sans-serif; }
        body { background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; }
        .header-content { max-width: 1400px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; }
        .container { max-width: 1400px; margin: 30px auto; padding: 0 20px; }
        .card { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .btn { display: inline-block; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-size: 14px; }
        .btn-primary { background: #3498db; color: white; }
        .btn-secondary { background: #95a5a6; color: white; }
        .btn-danger { background: #e74c3c; color: white; }
        .btn:hover { opacity: 0.9; }
        .admin-nav { background: #34495e; padding: 15px 0; margin-bottom: 20px; }
        .admin-nav ul { list-style: none; display: flex; justify-content: center; gap: 20px; max-width: 1400px; margin: 0 auto; padding: 0 20px; }
        .admin-nav a { color: white; text-decoration: none; padding: 8px 16px; border-radius: 5px; transition: background 0.3s; }
        .admin-nav a:hover { background: rgba(255,255,255,0.1); }
        .admin-nav a.active { background: #3498db; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: bold; color: #333; }
        tr:hover { background: #f9f9f9; }
        .log-type { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }
        .log-login { background: #e3f2fd; color: #1565c0; }
        .log-security { background: #ffebee; color: #c62828; }
        .log-system { background: #f3e5f5; color: #7b1fa2; }
        .log-user { background: #e8f5e9; color: #2e7d32; }
        .empty-state { text-align: center; padding: 50px 20px; color: #666; }
        .empty-state h3 { margin-bottom: 15px; }
        .placeholder-note { background: #fff3e0; padding: 20px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ff9800; }
        .filter-bar { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .filter-btn { padding: 8px 16px; background: #e0e0e0; border: none; border-radius: 5px; cursor: pointer; }
        .filter-btn.active { background: #3498db; color: white; }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1>📋 <?php echo $page_title; ?></h1>
            <div>
                <a href="dashboard.php" class="btn btn-secondary">← Admin Dashboard</a>
                <a href="../index.php" class="btn btn-secondary" style="margin-left: 10px;">← User View</a>
            </div>
        </div>
    </div>
    
    <div class="admin-nav">
        <ul>
            <li><a href="dashboard.php">📊 Dashboard</a></li>
            <li><a href="audit_log.php" class="active">📋 Audit Log</a></li>
            <li><a href="manage_users.php">👥 Manage Users</a></li>
            <li><a href="all_tasks.php">📝 All Tasks</a></li>
            <li><a href="system_logs.php">🔧 System Logs</a></li>
        </ul>
    </div>
    
    <div class="container">
        <!-- Placeholder Note for Security Team -->
        <div class="placeholder-note">
            <h3>⚠️ AUDIT LOG PLACEHOLDER - Security Team Implementation Required</h3>
            <p><strong>This page is a placeholder for the security team to implement proper audit logging.</strong></p>
            <p>Security team should implement:</p>
            <ul style="margin: 10px 0 10px 20px;">
                <li>✅ Log all login attempts (success/failure)</li>
                <li>✅ Log all user actions (create/edit/delete tasks)</li>
                <li>✅ Log admin actions (user management, system changes)</li>
                <li>✅ Log security events (failed validations, suspicious activity)</li>
                <li>✅ Store logs in database with timestamp, user, IP, and action</li>
                <li>✅ Implement log rotation and archiving</li>
                <li>✅ Add search and filter functionality</li>
            </ul>
            <p><em>Current implementation shows sample data for demonstration only.</em></p>
        </div>
        
        <div class="card">
            <h2>📋 System Audit Log</h2>
            <p>View all security and system events logged by the application.</p>
            
            <!-- Filter Bar -->
            <div class="filter-bar">
                <button class="filter-btn active" onclick="filterLogs('all')">All Events</button>
                <button class="filter-btn" onclick="filterLogs('login')">🔐 Login Events</button>
                <button class="filter-btn" onclick="filterLogs('security')">🛡️ Security Events</button>
                <button class="filter-btn" onclick="filterLogs('user')">👤 User Actions</button>
                <button class="filter-btn" onclick="filterLogs('system')">🔧 System Events</button>
            </div>
            
            <!-- Sample Audit Log Table -->
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Timestamp</th>
                        <th>Event Type</th>
                        <th>User</th>
                        <th>IP Address</th>
                        <th>Action</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    <!-- Sample Data - Security Team will replace with real logs -->
                    <tr class="log-login">
                        <td>1001</td>
                        <td>2025-12-19 15:10:01</td>
                        <td><span class="log-type log-login">LOGIN</span></td>
                        <td>admin</td>
                        <td>192.168.1.100</td>
                        <td>Successful login</td>
                        <td>User logged in from Chrome on Windows</td>
                    </tr>
                    <tr class="log-user">
                        <td>1002</td>
                        <td>2025-12-19 15:15:30</td>
                        <td><span class="log-type log-user">USER ACTION</span></td>
                        <td>user1</td>
                        <td>192.168.1.101</td>
                        <td>Task created</td>
                        <td>Created task: "Complete project report"</td>
                    </tr>
                    <tr class="log-security">
                        <td>1003</td>
                        <td>2025-12-19 15:20:45</td>
                        <td><span class="log-type log-security">SECURITY</span></td>
                        <td>unknown</td>
                        <td>192.168.1.102</td>
                        <td>Failed login attempt</td>
                        <td>3 failed attempts for user 'testuser'</td>
                    </tr>
                    <tr class="log-system">
                        <td>1004</td>
                        <td>2025-12-19 15:25:10</td>
                        <td><span class="log-type log-system">SYSTEM</span></td>
                        <td>system</td>
                        <td>127.0.0.1</td>
                        <td>Database backup</td>
                        <td>Automatic daily backup completed</td>
                    </tr>
                    <tr class="log-user">
                        <td>1005</td>
                        <td>2025-12-19 15:30:20</td>
                        <td><span class="log-type log-user">USER ACTION</span></td>
                        <td>admin</td>
                        <td>192.168.1.100</td>
                        <td>Task updated</td>
                        <td>Updated task #1 status to "in progress"</td>
                    </tr>
                    <tr class="log-login">
                        <td>1006</td>
                        <td>2025-12-19 15:35:55</td>
                        <td><span class="log-type log-login">LOGIN</span></td>
                        <td>user1</td>
                        <td>192.168.1.101</td>
                        <td>Successful login</td>
                        <td>User logged in from Firefox on Windows</td>
                    </tr>
                    <tr class="log-security">
                        <td>1007</td>
                        <td>2025-12-19 15:40:30</td>
                        <td><span class="log-type log-security">SECURITY</span></td>
                        <td>unknown</td>
                        <td>192.168.1.103</td>
                        <td>SQL injection attempt blocked</td>
                        <td>Blocked malicious query in login form</td>
                    </tr>
                    <tr class="log-user">
                        <td>1008</td>
                        <td>2025-12-19 15:45:15</td>
                        <td><span class="log-type log-user">USER ACTION</span></td>
                        <td>user1</td>
                        <td>192.168.1.101</td>
                        <td>Task deleted</td>
                        <td>Deleted task #2: "Test task"</td>
                    </tr>
                    <tr class="log-system">
                        <td>1009</td>
                        <td>2025-12-19 15:50:00</td>
                        <td><span class="log-type log-system">SYSTEM</span></td>
                        <td>system</td>
                        <td>127.0.0.1</td>
                        <td>Session cleanup</td>
                        <td>Cleaned up 5 expired sessions</td>
                    </tr>
                    <tr class="log-login">
                        <td>1010</td>
                        <td>2025-12-19 15:55:40</td>
                        <td><span class="log-type log-login">LOGIN</span></td>
                        <td>admin</td>
                        <td>192.168.1.100</td>
                        <td>Logout</td>
                        <td>User logged out successfully</td>
                    </tr>
                </tbody>
            </table>
            
            <div style="text-align: center; margin-top: 20px;">
                <button class="btn btn-primary">Export Logs (CSV)</button>
                <button class="btn btn-secondary" style="margin-left: 10px;">Clear Old Logs</button>
                <button class="btn btn-danger" style="margin-left: 10px;">Generate Report</button>
            </div>
        </div>
        
        <!-- Log Statistics -->
        <div class="card">
            <h2>📊 Log Statistics</h2>
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-top: 15px;">
                <div style="text-align: center; padding: 15px; background: #e3f2fd; border-radius: 5px;">
                    <h3>🔐 Login Events</h3>
                    <div style="font-size: 24px; font-weight: bold;">8</div>
                    <small>Today</small>
                </div>
                <div style="text-align: center; padding: 15px; background: #ffebee; border-radius: 5px;">
                    <h3>🛡️ Security Events</h3>
                    <div style="font-size: 24px; font-weight: bold;">2</div>
                    <small>Blocked attempts</small>
                </div>
                <div style="text-align: center; padding: 15px; background: #e8f5e9; border-radius: 5px;">
                    <h3>👤 User Actions</h3>
                    <div style="font-size: 24px; font-weight: bold;">45</div>
                    <small>Today</small>
                </div>
                <div style="text-align: center; padding: 15px; background: #f3e5f5; border-radius: 5px;">
                    <h3>🔧 System Events</h3>
                    <div style="font-size: 24px; font-weight: bold;">12</div>
                    <small>Automated</small>
                </div>
            </div>
        </div>
    </div>
    
    <div style="text-align: center; margin: 30px; color: #666; padding: 20px; border-top: 1px solid #ddd;">
        <p>📋 <strong>Audit Log System</strong> - Security monitoring and tracking</p>
        <p><small>Placeholder for OWASP security implementation - Real logging required for production</small></p>
    </div>
    
    <script>
        function filterLogs(type) {
            const rows = document.querySelectorAll('tbody tr');
            rows.forEach(row => {
                if (type === 'all' || row.classList.contains('log-' + type)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
            
            // Update active filter button
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
        }
    </script>
</body>
</html>