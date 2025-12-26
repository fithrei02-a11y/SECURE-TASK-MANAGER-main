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

// Get filter parameters
$user_filter = isset($_GET['user_id']) ? intval($_GET['user_id']) : 0;
$status_filter = isset($_GET['status']) ? $_GET['status'] : 'all';

// Build query
$where_clause = "1=1";
if ($user_filter > 0) {
    $where_clause .= " AND t.user_id = $user_filter";
}
if ($status_filter != 'all') {
    $where_clause .= " AND t.status = '" . $conn->real_escape_string($status_filter) . "'";
}

// Get all tasks with user info
$tasks_sql = "SELECT t.*, u.username, u.email 
              FROM tasks t 
              JOIN users u ON t.user_id = u.id 
              WHERE $where_clause 
              ORDER BY t.created_at DESC";
$tasks_result = $conn->query($tasks_sql);
$total_tasks = $tasks_result->num_rows;

// Get user list for filter
$users_result = $conn->query("SELECT id, username FROM users ORDER BY username");

$page_title = "All Tasks";
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
        .btn-success { background: #2ecc71; color: white; }
        .btn-danger { background: #e74c3c; color: white; }
        .btn-warning { background: #f39c12; color: white; }
        .btn-secondary { background: #95a5a6; color: white; }
        .btn-sm { padding: 5px 10px; font-size: 12px; }
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
        .filter-bar { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; align-items: center; }
        .filter-select { padding: 8px 12px; border: 1px solid #ddd; border-radius: 5px; }
        .status-badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }
        .badge-todo { background: #fff3e0; color: #e65100; }
        .badge-progress { background: #e3f2fd; color: #1565c0; }
        .badge-completed { background: #e8f5e9; color: #2e7d32; }
        .user-link { color: #3498db; text-decoration: none; }
        .user-link:hover { text-decoration: underline; }
        .task-title { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .empty-state { text-align: center; padding: 50px 20px; color: #666; }
        .empty-state h3 { margin-bottom: 15px; }
        .stats-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 15px; border-radius: 5px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1>📝 <?php echo $page_title; ?></h1>
            <div>
                <a href="dashboard.php" class="btn btn-secondary">← Admin Dashboard</a>
                <a href="../add_task.php" class="btn btn-success" style="margin-left: 10px;">➕ Create Task</a>
            </div>
        </div>
    </div>
    
    <div class="admin-nav">
        <ul>
            <li><a href="dashboard.php">📊 Dashboard</a></li>
            <li><a href="audit_log.php">📋 Audit Log</a></li>
            <li><a href="manage_users.php">👥 Manage Users</a></li>
            <li><a href="all_tasks.php" class="active">📝 All Tasks</a></li>
            <li><a href="system_logs.php">🔧 System Logs</a></li>
        </ul>
    </div>
    
    <div class="container">
        <!-- Task Statistics -->
        <div class="stats-row">
            <?php
            $status_counts = [
                'all' => $conn->query("SELECT COUNT(*) as count FROM tasks")->fetch_assoc()['count'],
                'todo' => $conn->query("SELECT COUNT(*) as count FROM tasks WHERE status = 'todo'")->fetch_assoc()['count'],
                'in progress' => $conn->query("SELECT COUNT(*) as count FROM tasks WHERE status = 'in progress'")->fetch_assoc()['count'],
                'completed' => $conn->query("SELECT COUNT(*) as count FROM tasks WHERE status = 'completed'")->fetch_assoc()['count']
            ];
            ?>
            <div class="stat-card">
                <h3>Total Tasks</h3>
                <div style="font-size: 24px; font-weight: bold;"><?php echo $status_counts['all']; ?></div>
            </div>
            <div class="stat-card" style="border-top: 3px solid #ff9800;">
                <h3>To Do</h3>
                <div style="font-size: 24px; font-weight: bold;"><?php echo $status_counts['todo']; ?></div>
            </div>
            <div class="stat-card" style="border-top: 3px solid #2196F3;">
                <h3>In Progress</h3>
                <div style="font-size: 24px; font-weight: bold;"><?php echo $status_counts['in progress']; ?></div>
            </div>
            <div class="stat-card" style="border-top: 3px solid #4CAF50;">
                <h3>Completed</h3>
                <div style="font-size: 24px; font-weight: bold;"><?php echo $status_counts['completed']; ?></div>
            </div>
        </div>
        
        <div class="card">
            <h2>📝 All System Tasks</h2>
            <p>View and manage tasks created by all users in the system.</p>
            
            <!-- Filter Bar -->
            <div class="filter-bar">
                <strong>Filters:</strong>
                
                <select class="filter-select" onchange="window.location.href='all_tasks.php?status=' + this.value">
                    <option value="all" <?php echo $status_filter == 'all' ? 'selected' : ''; ?>>All Status</option>
                    <option value="todo" <?php echo $status_filter == 'todo' ? 'selected' : ''; ?>>📝 To Do</option>
                    <option value="in progress" <?php echo $status_filter == 'in progress' ? 'selected' : ''; ?>>🔄 In Progress</option>
                    <option value="completed" <?php echo $status_filter == 'completed' ? 'selected' : ''; ?>>✅ Completed</option>
                </select>
                
                <select class="filter-select" onchange="window.location.href='all_tasks.php?user_id=' + this.value">
                    <option value="0">All Users</option>
                    <?php while($user = $users_result->fetch_assoc()): ?>
                        <option value="<?php echo $user['id']; ?>" <?php echo $user_filter == $user['id'] ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($user['username']); ?>
                        </option>
                    <?php endwhile; ?>
                </select>
                
                <input type="text" class="filter-select" placeholder="Search tasks..." style="flex: 1;" id="searchInput" onkeyup="searchTasks()">
                
                <button class="btn btn-secondary" onclick="clearFilters()">Clear Filters</button>
            </div>
            
            <!-- Tasks Table -->
            <?php if ($total_tasks == 0): ?>
                <div class="empty-state">
                    <h3>No tasks found! 📭</h3>
                    <p>No tasks match your current filters.</p>
                    <a href="all_tasks.php" class="btn btn-primary" style="margin-top: 15px;">View All Tasks</a>
                </div>
            <?php else: ?>
                <table id="tasksTable">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Task Title</th>
                            <th>Description</th>
                            <th>User</th>
                            <th>Status</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while($task = $tasks_result->fetch_assoc()): 
                            $status_class = str_replace(' ', '-', $task['status']);
                            $is_owner = ($task['user_id'] == $_SESSION['user_id']);
                        ?>
                        <tr>
                            <td><?php echo $task['id']; ?></td>
                            <td class="task-title">
                                <strong><?php echo htmlspecialchars($task['title']); ?></strong>
                                <?php if ($is_owner): ?>
                                    <small style="color: #2e7d32;">(Yours)</small>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if (!empty($task['description'])): ?>
                                    <?php echo htmlspecialchars(substr($task['description'], 0, 50)); ?>
                                    <?php if (strlen($task['description']) > 50): ?>...<?php endif; ?>
                                <?php else: ?>
                                    <span style="color: #999;">No description</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <a href="manage_users.php" class="user-link">
                                    <?php echo htmlspecialchars($task['username']); ?>
                                </a>
                                <br>
                                <small style="color: #666;"><?php echo htmlspecialchars($task['email']); ?></small>
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
                            <td><?php echo date('M d, Y', strtotime($task['created_at'])); ?></td>
                            <td>
                                <div style="display: flex; gap: 5px;">
                                    <a href="../edit_task.php?id=<?php echo $task['id']; ?>" class="btn btn-sm btn-warning">View</a>
                                    <?php if ($is_owner || $_SESSION['is_admin'] == 1): ?>
                                        <a href="../delete_task.php?id=<?php echo $task['id']; ?>" 
                                           class="btn btn-sm btn-danger"
                                           onclick="return confirm('Are you sure you want to delete this task?\n\nTask: <?php echo addslashes($task['title']); ?>')">
                                            Delete
                                        </a>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
                
                <div style="text-align: center; margin-top: 20px;">
                    <button class="btn btn-primary" onclick="exportTasks()">Export Tasks (CSV)</button>
                    <a href="../add_task.php" class="btn btn-success">➕ Create New Task</a>
                    <button class="btn btn-warning" onclick="showBulkTaskActions()">Bulk Actions</button>
                </div>
            <?php endif; ?>
        </div>
    </div>
    
    <div style="text-align: center; margin: 30px; color: #666; padding: 20px; border-top: 1px solid #ddd;">
        <p>📝 <strong>Task Management System</strong> - Administrator view</p>
        <p><small>Showing <?php echo $total_tasks; ?> tasks | Filter: 
            <?php echo $status_filter == 'all' ? 'All statuses' : ucwords($status_filter); ?>
            <?php if ($user_filter > 0): ?> | User ID: <?php echo $user_filter; ?><?php endif; ?>
        </small></p>
    </div>
    
    <script>
        function searchTasks() {
            const input = document.getElementById('searchInput');
            const filter = input.value.toUpperCase();
            const table = document.getElementById('tasksTable');
            const tr = table.getElementsByTagName('tr');
            
            for (let i = 1; i < tr.length; i++) {
                const td = tr[i].getElementsByTagName('td');
                let found = false;
                
                for (let j = 0; j < td.length; j++) {
                    if (td[j]) {
                        const txtValue = td[j].textContent || td[j].innerText;
                        if (txtValue.toUpperCase().indexOf(filter) > -1) {
                            found = true;
                            break;
                        }
                    }
                }
                
                tr[i].style.display = found ? '' : 'none';
            }
        }
        
        function clearFilters() {
            window.location.href = 'all_tasks.php';
        }
        
        function exportTasks() {
            alert('Task export feature to be implemented by security team.');
        }
        
        function showBulkTaskActions() {
            alert('Bulk task actions to be implemented by security team.');
        }
    </script>
</body>
</html>