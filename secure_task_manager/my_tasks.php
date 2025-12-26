<?php
// ============================================================================
// SECURE TASK MANAGEMENT - OWASP COMPLIANT
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
$all_tasks = [];
$status_counts = ['todo' => 0, 'in progress' => 0, 'completed' => 0];
$error = '';
$success_message = '';
$filter_status = $_GET['status'] ?? 'all';

// Allowed status values for filtering (whitelist)
$allowed_statuses = ['all', 'todo', 'in progress', 'completed'];

// Validate filter status
if (!in_array($filter_status, $allowed_statuses)) {
    $filter_status = 'all';
}

// Check for success messages
if (isset($_GET['deleted']) && $_GET['deleted'] == '1') {
    $success_message = "Task deleted successfully!";
    log_security_event('Task deletion confirmed', [
        'user_id' => $user_id,
        'username' => $username
    ]);
}

if (isset($_GET['updated']) && $_GET['updated'] == '1') {
    $success_message = "Task updated successfully!";
}

if (isset($_GET['created']) && $_GET['created'] == '1') {
    $success_message = "Task created successfully!";
}

try {
    // Build SQL query with prepared statement
    if ($filter_status === 'all') {
        $sql = "SELECT id, title, description, status, created_at, updated_at 
                FROM tasks 
                WHERE user_id = ? 
                ORDER BY 
                    CASE status 
                        WHEN 'todo' THEN 1
                        WHEN 'in progress' THEN 2
                        WHEN 'completed' THEN 3
                    END,
                    created_at DESC";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $user_id);
    } else {
        $sql = "SELECT id, title, description, status, created_at, updated_at 
                FROM tasks 
                WHERE user_id = ? AND status = ? 
                ORDER BY created_at DESC";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("is", $user_id, $filter_status);
    }
    
    $stmt->execute();
    $result = $stmt->get_result();
    
    while ($row = $result->fetch_assoc()) {
        $all_tasks[] = $row;
        $status_counts[$row['status']]++;
    }
    $stmt->close();
    
    // Get total counts for statistics
    $stmt = $conn->prepare("SELECT status, COUNT(*) as count FROM tasks WHERE user_id = ? GROUP BY status");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $count_result = $stmt->get_result();
    
    $status_counts = ['todo' => 0, 'in progress' => 0, 'completed' => 0];
    while ($row = $count_result->fetch_assoc()) {
        $status_counts[$row['status']] = (int)$row['count'];
    }
    $stmt->close();
    
} catch (Exception $e) {
    log_system_event('ERROR', 'Failed to fetch tasks', [
        'user_id' => $user_id,
        'error' => $e->getMessage()
    ]);
    $error = "Unable to load tasks. Please try again.";
}

// Generate CSRF token for delete forms
$csrf_token = generate_csrf_token();

// Log access to tasks page
log_security_event('Viewed tasks list', [
    'user_id' => $user_id,
    'username' => $username,
    'filter' => $filter_status,
    'task_count' => count($all_tasks)
]);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Tasks - Secure Task Manager</title>
    
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
            padding: 30px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2); 
            margin-bottom: 20px; 
            backdrop-filter: blur(10px);
        }
        
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
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
        
        .stat-card.todo .stat-number { color: #ff9800; }
        .stat-card.in-progress .stat-number { color: #2196F3; }
        .stat-card.completed .stat-number { color: #4CAF50; }
        
        .task-list { 
            display: grid; 
            gap: 15px; 
            margin-top: 20px;
        }
        
        .task-item { 
            border-left: 5px solid #ddd; 
            padding: 25px; 
            background: rgba(255, 255, 255, 0.9); 
            border-radius: 10px; 
            display: flex; 
            justify-content: space-between; 
            align-items: center;
            transition: all 0.3s ease;
        }
        
        .task-item:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        
        .task-item.todo { 
            border-left-color: #ff9800; 
            background: linear-gradient(90deg, rgba(255, 152, 0, 0.05) 0%, rgba(255, 255, 255, 0.9) 100%);
        }
        
        .task-item.in-progress { 
            border-left-color: #2196F3; 
            background: linear-gradient(90deg, rgba(33, 150, 243, 0.05) 0%, rgba(255, 255, 255, 0.9) 100%);
        }
        
        .task-item.completed { 
            border-left-color: #4CAF50; 
            background: linear-gradient(90deg, rgba(76, 175, 80, 0.05) 0%, rgba(255, 255, 255, 0.9) 100%);
        }
        
        .task-info h3 { 
            margin-bottom: 8px; 
            color: #333; 
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .task-info p { 
            color: #666; 
            margin-bottom: 12px; 
            line-height: 1.5;
        }
        
        .task-meta { 
            font-size: 13px; 
            color: #888; 
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        
        .task-actions { 
            display: flex; 
            gap: 10px; 
            min-width: 160px;
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
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.2);
        }
        
        .btn-primary { 
            background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%); 
        }
        
        .btn-primary:hover { 
            background: linear-gradient(135deg, #1976D2 0%, #2196F3 100%);
        }
        
        .btn-danger { 
            background: linear-gradient(135deg, #f44336 0%, #d32f2f 100%); 
        }
        
        .btn-danger:hover { 
            background: linear-gradient(135deg, #d32f2f 0%, #f44336 100%);
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
        
        .empty-state { 
            text-align: center; 
            padding: 60px 40px; 
            color: #666; 
            background: rgba(255, 255, 255, 0.8);
            border-radius: 15px;
            border: 2px dashed #ddd;
        }
        
        .empty-state h3 { 
            margin-bottom: 15px; 
            color: #333;
            font-size: 24px;
        }
        
        .status-badge { 
            display: inline-block; 
            padding: 6px 15px; 
            border-radius: 20px; 
            font-size: 12px; 
            font-weight: bold; 
        }
        
        .badge-todo { 
            background: linear-gradient(135deg, #ff9800 0%, #ff5722 100%); 
            color: white; 
        }
        
        .badge-in-progress { 
            background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%); 
            color: white; 
        }
        
        .badge-completed { 
            background: linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%); 
            color: white; 
        }
        
        .filter-buttons { 
            display: flex; 
            gap: 10px; 
            margin-bottom: 25px;
            flex-wrap: wrap;
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
            background: #2196F3; 
            color: white; 
            border-color: #1976D2;
        }
        
        .success-message { 
            background: rgba(46, 125, 50, 0.1); 
            color: #2e7d32; 
            padding: 15px; 
            border-radius: 8px; 
            margin-bottom: 25px; 
            border-left: 4px solid #2e7d32;
            text-align: center;
        }
        
        .error-message {
            background: rgba(244, 67, 54, 0.1);
            border-left: 4px solid #c62828;
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
            margin-bottom: 25px;
            font-size: 14px;
        }
        
        .quick-actions {
            display: flex;
            gap: 15px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .task-id {
            background: rgba(0, 0, 0, 0.05);
            padding: 2px 8px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
        }
        
        @media (max-width: 768px) {
            .task-item {
                flex-direction: column;
                align-items: flex-start;
                gap: 15px;
            }
            
            .task-actions {
                width: 100%;
                justify-content: flex-start;
            }
            
            .header-content {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }
            
            .quick-actions {
                flex-direction: column;
            }
            
            .btn {
                width: 100%;
                margin: 5px 0;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div>
                <h1>📋 My Tasks</h1>
                <p style="opacity: 0.8; font-size: 14px;">Secure Task Management | User: <?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></p>
            </div>
            <div>
                <a href="index.php" class="btn btn-secondary">← Dashboard</a>
                <a href="add_task.php" class="btn btn-success" style="margin-left: 10px;">➕ New Task</a>
            </div>
        </div>
    </div>
    
    <div class="container">
        <?php if ($error): ?>
            <div class="error-message">⚠️ <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        
        <?php if ($success_message): ?>
            <div class="success-message">✅ <?php echo htmlspecialchars($success_message, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        
        <div class="security-notice">
            🔒 <strong>Security Status:</strong> All tasks are protected with ownership verification. 
            You can only view and manage your own tasks.
        </div>
        
        <!-- Task Statistics -->
        <div class="stats-grid">
            <div class="stat-card todo" onclick="filterTasks('todo')">
                <h3>📝 To Do</h3>
                <div class="stat-number"><?php echo (int)$status_counts['todo']; ?></div>
                <p>Tasks pending</p>
            </div>
            <div class="stat-card in-progress" onclick="filterTasks('in-progress')">
                <h3>🔄 In Progress</h3>
                <div class="stat-number"><?php echo (int)$status_counts['in progress']; ?></div>
                <p>Active tasks</p>
            </div>
            <div class="stat-card completed" onclick="filterTasks('completed')">
                <h3>✅ Completed</h3>
                <div class="stat-number"><?php echo (int)$status_counts['completed']; ?></div>
                <p>Finished tasks</p>
            </div>
        </div>
        
        <!-- Filter Buttons -->
        <div class="card">
            <h2>All Tasks (<?php echo count($all_tasks); ?>)</h2>
            <p>Filter tasks by status:</p>
            
            <div class="filter-buttons">
                <button class="filter-btn <?php echo $filter_status === 'all' ? 'active' : ''; ?>" 
                        data-status="all" onclick="filterTasks('all')">
                    📋 All (<?php echo array_sum($status_counts); ?>)
                </button>
                <button class="filter-btn <?php echo $filter_status === 'todo' ? 'active' : ''; ?>" 
                        data-status="todo" onclick="filterTasks('todo')">
                    📝 To Do (<?php echo (int)$status_counts['todo']; ?>)
                </button>
                <button class="filter-btn <?php echo $filter_status === 'in progress' ? 'active' : ''; ?>" 
                        data-status="in-progress" onclick="filterTasks('in-progress')">
                    🔄 In Progress (<?php echo (int)$status_counts['in progress']; ?>)
                </button>
                <button class="filter-btn <?php echo $filter_status === 'completed' ? 'active' : ''; ?>" 
                        data-status="completed" onclick="filterTasks('completed')">
                    ✅ Completed (<?php echo (int)$status_counts['completed']; ?>)
                </button>
            </div>
        </div>
        
        <!-- Task List -->
        <div class="card">
            <?php if (count($all_tasks) == 0): ?>
                <div class="empty-state">
                    <h3>No tasks found! 🎉</h3>
                    <p>You don't have any tasks<?php echo $filter_status !== 'all' ? ' with this status' : ''; ?>.</p>
                    <div style="margin-top: 20px;">
                        <a href="add_task.php" class="btn btn-success">Create Your First Task</a>
                        <?php if ($filter_status !== 'all'): ?>
                            <a href="my_tasks.php" class="btn btn-secondary" style="margin-left: 10px;">Show All Tasks</a>
                        <?php endif; ?>
                    </div>
                </div>
            <?php else: ?>
                <div class="task-list" id="taskList">
                    <?php foreach ($all_tasks as $task): 
                        // Sanitize task data
                        $task_id = (int)$task['id'];
                        $task_title = htmlspecialchars($task['title'], ENT_QUOTES, 'UTF-8');
                        $task_desc = htmlspecialchars($task['description'] ?? '', ENT_QUOTES, 'UTF-8');
                        $task_status = htmlspecialchars($task['status'], ENT_QUOTES, 'UTF-8');
                        $created_at = htmlspecialchars(date('M d, Y H:i', strtotime($task['created_at'])), ENT_QUOTES, 'UTF-8');
                        $updated_at = htmlspecialchars(date('M d, Y H:i', strtotime($task['updated_at'])), ENT_QUOTES, 'UTF-8');
                        
                        // Status classes
                        $status_class = str_replace(' ', '-', $task_status);
                        
                        // Status badges
                        $status_badges = [
                            'todo' => ['text' => '📝 To Do', 'class' => 'badge-todo'],
                            'in-progress' => ['text' => '🔄 In Progress', 'class' => 'badge-in-progress'],
                            'completed' => ['text' => '✅ Completed', 'class' => 'badge-completed']
                        ];
                    ?>
                    <div class="task-item <?php echo $status_class; ?>" data-status="<?php echo $status_class; ?>">
                        <div class="task-info">
                            <h3>
                                <?php echo $task_title; ?>
                                <span class="status-badge <?php echo $status_badges[$status_class]['class']; ?>">
                                    <?php echo $status_badges[$status_class]['text']; ?>
                                </span>
                            </h3>
                            <?php if (!empty($task_desc)): ?>
                                <p><?php echo $task_desc; ?></p>
                            <?php endif; ?>
                            <div class="task-meta">
                                <span title="Created at">📅 <?php echo $created_at; ?></span>
                                <?php if ($task['updated_at'] != $task['created_at']): ?>
                                    <span title="Last updated">✏️ <?php echo $updated_at; ?></span>
                                <?php endif; ?>
                                <span class="task-id" title="Task ID">#<?php echo $task_id; ?></span>
                            </div>
                        </div>
                        <div class="task-actions">
                            <a href="edit_task.php?id=<?php echo $task_id; ?>&csrf=<?php echo urlencode($csrf_token); ?>" 
                               class="btn btn-primary">✏️ Edit</a>
                               
                            <!-- Secure Delete Form -->
                            <a href="delete_task.php?id=<?php echo $task['id']; ?>&csrf=<?php echo urlencode($csrf_token); ?>" 
                            class="btn btn-danger">
                            🗑️ Delete
                            </a>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
                
                <div style="text-align: center; margin-top: 30px;">
                    <p style="color: #666;">Showing <?php echo count($all_tasks); ?> task(s)</p>
                </div>
            <?php endif; ?>
        </div>
        
        <!-- Quick Actions -->
        <div class="card">
            <h3>🚀 Quick Actions</h3>
            <div class="quick-actions">
                <a href="add_task.php" class="btn btn-success">➕ Add New Task</a>
                <a href="index.php" class="btn btn-secondary">← Back to Dashboard</a>
                <?php if ($is_admin): ?>
                    <a href="admin/dashboard.php" class="btn btn-primary">👑 Admin Panel</a>
                    <a href="admin/all_task.php" class="btn btn-primary">📊 All Users' Tasks</a>
                <?php endif; ?>
                <button onclick="exportTasks()" class="btn btn-secondary">📄 Export Tasks</button>
            </div>
        </div>
    </div>

    <script>
        // Filter tasks by status
        function filterTasks(status) {
            const taskItems = document.querySelectorAll('.task-item');
            const filterBtns = document.querySelectorAll('.filter-btn');
            
            // Update URL without page reload
            const url = new URL(window.location);
            url.searchParams.set('status', status === 'all' ? 'all' : status);
            window.history.pushState({}, '', url);
            
            // Update active filter button
            filterBtns.forEach(btn => {
                btn.classList.remove('active');
                if (btn.dataset.status === status) {
                    btn.classList.add('active');
                }
            });
            
            // Filter tasks
            taskItems.forEach(task => {
                if (status === 'all' || task.dataset.status === status) {
                    task.style.display = 'flex';
                } else {
                    task.style.display = 'none';
                }
            });
        }
        
        // Secure delete confirmation
        function confirmDelete(button) {
            const form = button.closest('form');
            const taskTitle = form.closest('.task-item').querySelector('h3').firstChild.textContent.trim();
            
            if (confirm(`Are you sure you want to delete this task?\n\n"${taskTitle}"\n\nThis action cannot be undone and will be logged for security purposes.`)) {
                // Add loading state
                button.innerHTML = '🔄 Deleting...';
                button.disabled = true;
                
                // Submit form via AJAX for better UX
                fetch('delete_task.php', {
                    method: 'POST',
                    body: new FormData(form)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Remove task from UI
                        form.closest('.task-item').remove();
                        
                        // Show success message
                        showNotification('✅ Task deleted successfully!', 'success');
                        
                        // Update counts
                        updateTaskCounts();
                    } else {
                        showNotification('❌ ' + data.error, 'error');
                        button.innerHTML = '🗑️ Delete';
                        button.disabled = false;
                    }
                })
                .catch(error => {
                    console.error('Delete error:', error);
                    showNotification('❌ Delete failed. Please try again.', 'error');
                    button.innerHTML = '🗑️ Delete';
                    button.disabled = false;
                });
                
                return false; // Prevent default form submission
            }
            
            return false;
        }
        
        // Show notification
        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            notification.innerHTML = message;
            notification.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 15px 25px;
                border-radius: 8px;
                color: white;
                font-weight: 600;
                z-index: 1000;
                animation: slideIn 0.3s ease;
            `;
            
            if (type === 'success') {
                notification.style.background = 'linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%)';
            } else {
                notification.style.background = 'linear-gradient(135deg, #f44336 0%, #d32f2f 100%)';
            }
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.remove();
            }, 3000);
        }
        
        // Update task counts after deletion
        function updateTaskCounts() {
            // This would ideally be done via AJAX to get updated counts from server
            // For now, we'll just reload the page after a short delay
            setTimeout(() => {
                window.location.reload();
            }, 1500);
        }
        
        // Export tasks (mock function)
        function exportTasks() {
            alert('Export functionality would generate a secure PDF/CSV file of your tasks.\n\nThis feature requires additional server-side implementation.');
        }
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Secure task manager loaded.');
            
            // Apply initial filter
            const urlParams = new URLSearchParams(window.location.search);
            const status = urlParams.get('status') || 'all';
            if (status !== 'all') {
                filterTasks(status);
            }
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 'n') {
                e.preventDefault();
                window.location.href = 'add_task.php';
            }
            if (e.key === 'Escape') {
                window.location.href = 'index.php';
            }
        });
    </script>
    
    <style>
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
    </style>
</body>
</html>