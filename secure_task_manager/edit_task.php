<?php
// ============================================================================
// SECURE TASK EDITING - OWASP COMPLIANT
// ============================================================================

// Include secure configuration
require_once 'includes/config.php';

// Require authentication
require_auth();

// Get user information
$user_id = $_SESSION['user_id'];
$username = $_SESSION['username'];

// Initialize variables
$error = '';
$success = '';
$task = null;
$form_data = [];

// Allowed status values (whitelist)
$allowed_statuses = ['todo', 'in progress', 'completed'];

// Get and validate task ID
$task_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

// CSRF token for GET requests (if provided in URL)
$url_csrf = $_GET['csrf'] ?? '';
if ($url_csrf && !validate_csrf_token($url_csrf)) {
    $error = "Security token invalid. Access denied.";
    log_security_event('Invalid CSRF token on task edit access', [
        'user_id' => $user_id,
        'task_id' => $task_id,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
    ]);
}

// Fetch task details with authorization check
if ($task_id > 0 && !$error) {
    try {
        $stmt = $conn->prepare("SELECT id, title, description, status, created_at, updated_at FROM tasks WHERE id = ? AND user_id = ?");
        $stmt->bind_param("ii", $task_id, $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows == 1) {
            $task = $result->fetch_assoc();
            
            // Log task view for editing
            log_security_event('Viewed task for editing', [
                'user_id' => $user_id,
                'username' => $username,
                'task_id' => $task_id,
                'task_title' => $task['title']
            ]);
        } else {
            // Task not found or unauthorized access
            $error = "Task not found or you don't have permission to edit it!";
            
            // Log unauthorized access attempt
            log_security_event('Unauthorized task edit attempt', [
                'user_id' => $user_id,
                'username' => $username,
                'attempted_task_id' => $task_id,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
            ]);
        }
        $stmt->close();
        
    } catch (Exception $e) {
        $error = "Unable to load task details.";
        log_system_event('ERROR', 'Failed to fetch task for editing', [
            'user_id' => $user_id,
            'task_id' => $task_id,
            'error' => $e->getMessage()
        ]);
    }
} else if ($task_id <= 0) {
    $error = "No task specified!";
}

// Process form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST' && $task && !$error) {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        $error = "Security token invalid. Please refresh the page and try again.";
        log_security_event('CSRF attempt on task update', [
            'user_id' => $user_id,
            'task_id' => $task_id,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
        ]);
    } else {
        // Sanitize and validate inputs
        $title = sanitize_input($_POST['title'] ?? '');
        $description = sanitize_input($_POST['description'] ?? '');
        $status = $_POST['status'] ?? 'todo';
        
        // Store for form re-population
        $form_data = compact('title', 'description', 'status');
        
        // Validate inputs
        if (empty($title)) {
            $error = "Task title is required!";
        } elseif (strlen($title) < 3 || strlen($title) > 200) {
            $error = "Task title must be between 3 and 200 characters.";
        } elseif (strlen($description) > 1000) {
            $error = "Description cannot exceed 1000 characters.";
        } elseif (!in_array($status, $allowed_statuses)) {
            $error = "Invalid status selected.";
        } else {
            try {
                // Update task using prepared statement
                $stmt = $conn->prepare("UPDATE tasks SET title = ?, description = ?, status = ?, updated_at = NOW() WHERE id = ? AND user_id = ?");
                $stmt->bind_param("sssii", $title, $description, $status, $task_id, $user_id);
                
                if ($stmt->execute() && $stmt->affected_rows > 0) {
                    $success = "Task updated successfully!";
                    
                    // Update local task data
                    $task['title'] = $title;
                    $task['description'] = $description;
                    $task['status'] = $status;
                    
                    // Log task update
                    log_security_event('Task updated', [
                        'user_id' => $user_id,
                        'username' => $username,
                        'task_id' => $task_id,
                        'old_title' => $task['title'],
                        'new_title' => $title,
                        'status_changed_to' => $status
                    ]);
                    
                    // Log system event
                    log_system_event('INFO', 'Task updated', [
                        'task_id' => $task_id,
                        'user_id' => $user_id,
                        'title' => $title
                    ]);
                    
                } else {
                    // No rows affected - task doesn't exist or unauthorized
                    $error = "Unable to update task. Please verify the task exists and you have permission to edit it.";
                    
                    log_security_event('Failed task update - no rows affected', [
                        'user_id' => $user_id,
                        'task_id' => $task_id,
                        'title' => $title
                    ]);
                }
                
                $stmt->close();
                
            } catch (Exception $e) {
                $error = "Failed to update task. Please try again.";
                log_system_event('ERROR', 'Task update failed', [
                    'user_id' => $user_id,
                    'task_id' => $task_id,
                    'error' => $e->getMessage()
                ]);
            }
        }
    }
}

// If no task found and no specific error, redirect
if (!$task && !$error) {
    header("Location: my_tasks.php");
    exit();
}

// Generate CSRF token for form
$csrf_token = generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Task - Secure Task Manager</title>
    
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
            max-width: 800px; 
            margin: 30px auto; 
            padding: 0 20px; 
        }
        
        .card { 
            background: rgba(255, 255, 255, 0.95); 
            padding: 40px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2); 
            backdrop-filter: blur(10px);
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
        
        input, textarea, select { 
            width: 100%; 
            padding: 14px; 
            border: 2px solid #ddd; 
            border-radius: 8px; 
            font-size: 16px; 
            transition: border 0.3s;
            background: rgba(255, 255, 255, 0.9);
        }
        
        input:focus, textarea:focus, select:focus { 
            border-color: #2196F3; 
            outline: none;
            box-shadow: 0 0 0 3px rgba(33, 150, 243, 0.1);
        }
        
        textarea { 
            min-height: 140px; 
            resize: vertical; 
            line-height: 1.5;
        }
        
        .char-counter {
            text-align: right;
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        
        .char-counter.warning {
            color: #ff9800;
        }
        
        .char-counter.danger {
            color: #f44336;
        }
        
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
            background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%); 
        }
        
        .btn-primary:hover { 
            background: linear-gradient(135deg, #1976D2 0%, #2196F3 100%);
        }
        
        .btn-success { 
            background: linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%); 
        }
        
        .btn-success:hover { 
            background: linear-gradient(135deg, #2E7D32 0%, #4CAF50 100%);
        }
        
        .btn-danger { 
            background: linear-gradient(135deg, #f44336 0%, #d32f2f 100%); 
        }
        
        .btn-danger:hover { 
            background: linear-gradient(135deg, #d32f2f 0%, #f44336 100%);
        }
        
        .btn-secondary { 
            background: linear-gradient(135deg, #6c757d 0%, #495057 100%); 
        }
        
        .btn-secondary:hover { 
            background: linear-gradient(135deg, #495057 0%, #6c757d 100%);
        }
        
        .btn:disabled {
            background: #cccccc;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
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
        
        .form-actions { 
            display: flex; 
            gap: 15px; 
            margin-top: 30px; 
            flex-wrap: wrap;
        }
        
        .task-info {
            background: rgba(248, 249, 250, 0.9);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            border-left: 4px solid #2196F3;
        }
        
        .info-row { 
            display: flex; 
            margin-bottom: 12px; 
            align-items: center;
        }
        
        .info-label { 
            font-weight: 600; 
            width: 140px; 
            color: #666; 
            font-size: 14px;
        }
        
        .info-value { 
            color: #333; 
            flex: 1;
        }
        
        .status-indicator { 
            display: inline-block; 
            padding: 6px 16px; 
            border-radius: 20px; 
            font-size: 14px; 
            font-weight: 600;
            margin-left: 10px;
        }
        
        .status-todo { 
            background: linear-gradient(135deg, #ff9800 0%, #ff5722 100%); 
            color: white; 
        }
        
        .status-in-progress { 
            background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%); 
            color: white; 
        }
        
        .status-completed { 
            background: linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%); 
            color: white; 
        }
        
        .security-notice {
            background: rgba(33, 150, 243, 0.1);
            border-left: 4px solid #2196F3;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 25px;
            font-size: 14px;
        }
        
        .delete-form {
            display: inline;
        }
        
        @media (max-width: 768px) {
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
            
            .form-actions {
                flex-direction: column;
            }
            
            .btn {
                width: 100%;
                margin: 5px 0;
            }
            
            .info-row {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .info-label {
                width: 100%;
                margin-bottom: 5px;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div>
                <h1>✏️ Edit Task</h1>
                <p style="opacity: 0.8; font-size: 14px;">Secure Task Editing | User: <?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></p>
            </div>
            <div>
                <a href="my_tasks.php" class="btn btn-secondary">← My Tasks</a>
            </div>
        </div>
    </div>
    
    <div class="container">
        <?php if ($error && !$task): ?>
            <div class="error">❌ <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
            <div class="card" style="text-align: center;">
                <h3>Access Denied</h3>
                <p>You don't have permission to edit this task or it doesn't exist.</p>
                <div style="margin-top: 20px;">
                    <a href="my_tasks.php" class="btn btn-primary">Back to My Tasks</a>
                    <a href="index.php" class="btn btn-secondary">Go to Dashboard</a>
                </div>
            </div>
        <?php else: ?>
            <div class="security-notice">
                🔒 <strong>Security Enabled:</strong> This form uses CSRF protection, input validation, and ownership verification.
            </div>
            
            <div class="card">
                <h2>✏️ Edit Task #<?php echo (int)$task['id']; ?></h2>
                
                <!-- Task Information -->
                <div class="task-info">
                    <div class="info-row">
                        <div class="info-label">Task ID:</div>
                        <div class="info-value">
                            <strong>#<?php echo (int)$task['id']; ?></strong>
                            <span class="status-indicator status-<?php echo str_replace(' ', '-', htmlspecialchars($task['status'], ENT_QUOTES, 'UTF-8')); ?>">
                                <?php 
                                $status_icons = [
                                    'todo' => '📝',
                                    'in-progress' => '🔄',
                                    'completed' => '✅'
                                ];
                                $status_key = str_replace(' ', '-', $task['status']);
                                echo $status_icons[$status_key] . ' ' . htmlspecialchars(ucwords($task['status']), ENT_QUOTES, 'UTF-8');
                                ?>
                            </span>
                        </div>
                    </div>
                    <div class="info-row">
                        <div class="info-label">Created:</div>
                        <div class="info-value">📅 <?php echo htmlspecialchars(date('F d, Y H:i', strtotime($task['created_at'])), ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                    <div class="info-row">
                        <div class="info-label">Last Updated:</div>
                        <div class="info-value">✏️ <?php echo htmlspecialchars(date('F d, Y H:i', strtotime($task['updated_at'])), ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                    <div class="info-row">
                        <div class="info-label">Ownership:</div>
                        <div class="info-value">👤 <?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?> (User ID: <?php echo (int)$user_id; ?>)</div>
                    </div>
                </div>
                
                <?php if ($error): ?>
                    <div class="error">❌ <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
                <?php endif; ?>
                
                <?php if ($success): ?>
                    <div class="success">✅ <?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></div>
                    <div style="text-align: center; margin: 20px 0;">
                        <a href="my_tasks.php" class="btn btn-primary">Back to My Tasks</a>
                        <a href="edit_task.php?id=<?php echo (int)$task_id; ?>&csrf=<?php echo urlencode(generate_csrf_token()); ?>" class="btn btn-secondary">Continue Editing</a>
                    </div>
                <?php endif; ?>
                
                <?php if (!$success): ?>
                <!-- Edit Form -->
                <form method="POST" action="" id="editTaskForm" autocomplete="off">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                    
                    <div class="form-group">
                        <label for="title" class="required">Task Title</label>
                        <input type="text" 
                               id="title" 
                               name="title" 
                               value="<?php echo htmlspecialchars($form_data['title'] ?? $task['title'], ENT_QUOTES, 'UTF-8'); ?>"
                               placeholder="What needs to be done? (3-200 characters)"
                               required
                               minlength="3"
                               maxlength="200"
                               oninput="updateCharCounter('title', 200)">
                        <div class="char-counter" id="titleCounter"><?php echo strlen($form_data['title'] ?? $task['title']); ?>/200</div>
                    </div>
                    
                    <div class="form-group">
                        <label for="description">Description</label>
                        <textarea id="description" 
                                  name="description" 
                                  placeholder="Add details about this task... (max 1000 characters)"
                                  rows="6"
                                  maxlength="1000"
                                  oninput="updateCharCounter('description', 1000)"><?php echo htmlspecialchars($form_data['description'] ?? $task['description'], ENT_QUOTES, 'UTF-8'); ?></textarea>
                        <div class="char-counter" id="descriptionCounter"><?php echo strlen($form_data['description'] ?? $task['description']); ?>/1000</div>
                    </div>
                    
                    <div class="form-group">
                        <label for="status">Status</label>
                        <select id="status" name="status" class="status-select">
                            <option value="todo" <?php echo ($form_data['status'] ?? $task['status']) === 'todo' ? 'selected' : ''; ?>>📝 To Do</option>
                            <option value="in progress" <?php echo ($form_data['status'] ?? $task['status']) === 'in progress' ? 'selected' : ''; ?>>🔄 In Progress</option>
                            <option value="completed" <?php echo ($form_data['status'] ?? $task['status']) === 'completed' ? 'selected' : ''; ?>>✅ Completed</option>
                        </select>
                    </div>
                    
                    <div class="form-actions">
                        <button type="submit" class="btn btn-success" id="submitBtn">
                            💾 Save Changes
                        </button>
                        <a href="my_tasks.php" class="btn btn-secondary">Cancel</a>
                        
                    <!-- Secure Delete Form -->
                        <a href="delete_task.php?id=<?php echo $task['id']; ?>&csrf=<?php echo urlencode($csrf_token); ?>" 
                        class="btn btn-danger">
                        🗑️ Delete Task
                        </a>
                    </form>
                    </div>
                </form>
                <?php endif; ?>
            </div>
            
            <!-- Quick Navigation -->
            <div class="card" style="margin-top: 20px;">
                <h3>🚀 Quick Navigation</h3>
                <div style="display: flex; gap: 10px; margin-top: 15px; flex-wrap: wrap;">
                    <a href="my_tasks.php" class="btn btn-primary">📋 View All Tasks</a>
                    <a href="add_task.php" class="btn btn-success">➕ Add New Task</a>
                    <a href="index.php" class="btn btn-secondary">🏠 Dashboard</a>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <script>
        // Character counter
        function updateCharCounter(fieldId, maxLength) {
            const field = document.getElementById(fieldId);
            const counter = document.getElementById(fieldId + 'Counter');
            const length = field.value.length;
            
            counter.textContent = `${length}/${maxLength}`;
            
            // Update counter color based on length
            counter.className = 'char-counter';
            if (length > maxLength * 0.9) {
                counter.className = 'char-counter danger';
            } else if (length > maxLength * 0.7) {
                counter.className = 'char-counter warning';
            }
            
            // Enforce max length
            if (length > maxLength) {
                field.value = field.value.substring(0, maxLength);
            }
        }
        
        // Confirm task deletion
        function confirmDeleteTask() {
            const taskTitle = document.getElementById('title').value.trim();
            return confirm(`⚠️ Are you sure you want to delete this task?\n\n"${taskTitle}"\n\nThis action cannot be undone and will be logged for security purposes.`);
        }
        
        // Form validation and submission
        const editTaskForm = document.getElementById('editTaskForm');
        if (editTaskForm) {
            editTaskForm.addEventListener('submit', function(e) {
                const title = document.getElementById('title').value.trim();
                const description = document.getElementById('description').value;
                const submitBtn = document.getElementById('submitBtn');
                
                // Client-side validation
                if (title.length < 3) {
                    e.preventDefault();
                    alert('Task title must be at least 3 characters long.');
                    document.getElementById('title').focus();
                    return;
                }
                
                if (title.length > 200) {
                    e.preventDefault();
                    alert('Task title cannot exceed 200 characters.');
                    document.getElementById('title').focus();
                    return;
                }
                
                if (description.length > 1000) {
                    e.preventDefault();
                    alert('Description cannot exceed 1000 characters.');
                    document.getElementById('description').focus();
                    return;
                }
                
                // Disable button to prevent double submission
                submitBtn.disabled = true;
                submitBtn.innerHTML = '🔄 Saving Changes...';
                
                // Add form data attribute for beforeunload warning
                this.setAttribute('data-unsaved', 'true');
            });
        }
        
        // Status selector styling
        document.querySelectorAll('.status-select').forEach(select => {
            select.addEventListener('change', function() {
                const colors = {
                    'todo': '#ff9800',
                    'in progress': '#2196F3',
                    'completed': '#4CAF50'
                };
                this.style.borderColor = colors[this.value] || '#ddd';
                this.style.color = colors[this.value] || '#333';
            });
            
            // Trigger initial color
            select.dispatchEvent(new Event('change'));
        });
        
        // Initialize character counters
        document.addEventListener('DOMContentLoaded', function() {
            updateCharCounter('title', 200);
            updateCharCounter('description', 1000);
            
            // Auto-focus title field
            document.getElementById('title')?.focus();
            
            // Warn before leaving with unsaved changes
            window.addEventListener('beforeunload', function (e) {
                const form = document.getElementById('editTaskForm');
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
                window.location.href = 'my_tasks.php';
            }
        });

        // Confirm task deletion
        function confirmDeleteTask() {
            const taskTitle = document.getElementById('title').value.trim();
            return confirm(`⚠️ Are you sure you want to delete this task?\n\n"${taskTitle}"\n\nThis action cannot be undone and will be logged for security purposes.`);
        }
    </script>
</body>
</html>