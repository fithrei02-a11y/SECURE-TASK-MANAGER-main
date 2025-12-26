<?php
// ============================================================================
// SECURE TASK CREATION - OWASP COMPLIANT
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
$title = '';
$description = '';
$status = 'todo';
$form_data = [];

// Allowed status values (whitelist)
$allowed_statuses = ['todo', 'in progress', 'completed'];

// Process form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        $error = "Security token invalid. Please refresh the page and try again.";
        log_security_event('CSRF attempt on task creation', [
            'user_id' => $user_id,
            'username' => $username,
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
                // Insert task using prepared statement
                $stmt = $conn->prepare("INSERT INTO tasks (title, description, status, user_id) VALUES (?, ?, ?, ?)");
                $stmt->bind_param("sssi", $title, $description, $status, $user_id);
                
                if ($stmt->execute()) {
                    $task_id = $stmt->insert_id;
                    $success = "Task created successfully!";
                    
                    // Log task creation
                    log_security_event('Task created', [
                        'user_id' => $user_id,
                        'username' => $username,
                        'task_id' => $task_id,
                        'task_title' => $title,
                        'status' => $status
                    ]);
                    
                    // Log system event
                    log_system_event('INFO', 'New task created', [
                        'task_id' => $task_id,
                        'user_id' => $user_id,
                        'title' => $title
                    ]);
                    
                    // Clear form data on success
                    $form_data = [];
                    
                    // Optional: Redirect to task list after delay
                    // header("Refresh: 3; url=my_tasks.php");
                    
                } else {
                    throw new Exception("Database error: " . $stmt->error);
                }
                
                $stmt->close();
                
            } catch (Exception $e) {
                $error = "Failed to create task. Please try again.";
                log_system_event('ERROR', 'Task creation failed', [
                    'user_id' => $user_id,
                    'error' => $e->getMessage(),
                    'title' => $title
                ]);
            }
        }
    }
}

// Generate CSRF token
$csrf_token = generate_csrf_token();

// Set security headers (already done in config.php, but ensure)
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add New Task - Secure Task Manager</title>
    
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
            border-color: #4CAF50; 
            outline: none;
            box-shadow: 0 0 0 3px rgba(76, 175, 80, 0.1);
        }
        
        textarea { 
            min-height: 120px; 
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
            background: linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%); 
        }
        
        .btn-primary:hover { 
            background: linear-gradient(135deg, #2E7D32 0%, #4CAF50 100%);
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
        }
        
        .info-box {
            background: rgba(33, 150, 243, 0.1);
            border-left: 4px solid #2196F3;
            padding: 20px;
            border-radius: 8px;
            margin-top: 30px;
        }
        
        .security-notice {
            background: rgba(255, 152, 0, 0.1);
            border-left: 4px solid #ff9800;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 25px;
            font-size: 14px;
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
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div>
                <h1>➕ Add New Task</h1>
                <p style="opacity: 0.8; font-size: 14px;">Secure Task Creation | User: <?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></p>
            </div>
            <div>
                <a href="index.php" class="btn btn-secondary">← Back to Dashboard</a>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="security-notice">
            🔒 <strong>Security Enabled:</strong> This form uses CSRF protection, input validation, and SQL injection prevention.
        </div>
        
        <div class="card">
            <h2>📝 Create New Task</h2>
            <p>Fill in the details below to create a new task. All fields are validated for security.</p>
            
            <?php if ($error): ?>
                <div class="error">❌ <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="success">✅ <?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></div>
                <div style="text-align: center; margin: 20px 0;">
                    <a href="my_tasks.php" class="btn btn-primary">View Your Tasks</a>
                    <a href="add_task.php" class="btn btn-secondary">Create Another Task</a>
                </div>
            <?php endif; ?>
            
            <?php if (!$success): ?>
            <form method="POST" action="" id="taskForm" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                
                <div class="form-group">
                    <label for="title" class="required">Task Title</label>
                    <input type="text" 
                           id="title" 
                           name="title" 
                           value="<?php echo htmlspecialchars($form_data['title'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                           placeholder="What needs to be done? (3-200 characters)"
                           required
                           minlength="3"
                           maxlength="200"
                           oninput="updateCharCounter('title', 200)">
                    <div class="char-counter" id="titleCounter">0/200</div>
                </div>
                
                <div class="form-group">
                    <label for="description">Description</label>
                    <textarea id="description" 
                              name="description" 
                              placeholder="Add details about this task... (max 1000 characters)"
                              rows="4"
                              maxlength="1000"
                              oninput="updateCharCounter('description', 1000)"><?php echo htmlspecialchars($form_data['description'] ?? '', ENT_QUOTES, 'UTF-8'); ?></textarea>
                    <div class="char-counter" id="descriptionCounter">0/1000</div>
                </div>
                
                <div class="form-group">
                    <label for="status">Status</label>
                    <select id="status" name="status" class="status-select">
                        <option value="todo" <?php echo ($form_data['status'] ?? 'todo') === 'todo' ? 'selected' : ''; ?>>📝 To Do</option>
                        <option value="in progress" <?php echo ($form_data['status'] ?? 'todo') === 'in progress' ? 'selected' : ''; ?>>🔄 In Progress</option>
                        <option value="completed" <?php echo ($form_data['status'] ?? 'todo') === 'completed' ? 'selected' : ''; ?>>✅ Completed</option>
                    </select>
                </div>
                
                <div class="form-actions">
                    <button type="submit" class="btn btn-primary" id="submitBtn">
                        ➕ Create Task
                    </button>
                    <a href="index.php" class="btn btn-secondary">Cancel</a>
                </div>
            </form>
            <?php endif; ?>
            
            <div class="info-box">
                <h3>ℹ️ Task Guidelines</h3>
                <ul style="margin-top: 10px; padding-left: 20px;">
                    <li><strong>Title:</strong> Should be clear and descriptive (3-200 characters)</li>
                    <li><strong>Description:</strong> Optional details (max 1000 characters)</li>
                    <li><strong>Status:</strong> You can change this later when editing tasks</li>
                    <li><strong>Security:</strong> All inputs are validated and sanitized</li>
                    <li><strong>Logging:</strong> Task creation is logged for audit purposes</li>
                </ul>
                <p style="margin-top: 10px; font-style: italic; color: #666;">
                    ✅ All tasks are securely stored with proper authorization checks.
                </p>
            </div>
        </div>
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
        
        // Form validation and submission
        document.getElementById('taskForm')?.addEventListener('submit', function(e) {
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
            submitBtn.innerHTML = '🔄 Creating Task...';
            
            // Add form data attribute for beforeunload warning
            this.setAttribute('data-unsaved', 'true');
        });
        
        // Initialize character counters
        document.addEventListener('DOMContentLoaded', function() {
            updateCharCounter('title', 200);
            updateCharCounter('description', 1000);
            
            // Auto-focus title field
            document.getElementById('title')?.focus();
            
            // Warn before leaving with unsaved changes
            window.addEventListener('beforeunload', function (e) {
                const form = document.getElementById('taskForm');
                if (form && form.hasAttribute('data-unsaved')) {
                    e.preventDefault();
                    e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
                }
            });
            
            // Remove unsaved flag on successful form reset
            document.getElementById('taskForm')?.addEventListener('reset', function() {
                this.removeAttribute('data-unsaved');
            });
        });
        
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
    </script>
</body>
</html>