<?php
// ============================================================================
// SECURE TASK DELETION - OWASP COMPLIANT
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
$success = false;
$task_info = null;

// Handle both GET (with CSRF in URL) and POST requests
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // GET method: validate CSRF token from URL
    $task_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
    $url_csrf = $_GET['csrf'] ?? '';
    
    if ($task_id <= 0) {
        $error = "Invalid task ID.";
    } elseif (!$url_csrf || !validate_csrf_token($url_csrf)) {
        $error = "Security token invalid. Access denied.";
        log_security_event('Invalid CSRF token on task deletion (GET)', [
            'user_id' => $user_id,
            'task_id' => $task_id,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
        ]);
    } else {
        // Valid GET request with CSRF token - show confirmation page
        display_delete_confirmation($task_id, $user_id, $is_admin);
        exit();
    }
    
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // POST method: process deletion
    $task_id = isset($_POST['task_id']) ? (int)$_POST['task_id'] : 0;
    $post_csrf = $_POST['csrf_token'] ?? '';
    
    // Validate CSRF token
    if (!$post_csrf || !validate_csrf_token($post_csrf)) {
        $error = "Security token invalid. Access denied.";
        log_security_event('Invalid CSRF token on task deletion (POST)', [
            'user_id' => $user_id,
            'task_id' => $task_id,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
        ]);
        $success = false;
    } elseif ($task_id <= 0) {
        $error = "Invalid task ID.";
        $success = false;
    } else {
        // Get task info before deletion for logging
        $task_info = get_task_info($task_id, $user_id, $is_admin);
        
        if (!$task_info) {
            $error = "Task not found or you don't have permission to delete it.";
            log_security_event('Unauthorized task deletion attempt', [
                'user_id' => $user_id,
                'task_id' => $task_id,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
            ]);
            $success = false;
        } else {
            // Perform deletion
            $success = delete_task($task_id, $user_id, $is_admin, $task_info);
            
            if ($success) {
                // Success - prepare JSON response or redirect
                handle_success_response($task_id);
            } else {
                $error = "Failed to delete task. Please try again.";
                $success = false;
            }
        }
    }
    
    // Handle AJAX requests
    if (is_ajax_request()) {
        header('Content-Type: application/json');
        echo json_encode([
            'success' => $success,
            'error' => $error,
            'task_id' => $task_id,
            'redirect' => $success ? 'my_tasks.php?deleted=1' : 'my_tasks.php?error=delete_failed'
        ]);
        exit();
    }
    
    // Regular HTTP request - redirect
    if ($success) {
        header("Location: my_tasks.php?deleted=1");
    } else {
        header("Location: my_tasks.php?error=" . urlencode($error ?: 'delete_failed'));
    }
    exit();
} else {
    // Invalid method
    http_response_code(405);
    $error = "Method not allowed.";
}

// If we reach here, there was an error
handle_error($error);

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Display delete confirmation page
 */
function display_delete_confirmation($task_id, $user_id, $is_admin) {
    global $conn;
    
    // Get task information
    $task_info = get_task_info($task_id, $user_id, $is_admin);
    
    if (!$task_info) {
        header("Location: my_tasks.php?error=task_not_found");
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
    <title>Confirm Deletion - Secure Task Manager</title>
    
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
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .confirmation-container { 
            background: rgba(255, 255, 255, 0.95); 
            padding: 40px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3); 
            max-width: 600px; 
            width: 100%;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .warning-icon {
            font-size: 60px;
            text-align: center;
            margin-bottom: 20px;
            color: #f44336;
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
            font-size: 16px;
        }
        
        .task-info {
            background: rgba(248, 249, 250, 0.9);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            border-left: 4px solid #f44336;
        }
        
        .task-info h3 {
            color: #333;
            margin-bottom: 15px;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        
        .info-row {
            display: flex;
            margin-bottom: 10px;
        }
        
        .info-label {
            font-weight: 600;
            width: 120px;
            color: #666;
            font-size: 14px;
        }
        
        .info-value {
            color: #333;
            flex: 1;
        }
        
        .danger-zone {
            background: rgba(244, 67, 54, 0.1);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            border: 2px dashed #f44336;
        }
        
        .danger-zone h3 {
            color: #c62828;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
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
            min-width: 140px;
        }
        
        .btn:hover { 
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
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
        
        .form-actions { 
            display: flex; 
            gap: 15px; 
            justify-content: center;
            margin-top: 30px;
        }
        
        .security-notice {
            background: rgba(33, 150, 243, 0.1);
            border-left: 4px solid #2196F3;
            padding: 15px;
            border-radius: 8px;
            margin-top: 25px;
            font-size: 14px;
        }
        
        .checkbox-container {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 20px;
        }
        
        .checkbox-container input[type="checkbox"] {
            width: 20px;
            height: 20px;
        }
        
        .checkbox-container label {
            color: #c62828;
            font-weight: 600;
            cursor: pointer;
        }
        
        @media (max-width: 768px) {
            .confirmation-container {
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
    <div class="confirmation-container">
        <div class="warning-icon">
            ⚠️
        </div>
        
        <h1>Confirm Task Deletion</h1>
        <p class="subtitle">This action is permanent and cannot be undone.</p>
        
        <div class="task-info">
            <h3>📋 Task Information</h3>
            <div class="info-row">
                <div class="info-label">Task ID:</div>
                <div class="info-value">#<?php echo (int)$task_info['id']; ?></div>
            </div>
            <div class="info-row">
                <div class="info-label">Title:</div>
                <div class="info-value"><strong><?php echo htmlspecialchars($task_info['title'], ENT_QUOTES, 'UTF-8'); ?></strong></div>
            </div>
            <?php if (!empty($task_info['description'])): ?>
            <div class="info-row">
                <div class="info-label">Description:</div>
                <div class="info-value"><?php echo htmlspecialchars(substr($task_info['description'], 0, 100), ENT_QUOTES, 'UTF-8'); ?><?php echo strlen($task_info['description']) > 100 ? '...' : ''; ?></div>
            </div>
            <?php endif; ?>
            <div class="info-row">
                <div class="info-label">Status:</div>
                <div class="info-value"><?php echo htmlspecialchars(ucwords($task_info['status']), ENT_QUOTES, 'UTF-8'); ?></div>
            </div>
            <div class="info-row">
                <div class="info-label">Created:</div>
                <div class="info-value"><?php echo htmlspecialchars(date('M d, Y H:i', strtotime($task_info['created_at'])), ENT_QUOTES, 'UTF-8'); ?></div>
            </div>
        </div>
        
        <div class="danger-zone">
            <h3>⚠️ DANGER ZONE</h3>
            <p>You are about to permanently delete this task. This action will:</p>
            <ul style="margin: 10px 0 15px 20px; color: #666;">
                <li>Immediately remove the task from the database</li>
                <li>Log this deletion in the audit trail</li>
                <li>This action <strong>cannot be undone</strong></li>
                <li>No backup will be created</li>
            </ul>
        </div>
        
        <form method="POST" action="delete_task.php" id="deleteForm">
            <input type="hidden" name="task_id" value="<?php echo (int)$task_id; ?>">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
            
            <div class="checkbox-container">
                <input type="checkbox" id="confirmDelete" name="confirmDelete" required>
                <label for="confirmDelete">I understand this action is permanent and cannot be undone</label>
            </div>
            
            <div class="form-actions">
                <button type="submit" class="btn btn-danger" id="deleteBtn" disabled>
                    🗑️ Delete Permanently
                </button>
                <a href="my_tasks.php" class="btn btn-secondary">Cancel and Go Back</a>
            </div>
        </form>
        
        <div class="security-notice">
            🔒 <strong>Security Notice:</strong> This deletion will be logged for audit purposes. 
            All actions are recorded with your user ID, IP address, and timestamp.
        </div>
    </div>

    <script>
        // Enable delete button only when checkbox is checked
        document.getElementById('confirmDelete').addEventListener('change', function() {
            document.getElementById('deleteBtn').disabled = !this.checked;
        });
        
        // Form submission handling
        document.getElementById('deleteForm').addEventListener('submit', function(e) {
            const deleteBtn = document.getElementById('deleteBtn');
            const taskTitle = "<?php echo addslashes($task_info['title']); ?>";
            
            // Final confirmation
            if (!confirm(`FINAL WARNING: Are you absolutely sure you want to delete this task?\n\n"${taskTitle}"\n\nThis is your last chance to cancel.`)) {
                e.preventDefault();
                return;
            }
            
            // Disable button and show loading state
            deleteBtn.disabled = true;
            deleteBtn.innerHTML = '🔄 Deleting...';
            
            // Handle AJAX submission
            e.preventDefault();
            
            fetch('delete_task.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams(new FormData(this))
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Show success message and redirect
                    deleteBtn.innerHTML = '✅ Deleted!';
                    deleteBtn.style.background = 'linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%)';
                    
                    setTimeout(() => {
                        window.location.href = data.redirect;
                    }, 1000);
                } else {
                    // Show error
                    alert('Delete failed: ' + data.error);
                    deleteBtn.innerHTML = '🗑️ Delete Permanently';
                    deleteBtn.disabled = false;
                }
            })
            .catch(error => {
                console.error('Delete error:', error);
                alert('Delete failed. Please try again.');
                deleteBtn.innerHTML = '🗑️ Delete Permanently';
                deleteBtn.disabled = false;
            });
        });
        
        // Prevent accidental navigation
        let formModified = false;
        document.getElementById('deleteForm').addEventListener('change', () => formModified = true);
        
        window.addEventListener('beforeunload', function (e) {
            if (formModified) {
                e.preventDefault();
                e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
            }
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                window.location.href = 'my_tasks.php';
            }
        });
    </script>
</body>
</html>
    <?php
    exit();
}

/**
 * Get task information with authorization check
 */
function get_task_info($task_id, $user_id, $is_admin) {
    global $conn;
    
    try {
        if ($is_admin) {
            // Admins can delete any task
            $stmt = $conn->prepare("SELECT t.id, t.title, t.description, t.status, t.created_at, t.user_id, u.username 
                                   FROM tasks t 
                                   JOIN users u ON t.user_id = u.id 
                                   WHERE t.id = ?");
            $stmt->bind_param("i", $task_id);
        } else {
            // Regular users can only delete their own tasks
            $stmt = $conn->prepare("SELECT t.id, t.title, t.description, t.status, t.created_at, t.user_id, u.username 
                                   FROM tasks t 
                                   JOIN users u ON t.user_id = u.id 
                                   WHERE t.id = ? AND t.user_id = ?");
            $stmt->bind_param("ii", $task_id, $user_id);
        }
        
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows == 1) {
            return $result->fetch_assoc();
        }
        
        $stmt->close();
        return null;
        
    } catch (Exception $e) {
        log_system_event('ERROR', 'Failed to fetch task info for deletion', [
            'task_id' => $task_id,
            'error' => $e->getMessage()
        ]);
        return null;
    }
}

/**
 * Delete task with authorization check
 */
function delete_task($task_id, $user_id, $is_admin, $task_info) {
    global $conn;
    
    try {
        if ($is_admin) {
            // Admins can delete any task
            $stmt = $conn->prepare("DELETE FROM tasks WHERE id = ?");
            $stmt->bind_param("i", $task_id);
        } else {
            // Regular users can only delete their own tasks
            $stmt = $conn->prepare("DELETE FROM tasks WHERE id = ? AND user_id = ?");
            $stmt->bind_param("ii", $task_id, $user_id);
        }
        
        $stmt->execute();
        $affected_rows = $stmt->affected_rows;
        $stmt->close();
        
        if ($affected_rows > 0) {
            // Log successful deletion
            log_security_event('Task deleted', [
                'deleted_by_user_id' => $user_id,
                'deleted_by_username' => $_SESSION['username'],
                'task_id' => $task_id,
                'task_title' => $task_info['title'],
                'task_owner_id' => $task_info['user_id'],
                'task_owner_username' => $task_info['username'],
                'is_admin_action' => $is_admin,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
            ]);
            
            log_system_event('INFO', 'Task deleted', [
                'task_id' => $task_id,
                'deleted_by' => $user_id,
                'task_title' => $task_info['title']
            ]);
            
            return true;
        }
        
        return false;
        
    } catch (Exception $e) {
        log_system_event('ERROR', 'Task deletion failed', [
            'task_id' => $task_id,
            'user_id' => $user_id,
            'error' => $e->getMessage()
        ]);
        return false;
    }
}

/**
 * Check if request is AJAX
 */
function is_ajax_request() {
    return isset($_SERVER['HTTP_X_REQUESTED_WITH']) && 
           strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}

/**
 * Handle success response
 */
function handle_success_response($task_id) {
    global $user_id;
    
    // Log success
    log_system_event('INFO', 'Task deletion successful via ' . (is_ajax_request() ? 'AJAX' : 'HTTP'), [
        'task_id' => $task_id,
        'user_id' => $user_id
    ]);
}

/**
 * Handle error
 */
function handle_error($error) {
    log_system_event('ERROR', 'Task deletion error', [
        'error' => $error,
        'user_id' => $_SESSION['user_id'] ?? 'unknown'
    ]);
    
    if (is_ajax_request()) {
        header('Content-Type: application/json');
        echo json_encode([
            'success' => false,
            'error' => $error
        ]);
    } else {
        header("Location: my_tasks.php?error=" . urlencode($error));
    }
    exit();
}
?>