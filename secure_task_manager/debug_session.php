<?php
// ============================================================================
// SECURE SESSION DEBUGGER - FOR DEVELOPMENT ONLY
// ============================================================================

// Include secure configuration
require_once 'includes/config.php';

// Only allow in development environment
if (ENVIRONMENT !== 'development') {
    http_response_code(403);
    die('Access denied. This debug tool is only available in development environment.');
}

// Require admin privileges for security
require_admin();

// Get current session information
$session_id = session_id();
$session_status = session_status();
$session_name = session_name();

// Get session file path (if using file-based sessions)
$session_save_path = session_save_path();
$session_file = $session_save_path . '/sess_' . $session_id;

// Get all session variables
$session_data = $_SESSION;

// Get security information
$security_info = [
    'session.cookie_httponly' => ini_get('session.cookie_httponly'),
    'session.cookie_secure' => ini_get('session.cookie_secure'),
    'session.cookie_samesite' => ini_get('session.cookie_samesite'),
    'session.use_strict_mode' => ini_get('session.use_strict_mode'),
    'session.cookie_lifetime' => ini_get('session.cookie_lifetime'),
    'session.gc_maxlifetime' => ini_get('session.gc_maxlifetime'),
];

// Get request information
$request_info = [
    'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
    'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'Unknown',
    'https' => isset($_SERVER['HTTPS']) ? 'Yes' : 'No',
];

// Log access to this debug page
log_security_event('Admin accessed session debug page', [
    'admin_id' => $_SESSION['user_id'],
    'admin_username' => $_SESSION['username'],
    'ip' => $_SERVER['REMOTE_ADDR']
]);

// Generate CSRF token for any actions
$csrf_token = generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Session Debug - Admin Only</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Courier New', monospace; }
        body { background: #1a1a1a; color: #00ff00; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #003300; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .section { background: #002200; padding: 20px; border-radius: 5px; margin-bottom: 20px; border: 1px solid #005500; }
        .section h2 { color: #00cc00; margin-bottom: 15px; border-bottom: 1px solid #005500; padding-bottom: 10px; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }
        .info-item { background: #001100; padding: 15px; border-radius: 5px; border-left: 3px solid #00aa00; }
        .info-label { color: #88ff88; font-weight: bold; margin-bottom: 5px; }
        .info-value { color: #ffffff; word-break: break-all; }
        .warning { background: #332200; border-left: 3px solid #ff9900; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
        .danger { background: #330000; border-left: 3px solid #ff0000; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
        .btn { display: inline-block; padding: 10px 20px; background: #005500; color: white; text-decoration: none; border-radius: 3px; margin: 5px; border: none; cursor: pointer; }
        .btn:hover { background: #007700; }
        .btn-danger { background: #550000; }
        .btn-danger:hover { background: #770000; }
        pre { background: #001100; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .actions { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 20px; }
        .form-inline { display: inline; }
        input[type="hidden"] { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Secure Session Debugger</h1>
            <p><strong>⚠️ WARNING:</strong> This page contains sensitive information. Access restricted to administrators only.</p>
            <p>Environment: <?php echo ENVIRONMENT; ?> | Time: <?php echo date('Y-m-d H:i:s'); ?></p>
        </div>
        
        <div class="warning">
            <h3>⚠️ SECURITY NOTICE</h3>
            <p>This debug page exposes sensitive session information. It should:</p>
            <ul>
                <li>Only be accessible in development environment</li>
                <li>Only be accessible to administrators</li>
                <li>Be disabled in production (ENVIRONMENT !== 'development')</li>
                <li>All access is logged to audit logs</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>📊 Session Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Session ID (Hashed):</div>
                    <div class="info-value"><?php echo hash('sha256', $session_id); ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Session Status:</div>
                    <div class="info-value">
                        <?php 
                        switch($session_status) {
                            case PHP_SESSION_DISABLED: echo 'Disabled'; break;
                            case PHP_SESSION_NONE: echo 'None'; break;
                            case PHP_SESSION_ACTIVE: echo 'Active'; break;
                            default: echo 'Unknown';
                        }
                        ?>
                    </div>
                </div>
                <div class="info-item">
                    <div class="info-label">Session Name:</div>
                    <div class="info-value"><?php echo htmlspecialchars($session_name, ENT_QUOTES, 'UTF-8'); ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Session Save Path:</div>
                    <div class="info-value"><?php echo htmlspecialchars($session_save_path, ENT_QUOTES, 'UTF-8'); ?></div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>👤 User Session Data</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">User ID:</div>
                    <div class="info-value"><?php echo isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : 'Not set'; ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Username:</div>
                    <div class="info-value"><?php echo isset($_SESSION['username']) ? htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8') : 'Not set'; ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Email:</div>
                    <div class="info-value"><?php echo isset($_SESSION['email']) ? htmlspecialchars($_SESSION['email'], ENT_QUOTES, 'UTF-8') : 'Not set'; ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Is Admin:</div>
                    <div class="info-value"><?php echo isset($_SESSION['is_admin']) ? ($_SESSION['is_admin'] ? 'Yes 👑' : 'No') : 'Not set'; ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Last Activity:</div>
                    <div class="info-value"><?php echo isset($_SESSION['last_activity']) ? date('Y-m-d H:i:s', $_SESSION['last_activity']) : 'Not set'; ?></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Login Time:</div>
                    <div class="info-value"><?php echo isset($_SESSION['login_time']) ? date('Y-m-d H:i:s', $_SESSION['login_time']) : 'Not set'; ?></div>
                </div>
            </div>
            
            <div style="margin-top: 20px;">
                <h3>Full Session Data (JSON):</h3>
                <pre><?php echo json_encode($session_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
            </div>
        </div>
        
        <div class="section">
            <h2>🔒 Security Configuration</h2>
            <div class="info-grid">
                <?php foreach($security_info as $key => $value): ?>
                <div class="info-item">
                    <div class="info-label"><?php echo htmlspecialchars($key, ENT_QUOTES, 'UTF-8'); ?>:</div>
                    <div class="info-value"><?php echo htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); ?></div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        
        <div class="section">
            <h2>🌐 Request Information</h2>
            <div class="info-grid">
                <?php foreach($request_info as $key => $value): ?>
                <div class="info-item">
                    <div class="info-label"><?php echo htmlspecialchars($key, ENT_QUOTES, 'UTF-8'); ?>:</div>
                    <div class="info-value"><?php echo htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); ?></div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        
        <div class="danger">
            <h3>⚠️ DANGER ZONE - ADMIN ACTIONS</h3>
            <p>These actions can affect system security and user sessions. Use with extreme caution.</p>
            
            <div class="actions">
                <!-- Regenerate Session ID -->
                <form class="form-inline" method="POST" action="?action=regenerate_session" onsubmit="return confirm('Are you sure you want to regenerate the session ID?')">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                    <button type="submit" class="btn">🔄 Regenerate Session ID</button>
                </form>
                
                <!-- Clear Session Data -->
                <form class="form-inline" method="POST" action="?action=clear_session" onsubmit="return confirm('Are you sure you want to clear all session data?')">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                    <button type="submit" class="btn">🗑️ Clear Session Data</button>
                </form>
                
                <!-- Destroy Session -->
                <form class="form-inline" method="POST" action="?action=destroy_session" onsubmit="return confirm('Are you sure you want to destroy the session? You will be logged out.')">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                    <button type="submit" class="btn btn-danger">💀 Destroy Session</button>
                </form>
                
                <!-- View All Active Sessions (Admin only) -->
                <a href="admin/system_logs.php?filter=session" class="btn">📋 View Session Logs</a>
                
                <!-- Back to Dashboard -->
                <a href="index.php" class="btn">🏠 Back to Dashboard</a>
            </div>
        </div>
        
        <?php
        // Handle form actions
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $action = $_GET['action'] ?? '';
            
            // Validate CSRF token
            if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
                echo '<div class="danger">CSRF token validation failed!</div>';
            } else {
                switch($action) {
                    case 'regenerate_session':
                        if (session_status() === PHP_SESSION_ACTIVE) {
                            session_regenerate_id(true);
                            log_security_event('Admin regenerated session ID', [
                                'admin_id' => $_SESSION['user_id'],
                                'old_session_id' => $session_id
                            ]);
                            echo '<div class="section" style="background: #003300;">✅ Session ID regenerated successfully!</div>';
                        }
                        break;
                        
                    case 'clear_session':
                        $_SESSION = [];
                        log_security_event('Admin cleared session data', [
                            'admin_id' => $_SESSION['user_id']
                        ]);
                        echo '<div class="section" style="background: #003300;">✅ Session data cleared!</div>';
                        break;
                        
                    case 'destroy_session':
                        session_destroy();
                        log_security_event('Admin destroyed session', [
                            'admin_id' => isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null
                        ]);
                        echo '<div class="section" style="background: #003300;">✅ Session destroyed! Redirecting to login...</div>';
                        echo '<script>setTimeout(function(){ window.location.href = "login.php"; }, 2000);</script>';
                        break;
                }
            }
        }
        ?>
        
        <div class="section">
            <h2>📝 Access Log</h2>
            <p>All access to this page is logged in the audit system.</p>
            <p><strong>Last Access:</strong> <?php echo date('Y-m-d H:i:s'); ?></p>
            <p><strong>Access Count:</strong> <?php 
                // This would come from a database query in real implementation
                echo "Logged in audit_logs table"; 
            ?></p>
        </div>
    </div>
    
    <script>
        // Auto-refresh session data every 30 seconds
        setTimeout(function() {
            location.reload();
        }, 30000);
        
        // Copy session ID hash to clipboard
        function copySessionHash() {
            const hash = document.querySelector('.info-value').textContent;
            navigator.clipboard.writeText(hash).then(() => {
                alert('Session hash copied to clipboard!');
            });
        }
        
        // Confirm before leaving page if changes were made
        window.addEventListener('beforeunload', function (e) {
            const forms = document.querySelectorAll('form');
            let hasChanges = false;
            
            forms.forEach(form => {
                if (form.hasAttribute('data-modified')) {
                    hasChanges = true;
                }
            });
            
            if (hasChanges) {
                e.preventDefault();
                e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
            }
        });
    </script>
</body>
</html>