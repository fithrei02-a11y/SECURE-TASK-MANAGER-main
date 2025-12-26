<?php
// ============================================================================
// SECURE LOGOUT SYSTEM - OWASP COMPLIANT
// ============================================================================

// Include secure configuration
require_once 'includes/config.php';

// Check if user is authenticated to log the event
$user_id = $_SESSION['user_id'] ?? null;
$username = $_SESSION['username'] ?? 'Guest';
$ip_address = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';

// CSRF protection for logout (if triggered via GET with token)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['token'])) {
    if (!validate_csrf_token($_GET['token'])) {
        // Log CSRF attempt
        log_security_event('CSRF logout attempt blocked', [
            'ip' => $ip_address,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
        ]);
        
        // Redirect with error
        $_SESSION['error'] = 'Security token invalid';
        header('Location: login.php');
        exit();
    }
}

// Log the logout event if user was authenticated
if ($user_id) {
    log_security_event('User logged out', [
        'user_id' => $user_id,
        'username' => $username,
        'ip' => $ip_address,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
        'logout_method' => isset($_GET['timeout']) ? 'session_timeout' : 'manual'
    ]);
    
    // Log system event
    log_system_event('INFO', 'User logged out', [
        'user_id' => $user_id,
        'username' => $username
    ]);
}

// ============================================================================
// SECURE SESSION DESTRUCTION
// ============================================================================

// Store session ID for complete destruction
$session_id = session_id();

// Unset all session variables
$_SESSION = [];

// Regenerate session ID to prevent session fixation
if (session_status() === PHP_SESSION_ACTIVE) {
    // Attempt to regenerate ID with deletion of old session
    if (function_exists('session_regenerate_id')) {
        session_regenerate_id(true);
    }
}

// Delete session cookie with secure parameters
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    
    // Set expiration to past date
    $expire_time = time() - 3600; // 1 hour ago
    
    // Delete cookie with secure attributes
    setcookie(
        session_name(),
        '',
        [
            'expires' => $expire_time,
            'path' => $params["path"],
            'domain' => $params["domain"],
            'secure' => $params["secure"] ?? false,
            'httponly' => $params["httponly"] ?? true,
            'samesite' => 'Strict'
        ]
    );
    
    // Additional cookie deletion for common session names
    $common_session_names = ['PHPSESSID', 'session_id', 'sid'];
    foreach ($common_session_names as $cookie_name) {
        if (isset($_COOKIE[$cookie_name])) {
            setcookie($cookie_name, '', $expire_time, '/');
        }
    }
}

// Clear session data from memory
session_unset();

// Destroy the session
if (session_status() === PHP_SESSION_ACTIVE) {
    session_destroy();
}

// Clear any residual session data in memory
unset($_SESSION);
unset($GLOBALS['_SESSION']);

// Clear session ID
if ($session_id) {
    // Log session destruction for audit
    if ($user_id) {
        log_system_event('SECURITY', 'Session destroyed', [
            'old_session_id' => $session_id,
            'user_id' => $user_id,
            'ip' => $ip_address
        ]);
    }
}

// ============================================================================
// ADDITIONAL SECURITY CLEANUP
// ============================================================================

// Clear browser cache headers to prevent back button access
header("Cache-Control: no-cache, no-store, must-revalidate"); // HTTP 1.1
header("Pragma: no-cache"); // HTTP 1.0
header("Expires: 0"); // Proxies

// Security headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

// Clear any output buffering
while (ob_get_level()) {
    ob_end_clean();
}

// ============================================================================
// REDIRECTION WITH APPROPRIATE MESSAGE
// ============================================================================

// Set logout message
$message = '';

if (isset($_GET['timeout'])) {
    $message = '?timeout=1&message=' . urlencode('Your session has expired due to inactivity. Please login again.');
} elseif (isset($_GET['force'])) {
    $message = '?message=' . urlencode('You have been logged out by the system administrator.');
} else {
    $message = '?message=' . urlencode('You have been successfully logged out.');
}

// Check for AJAX request
if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
    // AJAX response
    header('Content-Type: application/json');
    echo json_encode([
        'status' => 'success',
        'message' => 'Logged out successfully',
        'redirect' => 'login.php' . $message
    ]);
    exit();
}

// Regular HTTP redirect
header('Location: login.php' . $message);

// Force exit to prevent any further execution
exit(0);

// ============================================================================
// ALTERNATIVE: LOGOUT FUNCTION FOR INCLUSION IN OTHER FILES
// ============================================================================

/**
 * Secure logout function that can be called from anywhere
 */
function secure_logout($reason = 'manual') {
    global $conn;
    
    $user_id = $_SESSION['user_id'] ?? null;
    $username = $_SESSION['username'] ?? 'Guest';
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    
    // Log logout event
    if ($user_id) {
        $stmt = $conn->prepare("INSERT INTO audit_logs (user_id, username, action, ip_address, details) VALUES (?, ?, ?, ?, ?)");
        $action = "Logged out ($reason)";
        $details = json_encode(['reason' => $reason, 'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown']);
        $stmt->bind_param("issss", $user_id, $username, $action, $ip_address, $details);
        $stmt->execute();
        $stmt->close();
    }
    
    // Destroy session
    $_SESSION = [];
    
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 3600,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    
    session_destroy();
    
    // Return redirect URL
    return 'login.php?message=' . urlencode("Logged out successfully. Reason: $reason");
}
?>