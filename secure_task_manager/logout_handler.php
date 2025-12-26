<?php
// logout_handler.php
require_once 'includes/config.php';

// Only accept POST requests for logout to prevent CSRF
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); // Method Not Allowed
    header('Allow: POST');
    echo json_encode(['error' => 'Method not allowed']);
    exit();
}

// Validate CSRF token
if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
    http_response_code(403); // Forbidden
    log_security_event('Invalid CSRF token on logout', [
        'ip' => $_SERVER['REMOTE_ADDR']
    ]);
    echo json_encode(['error' => 'Security token invalid']);
    exit();
}

// Get user info before destroying session
$user_id = $_SESSION['user_id'] ?? null;
$username = $_SESSION['username'] ?? 'Guest';

// Log logout event
if ($user_id) {
    log_security_event('User logged out via form', [
        'user_id' => $user_id,
        'username' => $username,
        'ip' => $_SERVER['REMOTE_ADDR']
    ]);
}

// Destroy session
$_SESSION = [];
session_destroy();

// Clear session cookie
setcookie(session_name(), '', time() - 3600, '/', '', true, true);

// Response
header('Content-Type: application/json');
echo json_encode([
    'success' => true,
    'message' => 'Logged out successfully',
    'redirect' => 'login.php?message=' . urlencode('You have been logged out successfully.')
]);
exit();