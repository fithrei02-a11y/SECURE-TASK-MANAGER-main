<?php
// ============================================================================
// SECURE CONFIGURATION FILE - OWASP COMPLIANT
// ============================================================================

// Start session with secure settings BEFORE any output
if (session_status() == PHP_SESSION_NONE) {
    // Session configuration for security
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 1); // Enable only if HTTPS is used
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
    
    session_start();
    
    // Regenerate session ID to prevent fixation
    if (!isset($_SESSION['initiated'])) {
        session_regenerate_id(true);
        $_SESSION['initiated'] = true;
    }
}

// Error reporting - Different for development and production
if ($_SERVER['SERVER_NAME'] === 'localhost' || $_SERVER['SERVER_ADDR'] === '127.0.0.1') {
    // Development environment
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
    ini_set('log_errors', 1);
    define('ENVIRONMENT', 'development');
} else {
    // Production environment
    error_reporting(0);
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    ini_set('error_log', '/path/to/secure/error.log'); // Set your error log path
    define('ENVIRONMENT', 'production');
}

// ============================================================================
// DATABASE CONFIGURATION
// ============================================================================

// Use environment variables for production (never hardcode)
if (ENVIRONMENT === 'production') {
    // For production, these should be set in .env file or server environment
    define('DB_HOST', getenv('DB_HOST') ?: 'localhost');
    define('DB_USER', getenv('DB_USER') ?: 'root');
    define('DB_PASS', getenv('DB_PASS') ?: '');
    define('DB_NAME', getenv('DB_NAME') ?: 'task_manager');
} else {
    // Development defaults
    define('DB_HOST', 'localhost');
    define('DB_USER', 'root');
    define('DB_PASS', '');
    define('DB_NAME', 'task_manager');
}

// Create database connection with error handling
try {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if ($conn->connect_error) {
        throw new Exception("Database connection failed");
    }
    
    // Set charset to UTF-8
    if (!$conn->set_charset("utf8mb4")) {
        throw new Exception("Error setting character set: " . $conn->error);
    }
    
} catch (Exception $e) {
    // Log error securely
    error_log("Database connection error: " . $e->getMessage());
    
    // Show generic error message to user
    if (ENVIRONMENT === 'development') {
        die("Database connection error: " . htmlspecialchars($e->getMessage()));
    } else {
        die("System temporarily unavailable. Please try again later.");
    }
}

// ============================================================================
// SECURITY FUNCTIONS
// ============================================================================

/**
 * Generate CSRF token
 */
function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Validate CSRF token
 */
function validate_csrf_token($token) {
    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        // Log CSRF attempt
        log_security_event('CSRF attack attempt', [
            'ip' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
        ]);
        return false;
    }
    return true;
}

/**
 * Sanitize input data
 */
function sanitize_input($data) {
    if (is_array($data)) {
        return array_map('sanitize_input', $data);
    }
    
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    return $data;
}

/**
 * Validate email format
 */
function validate_email($email) {
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }
    
    // Additional checks for email security
    $email = filter_var($email, FILTER_SANITIZE_EMAIL);
    
    // Check for dangerous characters
    if (preg_match('/[\r\n]/', $email)) {
        return false;
    }
    
    return $email;
}

/**
 * Validate password strength
 */
function validate_password($password) {
    // OWASP password recommendations
    $min_length = 12;
    
    if (strlen($password) < $min_length) {
        return "Password must be at least $min_length characters long";
    }
    
    // Check for common patterns
    if (preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\d\s:]).{12,}$/', $password)) {
        return true;
    }
    
    return "Password must contain uppercase, lowercase, numbers, and special characters";
}

/**
 * Hash password using bcrypt
 */
function hash_password($password) {
    // REMOVE THIS LINE:
    // return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    
    // REPLACE WITH (plaintext storage - INSECURE):
    return $password;
}
/**
 * Verify password
 */
function verify_password($password, $stored_password) {
    // REMOVE THIS LINE:
    // return password_verify($password, $hash);
    
    // REPLACE WITH (plaintext comparison - INSECURE):
    return $password === $stored_password;
}

/**
 * Log security events
 */
function log_security_event($action, $details = []) {
    global $conn;
    
    $user_id = $_SESSION['user_id'] ?? null;
    $username = $_SESSION['username'] ?? 'Guest';
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    
    $details_json = json_encode($details);
    
    $stmt = $conn->prepare("INSERT INTO audit_logs (user_id, username, action, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("isssss", $user_id, $username, $action, $ip_address, $user_agent, $details_json);
    $stmt->execute();
    $stmt->close();
}

/**
 * Log system events
 */
function log_system_event($level, $message, $context = []) {
    global $conn;
    
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    $user_id = $_SESSION['user_id'] ?? null;
    $context_json = json_encode($context);
    
    $stmt = $conn->prepare("INSERT INTO system_logs (level, message, context, ip_address, user_id) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssi", $level, $message, $context_json, $ip_address, $user_id);
    $stmt->execute();
    $stmt->close();
}

/**
 * Check if user is authenticated
 */
function is_authenticated() {
    return isset($_SESSION['user_id'], $_SESSION['username'], $_SESSION['last_activity']);
}

/**
 * Check if user is admin
 */
function is_admin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === 1;
}

/**
 * Require authentication
 */
function require_auth() {
    if (!is_authenticated()) {
        $_SESSION['redirect_url'] = $_SERVER['REQUEST_URI'];
        header('Location: login.php');
        exit;
    }
    
    // Check session timeout (30 minutes)
    if (time() - $_SESSION['last_activity'] > 1800) {
        session_destroy();
        header('Location: login.php?timeout=1');
        exit;
    }
    
    $_SESSION['last_activity'] = time();
}

/**
 * Require admin privileges
 */
function require_admin() {
    require_auth();
    
    if (!is_admin()) {
        header('HTTP/1.1 403 Forbidden');
        include('403.php'); // Create this error page
        exit;
    }
}

/**
 * Set security headers
 */
function set_security_headers() {
    // Prevent clickjacking
    header('X-Frame-Options: DENY');
    
    // Enable XSS protection
    header('X-XSS-Protection: 1; mode=block');
    
    // Prevent MIME sniffing
    header('X-Content-Type-Options: nosniff');
    
    // Referrer policy
    header('Referrer-Policy: strict-origin-when-cross-origin');
    
    // Content Security Policy
    $csp = "default-src 'self'; ";
    $csp .= "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; ";
    $csp .= "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; ";
    $csp .= "img-src 'self' data:; ";
    $csp .= "connect-src 'self'; ";
    $csp .= "font-src 'self' https://cdnjs.cloudflare.com; ";
    $csp .= "object-src 'none'; ";
    $csp .= "frame-ancestors 'none'; ";
    $csp .= "base-uri 'self'; ";
    $csp .= "form-action 'self';";
    
    header("Content-Security-Policy: " . $csp);
}

// Set security headers
set_security_headers();

// Generate CSRF token for forms
$csrf_token = generate_csrf_token();

// Initialize security logging
register_shutdown_function(function() {
    if (ENVIRONMENT === 'production') {
        $error = error_get_last();
        if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            log_system_event('ERROR', $error['message'], [
                'file' => $error['file'],
                'line' => $error['line']
            ]);
        }
    }
});

?>