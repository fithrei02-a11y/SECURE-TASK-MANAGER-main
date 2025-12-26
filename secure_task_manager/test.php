<?php
require_once 'includes/config.php';

echo "<h1>Database Connection Test</h1>";

if ($conn) {
    echo "✅ Database connected successfully!<br>";
    
    // Test query
    $result = $conn->query("SELECT COUNT(*) as count FROM users");
    $row = $result->fetch_assoc();
    echo "✅ Users in database: " . $row['count'] . "<br>";
    
    echo "✅ Your XAMPP setup is working!";
} else {
    echo "❌ Database connection failed!";
}
?>