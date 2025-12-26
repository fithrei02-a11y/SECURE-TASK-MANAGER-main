<?php
require_once __DIR__ . '/../includes/config.php';

echo "<h2>⚠️ Database Users (Plain Text Passwords Visible)</h2>";
echo "<p style='color: red;'>SECURITY WARNING: This exposes all passwords!</p>";

$result = $conn->query("SELECT id, username, email, password, created_at FROM users ORDER BY id");

echo "<table border='1' cellpadding='10' cellspacing='0' style='border-collapse: collapse;'>";
echo "<tr style='background: #333; color: white;'>
        <th>ID</th>
        <th>Username</th>
        <th>Email</th>
        <th>Password (Plain Text)</th>
        <th>Created</th>
      </tr>";

while ($row = $result->fetch_assoc()) {
    echo "<tr>";
    echo "<td>{$row['id']}</td>";
    echo "<td>{$row['username']}</td>";
    echo "<td>{$row['email']}</td>";
    echo "<td style='color: green; font-weight: bold;'>{$row['password']}</td>";
    echo "<td>{$row['created_at']}</td>";
    echo "</tr>";
}

echo "</table>";
echo "<br><p>Total users: " . $result->num_rows . "</p>";
?>

<br>
<a href="login_plain.php">← Back to Login</a>