<?php
session_start();
require_once '../includes/config.php';

// Redirect to login if not logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: ../login.php");
    exit();
}

// Check if user is admin
if ($_SESSION['is_admin'] != 1) {
    header("Location: ../index.php");
    exit();
}

$page_title = "System Logs";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $page_title; ?> - Admin Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Courier New', monospace; }
        body { background: #1a1a1a; color: #e0e0e0; }
        .header { background: #000; color: #00ff00; padding: 20px; border-bottom: 1px solid #333; }
        .header-content { max-width: 1400px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; }
        .container { max-width: 1400px; margin: 30px auto; padding: 0 20px; }
        .card { background: #2a2a2a; padding: 25px; border-radius: 5px; border: 1px solid #444; margin-bottom: 20px; }
        .btn { display: inline-block; padding: 8px 16px; text-decoration: none; border-radius: 3px; font-size: 14px; border: none; cursor: pointer; }
        .btn-primary { background: #0066cc; color: white; }
        .btn-danger { background: #cc0000; color: white; }
        .btn-success { background: #00cc00; color: black; }
        .btn-secondary { background: #666; color: white; }
        .btn:hover { opacity: 0.8; }
        .admin-nav { background: #111; padding: 15px 0; margin-bottom: 20px; border-bottom: 1px solid #333; }
        .admin-nav ul { list-style: none; display: flex; justify-content: center; gap: 20px; max-width: 1400px; margin: 0 auto; padding: 0 20px; }
        .admin-nav a { color: #00ff00; text-decoration: none; padding: 8px 16px; border-radius: 3px; transition: background 0.3s; font-family: 'Courier New', monospace; }
        .admin-nav a:hover { background: #333; }
        .admin-nav a.active { background: #006600; }
        .log-container { background: #000; padding: 20px; border-radius: 5px; border: 1px solid #444; font-family: 'Courier New', monospace; font-size: 14px; line-height: 1.5; }
        .log-line { margin-bottom: 5px; padding: 2px 5px; border-left: 3px solid transparent; }
        .log-line:hover { background: #333; }
        .log-info { border-left-color: #0066cc; color: #66b3ff; }
        .log-warning { border-left-color: #ff9900; color: #ffcc66; }
        .log-error { border-left-color: #cc0000; color: #ff6666; }
        .log-success { border-left-color: #00cc00; color: #66ff66; }
        .log-debug { border-left-color: #9933cc; color: #cc99ff; }
        .log-timestamp { color: #888; margin-right: 15px; }
        .log-source { color: #ff9900; margin-right: 10px; }
        .log-message { color: #e0e0e0; }
        .controls { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .search-box { flex: 1; padding: 8px; background: #000; border: 1px solid #444; color: #00ff00; border-radius: 3px; font-family: 'Courier New', monospace; }
        .placeholder-note { background: #332200; padding: 20px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ff9900; }
        .terminal { background: #000; color: #00ff00; padding: 20px; border-radius: 5px; font-family: 'Courier New', monospace; margin-top: 20px; }
        .terminal-prompt { color: #00ff00; }
        .terminal-command { color: #66b3ff; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
        .stat-box { background: #333; padding: 15px; border-radius: 5px; text-align: center; border: 1px solid #444; }
        .blink { animation: blink 1s infinite; }
        @keyframes blink { 50% { opacity: 0; } }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1 style="color: #00ff00; font-family: 'Courier New', monospace;">🔧 SYSTEM LOGS <span class="blink">_</span></h1>
            <div>
                <a href="dashboard.php" class="btn btn-secondary">← Admin Dashboard</a>
                <button class="btn btn-danger" onclick="clearLogs()" style="margin-left: 10px;">🚨 Clear Logs</button>
            </div>
        </div>
    </div>
    
    <div class="admin-nav">
        <ul>
            <li><a href="dashboard.php">📊 Dashboard</a></li>
            <li><a href="audit_log.php">📋 Audit Log</a></li>
            <li><a href="manage_users.php">👥 Manage Users</a></li>
            <li><a href="all_tasks.php">📝 All Tasks</a></li>
            <li><a href="system_logs.php" class="active">🔧 System Logs</a></li>
        </ul>
    </div>
    
    <div class="container">
        <!-- Placeholder Note -->
        <div class="placeholder-note">
            <h3 style="color: #ff9900;">⚠️ SYSTEM LOGS PLACEHOLDER - Security/DevOps Implementation Required</h3>
            <p><strong>This page simulates system logs for demonstration purposes.</strong></p>
            <p>In a production environment, this should connect to:</p>
            <ul style="margin: 10px 0 10px 20px; color: #e0e0e0;">
                <li>✅ Apache/Nginx error logs</li>
                <li>✅ PHP error logs</li>
                <li>✅ MySQL query logs</li>
                <li>✅ Application performance logs</li>
                <li>✅ Security monitoring logs</li>
                <li>✅ System resource usage</li>
            </ul>
            <p><em>Current implementation shows simulated logs only.</em></p>
        </div>
        
        <!-- Log Statistics -->
        <div class="stats-grid">
            <div class="stat-box">
                <h3>Total Logs</h3>
                <div style="font-size: 24px; font-weight: bold; color: #66b3ff;">1,247</div>
                <small style="color: #888;">24 hours</small>
            </div>
            <div class="stat-box">
                <h3>Errors</h3>
                <div style="font-size: 24px; font-weight: bold; color: #ff6666;">12</div>
                <small style="color: #888;">Critical: 2</small>
            </div>
            <div class="stat-box">
                <h3>Warnings</h3>
                <div style="font-size: 24px; font-weight: bold; color: #ffcc66;">45</div>
                <small style="color: #888;">Needs attention</small>
            </div>
            <div class="stat-box">
                <h3>System Uptime</h3>
                <div style="font-size: 24px; font-weight: bold; color: #66ff66;">99.8%</div>
                <small style="color: #888;">Last 30 days</small>
            </div>
        </div>
        
        <!-- Log Controls -->
        <div class="card">
            <h2 style="color: #00ff00;">🔧 System Log Console</h2>
            
            <div class="controls">
                <input type="text" class="search-box" placeholder="grep -i 'error|warning' /var/log/..." id="logSearch">
                <button class="btn btn-primary" onclick="searchLogs()">Search Logs</button>
                <select class="search-box" style="flex: 0 0 auto; width: 150px;" onchange="filterLogs(this.value)">
                    <option value="all">All Log Types</option>
                    <option value="error">Errors Only</option>
                    <option value="warning">Warnings Only</option>
                    <option value="info">Info Only</option>
                    <option value="debug">Debug Only</option>
                </select>
                <button class="btn btn-success" onclick="refreshLogs()">🔄 Refresh</button>
                <button class="btn btn-danger" onclick="clearLogs()">🗑️ Clear Display</button>
            </div>
            
            <!-- Log Display -->
            <div class="log-container" id="logDisplay" style="height: 500px; overflow-y: auto;">
                <!-- Sample Log Entries -->
                <div class="log-line log-info">
                    <span class="log-timestamp">[2025-12-19 15:00:01]</span>
                    <span class="log-source">[SYSTEM]</span>
                    <span class="log-message">System startup completed successfully</span>
                </div>
                <div class="log-line log-info">
                    <span class="log-timestamp">[2025-12-19 15:00:05]</span>
                    <span class="log-source">[DATABASE]</span>
                    <span class="log-message">Connected to MySQL database 'task_manager' on localhost</span>
                </div>
                <div class="log-line log-success">
                    <span class="log-timestamp">[2025-12-19 15:00:10]</span>
                    <span class="log-source">[AUTH]</span>
                    <span class="log-message">User 'admin' logged in successfully from IP 192.168.1.100</span>
                </div>
                <div class="log-line log-info">
                    <span class="log-timestamp">[2025-12-19 15:05:30]</span>
                    <span class="log-source">[TASK]</span>
                    <span class="log-message">User 'user1' created new task #1: "Complete project report"</span>
                </div>
                <div class="log-line log-warning">
                    <span class="log-timestamp">[2025-12-19 15:10:15]</span>
                    <span class="log-source">[SECURITY]</span>
                    <span class="log-message">Failed login attempt for user 'unknown' from IP 192.168.1.102 (3 attempts)</span>
                </div>
                <div class="log-line log-error">
                    <span class="log-timestamp">[2025-12-19 15:15:45]</span>
                    <span class="log-source">[DATABASE]</span>
                    <span class="log-message">Query timeout on large result set (query took 5.2s)</span>
                </div>
                <div class="log-line log-info">
                    <span class="log-timestamp">[2025-12-19 15:20:30]</span>
                    <span class="log-source">[SESSION]</span>
                    <span class="log-message">Cleaned up 3 expired user sessions</span>
                </div>
                <div class="log-line log-debug">
                    <span class="log-timestamp">[2025-12-19 15:25:10]</span>
                    <span class="log-source">[CACHE]</span>
                    <span class="log-message">Cache cleared: user_list (size: 45KB)</span>
                </div>
                <div class="log-line log-warning">
                    <span class="log-timestamp">[2025-12-19 15:30:20]</span>
                    <span class="log-source">[PERFORMANCE]</span>
                    <span class="log-message">High memory usage detected: 85% (512MB/600MB)</span>
                </div>
                <div class="log-line log-success">
                    <span class="log-timestamp">[2025-12-19 15:35:55]</span>
                    <span class="log-source">[BACKUP]</span>
                    <span class="log-message">Automated database backup completed successfully (size: 2.4MB)</span>
                </div>
                <div class="log-line log-info">
                    <span class="log-timestamp">[2025-12-19 15:40:10]</span>
                    <span class="log-source">[EMAIL]</span>
                    <span class="log-message">Password reset email sent to user@example.com</span>
                </div>
                <div class="log-line log-error">
                    <span class="log-timestamp">[2025-12-19 15:45:30]</span>
                    <span class="log-source">[SECURITY]</span>
                    <span class="log-message">Blocked potential SQL injection attempt in login form</span>
                </div>
                <div class="log-line log-info">
                    <span class="log-timestamp">[2025-12-19 15:50:15]</span>
                    <span class="log-source">[SYSTEM]</span>
                    <span class="log-message">Daily maintenance task completed</span>
                </div>
                <div class="log-line log-warning">
                    <span class="log-timestamp">[2025-12-19 15:55:40]</span>
                    <span class="log-source">[DISK]</span>
                    <span class="log-message">Disk space usage at 78% (15.6GB/20GB)</span>
                </div>
                <div class="log-line log-success">
                    <span class="log-timestamp">[2025-12-19 16:00:01]</span>
                    <span class="log-source">[SYSTEM]</span>
                    <span class="log-message">Hourly health check passed: all systems operational</span>
                </div>
            </div>
            
            <div style="margin-top: 15px; display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <span style="color: #888;">Showing 15 of 1,247 log entries</span>
                </div>
                <div>
                    <button class="btn btn-secondary" onclick="loadMoreLogs()">Load More</button>
                    <button class="btn btn-primary" onclick="downloadLogs()">Download Logs</button>
                </div>
            </div>
        </div>
        
        <!-- System Terminal (Simulated) -->
        <div class="card">
            <h2 style="color: #00ff00;">🖥️ System Terminal</h2>
            <div class="terminal" id="terminal">
                <div class="log-line">
                    <span class="terminal-prompt">root@server:~# </span>
                    <span class="terminal-command">tail -f /var/log/system.log</span>
                </div>
                <div class="log-line log-info">
                    <span class="log-timestamp">[2025-12-19 16:05:00]</span>
                    <span class="log-message">Live log monitoring started</span>
                </div>
                <div class="log-line log-info">
                    <span class="log-timestamp">[2025-12-19 16:05:01]</span>
                    <span class="log-message">Listening for new log entries...</span>
                </div>
                <div id="liveLogs"></div>
                <div class="log-line">
                    <span class="terminal-prompt">root@server:~# </span>
                    <span><input type="text" id="terminalInput" style="background: transparent; border: none; color: #66b3ff; width: 70%; font-family: 'Courier New', monospace; outline: none;" placeholder="Type command..."></span>
                </div>
            </div>
        </div>
    </div>
    
    <div style="text-align: center; margin: 30px; color: #666; padding: 20px; border-top: 1px solid #333;">
        <p style="color: #00ff00; font-family: 'Courier New', monospace;">🔧 <strong>SYSTEM LOG CONSOLE</strong> - Administrator Access Only</p>
        <p><small style="color: #888;">Simulated interface for system monitoring and debugging</small></p>
    </div>
    
    <script>
        let liveLogInterval;
        
        function searchLogs() {
            const searchTerm = document.getElementById('logSearch').value.toLowerCase();
            const logLines = document.querySelectorAll('.log-line');
            logLines.forEach(line => {
                const text = line.textContent.toLowerCase();
                line.style.display = text.includes(searchTerm) ? '' : 'none';
            });
        }
        
        function filterLogs(type) {
            const logLines = document.querySelectorAll('.log-line');
            logLines.forEach(line => {
                if (type === 'all') {
                    line.style.display = '';
                } else if (line.classList.contains('log-' + type)) {
                    line.style.display = '';
                } else {
                    line.style.display = 'none';
                }
            });
        }
        
        function refreshLogs() {
            // Simulate adding new log entries
            const logDisplay = document.getElementById('logDisplay');
            const newLog = document.createElement('div');
            newLog.className = 'log-line log-info';
            newLog.innerHTML = `
                <span class="log-timestamp">[${new Date().toISOString().replace('T', ' ').substr(0, 19)}]</span>
                <span class="log-source">[SYSTEM]</span>
                <span class="log-message">Log display refreshed manually by admin</span>
            `;
            logDisplay.prepend(newLog);
            alert('Logs refreshed! Added new simulated entry.');
        }
        
        function clearLogs() {
            if (confirm('Are you sure you want to clear the log display?\n\nThis only clears the display, not actual log files.')) {
                document.getElementById('logDisplay').innerHTML = '<div class="log-line log-info"><span class="log-message">Log display cleared at ' + new Date().toLocaleTimeString() + '</span></div>';
            }
        }
        
        function loadMoreLogs() {
            alert('Load more feature would connect to actual log files in production.');
        }
        
        function downloadLogs() {
            alert('Log download would generate a .log file in production.');
        }
        
        // Simulate live logs in terminal
        function startLiveLogs() {
            const liveLogs = document.getElementById('liveLogs');
            const messages = [
                'User session created for ID: 5',
                'Database query executed: SELECT * FROM tasks',
                'Cache hit for user_profile:8',
                'API request received from client',
                'Task status updated: #3 -> completed',
                'Email queue processed: 2 messages sent',
                'Memory usage: 72% (432MB/600MB)',
                'New user registered: testuser3',
                'Session expired: user_id=2',
                'Backup initiated: incremental_backup_20251219'
            ];
            
            let count = 0;
            liveLogInterval = setInterval(() => {
                if (count < 10) {
                    const newLog = document.createElement('div');
                    newLog.className = 'log-line log-info';
                    const now = new Date();
                    const timestamp = `[${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}]`;
                    newLog.innerHTML = `<span class="log-timestamp">${timestamp}</span> <span class="log-message">${messages[count]}</span>`;
                    liveLogs.appendChild(newLog);
                    count++;
                    
                    // Auto-scroll to bottom
                    liveLogs.parentElement.scrollTop = liveLogs.parentElement.scrollHeight;
                } else {
                    clearInterval(liveLogInterval);
                }
            }, 2000);
        }
        
        // Terminal input
        document.getElementById('terminalInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                const command = this.value.trim();
                if (command) {
                    const terminal = document.getElementById('terminal');
                    const newLine = document.createElement('div');
                    newLine.className = 'log-line';
                    newLine.innerHTML = `<span class="terminal-prompt">root@server:~# </span><span class="terminal-command">${command}</span>`;
                    terminal.insertBefore(newLine, this.parentElement.parentElement);
                    
                    // Simulate command output
                    const output = document.createElement('div');
                    output.className = 'log-line log-info';
                    output.innerHTML = `<span class="log-message">Command executed: ${command} (simulated)</span>`;
                    terminal.insertBefore(output, this.parentElement.parentElement);
                    
                    this.value = '';
                }
            }
        });
        
        // Start live logs on page load
        window.onload = function() {
            startLiveLogs();
        };
        
        // Clean up interval on page unload
        window.onunload = function() {
            if (liveLogInterval) clearInterval(liveLogInterval);
        };
    </script>
</body>
</html>