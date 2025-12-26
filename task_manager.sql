-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Dec 21, 2025 at 08:31 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `task_manager`
--

-- --------------------------------------------------------

--
-- Table structure for table `audit_logs`
--

CREATE TABLE `audit_logs` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `username` varchar(50) DEFAULT NULL,
  `action` varchar(100) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `details` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `audit_logs`
--

INSERT INTO `audit_logs` (`id`, `user_id`, `username`, `action`, `ip_address`, `user_agent`, `details`, `created_at`) VALUES
(4, 1, 'admin', 'Attempted login to locked account', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"username\":\"admin\",\"ip\":\"::1\"}', '2025-12-21 17:44:56'),
(8, 1, 'admin', 'New user registration', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":7,\"username\":\"fitriaris\",\"email\":\"fitri@task.com\",\"ip\":\"::1\"}', '2025-12-21 18:00:44'),
(12, 1, 'admin', 'New user registration', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":8,\"username\":\"haziqjoe\",\"email\":\"haziqjoe@gmail.com\",\"ip\":\"::1\"}', '2025-12-21 18:18:41'),
(13, 1, 'admin', 'New user registration (PLAINTEXT PASSWORD WARNING)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":9,\"username\":\"zafpunk\",\"email\":\"zafpunk@task.com\",\"ip\":\"::1\",\"SECURITY_WARNING\":\"Passwords stored in plaintext!\"}', '2025-12-21 18:37:32'),
(21, 1, 'admin', 'Successful login', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"username\":\"admin\",\"ip\":\"::1\",\"user_agent\":\"Mozilla\\/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit\\/537.36 (KHTML, like Gecko) Chrome\\/143.0.0.0 Safari\\/537.36\"}', '2025-12-21 18:51:38'),
(22, 1, 'admin', 'User logged out via form', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":1,\"username\":\"admin\",\"ip\":\"::1\"}', '2025-12-21 18:51:54'),
(23, NULL, 'Guest', 'Failed login attempt', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"username\":\"zafpunk\",\"ip\":\"::1\",\"attempts\":1}', '2025-12-21 18:52:14'),
(24, NULL, 'Guest', 'New user registration (PLAINTEXT PASSWORD WARNING)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":10,\"username\":\"user1\",\"email\":\"user1@gmail.com\",\"ip\":\"::1\",\"SECURITY_WARNING\":\"Passwords stored in plaintext!\"}', '2025-12-21 18:55:25'),
(25, 10, 'user1', 'Successful login', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"username\":\"user1\",\"ip\":\"::1\",\"user_agent\":\"Mozilla\\/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit\\/537.36 (KHTML, like Gecko) Chrome\\/143.0.0.0 Safari\\/537.36\"}', '2025-12-21 18:55:32'),
(26, 10, 'user1', 'Password changed', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":10,\"username\":\"user1\",\"ip\":\"::1\"}', '2025-12-21 18:56:02'),
(27, 10, 'user1', 'Task created', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":10,\"username\":\"user1\",\"task_id\":10,\"task_title\":\"FYP 1\",\"status\":\"todo\"}', '2025-12-21 18:58:00'),
(28, 10, 'user1', 'Viewed tasks list', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":10,\"username\":\"user1\",\"filter\":\"all\",\"task_count\":1}', '2025-12-21 18:58:02'),
(29, 10, 'user1', 'Viewed task for editing', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":10,\"username\":\"user1\",\"task_id\":10,\"task_title\":\"FYP 1\"}', '2025-12-21 18:58:05'),
(30, 10, 'user1', 'Viewed task for editing', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":10,\"username\":\"user1\",\"task_id\":10,\"task_title\":\"FYP 1\"}', '2025-12-21 18:58:10'),
(31, 10, 'user1', 'Task updated', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":10,\"username\":\"user1\",\"task_id\":10,\"old_title\":\"FYP 1\",\"new_title\":\"FYP 1\",\"status_changed_to\":\"in progress\"}', '2025-12-21 18:58:10'),
(32, 10, 'user1', 'Viewed tasks list', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":10,\"username\":\"user1\",\"filter\":\"all\",\"task_count\":1}', '2025-12-21 18:58:15'),
(33, 10, 'user1', 'Viewed task for editing', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":10,\"username\":\"user1\",\"task_id\":10,\"task_title\":\"FYP 1\"}', '2025-12-21 18:58:23'),
(34, 10, 'user1', 'Viewed tasks list', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":10,\"username\":\"user1\",\"filter\":\"all\",\"task_count\":1}', '2025-12-21 18:58:32'),
(35, 10, 'user1', 'User logged out', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":10,\"username\":\"user1\",\"ip\":\"::1\",\"user_agent\":\"Mozilla\\/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit\\/537.36 (KHTML, like Gecko) Chrome\\/143.0.0.0 Safari\\/537.36\",\"logout_method\":\"manual\"}', '2025-12-21 19:16:59'),
(36, NULL, 'Guest', 'New user registration (PLAINTEXT PASSWORD WARNING)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"user_id\":11,\"username\":\"kickwall0306\",\"email\":\"kickwall@gmail.com\",\"ip\":\"::1\",\"SECURITY_WARNING\":\"Passwords stored in plaintext!\"}', '2025-12-21 19:30:40'),
(37, 11, 'kickwall0306', 'Successful login', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', '{\"username\":\"kickwall0306\",\"ip\":\"::1\",\"user_agent\":\"Mozilla\\/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit\\/537.36 (KHTML, like Gecko) Chrome\\/143.0.0.0 Safari\\/537.36\"}', '2025-12-21 19:31:07');

-- --------------------------------------------------------

--
-- Table structure for table `system_logs`
--

CREATE TABLE `system_logs` (
  `id` int(11) NOT NULL,
  `level` enum('INFO','WARNING','ERROR','SECURITY') DEFAULT 'INFO',
  `message` text NOT NULL,
  `context` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `system_logs`
--

INSERT INTO `system_logs` (`id`, `level`, `message`, `context`, `ip_address`, `user_id`, `created_at`) VALUES
(1, 'INFO', 'Password reset requested', '{\"user_id\":7,\"username\":\"fitriaris\",\"email\":\"fitri@task.com\"}', '::1', 1, '2025-12-21 18:11:59'),
(2, 'INFO', 'Password reset requested', '{\"user_id\":7,\"username\":\"fitriaris\",\"email\":\"fitri@task.com\"}', '::1', 1, '2025-12-21 18:14:23'),
(3, 'INFO', 'Profile updated with password change', '{\"user_id\":10,\"username\":\"user1\"}', '::1', 10, '2025-12-21 18:56:02'),
(4, 'INFO', 'New task created', '{\"task_id\":10,\"user_id\":10,\"title\":\"FYP 1\"}', '::1', 10, '2025-12-21 18:58:00'),
(5, 'INFO', 'Task updated', '{\"task_id\":10,\"user_id\":10,\"title\":\"FYP 1\"}', '::1', 10, '2025-12-21 18:58:10'),
(6, 'INFO', 'User logged out', '{\"user_id\":10,\"username\":\"user1\"}', '::1', 10, '2025-12-21 19:16:59'),
(7, 'SECURITY', 'Session destroyed', '{\"old_session_id\":\"a2f88d0f8bqjvspb5tnur1bp45\",\"user_id\":10,\"ip\":\"::1\"}', '::1', NULL, '2025-12-21 19:16:59');

-- --------------------------------------------------------

--
-- Table structure for table `tasks`
--

CREATE TABLE `tasks` (
  `id` int(11) NOT NULL,
  `title` varchar(200) NOT NULL,
  `description` text DEFAULT NULL,
  `status` enum('todo','in progress','completed') DEFAULT 'todo',
  `user_id` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tasks`
--

INSERT INTO `tasks` (`id`, `title`, `description`, `status`, `user_id`, `created_at`, `updated_at`) VALUES
(5, 'test_task_for_admin', 'saje_test', 'todo', 1, '2025-12-19 14:41:05', '2025-12-19 14:41:05'),
(10, 'FYP 1', 'PROJECT RENTAL BUS SYSTEM', 'in progress', 10, '2025-12-21 18:58:00', '2025-12-21 18:58:10');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `is_admin` tinyint(4) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `failed_attempts` int(11) DEFAULT 0,
  `locked_until` datetime DEFAULT NULL,
  `reset_token` varchar(64) DEFAULT NULL,
  `token_expires` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `password`, `is_admin`, `created_at`, `failed_attempts`, `locked_until`, `reset_token`, `token_expires`) VALUES
(1, 'admin', 'admin@task.com', 'Admin@123456', 1, '2025-12-19 13:08:30', 0, NULL, NULL, NULL),
(10, 'user1', 'user1@gmail.com', 'Anak@ali1234', 0, '2025-12-21 18:55:25', 0, NULL, NULL, NULL),
(11, 'kickwall0306', 'kickwall@gmail.com', 'Socceraid@0505', 0, '2025-12-21 19:30:40', 0, NULL, NULL, NULL);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `audit_logs`
--
ALTER TABLE `audit_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `created_at` (`created_at`);

--
-- Indexes for table `system_logs`
--
ALTER TABLE `system_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `level` (`level`),
  ADD KEY `created_at` (`created_at`);

--
-- Indexes for table `tasks`
--
ALTER TABLE `tasks`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`),
  ADD KEY `idx_reset_token` (`reset_token`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `audit_logs`
--
ALTER TABLE `audit_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=38;

--
-- AUTO_INCREMENT for table `system_logs`
--
ALTER TABLE `system_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- AUTO_INCREMENT for table `tasks`
--
ALTER TABLE `tasks`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `tasks`
--
ALTER TABLE `tasks`
  ADD CONSTRAINT `tasks_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
