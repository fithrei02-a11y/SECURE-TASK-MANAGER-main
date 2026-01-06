# Secure Task Manager System

## 📋 Project Overview
A secure web-based task management system built for the **Secure Software Development** course (IKB 21503). This project demonstrates OWASP security principles in a functional web application.

## 🎯 Project Requirements Met
- ✅ User Registration & Authentication
- ✅ Role-Based Access Control (Admin/User)
- ✅ CRUD Operations (Task Management)
- ✅ User Profile Management
- ✅ Audit Log System
- ✅ OWASP Security Placeholders

## 🛠️ Technologies Used
- **Frontend:** HTML5, CSS3, JavaScript
- **Backend:** PHP 7.4+
- **Database:** MySQL
- **Security:** OWASP Top 10 Implementation
- **Server:** Apache (XAMPP)

## 📁 Project Structure
secure_task_manager/
├── index.php # Dashboard
├── login.php # Login page
├── register.php # Registration
├── profile.php # User profile
├── add_task.php # Add tasks
├── my_tasks.php # View tasks
├── edit_task.php # Edit tasks
├── delete_task.php # Delete tasks
├── logout.php # Logout
├── includes/config.php # Database config
├── admin/ # Admin panel
│ ├── dashboard.php
│ ├── audit_log.php
│ ├── manage_users.php
│ ├── all_tasks.php
│ └── system_logs.php
└── README.md # This file


## 🚀 Installation Guide

### Prerequisites
- XAMPP (Apache + MySQL + PHP)
- Git (for version control)
- Web browser

### Setup Steps
1. **Install XAMPP**
   - Download from [Apache Friends](https://www.apachefriends.org/)
   - Install with default settings

2. **Start Services**
   - Open XAMPP Control Panel
   - Start **Apache** and **MySQL**

3. **Setup Database**
   - Open phpMyAdmin (`http://localhost/phpmyadmin`)
   - Create database: `task_manager`
   - Import SQL from `/database/task_manager.sql` (if available)

4. **Configure Project**
   - Clone this repository to `C:\xampp\htdocs\`
   - Update `includes/config.php` with your database credentials
   - Access via `http://localhost/secure_task_manager/`

## 👥 User Accounts
### Test Accounts:
- **Admin:** `admin` / `admin123`
- **Regular User:** `user1` / `user123`

### Create New Users:
Register via `http://localhost/secure_task_manager/register.php`

## 🔒 Security Features (To Be Implemented)
This project includes placeholders for OWASP security controls:
- [ ] Password hashing (bcrypt/Argon2)
- [ ] SQL injection prevention
- [ ] XSS protection
- [ ] CSRF tokens
- [ ] Input validation
- [ ] Session security
- [ ] Audit logging
- [ ] Error handling

## 👨‍💼 Team Members
- [Czar Ritzman Mohamed] - Website Development
- [Ahmad Yassin] - Security Implementation
- [Muhammad Fitri] - Security Testing
- [Muhammad Amir] - Documentation & Reporting

## 📚 Course Information
- **Course:** Secure Software Development (IKB 21503)
- **Institution:** Universiti Kuala Lumpur (UniKL)
- **Lecturer:** Mardiana Mahari
- **Semester:** October 2025

## 📄 License
Educational Project - For Academic Purposes Only

## 📞 Support
For project-related questions, contact your team members or course lecturer.
