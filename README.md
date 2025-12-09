# Database Management System - Tutoring Platform

A comprehensive tutoring platform built with Python and PostgreSQL, featuring a Tkinter GUI for managing tutoring requests, course bookings, and user interactions.

## Requirements
```
PostgreSQL >= 16 (for importing sql file)
```

### System Requirements
- **PostgreSQL**: Version 16 or higher
- **Python**: Version 3.8 or higher
- **Operating System**: Linux, macOS, or Windows (Not tested on Windows)

### Python Dependencies
```
psycopg2

# below usually comes with python
# tkinter
# hashlib
```

## Running

### 

```
python3 interface.py
```

### Test Credentials

The database comes with pre-populated test accounts:

**Regular Users:**
- Username: `user1`, Password: `password1`
- Username: `user2`, Password: `password2`
- ... (user1 through user5000)

**Note:** All passwords are securely hashed using PBKDF2-SHA256.

## Usage Guide

### For Regular Users

1. **Sign Up**: Create a new account with username, password, real name, and email
2. **Login**: Use your credentials to access the system
3. **Post Request**: 
   - Select your role (Teacher/Student)
   - Specify subject, grade level, reward
   - Select available time slots
   - Add location and description
4. **Search Requests**: Find matching tutoring opportunities
5. **Take Request**: Apply to requests by selecting your available times
6. **Manage Courses**: View and rate your active courses
7. **Profile Management**: Edit password or delete account

### For Administrators

1. **User Management**: Search, modify, or suspend user accounts
2. **Request Moderation**: Search and delete inappropriate requests
3. **Course Management**: View, modify, or delete courses
4. **Take Management**: Monitor and manage take_request records

## Project Structure

```
Final_project/
├── interface.py              # Main GUI application
├── back_DB.py               # Database layer and API functions
├── backend.py               # Backend API wrapper
├── db2025_final4.sql        # Database schema and data
├── setup_admin_users.py     # Utility for creating admin users
└── README.md                # This file
```

## Database Schema

The database includes the following main tables:

- **USER**: User accounts with authentication
- **user_request**: Tutoring requests
- **take_request**: Applications to requests
- **course**: Active tutoring courses

Key features:
- Bitwise operations for time slots (168-bit for 24×7 schedule)
- Grade level filtering (8-bit for grades 1-8)
- Referential integrity with foreign keys
- Soft deletes with status tracking

## Security Features

- **Password Hashing**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Salt**: 32-byte random salt per password
- **SQL Injection Protection**: Parameterized queries
- **Status Tracking**: Active/suspended/deleted account states

## Contributing

This is a course project for Database Management (IM3008) class. 

## License

This project is created for educational purposes as part of the 114-1 semester coursework.

## Authors

- B10401019 呂祐寬 (lusteven901228)
- B09705051 郭騏禎

## Acknowledgments

- Course: Database Management (IM3008)
- Semester: 114-1
- Institution: National Taiwan University
