# SecureShare - Secure File Sharing System

## Overview

A secure file sharing web application built with Python (Flask), HTML, CSS, and PostgreSQL.

## Stack

- **Backend**: Python 3.12 with Flask
- **Frontend**: HTML (Jinja2 templates) + CSS
- **Database**: PostgreSQL
- **Authentication**: Werkzeug password hashing

## Features

- User registration and login with secure password hashing
- File upload with drag & drop support (max 16MB)
- Share files directly with other users (view/download permissions)
- Generate share links with:
  - Password protection
  - Expiration dates
  - Download limits
- Dashboard with file statistics and activity log
- User profile page

## Project Structure

```
secure_file_sharing/
  app.py              # Main Flask application
  templates/          # HTML templates (Jinja2)
    base.html         # Base layout template
    index.html        # Landing page
    login.html        # Login page
    register.html     # Registration page
    dashboard.html    # User dashboard
    upload.html       # File upload page
    my_files.html     # File listing page
    share.html        # File sharing page
    shared_with_me.html
    shared_download.html
    shared_password.html
    shared_expired.html
    profile.html
  static/
    css/style.css     # All CSS styles
  uploads/            # Uploaded files storage
```

## Database Tables

- **users** - User accounts
- **files** - Uploaded file metadata
- **share_links** - Generated share links with tokens
- **file_shares** - Direct user-to-user sharing
- **activity_log** - User activity tracking

## Running

The app runs via the "SecureShare App" workflow on port 5000.
