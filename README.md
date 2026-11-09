# WP-Scope (WordPress Vulnerability Scanner)

WP-Scope is a lightweight static analysis tool designed for security researchers. 
It helps identify potential vulnerabilities in WordPress plugins by scanning for dangerous functions and missing security checks.

## Features
- Detects unauthenticated AJAX handlers (wp_ajax_nopriv)
- Finds unprepared SQL queries
- Flags dangerous file operations (file_get_contents, eval)
- Checks for CSRF/IDOR risks (missing nonces)

## Usage
python3 wp-scope.py -d /path/to/plugin

## Disclaimer
This tool is for educational purposes and ethical security research only.
