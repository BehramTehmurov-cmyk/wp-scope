# 🛡️ WP-Scope (WordPress Vulnerability Scanner)

**WP-Scope** is a fast, lightweight static analysis tool designed for security researchers. It helps identify potential vulnerabilities in WordPress plugins by scanning for dangerous functions, missing security checks, and SSRF vectors.

## ✨ Features
- **Auto-Download**: Automatically downloads the latest plugin version from WordPress.org.
- **Dangerous Functions**: Detects eval, system, exec, shell_exec.
- **CSRF/IDOR**: Flags unauthenticated AJAX handlers (wp_ajax_nopriv).
- **SSRF**: Detects external HTTP requests (wp_remote_get/post).
- **Object Injection**: Flags unserialize() usage.
- **Beautiful Reports**: Generates both JSON and a beautiful HTML report.

## 🚀 Installation
git clone https://github.com/BehramTehmurov-cmyk/wp-scope.git
cd wp-scope

## 🛠️ Usage
Scan a local directory:
python3 wp-scope.py -d /path/to/plugin

Auto-download and scan a plugin from WordPress.org:
python3 wp-scope.py -p contact-form-7

## 📊 Output
- wp-scope-report.json (For automation)
- wp-scope-report.html (For visual review)

## ⚠️ Disclaimer
This tool is for educational purposes and ethical security research only. Always get permission before testing third-party sites.
