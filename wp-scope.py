#!/usr/bin/env python3
import os
import re
import sys
import json
import argparse
import urllib.request
import zipfile
from pathlib import Path

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

PATTERNS = {
    "Unauthenticated AJAX (wp_ajax_nopriv)": r"wp_ajax_nopriv_",
    "Dangerous Functions (eval, system, exec)": r"\b(eval|system|exec|shell_exec|passthru)\s*\(",
    "File Inclusion (LFI/RFI)": r"\b(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST)",
    "File Upload (move_uploaded_file)": r"move_uploaded_file\s*\(",
    "PHP Object Injection (unserialize)": r"\bunserialize\s*\(",
    "Potential SSRF (wp_remote_get/post)": r"wp_remote_(get|post|request)\s*\(",
    "Privilege Escalation (update_option)": r"update_option\s*\(\s*['\"].*role",
}

def download_plugin(slug):
    url = f"https://downloads.wordpress.org/plugin/{slug}.zip"
    zip_path = f"/tmp/{slug}.zip"
    print(f"{Colors.BLUE}[*] Downloading {slug} from WordPress.org...{Colors.ENDC}")
    try:
        urllib.request.urlretrieve(url, zip_path)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            extract_path = f"/tmp/wp-scope-{slug}"
            zip_ref.extractall(extract_path)
        print(f"{Colors.GREEN}[+] Downloaded and extracted to {extract_path}{Colors.ENDC}\n")
        return extract_path
    except Exception as e:
        print(f"{Colors.FAIL}[!] Failed to download {slug}: {e}{Colors.ENDC}")
        sys.exit(1)

def scan_file(filepath):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
            
            for name, pattern in PATTERNS.items():
                for i, line in enumerate(lines):
                    if re.search(pattern, line):
                        if "AJAX" in name:
                            context = "\n".join(lines[i:i+15])
                            if "check_ajax_referer" in context or "wp_verify_nonce" in context:
                                continue
                                
                        findings.append({
                            "file": filepath,
                            "line": i + 1,
                            "type": name,
                            "code": line.strip()[:100]
                        })
    except Exception as e:
        pass
    return findings

def main():
    parser = argparse.ArgumentParser(description="WP-Scope - Advanced WordPress Plugin Vulnerability Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--directory", help="Path to the local plugin directory")
    group.add_argument("-p", "--plugin", help="WordPress plugin slug (e.g., contact-form-7) to download and scan")
    parser.add_argument("-o", "--output", help="Output JSON report file", default="wp-scope-report.json")
    args = parser.parse_args()

    target_dir = args.directory if args.directory else download_plugin(args.plugin)

    if not os.path.isdir(target_dir):
        print(f"{Colors.FAIL}[!] Directory not found: {target_dir}{Colors.ENDC}")
        sys.exit(1)

    print(f"{Colors.HEADER}{Colors.BOLD}=== WP-Scope Vulnerability Scanner ==={Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Scanning directory: {target_dir}{Colors.ENDC}\n")

    all_findings = []
    php_files = list(Path(target_dir).rglob("*.php"))
    
    for php_file in php_files:
        findings = scan_file(php_file)
        all_findings.extend(findings)

    if not all_findings:
        print(f"{Colors.GREEN}[+] No suspicious patterns found. The plugin looks clean!{Colors.ENDC}")
    else:
        current_file = None
        for f in all_findings:
            if f["file"] != current_file:
                current_file = f["file"]
                print(f"{Colors.CYAN}{Colors.BOLD}File: {current_file}{Colors.ENDC}")
            
            print(f"  {Colors.WARNING}[Line {f['line']}] {f['type']}{Colors.ENDC}")
            print(f"    -> {f['code']}")
        
        print(f"\n{Colors.HEADER}[*] Scan complete. Total findings: {len(all_findings)}{Colors.ENDC}")

    # JSON Report
    with open(args.output, 'w') as outfile:
        json.dump(all_findings, outfile, indent=4)
    print(f"{Colors.GREEN}[+] JSON report saved to {args.output}{Colors.ENDC}")

if __name__ == "__main__":
    main()
