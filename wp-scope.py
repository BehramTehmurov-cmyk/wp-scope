#!/usr/bin/env python3
import os
import re
import sys
import argparse
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

# Təkmilləşdirilmiş pattern-lər
PATTERNS = {
    "Unauthenticated AJAX (wp_ajax_nopriv)": r"wp_ajax_nopriv_",
    "Dangerous Functions (eval, system, exec)": r"\b(eval|system|exec|shell_exec|passthru)\s*\(",
    "File Inclusion (LFI/RFI)": r"\b(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST)",
    "File Upload (move_uploaded_file)": r"move_uploaded_file\s*\(",
}

def scan_file(filepath):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
            
            for name, pattern in PATTERNS.items():
                for i, line in enumerate(lines):
                    if re.search(pattern, line):
                        # Xüsusi yoxlama: Əgər AJAX-dirsə, yaxınlıqda nonce varmı?
                        if "AJAX" in name:
                            context = "\n".join(lines[i:i+15]) # Növbəti 15 sətir
                            if "check_ajax_referer" in context or "wp_verify_nonce" in context:
                                continue # Nonce varsa, keç
                                
                        findings.append({
                            "file": filepath,
                            "line": i + 1,
                            "type": name,
                            "code": line.strip()[:100]
                        })
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error reading {filepath}: {e}{Colors.ENDC}")
    return findings

def main():
    parser = argparse.ArgumentParser(description="WP-Scope - WordPress Plugin Vulnerability Scanner")
    parser.add_argument("-d", "--directory", required=True, help="Path to the WordPress plugin directory")
    args = parser.parse_args()

    target_dir = Path(args.directory)
    if not target_dir.is_dir():
        print(f"{Colors.FAIL}[!] Directory not found: {target_dir}{Colors.ENDC}")
        sys.exit(1)

    print(f"{Colors.HEADER}{Colors.BOLD}=== WP-Scope Vulnerability Scanner ==={Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Scanning directory: {target_dir}{Colors.ENDC}\n")

    all_findings = []
    php_files = list(target_dir.rglob("*.php"))
    
    for php_file in php_files:
        findings = scan_file(php_file)
        all_findings.extend(findings)

    if not all_findings:
        print(f"{Colors.GREEN}[+] No suspicious patterns found. The plugin looks clean!{Colors.ENDC}")
        return

    current_file = None
    for f in all_findings:
        if f["file"] != current_file:
            current_file = f["file"]
            print(f"{Colors.CYAN}{Colors.BOLD}File: {current_file}{Colors.ENDC}")
        
        print(f"  {Colors.WARNING}[Line {f['line']}] {f['type']}{Colors.ENDC}")
        print(f"    -> {f['code']}")
    
    print(f"\n{Colors.HEADER}[*] Scan complete. Total findings: {len(all_findings)}{Colors.ENDC}")

if __name__ == "__main__":
    main()
