#!/usr/bin/env python3
import os
import re
import sys
import json
import argparse
import urllib.request
import zipfile
from pathlib import Path
from datetime import datetime

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
    "Unauthenticated AJAX (wp_ajax_nopriv)": {"regex": r"wp_ajax_nopriv_", "severity": "HIGH"},
    "Dangerous Function (eval/system/exec)": {"regex": r"\b(eval|system|exec|shell_exec|passthru)\s*\(", "severity": "HIGH"},
    "File Inclusion (LFI/RFI)": {"regex": r"\b(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST)", "severity": "HIGH"},
    "File Upload (move_uploaded_file)": {"regex": r"move_uploaded_file\s*\(", "severity": "MEDIUM"},
    "PHP Object Injection (unserialize)": {"regex": r"\bunserialize\s*\(", "severity": "HIGH"},
    "Potential SSRF (wp_remote_get/post)": {"regex": r"wp_remote_(get|post|request)\s*\(", "severity": "MEDIUM"},
    "Unescaped Output (XSS)": {"regex": r"echo\s+\$_(GET|POST|REQUEST)", "severity": "HIGH"},
    "SQL Injection (wpdb->query)": {"regex": r"\$wpdb->(query|get_results|get_var)\s*\(", "severity": "HIGH"},
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
            
            for name, data in PATTERNS.items():
                pattern = data["regex"]
                severity = data["severity"]
                
                for i, line in enumerate(lines):
                    if re.search(pattern, line):
                        if "AJAX" in name:
                            context = "\n".join(lines[i:i+15])
                            if "check_ajax_referer" in context or "wp_verify_nonce" in context:
                                continue
                        
                        # Xüsusi SQL Injection Yoxlaması
                        if "SQL" in name:
                            context = "\n".join(lines[i:i+5])
                            if "prepare" in context:
                                continue

                        findings.append({
                            "file": str(filepath), "line": i + 1,
                            "type": name, "severity": severity, "code": line.strip()[:100]
                        })
    except Exception:
        pass
    return findings

def generate_html_report(findings, output_path):
    color_map = {"HIGH": "#dc3545", "MEDIUM": "#fd7e14", "LOW": "#28a745"}
    
    # Xülasə hesablanması
    high_count = sum(1 for f in findings if f['severity'] == 'HIGH')
    medium_count = sum(1 for f in findings if f['severity'] == 'MEDIUM')
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>WP-Scope Security Report</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background-color: #f4f7f6; color: #333; margin: 0; padding: 20px; }}
            .container {{ max-width: 1000px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; text-align: center; }}
            .summary {{ display: flex; justify-content: space-around; margin-bottom: 20px; padding: 15px; background: #e9ecef; border-radius: 8px; }}
            .summary-item {{ font-size: 18px; font-weight: bold; }}
            .filters {{ text-align: center; margin-bottom: 20px; }}
            .filters button {{ padding: 8px 16px; margin: 0 5px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }}
            .btn-all {{ background: #6c757d; color: white; }}
            .btn-high {{ background: #dc3545; color: white; }}
            .btn-medium {{ background: #fd7e14; color: white; }}
            .finding {{ background: #fff; border-left: 5px solid #ccc; padding: 15px; margin-bottom: 15px; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); display: block; }}
            .code {{ background: #2d2d2d; color: #f8f8f2; padding: 10px; border-radius: 4px; font-family: monospace; overflow-x: auto; }}
            .severity {{ display: inline-block; padding: 3px 8px; border-radius: 4px; color: white; font-size: 12px; font-weight: bold; margin-left: 10px; }}
            .clean {{ background: #d4edda; border-left: 5px solid #28a745; padding: 15px; color: #155724; border-radius: 4px; text-align: center; font-weight: bold; }}
        </style>
        <script>
            function filter(severity) {{
                const items = document.querySelectorAll('.finding');
                items.forEach(item => {{
                    if (severity === 'ALL' || item.getAttribute('data-severity') === severity) {{
                        item.style.display = 'block';
                    }} else {{
                        item.style.display = 'none';
                    }}
                }});
            }}
        </script>
    </head>
    <body>
        <div class="container">
            <h1>WP-Scope Security Report</h1>
            <div class="summary">
                <div class="summary-item" style="color: #dc3545;">HIGH: {high_count}</div>
                <div class="summary-item" style="color: #fd7e14;">MEDIUM: {medium_count}</div>
            </div>
    """
    
    if not findings:
        html_content += '<div class="clean">✅ No suspicious patterns found. The plugin looks clean!</div>'
    else:
        html_content += """
            <div class="filters">
                <button class="btn-all" onclick="filter('ALL')">Show All</button>
                <button class="btn-high" onclick="filter('HIGH')">High Only</button>
                <button class="btn-medium" onclick="filter('MEDIUM')">Medium Only</button>
            </div>
        """
        
        for f in findings:
            color = color_map.get(f['severity'], "#ccc")
            html_content += f"""
            <div class="finding" data-severity="{f['severity']}" style="border-left-color: {color};">
                <h3>{f['type']} <span class="severity" style="background-color: {color};">{f['severity']}</span></h3>
                <p><strong>File:</strong> {f['file']} <strong>(Line {f['line']})</strong></p>
                <div class="code">{f['code']}</div>
            </div>
            """
            
    html_content += """
        </div>
    </body>
    </html>
    """
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

def main():
    parser = argparse.ArgumentParser(description="WP-Scope - Advanced WordPress Plugin Vulnerability Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--directory", help="Path to the local plugin directory")
    group.add_argument("-p", "--plugin", help="WordPress plugin slug to download and scan")
    parser.add_argument("-o", "--output", help="Output JSON report file", default="wp-scope-report.json")
    parser.add_argument("--html", help="Output HTML report file", default="wp-scope-report.html")
    args = parser.parse_args()

    target_dir = args.directory if args.directory else download_plugin(args.plugin)

    if not os.path.isdir(target_dir):
        print(f"{Colors.FAIL}[!] Directory not found: {target_dir}{Colors.ENDC}")
        sys.exit(1)

    print(f"{Colors.HEADER}{Colors.BOLD}=== WP-Scope Vulnerability Scanner ==={Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Scanning directory: {target_dir}{Colors.ENDC}\n")

    all_findings = []
    # Həm .php, həm də .js fayllarını skan edirik
    target_files = list(Path(target_dir).rglob("*.php")) + list(Path(target_dir).rglob("*.js"))
    
    for file in target_files:
        findings = scan_file(file)
        all_findings.extend(findings)

    if not all_findings:
        print(f"{Colors.GREEN}[+] No suspicious patterns found. The plugin looks clean!{Colors.ENDC}")
    else:
        current_file = None
        for f in all_findings:
            if f["file"] != current_file:
                current_file = f["file"]
                print(f"{Colors.CYAN}{Colors.BOLD}File: {current_file}{Colors.ENDC}")
            
            print(f"  {Colors.WARNING}[Line {f['line']}] {f['type']} ({f['severity']}){Colors.ENDC}")
            print(f"    -> {f['code']}")
        
        print(f"\n{Colors.HEADER}[*] Scan complete. Total findings: {len(all_findings)}{Colors.ENDC}")

    with open(args.output, 'w') as outfile:
        json.dump(all_findings, outfile, indent=4, default=str)
    print(f"{Colors.GREEN}[+] JSON report saved to {args.output}{Colors.ENDC}")

    generate_html_report(all_findings, args.html)
    print(f"{Colors.GREEN}[+] HTML report saved to {args.html}{Colors.ENDC}")

if __name__ == "__main__":
    main()
