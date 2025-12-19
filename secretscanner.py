#!/usr/bin/env python3
import os
import re
import sys
import time
from datetime import datetime

def print_banner():
    banner = r"""
                                        __                                                   
  ______ ____   ___________   _____/  |_  ______ ____ _____    ____   ____   ___________ 
 /  ___// __ \_/ ___\_  __ \_/ __ \   __\/  ___// ___\\__  \  /    \ /    \_/ __ \_  __ \
 \___ \\  ___/\  \___|  | \/\  ___/|  |  \___ \\  \___ / __ \|   |  \   |  \  ___/|  | \/
/____  >\___  >\___  >__|    \___  >__| /____  >\___  >____  /___|  /___|  /\___  >__|   
     \/     \/     \/            \/          \/     \/     \/     \/     \/     \/       
	
	 # secretscanner - secret scanning & extraction utility for mapxtractor #
"""
    print(banner)
    time.sleep(1.5)
    
# ================= COLORS =================
GREEN = "\033[92m"
RESET = "\033[0m"

# ================= CONFIG =================

OUTPUT_FILE = "secrets_found.txt"
MAX_LINE_LENGTH = 500   # Skip long/minified lines to avoid false positives

# ================= PATTERNS =================

PATTERNS = {
    # ---------- Secrets ----------
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),

    "AWS Secret Key": re.compile(
        r"(?i)aws.{0,20}(secret|access).{0,20}[:=]\s*['\"][0-9a-zA-Z\/+=]{40}['\"]"
    ),

    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),

    "GitHub Token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36,255}"),

    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),

    "JWT Token": re.compile(
        r"['\"]eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+['\"]"
    ),

    "Private Key": re.compile(
        r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"
    ),

    "Bearer Token": re.compile(
        r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"
    ),

    "Generic API Key": re.compile(
        r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9\-_=]{16,}['\"]"
    ),

    "OAuth Client Secret": re.compile(
        r"(?i)client[_-]?secret\s*[:=]\s*['\"][A-Za-z0-9\-_=]{16,}['\"]"
    ),

    "Firebase Key": re.compile(
        r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"
    ),

    # ---------- Internal IPs ----------
    "Internal IP": re.compile(
        r"\b("
        r"10\.(?:\d{1,3}\.){2}\d{1,3}|"
        r"192\.168\.(?:\d{1,3}\.)\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3}\.)\d{1,3}"
        r")\b"
    ),

    # ---------- Internal / Local URLs ----------
    "Localhost URL": re.compile(
        r"http[s]?://(?:localhost|127\.0\.0\.1)(?::\d+)?[^\s\"']*"
    ),

    "Internal Service URL": re.compile(
        r"http[s]?://"
        r"(?:"
        r"(?:[a-zA-Z0-9-]+\.)*(?:local|internal|intra|corp|lan)"
        r"|(?:10|192\.168|172\.(?:1[6-9]|2\d|3[0-1]))\."
        r")"
        r"[^\s\"']*"
    ),

    # ---------- Internal API / Endpoint Paths ----------
    "Internal API Endpoint": re.compile(
        r"(?i)(/api/v\d+/[a-z0-9_\-/]+|/internal/[a-z0-9_\-/]+)"
    ),
}

# ================= UTILS =================

def write_output(text):
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(text + "\n")

def scan_file(path):
    results = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                # Skip long/minified lines
                if len(line) > MAX_LINE_LENGTH:
                    continue

                for name, pattern in PATTERNS.items():
                    for match in pattern.findall(line):
                        value = match if isinstance(match, str) else match[0]
                        results.append({
                            "type": name,
                            "file": path,
                            "line": lineno,
                            "value": value,
                            "content": line.strip()
                        })
    except Exception:
        pass
    return results

def scan_directory(root):
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            findings = scan_file(full_path)
            for f in findings:
                output = (
                    f"{GREEN}[FOUND]{RESET} {f['type']}\n"
                    f"  File : {f['file']}\n"
                    f"  Line : {f['line']}\n"
                    f"  Code : {f['content']}\n"
                    f"{'-'*60}"
                )
                print(output)
                write_output(output)

# ================= MAIN =================

def main():
       
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <sourcemaps_directory>")
        sys.exit(1)

    root = sys.argv[1]

    if not os.path.isdir(root):
        print("[-] Invalid directory")
        sys.exit(1)

    # Init output file
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("# Secret & Internal Recon Scan Results\n")
        f.write(f"# Scan Time: {datetime.now()}\n")
        f.write(f"# Target Directory: {root}\n\n")

    print_banner()
    print(f"[+] Scanning secrets, internal IPs & endpoints under: {root}\n")
    scan_directory(root)
    print(f"[+] Scan completed")
    print(f"[+] Results written to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
