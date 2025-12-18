#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse
import time
import random
import re
import json
import os
import sys

requests.packages.urllib3.disable_warnings()

# ================= COLORS =================
GRAY  = "\033[90m"
GREEN = "\033[92m"
RED   = "\033[91m"
RESET = "\033[0m"

# ================= CONFIG =================
FETCH_TIMEOUT = 15
PROBE_TIMEOUT = 3

DEFAULT_PORTS = {"http": [80], "https": [443]}
EXTRA_PORTS = [8080, 8000, 8008, 8888, 8443, 3000, 5000, 7001, 9000]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/121.0.0.0 Safari/537.36",
]

JS_REGEX = re.compile(r"""["']([^"' ]+\.js(?:\?[^"' ]*)?)["']""", re.I)

SOURCEMAP_LOG = "sourcemaps.txt"

# ================= BANNER =================

def print_banner():
    banner = r"""
                                                    ░██                                      ░██                        
                                                    ░██                                      ░██                        
░█████████████   ░██████   ░████████  ░██    ░██ ░████████ ░██░████  ░██████    ░███████  ░████████  ░███████  ░██░████ 
░██   ░██   ░██       ░██  ░██    ░██  ░██  ░██     ░██    ░███           ░██  ░██    ░██    ░██    ░██    ░██ ░███     
░██   ░██   ░██  ░███████  ░██    ░██   ░█████      ░██    ░██       ░███████  ░██           ░██    ░██    ░██ ░██      
░██   ░██   ░██ ░██   ░██  ░███   ░██  ░██  ░██     ░██    ░██      ░██   ░██  ░██    ░██    ░██    ░██    ░██ ░██      
░██   ░██   ░██  ░█████░██ ░██░█████  ░██    ░██     ░████ ░██       ░█████░██  ░███████      ░████  ░███████  ░██      
                           ░██                                                                                          
                           ░██                                                                                          
                                                                                                                         
                        # mapxtractor v1.0 | SourceMap Extractor by Anil Celik (@ccelikanil) #
"""
    print(banner)

# ================= HELPERS =================

def random_ua(session):
    session.headers["User-Agent"] = random.choice(USER_AGENTS)

def sleep(rate):
    if rate:
        time.sleep(rate)

def in_scope(url, base_host):
    try:
        p = urlparse(url)
        if not p.hostname:
            return True
        return p.hostname == base_host or p.hostname.endswith("." + base_host)
    except Exception:
        return False

def fetch(session, url, timeout, rate):
    sleep(rate)
    random_ua(session)
    try:
        r = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
        for h in r.history:
            print(f"{GRAY}[REDIRECT]{RESET} {h.status_code} -> {h.url}")
        return r
    except requests.RequestException:
        print(f"{RED}[-] Request failed: {url}{RESET}")
        return None

# ================= SOURCEMAP =================

def valid_sourcemap(resp):
    try:
        ct = resp.headers.get("Content-Type", "").lower()
        if "image/" in ct or "text/html" in ct:
            return False
        data = resp.json()
    except Exception:
        return False

    return (
        isinstance(data, dict)
        and data.get("version") == 3
        and isinstance(data.get("mappings"), str)
        and len(data.get("mappings")) > 10
        and isinstance(data.get("sources"), list)
        and len(data.get("sources")) > 0
    )

def log_sourcemap(url):
    with open(SOURCEMAP_LOG, "a", encoding="utf-8") as f:
        f.write(url + "\n")

def dump_sources(resp, map_url, host):
    data = resp.json()
    sources = data.get("sources", [])
    contents = data.get("sourcesContent")

    if not contents:
        print(f"{GRAY}    [INFO]{RESET} sourcesContent not embedded")
        return

    base = os.path.join(
        "sourcemaps",
        host,
        map_url.replace("://", "_").replace("/", "_")
    )

    for src, content in zip(sources, contents):
        if not content:
            continue
        path = os.path.join(base, src.lstrip("./"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(content)
        print(f"{GREEN}    [DUMP]{RESET} {path}")

# ================= EXTRACTION =================

def extract_js(html, base_url):
    js = set()
    soup = BeautifulSoup(html, "html.parser")

    for s in soup.find_all("script"):
        if s.get("src"):
            js.add(urljoin(base_url, s["src"]))

    for m in JS_REGEX.findall(html):
        js.add(urljoin(base_url, m))

    for j in js:
        print(f"[!] JS file found: {j}")

    return js

# ================= URL NORMALIZATION =================

def normalize_target(session, raw, rate, use_extra_ports):
    if "://" not in raw:
        raw = "//" + raw

    p = urlparse(raw)
    host = p.hostname
    path = p.path or ""

    for scheme, ports in DEFAULT_PORTS.items():
        for port in ports:
            url = f"{scheme}://{host}{path}"
            if fetch(session, url, PROBE_TIMEOUT, rate):
                return url

    if use_extra_ports:
        for scheme in ["http", "https"]:
            for port in EXTRA_PORTS:
                url = f"{scheme}://{host}:{port}{path}"
                if fetch(session, url, PROBE_TIMEOUT, rate):
                    return url

    return None

# ================= MAIN =================

def main():
    print_banner()

    parser = argparse.ArgumentParser("mapxtractor")
    parser.add_argument("url", nargs="?")
    parser.add_argument("--list", help="File with target URLs")
    parser.add_argument("--rate-limit", type=float, help="Seconds between requests")
    parser.add_argument("--extra-ports", action="store_true", help="Scan common non-80/443 ports")
    parser.add_argument("--dump-sources", action="store_true", help="Dump embedded sourcesContent")

    args = parser.parse_args()
    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    targets = [args.url] if args.url else [l.strip() for l in open(args.list)]
    session = requests.Session()

    for i, raw in enumerate(targets, 1):
        print("\n" + "=" * 60)
        print(f"[URL: {i}/{len(targets)}] {raw}")
        print("=" * 60)

        target = normalize_target(session, raw, args.rate_limit, args.extra_ports)
        if not target:
            print(f"{RED}[-] Target unreachable{RESET}")
            continue

        base_host = urlparse(target).hostname
        resp = fetch(session, target, FETCH_TIMEOUT, args.rate_limit)
        if not resp:
            continue

        js_files = extract_js(resp.text, target)

        for js in js_files:
            if not in_scope(js, base_host):
                print(f"{GRAY}[SKIP]{RESET} Out-of-scope JS: {js}")
                continue

            print(f"[JS] {js}")
            map_url = js + ".map"

            map_resp = fetch(session, map_url, FETCH_TIMEOUT, args.rate_limit)
            if not map_resp:
                continue

            if valid_sourcemap(map_resp):
                print(f"{GREEN}    [FOUND]{RESET} Sourcemap -> {map_url}")
                log_sourcemap(map_url)
                if args.dump_sources:
                    dump_sources(map_resp, map_url, base_host)
            else:
                print(f"{RED}    [INVALID]{RESET} Not a sourcemap")

    print(f"\n{GREEN}[+] Scan completed{RESET}")
    print(f"{GREEN}[+] Sourcemaps logged to {SOURCEMAP_LOG}{RESET}")

if __name__ == "__main__":
    main()
