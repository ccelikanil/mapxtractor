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
import base64

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

JS_REGEX  = re.compile(r"""["']([^"' ]+\.js(?:\?[^"' ]*)?)["']""", re.I)
CSS_REGEX = re.compile(r"""["']([^"' ]+\.css(?:\?[^"' ]*)?)["']""", re.I)

SOURCEMAP_LOG = "sourcemaps.txt"

SOURCEMAP_COMMENT_RE = re.compile(r"sourceMappingURL\s*=\s*(.+)$", re.I)
INLINE_MAP_RE = re.compile(r"data:application/json;base64,(.+)", re.I)

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

def sanitize_path(p):
    # Prevent traversal / weird Windows paths
    p = p.replace("\\", "/")
    p = os.path.normpath(p)
    p = p.lstrip("/").replace("..", "")
    # Drop drive-letter patterns like C:
    p = p.replace(":", "")
    return p

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

def valid_sourcemap_data(data):
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
    dump_sources_data(data, map_url, host)

def dump_sources_data(data, map_id, host):
    sources = data.get("sources", [])
    contents = data.get("sourcesContent")

    if not contents:
        print(f"{GRAY}    [INFO]{RESET} sourcesContent not embedded")
        return

    base = os.path.join(
        "sourcemaps",
        host,
        map_id.replace("://", "_").replace("/", "_")
    )

    for src, content in zip(sources, contents):
        if not content:
            continue
        safe = sanitize_path(src.lstrip("./"))
        path = os.path.join(base, safe)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(content)
        print(f"{GREEN}    [DUMP]{RESET} {path}")
        
def dump_javascript(resp, js_url, host):
    try:
        content = resp.text
        path_parts = urlparse(js_url)
        filename = os.path.basename(path_parts.path).split("?")[0]  # query parametreyi temizle
        base = os.path.join("javascript", host)
        os.makedirs(base, exist_ok=True)
        full_path = os.path.join(base, filename)
        with open(full_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(content)
        print(f"{GREEN}    [JS SAVED]{RESET} {full_path}")
    except Exception as e:
        print(f"{RED}    [ERROR]{RESET} Failed to save JS: {e}")


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

def extract_css(html, base_url):
    css = set()
    soup = BeautifulSoup(html, "html.parser")

    for l in soup.find_all("link", rel=True):
        rel = " ".join(l.get("rel", [])).lower()
        if "stylesheet" in rel and l.get("href"):
            css.add(urljoin(base_url, l["href"]))

    for m in CSS_REGEX.findall(html):
        css.add(urljoin(base_url, m))

    for c in css:
        print(f"[!] CSS file found: {c}")

    return css

# ================= SOURCE MAP DISCOVERY =================

def handle_map_url(session, map_url, host, rate, dump, label="TRY"):
    print(f"{GRAY}    [{label}]{RESET} {map_url}")

    map_resp = fetch(session, map_url, FETCH_TIMEOUT, rate)
    if not map_resp:
        print(f"{RED}    [FAIL]{RESET} {map_url}")
        return

    if valid_sourcemap(map_resp):
        print(f"{GREEN}    [FOUND]{RESET} Sourcemap -> {map_url}")
        log_sourcemap(map_url)
        if dump:
            dump_sources(map_resp, map_url, host)
    else:
        print(f"{RED}    [INVALID]{RESET} Not a sourcemap")

def process_asset_sourcemaps(session, asset_url, host, rate, dump):
    tried_maps = set()

    def try_map(map_url, label):
        if map_url in tried_maps:
            return
        tried_maps.add(map_url)
        handle_map_url(session, map_url, host, rate, dump, label=label)

    asset_resp = fetch(session, asset_url, FETCH_TIMEOUT, rate)

    # (1) Header + comment based (only if asset fetched)
    if asset_resp:
        for h in ("SourceMap", "X-SourceMap"):
            if h in asset_resp.headers:
                hdr_map = urljoin(asset_url, asset_resp.headers[h])
                print(f"{GRAY}    [HEADER]{RESET} {h}: {hdr_map}")
                try_map(hdr_map, "TRY")

        for line in asset_resp.text.splitlines()[-10:]:
            m = SOURCEMAP_COMMENT_RE.search(line)
            if not m:
                continue

            val = m.group(1).strip().strip('"').strip("'")

            inline = INLINE_MAP_RE.search(val)
            if inline:
                try:
                    raw = base64.b64decode(inline.group(1))
                    data = json.loads(raw)
                    if valid_sourcemap_data(data):
                        print(f"{GREEN}    [FOUND]{RESET} Inline sourcemap in {asset_url}")
                        if dump:
                            inline_id = f"inline_{sanitize_path(urlparse(asset_url).path).replace('/', '_') or 'asset'}"
                            dump_sources_data(data, inline_id, host)
                except Exception:
                    print(f"{RED}    [INVALID]{RESET} Inline sourcemap decode failed")
            else:
                sm_url = urljoin(asset_url, val)
                try_map(sm_url, "TRY")

            break  # only first sourceMappingURL

    # (2) LEGACY fallback — always attempted, but de-duplicated
    legacy_map = asset_url + ".map"
    try_map(legacy_map, "LEGACY")

# ================= URL NORMALIZATION =================

def normalize_target(session, raw, rate, use_extra_ports):
    if "://" not in raw:
        raw = "//" + raw

    p = urlparse(raw)
    host = p.hostname
    path = p.path or ""

    for scheme, ports in DEFAULT_PORTS.items():
        for port in ports:
            # Keep original behavior (no explicit :80/:443), but probe reachability
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
    parser.add_argument("--javascript", action="store_true", help="Download JS files and save them locally")
    parser.add_argument("--timeout", type=float, default=15, help="Request timeout in seconds (default: 15)")


    args = parser.parse_args()
    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    targets = [args.url] if args.url else [l.strip() for l in open(args.list, encoding="utf-8", errors="ignore")]
    session = requests.Session()

    for i, raw in enumerate(targets, 1):
        if not raw:
            continue

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
        css_files = extract_css(resp.text, target)
        
        for js in js_files:
            js_clean = js.split("?")[0]  # Query parametrelerini temizle

        if not in_scope(js_clean, base_host):
            print(f"{GRAY}[SKIP]{RESET} Out-of-scope JS: {js}")
            continue

        print(f"[Probing JS] {js_clean}")
        process_asset_sourcemaps(session, js_clean, base_host, args.rate_limit, args.dump_sources)

        if args.javascript:
            js_resp = fetch(session, js_clean, FETCH_TIMEOUT, args.rate_limit)
            if js_resp:
                dump_javascript(js_resp, js_clean, base_host)


        # JS processing (keeps original behavior & adds advanced discovery)
        for js in js_files:
            if not in_scope(js, base_host):
                print(f"{GRAY}[SKIP]{RESET} Out-of-scope JS: {js}")
                continue

            print(f"[Probing JS] {js}")
            process_asset_sourcemaps(session, js, base_host, args.rate_limit, args.dump_sources)

        # CSS processing (new)
        for css in css_files:
            if not in_scope(css, base_host):
                print(f"{GRAY}[SKIP]{RESET} Out-of-scope CSS: {css}")
                continue

            print(f"[CSS] {css}")
            process_asset_sourcemaps(session, css, base_host, args.rate_limit, args.dump_sources)

    print(f"\n{GREEN}[+] Scan completed{RESET}")
    print(f"{GREEN}[+] Sourcemaps logged to {SOURCEMAP_LOG}{RESET}")

if __name__ == "__main__":
    main()
