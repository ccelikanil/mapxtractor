# 🐻 mapxtractor

**mapxtractor** is a lightweight offensive recon tool designed to **discover exposed JavaScript SourceMaps (`.js.map`)** on web applications and optionally **extract original source code** embedded inside them.

*Please also see **secretscanner** in below.*

Exposed SourceMaps can unintentionally reveal:
- Original (unminified) source code
- Internal API endpoints
- Application logic & routing
- Feature flags
- Secrets or hardcoded values
- Comments and developer notes

This tool automates the discovery and extraction process in a clean and scoped manner.

## ✨ Features

- 🔍 Automatically discovers JavaScript files from HTML
- 🧭 Scope-aware (avoids external CDN JS files)
- 🗺️ Detects valid SourceMap files
- 🧾 Logs discovered SourceMaps
- 📦 Dumps embedded `sourcesContent` to disk (optional)
- 🔄 Handles redirects & randomizes User-Agent
- ⏱️ Optional rate limiting
- 🌐 Optional scanning of common non-standard ports

## 📦 Installation

```
# git clone https://github.com/ccelikanil/mapxtractor.git
# cd mapxtractor
# pip install -r requirements.txt
```
## 🚀 Usage

Basic scan:
```
# python3 mapxtractor.py example.com
```

Basic scan (multiple targets)
```
# python3 mapxtractor.py --list targets.txt
```

Dump embedded source code from SourceMaps
```
# python3 mapxtractor.py example.com --dump-sources
```

Enable rate limiting (seconds between requests)
```
# python3 mapxtractor.py example.com --rate-limit <SECONDS>
```

Scan common non-standard ports
```
# python3 mapxtractor.py example.com --extra-ports
```

### Sample run
```
# python3 mapxtractor.py example.com --rate-limit 20 --dump-sources

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

============================================================
[URL: 1/1] example.com
============================================================

[!] JS file found: https://example.com/static/js/main.8f3a2c1e.js
[!] JS file found: https://example.com/static/js/vendor.2d91ab4f.js

[JS] https://example.com/static/js/main.8f3a2c1e.js
    [FOUND] Sourcemap -> https://example.com/static/js/main.8f3a2c1e.js.map
    [DUMP] sourcemaps/example.com/https_example.com_static_js_main.8f3a2c1e.js.map/src/app.ts
    [DUMP] sourcemaps/example.com/https_example.com_static_js_main.8f3a2c1e.js.map/src/api/client.ts
    [DUMP] sourcemaps/example.com/https_example.com_static_js_main.8f3a2c1e.js.map/src/config/env.ts

[JS] https://example.com/static/js/vendor.2d91ab4f.js
    [INVALID] Not a sourcemap

[+] Scan completed
[+] Sourcemaps logged to sourcemaps.txt
```

### Dumped source code structure
```
sourcemaps/
└── example.com/
    └── https_example.com_static_js_main.8f3a2c1e.js.map/
        ├── src/
        │   ├── app.ts
        │   ├── api/
        │   │   └── client.ts
        │   └── config/
        │       └── env.ts
```

### Example finding
```
// src/config/env.ts
export const API_BASE_URL = "https://api.internal.example.com";
export const FEATURE_FLAGS = {
  enableBetaAuth: true
};
```

## 🧠 How It Works (Execution Flow)

1. **Target normalization**
   - Automatically tries `http` and `https`
   - Optionally probes common non-standard web ports

2. **JavaScript discovery**
   - Parses `<script src="">` tags from HTML
   - Extracts `.js` references using regex patterns

3. **Scope filtering**
   - Only analyzes JavaScript files belonging to the same domain or its subdomains
   - Skips third-party and CDN-hosted scripts

4. **SourceMap detection**
   - Appends `.map` to each discovered JavaScript file
   - Validates SourceMap structure (`version`, `mappings`, `sources`)

5. **Optional source dumping**
   - Extracts embedded `sourcesContent` from SourceMaps
   - Reconstructs the original project structure locally

## 📁 Output Structure

```
.
├── sourcemaps.txt
└── sourcemaps/
    └── example.com/
        └── https_example.com_static_js_app.js.map/
            ├── src/
            │   ├── app.js
            │   ├── api/
            │   │   └── client.js
            │   └── config/
            │       └── constants.js
```

## 🎯 Example Use Cases

- Web application penetration testing
- Bug bounty reconnaissance
- Red team reconnaissance phase
- Identifying leaked frontend logic
- Hunting exposed API endpoints
- Reverse engineering client-side applications

## ⚠️ Notes

- SourceMaps are often unintentionally exposed in production environments.
- This tool **does not bypass authentication or authorization**.
- It only accesses publicly reachable resources.

# 🔐 secretscanner (mapxtractor companion)

**secretscanner** is a post-processing utility designed to work alongside **mapxtractor**. It recursively scans extracted SourceMap contents to identify **hardcoded secrets, internal infrastructure references, and hidden API endpoints**. This tool helps transform leaked frontend source code into **actionable reconnaissance findings**.

## ✨ Features

- 🔎 Recursive scanning of extracted SourceMap directories
- 🔐 Detection of common secrets:
  - AWS Access & Secret Keys
  - GitHub / Slack / Google API tokens
  - OAuth client secrets
  - JWT & Bearer tokens
- 🌐 Discovery of internal infrastructure:
  - Private IP addresses (10.x, 172.16–31.x, 192.168.x)
  - Localhost & internal service URLs
  - Internal API and service endpoints
- 📍 Precise findings:
  - File path
  - Line number
  - Code context
- 🟢 Colorized terminal output for confirmed findings
- 🧾 Automatic TXT report generation
- 🚫 Minified-code protection to reduce false positives

## 🚀 Usage

After running **mapxtractor** with source dumping enabled:

```
# python3 secretscanner.py sourcemaps/
```

## 📜 Disclaimer

This tool is intended for **authorized security testing and educational purposes only**.

The author is **not responsible for misuse** or any damage caused by this tool.  
Always obtain proper authorization before testing any system.

## ⭐ Contributing

Pull requests and improvements are welcome. Feel free to open an issue for bugs, ideas, or feature requests.

Before submitting a pull request:
- Ensure your code follows the existing style
- Keep changes focused and well-documented
- Test your changes against real targets (with authorization)

All contributions that improve stability, performance, or detection logic are appreciated.
