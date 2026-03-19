# KP WebScanner

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![kevinpirnie.com](https://img.shields.io/badge/site-kevinpirnie.com-2d7696?labelColor=599bb8)](https://kevinpirnie.com/)
[![Latest Build](https://img.shields.io/github/actions/workflow/status/kpirnie/webscanner/build.yml?branch=main&label=Latest+Build)](https://github.com/kpirnie/webscanner/pkgs/container/webscanner)
[![Dev Build](https://img.shields.io/github/actions/workflow/status/kpirnie/webscanner/build.yml?branch=develop&label=Dev+Build)](https://github.com/kpirnie/webscanner/pkgs/container/webscanner)

[![Nuclei](https://img.shields.io/github/v/release/projectdiscovery/nuclei?label=nuclei&logo=github)](https://github.com/projectdiscovery/nuclei/releases/latest)
[![httpx](https://img.shields.io/github/v/release/projectdiscovery/httpx?label=httpx&logo=github)](https://github.com/projectdiscovery/httpx/releases/latest)
[![subfinder](https://img.shields.io/github/v/release/projectdiscovery/subfinder?label=subfinder&logo=github)](https://github.com/projectdiscovery/subfinder/releases/latest)
[![naabu](https://img.shields.io/github/v/release/projectdiscovery/naabu?label=naabu&logo=github)](https://github.com/projectdiscovery/naabu/releases/latest)
[![katana](https://img.shields.io/github/v/release/projectdiscovery/katana?label=katana&logo=github)](https://github.com/projectdiscovery/katana/releases/latest)
[![dnsx](https://img.shields.io/github/v/release/projectdiscovery/dnsx?label=dnsx&logo=github)](https://github.com/projectdiscovery/dnsx/releases/latest)
[![gobuster](https://img.shields.io/github/v/release/OJ/gobuster?label=gobuster&logo=github)](https://github.com/OJ/gobuster/releases/latest)
[![ffuf](https://img.shields.io/github/v/release/ffuf/ffuf?label=ffuf&logo=github)](https://github.com/ffuf/ffuf/releases/latest)
[![sqlmap](https://img.shields.io/github/v/release/sqlmapproject/sqlmap?label=sqlmap&logo=github)](https://github.com/sqlmapproject/sqlmap/releases/latest)
[![dalfox](https://img.shields.io/github/v/release/hahwul/dalfox?label=dalfox&logo=github)](https://github.com/hahwul/dalfox/releases/latest)
[![arjun](https://img.shields.io/github/v/release/s0md3v/Arjun?label=arjun&logo=github)](https://github.com/s0md3v/Arjun/releases/latest)
[![osv-scanner](https://img.shields.io/github/v/release/google/osv-scanner?label=osv-scanner&logo=github)](https://github.com/google/osv-scanner/releases/latest)
[![nikto](https://img.shields.io/github/v/release/sullo/nikto?label=nikto&logo=github)](https://github.com/sullo/nikto/releases/latest)
[![WhatWeb](https://img.shields.io/github/v/release/urbanadventurer/WhatWeb?label=whatweb&logo=github)](https://github.com/urbanadventurer/WhatWeb/releases/latest)
[![testssl.sh](https://img.shields.io/github/v/release/drwetter/testssl.sh?label=testssl.sh&logo=github)](https://github.com/drwetter/testssl.sh/releases/latest)
[![WPScan](https://img.shields.io/github/v/release/wpscanteam/wpscan?label=wpscan&logo=github)](https://github.com/wpscanteam/wpscan/releases/latest)
[![ZAP](https://img.shields.io/github/v/release/zaproxy/zaproxy?label=owasp-zap&logo=github)](https://github.com/zaproxy/zaproxy/releases/latest)
[![bad-bot-blocker](https://img.shields.io/github/v/release/mitchellkrogza/nginx-ultimate-bad-bot-blocker?label=nginx-bad-bot-blocker&color=43819c)](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker)

---

**KP WebScanner** is a fully self-contained, Docker-based web security scanning suite. It bundles twenty-two industry-standard security tools into a single image, orchestrated by a single entrypoint script. Point it at any target and get a comprehensive security assessment covering passive recon, fingerprinting, subdomain enumeration, DNS analysis, port scanning, deep service fingerprinting, SSL/TLS auditing, HTTP security header grading, parameter discovery, XSS scanning, SQL injection testing, dependency vulnerability scanning, vulnerability detection, endpoint discovery, active scanning, and nginx bad bot blocker validation — with automatic WordPress-specific scanning when detected.

All tools install at their latest versions at image build time. No host dependencies beyond Docker or Podman are required.

> ⚠️ **Only scan targets you own or have explicit written permission to test. Unauthorized scanning is illegal.**

---

## Tools

| Tool | Category | Purpose |
|---|---|---|
| [Shodan](https://www.shodan.io) | Passive Recon | Query Shodan's index for open ports, banners & CVEs (zero active requests, optional API key) |
| [Censys](https://censys.io) | Passive Recon | Certificate, port & service intelligence from Censys (zero active requests, optional API credentials) |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability Scanning | Template-based CVE & misconfiguration detection |
| [httpx](https://github.com/projectdiscovery/httpx) | Fingerprinting | HTTP probing, tech detection, status codes |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Reconnaissance | Passive subdomain enumeration |
| [naabu](https://github.com/projectdiscovery/naabu) | Reconnaissance | Fast port scanning (top 1000, raw packet mode) |
| [Nmap](https://nmap.org) | Reconnaissance | Deep service fingerprinting and NSE vulnerability scripts against discovered ports |
| [katana](https://github.com/projectdiscovery/katana) | Discovery | Web crawling & JavaScript endpoint extraction |
| [dnsx](https://github.com/projectdiscovery/dnsx) | Reconnaissance | DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME) |
| [gobuster](https://github.com/OJ/gobuster) | Discovery | Directory & path brute-forcing |
| [ffuf](https://github.com/ffuf/ffuf) | Discovery | Fast web fuzzing |
| [sqlmap](https://github.com/sqlmapproject/sqlmap) | Injection Testing | Automated SQL injection detection & exploitation |
| [Dalfox](https://github.com/hahwul/dalfox) | XSS Scanning | Parameter analysis & XSS detection (reflected, DOM, stored) |
| [Arjun](https://github.com/s0md3v/Arjun) | Discovery | Hidden HTTP parameter discovery (25,890 param dictionary) |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Dependency Scanning | Scans exposed dependency/lockfiles for known CVEs via Google's OSV.dev database |
| [Nikto](https://github.com/sullo/nikto) | Vulnerability Scanning | Web server misconfiguration & known vulnerability checks |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | Fingerprinting | Web technology identification |
| [testssl.sh](https://github.com/drwetter/testssl.sh) | SSL/TLS | Cipher suite analysis, certificate validation, protocol weaknesses |
| [Mozilla Observatory](https://github.com/mdn/mdn-http-observatory) | Headers | HTTP security header grading (CSP, HSTS, SRI, X-Frame-Options, etc.) |
| [WPScan](https://github.com/wpscanteam/wpscan) | CMS | WordPress plugin/theme vuln scanning, user enumeration (auto-triggered) |
| [nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) | Validation | Verifies bad bots/referrers are blocked and good bots are not false-positived |
| [OWASP ZAP](https://github.com/zaproxy/zaproxy) | Active Scanning | Dynamic application security testing |

---

## Getting the Image

### Pull from GHCR

```bash
# Latest stable (main branch)
docker pull ghcr.io/kpirnie/webscanner:latest

# Development build
docker pull ghcr.io/kpirnie/webscanner:develop
```

### Build Locally

```bash
git clone https://github.com/kpirnie/webscanner.git
cd webscanner
docker build -t webscanner .
```

> First build takes approximately 10–20 minutes due to Go compilation and tool installation.

---

## Usage

```bash
docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    [-v /host/output/path:/output] \
    ghcr.io/kpirnie/webscanner:latest <target-uri> [options]
```

### Examples

```bash
# Quick scan — condensed findings summary to stdout
docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    ghcr.io/kpirnie/webscanner:latest https://example.com

# Full scan — all results written to host directory
docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    -v $(pwd)/results:/output \
    ghcr.io/kpirnie/webscanner:latest https://example.com -o results

# Targeted scan — high/critical only, skip ZAP and brute-forcing
docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    -v $(pwd)/results:/output \
    ghcr.io/kpirnie/webscanner:latest https://example.com \
    -o results --skip-zap --skip-brute --severity high,critical

# WordPress site with full vulnerability data (requires free API token)
docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    -e WPSCAN_API_TOKEN=your_token_here \
    -v $(pwd)/results:/output \
    ghcr.io/kpirnie/webscanner:latest https://example.com -o results
```

---

## Options

| Flag | Description |
|---|---|
| `<target-uri>` | Target to scan. Accepts bare domain (`example.com`) or full URI (`https://example.com:8443`) |
| `-o PATH` | Write all results to `/output/PATH` on the host. Requires a `-v` volume mount. Omit to print a condensed summary to stdout. |
| `--skip-zap` | Skip OWASP ZAP active scan |
| `--skip-brute` | Skip gobuster and ffuf directory brute-forcing |
| `--skip-nikto` | Skip Nikto scan |
| `--skip-sqlmap` | Skip sqlmap SQL injection scan |
| `--severity LEVEL` | Nuclei severity filter. Comma-separated. Default: `low,medium,high,critical` |

**Optional API keys** passed at runtime via `-e`:

| Variable | Tool | Get one at |
|---|---|---|
| `WPSCAN_API_TOKEN` | WPScan | [wpscan.com/register](https://wpscan.com/register) — 25 req/day free |
| `SHODAN_API_KEY` | Shodan | [account.shodan.io](https://account.shodan.io/register) — free tier available |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | Censys | [censys.io](https://censys.io/register) — free tier available |

---

## CMS Auto-Detection

KP WebScanner fingerprints the CMS during step 1 and automatically triggers WPScan when WordPress is detected. Drupal and Joomla are identified and logged — CVE coverage for both is handled by Nuclei's template library and ZAP's active scan.

| Detected CMS | Action |
|---|---|
| WordPress | WPScan (full plugin/theme/user enumeration) |
| Drupal | Detected & logged — Nuclei + ZAP provide coverage |
| Joomla | Detected & logged — Nuclei + ZAP provide coverage |

---

## Scan Pipeline

```
 1/18  Fingerprinting              WhatWeb, httpx
 2/18  Passive Recon               Shodan, Censys (optional API keys, zero active requests)
 3/18  Subdomain Enum              subfinder + httpx live probe
 4/18  DNS Enumeration             dnsx  (A, AAAA, CNAME, MX, NS, TXT)
 5/18  Port Scanning               naabu (top 1000, raw packet mode)
 6/18  Service Fingerprinting      Nmap (-sV -sC + vuln/safe NSE scripts on discovered ports)
 7/18  SSL/TLS Analysis            testssl.sh
 8/18  HTTP Security Headers       Mozilla Observatory
 9/18  Web Server Scan             Nikto (all CGI dirs, full tuning)
10/18  CMS Scanning                WPScan (WordPress only, auto-triggered)
11/18  Endpoint Discovery          katana, gobuster, ffuf
12/18  Parameter Discovery         Arjun (25,890 param dictionary)
13/18  XSS Scanning                Dalfox (reflected, DOM, stored)
14/18  SQL Injection               sqlmap (crawls + feeds katana endpoints)
15/18  Dependency Scanning         OSV-Scanner (scans exposed lockfiles via OSV.dev)
16/18  Vulnerability Scan          Nuclei
17/18  Bot Blocker Validation      nginx-ultimate-bad-bot-blocker (random sample, live lists)
18/18  Active Scan                 OWASP ZAP
```

---

## Output Structure

When using `-o`, each run creates a timestamped subdirectory:

```
results/
└── example.com_20260318_153000/
    ├── scan.log
    ├── whatweb.txt
    ├── httpx.txt
    ├── shodan.txt                           ← if SHODAN_API_KEY set
    ├── censys.txt                           ← if CENSYS_API_ID/SECRET set
    ├── subdomains.txt / subdomains_live.txt
    ├── dns.txt
    ├── ports.txt
    ├── nmap.txt / nmap.xml
    ├── testssl.txt / testssl.json
    ├── observatory.txt / observatory.json
    ├── nikto.txt / nikto.json
    ├── wpscan.txt / wpscan.json             ← WordPress only
    ├── endpoints.txt
    ├── gobuster.txt
    ├── ffuf.json
    ├── arjun.json
    ├── dalfox.txt
    ├── sqlmap/
    ├── osv_scanner.txt / osv_scanner.json   ← if exposed lockfiles found
    ├── nuclei.txt / nuclei.json
    ├── botblocker_test.txt
    └── zap_report.html
```

---

## Technical Notes

- `--network host` and `NET_ADMIN`/`NET_RAW` capabilities are required for naabu and Nmap raw packet scanning
- Nmap runs against ports discovered by naabu — if naabu finds nothing it falls back to common ports 80, 443, 8080, 8443
- OSV-Scanner downloads any exposed lockfiles/manifests found during endpoint discovery and scans them against the OSV.dev database; silently skipped if none are found
- OWASP ZAP runs directly inside the image — no nested container required
- ZAP heap is capped at 512MB via `JAVA_OPTS` to prevent OOM on memory-constrained hosts
- ZAP home directories are pre-created at build time to eliminate first-run initialization hangs
- Nuclei templates are baked into the image at build time and refreshed on each scan run
- Shodan and Censys do zero active scanning — both query existing indexes only; steps are silently skipped if no API keys are provided
- Arjun runs against the first 50 discovered endpoints to avoid excessive runtime
- Dalfox runs in file mode against all katana-discovered endpoints, falling back to the base URL if none found
- sqlmap runs at `--level=2 --risk=1` by default — safe for authorized testing without being overly aggressive
- Drupal and Joomla are detected and logged; CVE coverage is provided by Nuclei templates and ZAP rather than abandoned dedicated scanners
- Bot blocker validation fetches live lists from mitchellkrogza/nginx-ultimate-bad-bot-blocker at runtime, samples 20 random entries per category, and checks 5 known-good bots for false positives
- All Go-based tools are compiled in a separate builder stage; only binaries are copied to the final image, keeping image size lean

---

## License

[MIT](LICENSE) © 2026 [Kevin Pirnie](https://kevinpirnie.com/)