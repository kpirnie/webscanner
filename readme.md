# KP WebScanner

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GHCR Image](https://img.shields.io/badge/ghcr.io-kpirnie%2Fwebscanner-blue?logo=github)](https://github.com/kpirnie/webscanner/pkgs/container/webscanner)
[![Kevin Pirnie](https://img.shields.io/badge/www-kevinpirnie.com-orange)](https://kevinpirnie.com/)

[![Nuclei](https://img.shields.io/github/v/release/projectdiscovery/nuclei?label=nuclei&logo=github)](https://github.com/projectdiscovery/nuclei/releases/latest)
[![httpx](https://img.shields.io/github/v/release/projectdiscovery/httpx?label=httpx&logo=github)](https://github.com/projectdiscovery/httpx/releases/latest)
[![subfinder](https://img.shields.io/github/v/release/projectdiscovery/subfinder?label=subfinder&logo=github)](https://github.com/projectdiscovery/subfinder/releases/latest)
[![naabu](https://img.shields.io/github/v/release/projectdiscovery/naabu?label=naabu&logo=github)](https://github.com/projectdiscovery/naabu/releases/latest)
[![katana](https://img.shields.io/github/v/release/projectdiscovery/katana?label=katana&logo=github)](https://github.com/projectdiscovery/katana/releases/latest)
[![dnsx](https://img.shields.io/github/v/release/projectdiscovery/dnsx?label=dnsx&logo=github)](https://github.com/projectdiscovery/dnsx/releases/latest)
[![gobuster](https://img.shields.io/github/v/release/OJ/gobuster?label=gobuster&logo=github)](https://github.com/OJ/gobuster/releases/latest)
[![ffuf](https://img.shields.io/github/v/release/ffuf/ffuf?label=ffuf&logo=github)](https://github.com/ffuf/ffuf/releases/latest)
[![nikto](https://img.shields.io/github/v/release/sullo/nikto?label=nikto&logo=github)](https://github.com/sullo/nikto/releases/latest)
[![WhatWeb](https://img.shields.io/github/v/release/urbanadventurer/WhatWeb?label=whatweb&logo=github)](https://github.com/urbanadventurer/WhatWeb/releases/latest)
[![testssl.sh](https://img.shields.io/github/v/release/drwetter/testssl.sh?label=testssl.sh&logo=github)](https://github.com/drwetter/testssl.sh/releases/latest)
[![WPScan](https://img.shields.io/github/v/release/wpscanteam/wpscan?label=wpscan&logo=github)](https://github.com/wpscanteam/wpscan/releases/latest)
[![ZAP](https://img.shields.io/github/v/release/zaproxy/zaproxy?label=owasp-zap&logo=github)](https://github.com/zaproxy/zaproxy/releases/latest)

---

**KP WebScanner** is a fully self-contained, Docker-based web security scanning suite. It bundles thirteen industry-standard security tools into a single image, orchestrated by a single entrypoint script. Point it at any target and get a comprehensive security assessment covering fingerprinting, subdomain enumeration, DNS analysis, port scanning, SSL/TLS auditing, vulnerability detection, endpoint discovery, and active scanning — with automatic WordPress-specific scanning when WordPress is detected.

All tools install at their latest versions at image build time. No host dependencies beyond Docker or Podman are required.

> ⚠️ **Only scan targets you own or have explicit written permission to test. Unauthorized scanning is illegal.**

---

## Tools

| Tool | Category | Purpose |
|---|---|---|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability Scanning | Template-based CVE & misconfiguration detection |
| [httpx](https://github.com/projectdiscovery/httpx) | Fingerprinting | HTTP probing, tech detection, status codes |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Reconnaissance | Passive subdomain enumeration |
| [naabu](https://github.com/projectdiscovery/naabu) | Reconnaissance | Fast port scanning (raw packet mode) |
| [katana](https://github.com/projectdiscovery/katana) | Discovery | Web crawling & JavaScript endpoint extraction |
| [dnsx](https://github.com/projectdiscovery/dnsx) | Reconnaissance | DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME) |
| [gobuster](https://github.com/OJ/gobuster) | Discovery | Directory & path brute-forcing |
| [ffuf](https://github.com/ffuf/ffuf) | Discovery | Fast web fuzzing |
| [Nikto](https://github.com/sullo/nikto) | Vulnerability Scanning | Web server misconfiguration & known vulnerability checks |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | Fingerprinting | Web technology identification |
| [testssl.sh](https://github.com/drwetter/testssl.sh) | SSL/TLS | Cipher suite analysis, certificate validation, protocol weaknesses |
| [WPScan](https://github.com/wpscanteam/wpscan) | WordPress | Plugin/theme vulnerability scanning, user enumeration (auto-triggered) |
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
| `--severity LEVEL` | Nuclei severity filter. Comma-separated. Default: `low,medium,high,critical` |

---

## WPScan & API Token

WPScan is triggered automatically when WordPress is detected in the fingerprinting phase (via httpx or WhatWeb output). It enumerates vulnerable plugins, vulnerable themes, and user accounts.

Without an API token, WPScan still runs but returns no vulnerability data. A **free API token** providing 25 requests/day is available at [wpscan.com/register](https://wpscan.com/register). Pass it at runtime:

```bash
docker run ... -e WPSCAN_API_TOKEN=your_token_here ghcr.io/kpirnie/webscanner:latest ...
```

---

## Scan Pipeline

```
 1/10  Fingerprinting       WhatWeb, httpx
 2/10  Subdomain Enum       subfinder + httpx live probe
 3/10  DNS Enumeration      dnsx  (A, AAAA, CNAME, MX, NS, TXT)
 4/10  Port Scanning        naabu (top 1000 ports, raw packet mode)
 5/10  SSL/TLS Analysis     testssl.sh
 6/10  Web Server Scan      Nikto (all CGI dirs, full tuning)
 7/10  WordPress Scan       WPScan (auto-triggered if WordPress detected)
 8/10  Endpoint Discovery   katana, gobuster, ffuf
 9/10  Vulnerability Scan   Nuclei
10/10  Active Scan          OWASP ZAP
```

---

## Output Structure

When using `-o`, each run creates a timestamped subdirectory:

```
results/
└── example.com_20260318_153000/
    ├── scan.log                    ← full master log of the entire run
    ├── whatweb.txt
    ├── httpx.txt
    ├── subdomains.txt
    ├── subdomains_live.txt
    ├── dns.txt
    ├── ports.txt
    ├── testssl.txt
    ├── testssl.json
    ├── nikto.txt
    ├── nikto.json
    ├── wpscan.txt                  ← WordPress sites only
    ├── wpscan.json                 ← WordPress sites only
    ├── endpoints.txt
    ├── gobuster.txt
    ├── ffuf.json
    ├── nuclei.txt
    ├── nuclei.json
    └── zap_report.html
```

When `-o` is omitted, a condensed findings summary is printed to stdout covering fingerprint, open ports, SSL issues, Nikto findings, WPScan findings, and Nuclei results.

---

## Technical Notes

- `--network host` and `NET_ADMIN`/`NET_RAW` capabilities are required for naabu's raw packet port scanning
- OWASP ZAP runs directly inside the image — no nested container required
- ZAP heap is capped at 512MB via `JAVA_OPTS` to prevent OOM on memory-constrained hosts
- ZAP home directories are pre-created at build time to eliminate first-run initialization hangs
- Nuclei templates are baked into the image at build time and refreshed on each scan run
- All Go-based tools are compiled in a separate builder stage; only binaries are copied to the final image, keeping image size lean

---

## License

[MIT](LICENSE) © 2026 [Kevin Pirnie](https://kevinpirnie.com/)
