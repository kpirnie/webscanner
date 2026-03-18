# webscan

Full web security scanning suite in a single container.

## Tools

| Tool | Purpose |
|---|---|
| nuclei | CVE & vulnerability scanning |
| httpx | HTTP fingerprinting & tech detection |
| subfinder | Subdomain enumeration |
| naabu | Port scanning |
| katana | Web crawling & endpoint discovery |
| dnsx | DNS record enumeration |
| gobuster | Directory brute-forcing |
| ffuf | Web fuzzing |
| nikto | Web server misconfiguration & vuln scanning |
| whatweb | Web technology fingerprinting |
| testssl.sh | SSL/TLS analysis |
| wpscan | WordPress vulnerability scanner (auto-triggered if WP detected) |
| OWASP ZAP | Active web vulnerability scanner |

## Build

```bash
docker build -t webscan .
```

First build takes 10–20 minutes.

## Run

```bash
# Summary to stdout
docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    webscan https://example.com

# Write full results to host directory
docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    -v /host/path/to/results:/output \
    webscan https://example.com -o results

# Skip ZAP, high/critical only
docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    -v /host/path/to/results:/output \
    webscan https://example.com -o results --skip-zap --severity high,critical

# With WPScan API token for full vulnerability data
docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    -e WPSCAN_API_TOKEN=your_token_here \
    -v /host/path/to/results:/output \
    webscan https://example.com -o results
```

## Options

| Flag | Description |
|---|---|
| `-o PATH` | Write results to `/output/PATH` (requires `-v` mount). Omit to print summary to stdout. |
| `--skip-zap` | Skip OWASP ZAP |
| `--skip-brute` | Skip gobuster + ffuf |
| `--skip-nikto` | Skip nikto |
| `--severity LEVEL` | Nuclei severity filter (default: `low,medium,high,critical`) |

## WPScan API Token

WPScan runs automatically if WordPress is detected. Without an API token it still scans but returns no vulnerability data. A free token (25 req/day) is available at https://wpscan.com/register.

Pass it at runtime:

```bash
docker run ... -e WPSCAN_API_TOKEN=your_token_here webscan https://example.com
```

## Scan Steps

```
 1/10  Fingerprinting       whatweb, httpx
 2/10  Subdomain enum       subfinder + httpx probe
 3/10  DNS enumeration      dnsx
 4/10  Port scanning        naabu (top 1000)
 5/10  SSL/TLS analysis     testssl.sh
 6/10  Web server scan      nikto (all CGI dirs, full tuning)
 7/10  WordPress scan       wpscan (only if WordPress detected)
 8/10  Endpoint discovery   katana, gobuster, ffuf
 9/10  Vulnerability scan   nuclei
10/10  Active scan          OWASP ZAP
```

## Output

Each run creates a timestamped subdirectory under your mounted output path:

```
/host/path/to/results/
└── example.com_20260318_153000/
    ├── scan.log
    ├── whatweb.txt
    ├── httpx.txt
    ├── subdomains.txt / subdomains_live.txt
    ├── dns.txt
    ├── ports.txt
    ├── testssl.txt / testssl.json
    ├── nikto.txt / nikto.json
    ├── wpscan.txt / wpscan.json   (WordPress sites only)
    ├── endpoints.txt
    ├── gobuster.txt
    ├── ffuf.json
    ├── nuclei.txt / nuclei.json
    └── zap_report.html
```

## Notes

- `--network host` and `NET_ADMIN`/`NET_RAW` caps are required for naabu raw packet scanning
- ZAP runs directly inside the image — no nested container required
- ZAP heap is capped at 512MB to prevent OOM on memory-constrained hosts
- **Only scan targets you own or have explicit written permission to test**
