#!/usr/bin/env bash
# =============================================================================
# scan.sh — webscan entrypoint (runs inside container)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
ok()      { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
section() {
    echo -e "\n${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}${CYAN}  $*${RESET}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
}

usage() {
cat <<EOF

${BOLD}webscan${RESET} — Full web security scanning suite

${BOLD}Usage:${RESET}
  docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \\
    [-v /host/output/path:/output] \\
    webscan <target-uri> [options]

${BOLD}Arguments:${RESET}
  <target-uri>        Bare domain or full URI
                        example.com
                        https://example.com
                        https://example.com:8443

${BOLD}Options:${RESET}
  -o PATH               Write results to /output/PATH (requires volume mount)
                        Omit to print summary to stdout
  --severity LEVEL      Nuclei severity filter (default: low,medium,high,critical)

${BOLD}Skip Flags:${RESET}
  --skip-fingerprint    Skip WhatWeb + httpx
  --skip-recon          Skip Shodan + Censys
  --skip-subdomains     Skip subfinder subdomain enumeration
  --skip-dns            Skip dnsx DNS enumeration
  --skip-ports          Skip naabu port scanning
  --skip-nmap           Skip Nmap service + script scan
  --skip-ssl            Skip testssl.sh
  --skip-headers        Skip Mozilla Observatory
  --skip-nikto          Skip Nikto
  --skip-cms            Skip CMS detection + WPScan
  --skip-crawl          Skip katana crawling
  --skip-brute          Skip gobuster + ffuf
  --skip-arjun          Skip Arjun parameter discovery
  --skip-xss            Skip Dalfox XSS scanning
  --skip-sqlmap         Skip sqlmap SQL injection
  --skip-osv            Skip OSV-Scanner dependency scanning
  --skip-nuclei         Skip Nuclei vulnerability scanning
  --skip-botblocker     Skip nginx bad bot blocker validation
  --bot-sample N        Bad-bot random sample size per category (default: 50)
  --skip-zap            Skip OWASP ZAP active scan
  --help                Show this help

EOF
    exit 0
}

# -----------------------------------------------------------------------------
# Args
# -----------------------------------------------------------------------------
[[ $# -lt 1 || "$1" == "--help" ]] && usage

TARGET_RAW="$1"; shift

OUTPUT_PATH=""
SEVERITY="low,medium,high,critical"
SKIP_FINGERPRINT=false
SKIP_RECON=false
SKIP_SUBDOMAINS=false
SKIP_DNS=false
SKIP_PORTS=false
SKIP_NMAP=false
SKIP_SSL=false
SKIP_HEADERS=false
SKIP_NIKTO=false
SKIP_CMS=false
SKIP_CRAWL=false
SKIP_BRUTE=false
SKIP_ARJUN=false
SKIP_XSS=false
SKIP_SQLMAP=false
SKIP_OSV=false
SKIP_NUCLEI=false
SKIP_BOTBLOCKER=false
SKIP_ZAP=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o)                  OUTPUT_PATH="$2"; shift ;;
        --severity)          SEVERITY="$2"; shift ;;
        --skip-fingerprint)  SKIP_FINGERPRINT=true ;;
        --skip-recon)        SKIP_RECON=true ;;
        --skip-subdomains)   SKIP_SUBDOMAINS=true ;;
        --skip-dns)          SKIP_DNS=true ;;
        --skip-ports)        SKIP_PORTS=true ;;
        --skip-nmap)         SKIP_NMAP=true ;;
        --skip-ssl)          SKIP_SSL=true ;;
        --skip-headers)      SKIP_HEADERS=true ;;
        --skip-nikto)        SKIP_NIKTO=true ;;
        --skip-cms)          SKIP_CMS=true ;;
        --skip-crawl)        SKIP_CRAWL=true ;;
        --skip-brute)        SKIP_BRUTE=true ;;
        --skip-arjun)        SKIP_ARJUN=true ;;
        --skip-xss)          SKIP_XSS=true ;;
        --skip-sqlmap)       SKIP_SQLMAP=true ;;
        --skip-osv)          SKIP_OSV=true ;;
        --skip-nuclei)       SKIP_NUCLEI=true ;;
        --skip-botblocker)   SKIP_BOTBLOCKER=true ;;
        --bot-sample)        SAMPLE_SIZE="$2"; shift ;;
        --skip-zap)          SKIP_ZAP=true ;;
        --help)              usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
    shift
done

# -----------------------------------------------------------------------------
# Normalise target
# -----------------------------------------------------------------------------
TARGET_URI="${TARGET_RAW%/}"
[[ "${TARGET_URI}" != http* ]] && TARGET_URI="https://${TARGET_URI}"
TARGET_HOST=$(echo "${TARGET_URI}" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)

# -----------------------------------------------------------------------------
# Output directory
# -----------------------------------------------------------------------------
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCAN_NAME="${TARGET_HOST}_${TIMESTAMP}"

if [[ -n "${OUTPUT_PATH}" ]]; then
    OUT_DIR="/output/${OUTPUT_PATH}/${SCAN_NAME}"
    mkdir -p "${OUT_DIR}"
    exec > >(tee -a "${OUT_DIR}/scan.log") 2>&1
else
    OUT_DIR="/tmp/${SCAN_NAME}"
    mkdir -p "${OUT_DIR}"
fi

# Wordlist
WORDLIST=""
for wl in /usr/share/wordlists/big.txt \
          /usr/share/dirb/wordlists/big.txt \
          /usr/share/wordlists/dirb/big.txt \
          /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt; do
    [[ -f "${wl}" ]] && { WORDLIST="${wl}"; break; }
done

# -----------------------------------------------------------------------------
# Banner
# -----------------------------------------------------------------------------
section "webscan"
info "Target:      ${BOLD}${TARGET_URI}${RESET}"
info "Host:        ${TARGET_HOST}"
[[ -n "${OUTPUT_PATH}" ]] && info "Output:      ${OUT_DIR}"
info "Severity:    ${SEVERITY}"
info "Started:     $(date)"

# -----------------------------------------------------------------------------
# 1 — Fingerprinting
# -----------------------------------------------------------------------------
section "1/18 — Fingerprinting"

if [[ "${SKIP_FINGERPRINT}" == "false" ]]; then
    info "whatweb..."
    whatweb "${TARGET_URI}" --log-verbose="${OUT_DIR}/whatweb.txt" 2>&1 \
        | tee "${OUT_DIR}/whatweb_console.txt" || true
    ok "whatweb done"

    info "httpx..."
    echo "${TARGET_HOST}" | httpx \
        -title -tech-detect -status-code -content-length -web-server -ip \
        -follow-redirects -o "${OUT_DIR}/httpx.txt" 2>&1 \
        | tee "${OUT_DIR}/httpx_console.txt" || true
    ok "httpx done"
else
    warn "Fingerprinting skipped (--skip-fingerprint)"
fi

# -----------------------------------------------------------------------------
# 2 — Passive Recon
# -----------------------------------------------------------------------------
section "2/18 — Passive Recon (Shodan & Censys)"

TARGET_IP=$(dig +short "${TARGET_HOST}" | grep -E '^[0-9]+\.' | head -1)

if [[ "${SKIP_RECON}" == "false" ]]; then
    if [[ -n "${SHODAN_API_KEY:-}" ]]; then
        info "Shodan lookup..."
        if [[ -n "${TARGET_IP}" ]]; then
            shodan init "${SHODAN_API_KEY}" &>/dev/null
            shodan host "${TARGET_IP}" > "${OUT_DIR}/shodan.txt" 2>&1 || true
            ok "Shodan done → ${OUT_DIR}/shodan.txt"
        else
            warn "Could not resolve ${TARGET_HOST} for Shodan"
        fi
    else
        warn "SHODAN_API_KEY not set — skipping Shodan (free key at shodan.io)"
    fi

    if [[ -n "${CENSYS_APP_ID:-}" && -n "${CENSYS_TOKEN:-}" ]]; then
        info "Censys lookup..."
        curl -s -H "Authorization: Bearer ${CENSYS_TOKEN}" \
            "https://search.censys.io/api/v2/hosts/${TARGET_IP:-${TARGET_HOST}}" \
            > "${OUT_DIR}/censys.txt" 2>&1 || true
        ok "Censys done → ${OUT_DIR}/censys.txt"
    else
        warn "CENSYS_APP_ID/CENSYS_TOKEN not set — skipping Censys (free at censys.io)"
    fi
else
    warn "Passive recon skipped (--skip-recon)"
fi

# -----------------------------------------------------------------------------
# 3 — Subdomain Enumeration
# -----------------------------------------------------------------------------
section "3/18 — Subdomain Enumeration"

if [[ "${SKIP_SUBDOMAINS}" == "false" ]]; then
    info "subfinder..."
    subfinder -d "${TARGET_HOST}" -o "${OUT_DIR}/subdomains.txt" 2>&1 \
        | tee "${OUT_DIR}/subfinder_console.txt" || true
    ok "subfinder done"

    if [[ -s "${OUT_DIR}/subdomains.txt" ]]; then
        info "Probing live subdomains..."
        cat "${OUT_DIR}/subdomains.txt" | httpx \
            -title -tech-detect -status-code \
            -o "${OUT_DIR}/subdomains_live.txt" 2>&1 || true
        ok "Subdomain probe done"
    fi
else
    warn "Subdomain enumeration skipped (--skip-subdomains)"
fi

# -----------------------------------------------------------------------------
# 4 — DNS
# -----------------------------------------------------------------------------
section "4/18 — DNS Enumeration"

if [[ "${SKIP_DNS}" == "false" ]]; then
    info "dnsx..."
    echo "${TARGET_HOST}" | dnsx \
        -a -aaaa -cname -mx -ns -txt -resp \
        -o "${OUT_DIR}/dns.txt" 2>&1 \
        | tee "${OUT_DIR}/dnsx_console.txt" || true
    ok "dnsx done"
else
    warn "DNS enumeration skipped (--skip-dns)"
fi

# -----------------------------------------------------------------------------
# 5 — Ports
# -----------------------------------------------------------------------------
section "5/18 — Port Scanning"

if [[ "${SKIP_PORTS}" == "false" ]]; then
    info "naabu (top 1000)..."
    naabu -host "${TARGET_HOST}" -top-ports 1000 \
        -o "${OUT_DIR}/ports.txt" 2>&1 \
        | tee "${OUT_DIR}/naabu_console.txt" || true
    ok "naabu done"
else
    warn "Port scanning skipped (--skip-ports)"
fi

# -----------------------------------------------------------------------------
# 6 — Nmap
# -----------------------------------------------------------------------------
section "6/18 — Nmap Service & Script Scan"

if [[ "${SKIP_NMAP}" == "false" ]]; then
    info "nmap — service detection and NSE vuln scripts..."
    if [[ -s "${OUT_DIR}/ports.txt" ]]; then
        OPEN_PORTS=$(grep -oE ':[0-9]+' "${OUT_DIR}/ports.txt" | tr -d ':' | sort -u | tr '\n' ',' | sed 's/,$//')
    else
        OPEN_PORTS="80,443,8080,8443"
    fi

    nmap -sV -sC \
        --script "vuln,safe,default" \
        -p "${OPEN_PORTS}" \
        --open \
        -oN "${OUT_DIR}/nmap.txt" \
        -oX "${OUT_DIR}/nmap.xml" \
        --host-timeout 300s \
        --max-retries 2 \
        "${TARGET_HOST}" 2>&1 \
        | tee "${OUT_DIR}/nmap_console.txt" || true
    ok "nmap done"
else
    warn "Nmap skipped (--skip-nmap)"
fi

# -----------------------------------------------------------------------------
# 7 — SSL/TLS
# -----------------------------------------------------------------------------
section "7/18 — SSL/TLS Analysis"

if [[ "${SKIP_SSL}" == "false" ]]; then
    info "testssl.sh..."
    testssl.sh \
        --logfile "${OUT_DIR}/testssl.txt" \
        --jsonfile "${OUT_DIR}/testssl.json" \
        --severity LOW --quiet \
        "${TARGET_URI}" 2>&1 \
        | tee "${OUT_DIR}/testssl_console.txt" || true
    ok "testssl.sh done"
else
    warn "SSL/TLS analysis skipped (--skip-ssl)"
fi

# -----------------------------------------------------------------------------
# 8 — Mozilla HTTP Observatory
# -----------------------------------------------------------------------------
section "8/18 — HTTP Security Headers (Mozilla Observatory)"

if [[ "${SKIP_HEADERS}" == "false" ]]; then
    info "observatory..."
    if command -v mdn-http-observatory-scan &>/dev/null; then
        mdn-http-observatory-scan "${TARGET_HOST}" \
            > "${OUT_DIR}/observatory.json" \
            2> "${OUT_DIR}/observatory_error.txt" || true
        ok "observatory done"
    else
        info "observatory CLI not found, querying MDN API..."
        curl -sf --max-time 30 \
            -X POST \
            "https://observatory-api.mdn.mozilla.net/api/v2/scan?host=${TARGET_HOST}" \
            -o "${OUT_DIR}/observatory.json" \
            2> "${OUT_DIR}/observatory_error.txt" || true
        ok "observatory done (API fallback)"
    fi
else
    warn "HTTP header analysis skipped (--skip-headers)"
fi

# -----------------------------------------------------------------------------
# 9 — Nikto
# -----------------------------------------------------------------------------
section "9/18 — Nikto"

if [[ "${SKIP_NIKTO}" == "false" ]]; then
    info "nikto (all CGI dirs, full tuning)..."
    nikto -h "${TARGET_URI}" -C all -Tuning x -nointeractive \
        -Format txt -o "${OUT_DIR}/nikto.txt" 2>&1 \
        | tee "${OUT_DIR}/nikto_console.txt" || true
    nikto -h "${TARGET_URI}" -C all -Tuning x -nointeractive \
        -Format json -o "${OUT_DIR}/nikto.json" 2>&1 \
        >> "${OUT_DIR}/nikto_console.txt" || true
    ok "nikto done"
else
    warn "Nikto skipped (--skip-nikto)"
fi

# -----------------------------------------------------------------------------
# 10 — CMS Scanning
# -----------------------------------------------------------------------------
section "10/18 — CMS Scanning"

if [[ "${SKIP_CMS}" == "false" ]]; then
    IS_WORDPRESS=false
    IS_DRUPAL=false
    IS_JOOMLA=false

    grep -qi "wordpress" "${OUT_DIR}/httpx.txt"   2>/dev/null && IS_WORDPRESS=true
    grep -qi "wordpress" "${OUT_DIR}/whatweb.txt"  2>/dev/null && IS_WORDPRESS=true
    grep -qi "drupal"    "${OUT_DIR}/httpx.txt"   2>/dev/null && IS_DRUPAL=true
    grep -qi "drupal"    "${OUT_DIR}/whatweb.txt"  2>/dev/null && IS_DRUPAL=true
    grep -qi "joomla"    "${OUT_DIR}/httpx.txt"   2>/dev/null && IS_JOOMLA=true
    grep -qi "joomla"    "${OUT_DIR}/whatweb.txt"  2>/dev/null && IS_JOOMLA=true

    if [[ "${IS_WORDPRESS}" == "true" ]]; then
        info "WordPress detected — running WPScan..."
        WPSCAN_ARGS=(
            --url "${TARGET_URI}"
            --enumerate vp,vt,u
            --plugins-detection mixed
            --no-banner
            --format json
            --output "${OUT_DIR}/wpscan.json"
        )
        [[ -n "${WPSCAN_API_TOKEN:-}" ]] && WPSCAN_ARGS+=(--api-token "${WPSCAN_API_TOKEN}")
        wpscan "${WPSCAN_ARGS[@]}" 2>&1 | tee "${OUT_DIR}/wpscan_console.txt" || true
        wpscan --url "${TARGET_URI}" \
            --enumerate vp,vt,u \
            --plugins-detection mixed \
            --no-banner \
            ${WPSCAN_API_TOKEN:+--api-token "${WPSCAN_API_TOKEN}"} \
            --output "${OUT_DIR}/wpscan.txt" \
            2>/dev/null || true
        ok "WPScan done"
    else
        warn "WordPress not detected — skipping WPScan"
    fi

    [[ "${IS_DRUPAL}" == "true" ]]  && warn "Drupal detected — covered by Nuclei templates and ZAP active scan"
    [[ "${IS_JOOMLA}" == "true" ]]  && warn "Joomla detected — covered by Nuclei templates and ZAP active scan"
    [[ "${IS_WORDPRESS}" == "false" && "${IS_DRUPAL}" == "false" && "${IS_JOOMLA}" == "false" ]] && \
        info "No known CMS detected"
else
    warn "CMS scanning skipped (--skip-cms)"
fi

# -----------------------------------------------------------------------------
# 11 — Endpoint Discovery
# -----------------------------------------------------------------------------
section "11/18 — Endpoint Discovery"

if [[ "${SKIP_CRAWL}" == "false" ]]; then
    info "katana..."
    katana -u "${TARGET_URI}" -depth 3 -js-crawl \
        -o "${OUT_DIR}/endpoints.txt" 2>&1 \
        | tee "${OUT_DIR}/katana_console.txt" || true
    ok "katana done"
else
    warn "Crawling skipped (--skip-crawl)"
fi

if [[ "${SKIP_BRUTE}" == "false" ]]; then
    if [[ -n "${WORDLIST}" ]]; then
        info "gobuster..."
        gobuster dir -u "${TARGET_URI}" -w "${WORDLIST}" \
            -o "${OUT_DIR}/gobuster.txt" -k --timeout 10s \
            --delay 100ms 2>&1 \
            | tee "${OUT_DIR}/gobuster_console.txt" || true
        ok "gobuster done"

        info "ffuf..."
        ffuf -u "${TARGET_URI}/FUZZ" -w "${WORDLIST}" \
            -o "${OUT_DIR}/ffuf.json" -of json \
            -mc 200,201,204,301,302,307,401,403 -timeout 10 \
            -rate 50 2>&1 \
            | tee "${OUT_DIR}/ffuf_console.txt" || true
        ok "ffuf done"
    else
        warn "No wordlist found — skipping gobuster and ffuf"
    fi
else
    warn "Brute-forcing skipped (--skip-brute)"
fi

# -----------------------------------------------------------------------------
# 12 — Arjun
# -----------------------------------------------------------------------------
section "12/18 — Arjun (Parameter Discovery)"

if [[ "${SKIP_ARJUN}" == "false" ]]; then
    info "arjun — discovering hidden parameters..."
    if [[ -s "${OUT_DIR}/endpoints.txt" ]]; then
        head -50 "${OUT_DIR}/endpoints.txt" > "${OUT_DIR}/arjun_targets.txt"
        arjun -i "${OUT_DIR}/arjun_targets.txt" \
            -oJ "${OUT_DIR}/arjun.json" \
            -t 10 \
            2>&1 | tee "${OUT_DIR}/arjun_console.txt" || true
    else
        arjun -u "${TARGET_URI}" \
            -oJ "${OUT_DIR}/arjun.json" \
            -t 10 \
            2>&1 | tee "${OUT_DIR}/arjun_console.txt" || true
    fi
    ok "arjun done"
else
    warn "Arjun skipped (--skip-arjun)"
fi

# -----------------------------------------------------------------------------
# 13 — Dalfox
# -----------------------------------------------------------------------------
section "13/18 — Dalfox (XSS Scanning)"

if [[ "${SKIP_XSS}" == "false" ]]; then
    info "dalfox — scanning for XSS..."
    if [[ -s "${OUT_DIR}/endpoints.txt" ]]; then
        dalfox file "${OUT_DIR}/endpoints.txt" \
            --silence --no-spinner --follow-redirects \
            --output "${OUT_DIR}/dalfox.txt" \
            2>&1 | tee "${OUT_DIR}/dalfox_console.txt" || true
    else
        dalfox url "${TARGET_URI}" \
            --silence --no-spinner --follow-redirects \
            --output "${OUT_DIR}/dalfox.txt" \
            2>&1 | tee "${OUT_DIR}/dalfox_console.txt" || true
    fi
    ok "dalfox done"
else
    warn "XSS scanning skipped (--skip-xss)"
fi

# -----------------------------------------------------------------------------
# 14 — SQLMap
# -----------------------------------------------------------------------------
section "14/18 — SQLMap (SQL Injection)"

if [[ "${SKIP_SQLMAP}" == "false" ]]; then
    info "sqlmap — crawling target for injection points..."
    SQLMAP_ARGS=(
        -u "${TARGET_URI}"
        --crawl=2
        --forms
        --batch
        --level=2
        --risk=1
        --output-dir="${OUT_DIR}/sqlmap"
        --random-agent
        --timeout=10
        --retries=2
    )

    if [[ -s "${OUT_DIR}/endpoints.txt" ]]; then
        info "Feeding katana-discovered endpoints to sqlmap..."
        SQLMAP_ARGS+=(-m "${OUT_DIR}/endpoints.txt")
    fi

    sqlmap "${SQLMAP_ARGS[@]}" 2>&1 \
        | tee "${OUT_DIR}/sqlmap_console.txt" || true
    ok "sqlmap done"
else
    warn "sqlmap skipped (--skip-sqlmap)"
fi

# -----------------------------------------------------------------------------
# 15 — OSV-Scanner
# -----------------------------------------------------------------------------
section "15/18 — OSV-Scanner (Dependency Vulnerabilities)"

if [[ "${SKIP_OSV}" == "false" ]]; then
    info "osv-scanner — checking for exposed dependency files..."
    OSV_DIR="${OUT_DIR}/osv_scan"
    mkdir -p "${OSV_DIR}"

    if [[ -s "${OUT_DIR}/endpoints.txt" ]]; then
        while IFS= read -r url; do
            if echo "${url}" | grep -qiE \
                '(composer\.(json|lock)|package(-lock)?\.json|yarn\.lock|requirements.*\.txt|Gemfile(\.lock)?|go\.(mod|sum)|pom\.xml|Cargo\.(toml|lock)|\.csproj|packages\.config)$'; then
                SAFE_NAME=$(echo "${url}" | sed 's|[^a-zA-Z0-9._-]|_|g' | cut -c1-120)
                curl -sf --max-time 10 "${url}" \
                    -o "${OSV_DIR}/${SAFE_NAME}" 2>/dev/null && \
                    info "Downloaded: ${url}"
            fi
        done < "${OUT_DIR}/endpoints.txt"
    fi

    for dep_path in \
        composer.json composer.lock \
        package.json package-lock.json yarn.lock \
        requirements.txt requirements-dev.txt \
        Gemfile Gemfile.lock \
        go.mod go.sum \
        Cargo.toml Cargo.lock; do
        curl -sf --max-time 8 "${TARGET_URI}/${dep_path}" \
            -o "${OSV_DIR}/${dep_path}" 2>/dev/null && \
            info "Found exposed: ${dep_path}" || \
            rm -f "${OSV_DIR}/${dep_path}"
    done

    if find "${OSV_DIR}" -type f | grep -q .; then
        info "Running osv-scanner on discovered dependency files..."
        osv-scanner scan source \
            --recursive \
            --format json \
            "${OSV_DIR}" \
            > "${OUT_DIR}/osv_scanner.json" 2>&1 || true
        osv-scanner scan source \
            --recursive \
            "${OSV_DIR}" \
            > "${OUT_DIR}/osv_scanner.txt" 2>&1 || true
        ok "osv-scanner done"
    else
        warn "No exposed dependency files found — skipping osv-scanner"
    fi
else
    warn "OSV-Scanner skipped (--skip-osv)"
fi

# -----------------------------------------------------------------------------
# 16 — Nuclei
# -----------------------------------------------------------------------------
section "16/18 — Nuclei"

if [[ "${SKIP_NUCLEI}" == "false" ]]; then
    info "Updating templates..."
    nuclei -update-templates -silent 2>/dev/null || true

    info "nuclei..."
    nuclei -u "${TARGET_URI}" \
        -o "${OUT_DIR}/nuclei.txt" \
        -je "${OUT_DIR}/nuclei.json" \
        -severity "${SEVERITY}" -stats 2>&1 \
        | tee "${OUT_DIR}/nuclei_console.txt" || true
    ok "nuclei done"
else
    warn "Nuclei skipped (--skip-nuclei)"
fi

# -----------------------------------------------------------------------------
# 17 — Nginx Bad Bot Blocker Validation
# -----------------------------------------------------------------------------
section "17/18 — Nginx Bad Bot Blocker Validation"

if [[ "${SKIP_BOTBLOCKER}" == "false" ]]; then
    REPO_RAW="https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists"
    SAMPLE_SIZE=50
    BOT_REPORT="${OUT_DIR}/botblocker_test.txt"
    BLOCKED=0
    ALLOWED=0
    FP=0

    is_blocked() {
        local ua="${1:-}" ref="${2:-}"
        local http_code
        http_code=$(curl -sf \
            --max-time 8 \
            --connect-timeout 5 \
            ${ua:+-A "${ua}"} \
            ${ref:+-e "${ref}"} \
            -o /dev/null \
            -w "%{http_code}" \
            "${TARGET_URI}" 2>/dev/null) || { echo "blocked"; return; }
        if [[ "${http_code}" =~ ^[23][0-9][0-9]$ ]]; then
            echo "allowed"
        else
            echo "blocked"
        fi
    }

    info "Fetching bad user-agent list..."
    BAD_UA_LIST=$(curl -sf --max-time 15 "${REPO_RAW}/bad-user-agents.list" 2>/dev/null | \
        grep -v '^#' | grep -v '^[[:space:]]*$' | shuf | head -${SAMPLE_SIZE}) || true

    info "Fetching fake Googlebot list..."
    FAKE_GOOGLE_LIST=$(curl -sf --max-time 15 "${REPO_RAW}/fake-googlebots.list" 2>/dev/null | \
        grep -v '^#' | grep -v '^[[:space:]]*$' | shuf | head -${SAMPLE_SIZE}) || true

    info "Fetching bad referrer list..."
    BAD_REF_LIST=$(curl -sf --max-time 15 "${REPO_RAW}/bad-referrers.list" 2>/dev/null | \
        grep -v '^#' | grep -v '^[[:space:]]*$' | shuf | head -${SAMPLE_SIZE}) || true

    info "Fetching bad IP list..."
    BAD_IP_LIST=$(curl -sf --max-time 15 "${REPO_RAW}/bad-ip-addresses.list" 2>/dev/null | \
        grep -v '^#' | grep -v '^[[:space:]]*$' | grep -E '^[0-9]+\.' | shuf | head -${SAMPLE_SIZE}) || true

    {
    echo "ngxbottest — Nginx Bad Bot Blocker Validation"
    echo "Target:  ${TARGET_URI}"
    echo "Date:    $(date)"
    echo "Samples: ${SAMPLE_SIZE} per category"
    echo ""

    echo "=== BAD USER-AGENTS (should be BLOCKED) ==="
    if [[ -n "${BAD_UA_LIST}" ]]; then
        while IFS= read -r ua; do
            [[ -z "${ua}" ]] && continue
            result=$(is_blocked "${ua}" "")
            if [[ "${result}" == "blocked" ]]; then
                echo "  [BLOCKED ✓] UA: ${ua}"
                (( BLOCKED++ )) || true
            else
                echo "  [ALLOWED ✗] UA: ${ua}"
                (( ALLOWED++ )) || true
            fi
        done <<< "${BAD_UA_LIST}"
    else
        echo "  [!] Could not fetch bad user-agent list"
    fi

    echo ""
    echo "=== FAKE GOOGLEBOTS (should be BLOCKED) ==="
    if [[ -n "${FAKE_GOOGLE_LIST}" ]]; then
        while IFS= read -r ua; do
            [[ -z "${ua}" ]] && continue
            result=$(is_blocked "${ua}" "")
            if [[ "${result}" == "blocked" ]]; then
                echo "  [BLOCKED ✓] UA: ${ua}"
                (( BLOCKED++ )) || true
            else
                echo "  [ALLOWED ✗] UA: ${ua}"
                (( ALLOWED++ )) || true
            fi
        done <<< "${FAKE_GOOGLE_LIST}"
    else
        echo "  [!] Could not fetch fake Googlebot list"
    fi

    echo ""
    echo "=== BAD REFERRERS (should be BLOCKED) ==="
    if [[ -n "${BAD_REF_LIST}" ]]; then
        while IFS= read -r ref; do
            [[ -z "${ref}" ]] && continue
            [[ "${ref}" != http* ]] && ref="http://${ref}"
            result=$(is_blocked "" "${ref}")
            if [[ "${result}" == "blocked" ]]; then
                echo "  [BLOCKED ✓] Ref: ${ref}"
                (( BLOCKED++ )) || true
            else
                echo "  [ALLOWED ✗] Ref: ${ref}"
                (( ALLOWED++ )) || true
            fi
        done <<< "${BAD_REF_LIST}"
    else
        echo "  [!] Could not fetch bad referrer list"
    fi

    echo ""
    echo "=== BAD IP ADDRESSES (should be BLOCKED) ==="
    if [[ -n "${BAD_IP_LIST}" ]]; then
        while IFS= read -r ip; do
            [[ -z "${ip}" ]] && continue
            http_code=$(curl -sf \
                --max-time 8 \
                --connect-timeout 5 \
                --interface "${ip}" \
                -o /dev/null \
                -w "%{http_code}" \
                "${TARGET_URI}" 2>/dev/null) || http_code="blocked"
            if [[ "${http_code}" == "blocked" || -z "${http_code}" ]]; then
                http_code=$(curl -sf \
                    --max-time 8 \
                    --connect-timeout 5 \
                    -H "X-Forwarded-For: ${ip}" \
                    -H "X-Real-IP: ${ip}" \
                    -o /dev/null \
                    -w "%{http_code}" \
                    "${TARGET_URI}" 2>/dev/null) || http_code="000"
            fi
            if [[ "${http_code}" =~ ^[23][0-9][0-9]$ ]]; then
                echo "  [ALLOWED ✗] IP: ${ip} (${http_code})"
                (( ALLOWED++ )) || true
            else
                echo "  [BLOCKED ✓] IP: ${ip}"
                (( BLOCKED++ )) || true
            fi
        done <<< "${BAD_IP_LIST}"
    else
        echo "  [!] Could not fetch bad IP list"
    fi

    echo ""
    echo "=== GOOD BOTS (should be ALLOWED — false positive check) ==="
    declare -A GOOD_BOTS=(
        ["Googlebot"]="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        ["Bingbot"]="Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
        ["DuckDuckBot"]="DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)"
        ["Applebot"]="Mozilla/5.0 (compatible; Applebot/0.3)"
        ["FacebookBot"]="facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"
    )
    for name in "${!GOOD_BOTS[@]}"; do
        ua="${GOOD_BOTS[$name]}"
        result=$(is_blocked "${ua}" "")
        if [[ "${result}" == "allowed" ]]; then
            echo "  [ALLOWED ✓] ${name}"
        else
            echo "  [BLOCKED ✗] ${name} — FALSE POSITIVE"
            (( FP++ )) || true
        fi
    done

    echo ""
    echo "=== AI CRAWLERS (should be ALLOWED — AI bot check) ==="
    declare -A AI_BOTS=(
        ["GPTBot"]="Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)"
        ["OAI-SearchBot"]="Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)"
        ["ChatGPT-User"]="Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot)"
        ["ClaudeBot"]="Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/0.1; +claudebot@anthropic.com)"
        ["Claude-Web"]="Claude-Web/1.0 (+https://anthropic.com)"
        ["Google-Extended"]="Mozilla/5.0 (compatible; Google-Extended/1.0; +https://developers.google.com/search/docs/crawling-indexing/google-common-crawlers)"
        ["Gemini-Pro"]="Mozilla/5.0 (compatible; Gemini-Pro/1.0; +https://ai.google.dev)"
        ["PerplexityBot"]="Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)"
        ["Applebot-Extended"]="Mozilla/5.0 (compatible; Applebot-Extended/0.1; +http://www.apple.com/go/applebot)"
        ["Amazonbot"]="Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)"
        ["YouBot"]="Mozilla/5.0 (compatible; YouBot/1.0; +https://about.you.com/youbot/)"
        ["Bytespider"]="Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)"
        ["cohere-ai"]="cohere-ai/1.0 (+https://cohere.com; crawl@cohere.com)"
        ["Meta-ExternalFetcher"]="Meta-ExternalFetcher/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)"
    )
    AI_FP=0
    for name in "${!AI_BOTS[@]}"; do
        ua="${AI_BOTS[$name]}"
        result=$(is_blocked "${ua}" "")
        if [[ "${result}" == "allowed" ]]; then
            echo "  [ALLOWED ✓] ${name}"
        else
            echo "  [BLOCKED ✗] ${name} — FALSE POSITIVE"
            (( AI_FP++ )) || true
            (( FP++ )) || true
        fi
    done

    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "SUMMARY"
    echo "  Correctly blocked: ${BLOCKED}"
    echo "  Not blocked:       ${ALLOWED}"
    echo "  False positives:   ${FP} (AI crawlers blocked: ${AI_FP})"
    TOTAL=$(( BLOCKED + ALLOWED ))
    if [[ ${TOTAL} -gt 0 ]]; then
        PCT=$(( BLOCKED * 100 / TOTAL ))
        echo "  Block rate:        ${PCT}%"
    fi
    if [[ ${ALLOWED} -gt 0 ]]; then
        echo ""
        echo "  !! ${ALLOWED} bad bots/referrers were NOT blocked."
        echo "     Check your nginx-ultimate-bad-bot-blocker configuration."
    fi
    if [[ ${FP} -gt 0 ]]; then
        echo ""
        echo "  !! ${FP} legitimate bots were blocked — investigate whitelist."
    fi
    echo "═══════════════════════════════════════════════════"

    } | tee "${BOT_REPORT}"

    ok "Bot blocker test done → ${BOT_REPORT}"
else
    warn "Bot blocker validation skipped (--skip-botblocker)"
fi

# -----------------------------------------------------------------------------
# 18 — OWASP ZAP
# -----------------------------------------------------------------------------
section "18/18 — OWASP ZAP"

if [[ "${SKIP_ZAP}" == "false" ]]; then
    info "ZAP full scan (may take several minutes)..."
    timeout 600 zap.sh -cmd \
        -quickurl "${TARGET_URI}" \
        -quickout "${OUT_DIR}/zap_report.html" \
        -quickprogress 2>&1 \
        | tee "${OUT_DIR}/zap_console.txt" || {
            warn "ZAP exited non-zero or hit 10 min timeout — partial results may exist"
        }
    ok "ZAP done"
else
    warn "ZAP skipped (--skip-zap)"
fi

# -----------------------------------------------------------------------------
# HTML Report
# -----------------------------------------------------------------------------
section "Generating HTML Report"

REPORT_FILE="${OUT_DIR}/report.html"

file_content() {
    local f="$1"
    if [[ -s "${f}" ]]; then
        cat "${f}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
    else
        echo "(no output)"
    fi
}

json_content() {
    local f="$1"
    if [[ -s "${f}" ]]; then
        jq . "${f}" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' || file_content "${f}"
    else
        echo "(no output)"
    fi
}

OPEN_PORT_COUNT=0
[[ -s "${OUT_DIR}/ports.txt" ]] && OPEN_PORT_COUNT=$(wc -l < "${OUT_DIR}/ports.txt" | tr -d ' ')

SUBDOMAIN_COUNT=0
[[ -s "${OUT_DIR}/subdomains.txt" ]] && SUBDOMAIN_COUNT=$(wc -l < "${OUT_DIR}/subdomains.txt" | tr -d ' ')

ENDPOINT_COUNT=0
[[ -s "${OUT_DIR}/endpoints.txt" ]] && ENDPOINT_COUNT=$(wc -l < "${OUT_DIR}/endpoints.txt" | tr -d ' ')

NUCLEI_COUNT=0
[[ -s "${OUT_DIR}/nuclei.txt" ]] && NUCLEI_COUNT=$(wc -l < "${OUT_DIR}/nuclei.txt" | tr -d ' ')

NIKTO_COUNT=0
[[ -s "${OUT_DIR}/nikto.txt" ]] && NIKTO_COUNT=$(grep -c '^+' "${OUT_DIR}/nikto.txt" 2>/dev/null || echo 0)

XSS_COUNT=0
[[ -s "${OUT_DIR}/dalfox.txt" ]] && XSS_COUNT=$(grep -cE 'VULN|POC' "${OUT_DIR}/dalfox.txt" 2>/dev/null || echo 0)

SQLI_COUNT=0
[[ -s "${OUT_DIR}/sqlmap_console.txt" ]] && SQLI_COUNT=$(grep -c 'injectable' "${OUT_DIR}/sqlmap_console.txt" 2>/dev/null || echo 0)

SSL_ISSUES=0
[[ -s "${OUT_DIR}/testssl.txt" ]] && SSL_ISSUES=$(grep -cE 'WARN|CRITICAL|NOT ok' "${OUT_DIR}/testssl.txt" 2>/dev/null || echo 0)

BOT_BLOCK_RATE="N/A"
if [[ -s "${OUT_DIR}/botblocker_test.txt" ]]; then
    BOT_BLOCK_RATE=$(grep 'Block rate:' "${OUT_DIR}/botblocker_test.txt" | awk '{print $NF}' || echo "N/A")
fi

cat > "${REPORT_FILE}" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KP WebScanner — ${TARGET_HOST}</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/uikit/3.21.5/css/uikit.min.css"/>
<script src="https://cdnjs.cloudflare.com/ajax/libs/uikit/3.21.5/js/uikit.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/uikit/3.21.5/js/uikit-icons.min.js"></script>
<style>
  :root {
    --kp-dark:    #0d1117;
    --kp-surface: #161b22;
    --kp-border:  #30363d;
    --kp-accent:  #2d7696;
    --kp-accent2: #599bb8;
    --kp-text:    #c9d1d9;
    --kp-muted:   #8b949e;
    --kp-green:   #3fb950;
    --kp-red:     #f85149;
    --kp-yellow:  #d29922;
    --kp-orange:  #db6d28;
  }
  body { background: var(--kp-dark); color: var(--kp-text); font-family: 'Segoe UI', system-ui, sans-serif; }
  .kp-header { background: linear-gradient(135deg, var(--kp-surface) 0%, #1c2940 100%); border-bottom: 1px solid var(--kp-border); padding: 32px 40px 24px; }
  .kp-header h1 { color: var(--kp-accent2); margin: 0 0 4px; font-size: 2rem; font-weight: 700; }
  .kp-header .meta { color: var(--kp-muted); font-size: 0.9rem; }
  .kp-header .target { color: var(--kp-text); font-weight: 600; font-size: 1.1rem; }
  .kp-nav { background: var(--kp-surface); border-bottom: 1px solid var(--kp-border); position: sticky; top: 0; z-index: 100; }
  .kp-nav .uk-navbar-nav > li > a { color: var(--kp-muted); font-size: 0.82rem; padding: 0 12px; height: 44px; border-bottom: 2px solid transparent; transition: color 0.2s, border-color 0.2s; }
  .kp-nav .uk-navbar-nav > li > a:hover { color: var(--kp-accent2); border-bottom-color: var(--kp-accent2); }
  .kp-main { padding: 32px 40px; max-width: 1400px; margin: 0 auto; }
  .kp-card { background: var(--kp-surface); border: 1px solid var(--kp-border); border-radius: 8px; margin-bottom: 24px; }
  .kp-card-header { padding: 14px 20px; border-bottom: 1px solid var(--kp-border); display: flex; align-items: center; gap: 10px; }
  .kp-card-header h3 { margin: 0; font-size: 1rem; font-weight: 600; color: var(--kp-text); }
  .kp-card-header .step-badge { background: var(--kp-accent); color: #fff; font-size: 0.72rem; font-weight: 700; padding: 2px 8px; border-radius: 20px; white-space: nowrap; }
  .kp-card-body { padding: 16px 20px; }
  pre.kp-pre { background: var(--kp-dark); border: 1px solid var(--kp-border); border-radius: 6px; padding: 14px 16px; font-size: 0.78rem; line-height: 1.6; color: var(--kp-text); white-space: pre-wrap; word-break: break-all; max-height: 500px; overflow-y: auto; margin: 0; }
  .stat-card { background: var(--kp-surface); border: 1px solid var(--kp-border); border-radius: 8px; padding: 20px; text-align: center; }
  .stat-card .stat-num { font-size: 2.2rem; font-weight: 700; line-height: 1; margin-bottom: 6px; }
  .stat-card .stat-label { font-size: 0.78rem; color: var(--kp-muted); text-transform: uppercase; letter-spacing: 0.05em; }
  .stat-green  { color: var(--kp-green); }
  .stat-red    { color: var(--kp-red); }
  .stat-yellow { color: var(--kp-yellow); }
  .stat-blue   { color: var(--kp-accent2); }
  .stat-orange { color: var(--kp-orange); }
  .skipped-badge { display: inline-flex; align-items: center; gap: 6px; background: #21262d; border: 1px solid var(--kp-border); color: var(--kp-muted); border-radius: 6px; padding: 8px 14px; font-size: 0.85rem; }
  .uk-accordion-title { color: var(--kp-text) !important; background: transparent !important; font-size: 0.9rem; }
  .uk-accordion-title::before { color: var(--kp-accent2) !important; }
  .uk-open > .uk-accordion-title { color: var(--kp-accent2) !important; }
  footer { border-top: 1px solid var(--kp-border); padding: 20px 40px; text-align: center; color: var(--kp-muted); font-size: 0.8rem; }
  footer a { color: var(--kp-accent2); }
  @media(max-width:768px) { .kp-header, .kp-main { padding: 20px; } .kp-nav .uk-navbar-nav > li > a { padding: 0 6px; font-size: 0.75rem; } }
</style>
</head>
<body>

<div class="kp-header">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px;">
    <span uk-icon="icon:shield;ratio:1.6" style="color:var(--kp-accent2)"></span>
    <h1>KP WebScanner</h1>
  </div>
  <div class="target">${TARGET_URI}</div>
  <div class="meta" style="margin-top:6px;">
    <span uk-icon="icon:calendar;ratio:0.85"></span> ${TIMESTAMP}
    &nbsp;&nbsp;<span uk-icon="icon:server;ratio:0.85"></span> ${TARGET_HOST}
    &nbsp;&nbsp;<span uk-icon="icon:tag;ratio:0.85"></span> Severity: ${SEVERITY}
  </div>
</div>

<div class="kp-nav">
  <nav class="uk-navbar-container uk-navbar" uk-navbar style="background:transparent;">
    <div class="uk-navbar-left" style="padding-left:20px;">
      <ul class="uk-navbar-nav">
        <li><a href="#summary"><span uk-icon="icon:thumbnails;ratio:0.8"></span> Summary</a></li>
        <li><a href="#fingerprint"><span uk-icon="icon:search;ratio:0.8"></span> Fingerprint</a></li>
        <li><a href="#recon"><span uk-icon="icon:world;ratio:0.8"></span> Recon</a></li>
        <li><a href="#ports"><span uk-icon="icon:server;ratio:0.8"></span> Ports</a></li>
        <li><a href="#ssl"><span uk-icon="icon:lock;ratio:0.8"></span> SSL/TLS</a></li>
        <li><a href="#headers"><span uk-icon="icon:settings;ratio:0.8"></span> Headers</a></li>
        <li><a href="#cms"><span uk-icon="icon:social;ratio:0.8"></span> CMS</a></li>
        <li><a href="#endpoints"><span uk-icon="icon:link;ratio:0.8"></span> Endpoints</a></li>
        <li><a href="#vulns"><span uk-icon="icon:warning;ratio:0.8"></span> Vulns</a></li>
        <li><a href="#bots"><span uk-icon="icon:ban;ratio:0.8"></span> Bot Blocker</a></li>
        <li><a href="#zap"><span uk-icon="icon:bolt;ratio:0.8"></span> ZAP</a></li>
      </ul>
    </div>
  </nav>
</div>

<div class="kp-main">

<div id="summary" style="margin-bottom:32px;">
  <h2 style="color:var(--kp-accent2);font-size:1.1rem;margin-bottom:16px;display:flex;align-items:center;gap:8px;">
    <span uk-icon="icon:thumbnails"></span> Scan Summary
  </h2>
  <div class="uk-grid-small uk-child-width-1-4@m uk-child-width-1-2@s" uk-grid>
    <div><div class="stat-card"><div class="stat-num stat-blue">${OPEN_PORT_COUNT}</div><div class="stat-label">Open Ports</div></div></div>
    <div><div class="stat-card"><div class="stat-num stat-blue">${SUBDOMAIN_COUNT}</div><div class="stat-label">Subdomains</div></div></div>
    <div><div class="stat-card"><div class="stat-num stat-blue">${ENDPOINT_COUNT}</div><div class="stat-label">Endpoints</div></div></div>
    <div><div class="stat-card"><div class="stat-num stat-yellow">${NUCLEI_COUNT}</div><div class="stat-label">Nuclei Findings</div></div></div>
    <div><div class="stat-card"><div class="stat-num stat-orange">${NIKTO_COUNT}</div><div class="stat-label">Nikto Findings</div></div></div>
    <div><div class="stat-card"><div class="stat-num stat-red">${XSS_COUNT}</div><div class="stat-label">XSS Findings</div></div></div>
    <div><div class="stat-card"><div class="stat-num stat-red">${SQLI_COUNT}</div><div class="stat-label">SQLi Findings</div></div></div>
    <div><div class="stat-card"><div class="stat-num stat-yellow">${SSL_ISSUES}</div><div class="stat-label">SSL Issues</div></div></div>
  </div>
</div>

HTMLEOF

# ── 1: Fingerprinting ──────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="fingerprint" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:search" style="color:var(--kp-accent2)"></span>
    <h3>Fingerprinting</h3><span class="step-badge">1/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_FINGERPRINT}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-fingerprint)</div>' >> "${REPORT_FILE}"
else
    cat >> "${REPORT_FILE}" <<HTMLEOF
    <ul uk-accordion>
      <li><a class="uk-accordion-title" href="#">WhatWeb</a><div class="uk-accordion-content"><pre class="kp-pre">$(file_content "${OUT_DIR}/whatweb.txt")</pre></div></li>
      <li><a class="uk-accordion-title" href="#">httpx</a><div class="uk-accordion-content"><pre class="kp-pre">$(file_content "${OUT_DIR}/httpx.txt")</pre></div></li>
    </ul>
HTMLEOF
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 2: Passive Recon ───────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="recon" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:world" style="color:var(--kp-accent2)"></span>
    <h3>Passive Recon</h3><span class="step-badge">2/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_RECON}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-recon)</div>' >> "${REPORT_FILE}"
else
    cat >> "${REPORT_FILE}" <<HTMLEOF
    <ul uk-accordion>
      <li><a class="uk-accordion-title" href="#">Shodan</a><div class="uk-accordion-content"><pre class="kp-pre">$(file_content "${OUT_DIR}/shodan.txt")</pre></div></li>
      <li><a class="uk-accordion-title" href="#">Censys</a><div class="uk-accordion-content"><pre class="kp-pre">$(file_content "${OUT_DIR}/censys.txt")</pre></div></li>
    </ul>
HTMLEOF
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 3: Subdomains ──────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="subdomains" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:git-branch" style="color:var(--kp-accent2)"></span>
    <h3>Subdomain Enumeration</h3><span class="step-badge">3/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_SUBDOMAINS}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-subdomains)</div>' >> "${REPORT_FILE}"
else
    cat >> "${REPORT_FILE}" <<HTMLEOF
    <ul uk-accordion>
      <li><a class="uk-accordion-title" href="#">Subdomains (${SUBDOMAIN_COUNT} found)</a><div class="uk-accordion-content"><pre class="kp-pre">$(file_content "${OUT_DIR}/subdomains.txt")</pre></div></li>
      <li><a class="uk-accordion-title" href="#">Live Subdomains</a><div class="uk-accordion-content"><pre class="kp-pre">$(file_content "${OUT_DIR}/subdomains_live.txt")</pre></div></li>
    </ul>
HTMLEOF
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 4: DNS ─────────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="dns" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:database" style="color:var(--kp-accent2)"></span>
    <h3>DNS Enumeration</h3><span class="step-badge">4/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_DNS}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-dns)</div>' >> "${REPORT_FILE}"
else
    echo '<pre class="kp-pre">'"$(file_content "${OUT_DIR}/dns.txt")"'</pre>' >> "${REPORT_FILE}"
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 5+6: Ports ─────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="ports" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:server" style="color:var(--kp-accent2)"></span>
    <h3>Port &amp; Service Scanning</h3><span class="step-badge">5–6/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_PORTS}" == "true" && "${SKIP_NMAP}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-ports --skip-nmap)</div>' >> "${REPORT_FILE}"
else
    echo '<ul uk-accordion>' >> "${REPORT_FILE}"
    [[ "${SKIP_PORTS}" == "false" ]] && echo '<li><a class="uk-accordion-title" href="#">naabu — Open Ports ('"${OPEN_PORT_COUNT}"' found)</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/ports.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
    [[ "${SKIP_NMAP}" == "false" ]]  && echo '<li><a class="uk-accordion-title" href="#">Nmap — Service &amp; Script Scan</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/nmap.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
    echo '</ul>' >> "${REPORT_FILE}"
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 7: SSL ─────────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="ssl" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:lock" style="color:var(--kp-accent2)"></span>
    <h3>SSL/TLS Analysis</h3><span class="step-badge">7/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_SSL}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-ssl)</div>' >> "${REPORT_FILE}"
else
    if [[ -s "${OUT_DIR}/testssl.txt" ]]; then
        ISSUES=$(grep -E 'WARN|CRITICAL|NOT ok' "${OUT_DIR}/testssl.txt" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' || true)
        if [[ -n "${ISSUES}" ]]; then
            echo "<p style='color:var(--kp-yellow);margin-bottom:10px;'><span uk-icon='icon:warning'></span> ${SSL_ISSUES} issue(s) found</p><pre class='kp-pre'>${ISSUES}</pre>" >> "${REPORT_FILE}"
        else
            echo "<p style='color:var(--kp-green);'><span uk-icon='icon:check'></span> No WARN/CRITICAL issues found</p>" >> "${REPORT_FILE}"
        fi
        echo '<details style="margin-top:12px;"><summary style="cursor:pointer;color:var(--kp-muted);font-size:0.85rem;">Full testssl.sh output</summary><pre class="kp-pre" style="margin-top:8px;">'"$(file_content "${OUT_DIR}/testssl.txt")"'</pre></details>' >> "${REPORT_FILE}"
    else
        echo '<pre class="kp-pre">(no output)</pre>' >> "${REPORT_FILE}"
    fi
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 8: Headers ─────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="headers" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:settings" style="color:var(--kp-accent2)"></span>
    <h3>HTTP Security Headers</h3><span class="step-badge">8/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_HEADERS}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-headers)</div>' >> "${REPORT_FILE}"
else
    echo '<pre class="kp-pre">'"$(json_content "${OUT_DIR}/observatory.json")"'</pre>' >> "${REPORT_FILE}"
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 9: Nikto ───────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="nikto" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:warning" style="color:var(--kp-accent2)"></span>
    <h3>Nikto Web Server Scan</h3><span class="step-badge">9/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_NIKTO}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-nikto)</div>' >> "${REPORT_FILE}"
else
    if [[ -s "${OUT_DIR}/nikto.txt" ]]; then
        NIKTO_FINDINGS=$(grep '^+' "${OUT_DIR}/nikto.txt" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' || true)
        if [[ -n "${NIKTO_FINDINGS}" ]]; then
            echo "<p style='color:var(--kp-yellow);margin-bottom:10px;'><span uk-icon='icon:warning'></span> ${NIKTO_COUNT} finding(s)</p><pre class='kp-pre'>${NIKTO_FINDINGS}</pre>" >> "${REPORT_FILE}"
        else
            echo "<p style='color:var(--kp-green);'><span uk-icon='icon:check'></span> No findings</p>" >> "${REPORT_FILE}"
        fi
    else
        echo '<pre class="kp-pre">(no output)</pre>' >> "${REPORT_FILE}"
    fi
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 10: CMS ────────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="cms" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:social" style="color:var(--kp-accent2)"></span>
    <h3>CMS Scanning</h3><span class="step-badge">10/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_CMS}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-cms)</div>' >> "${REPORT_FILE}"
else
    cat >> "${REPORT_FILE}" <<HTMLEOF
    <ul uk-accordion>
      <li><a class="uk-accordion-title" href="#">WPScan Results</a><div class="uk-accordion-content"><pre class="kp-pre">$(file_content "${OUT_DIR}/wpscan.txt")</pre></div></li>
    </ul>
HTMLEOF
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 11: Endpoints ──────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="endpoints" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:link" style="color:var(--kp-accent2)"></span>
    <h3>Endpoint Discovery</h3><span class="step-badge">11/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_CRAWL}" == "true" && "${SKIP_BRUTE}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-crawl --skip-brute)</div>' >> "${REPORT_FILE}"
else
    echo '<ul uk-accordion>' >> "${REPORT_FILE}"
    [[ "${SKIP_CRAWL}" == "false" ]] && echo '<li><a class="uk-accordion-title" href="#">katana — Crawled Endpoints ('"${ENDPOINT_COUNT}"')</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/endpoints.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
    [[ "${SKIP_BRUTE}" == "false" ]] && {
        echo '<li><a class="uk-accordion-title" href="#">gobuster</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/gobuster.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
        echo '<li><a class="uk-accordion-title" href="#">ffuf</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(json_content "${OUT_DIR}/ffuf.json")"'</pre></div></li>' >> "${REPORT_FILE}"
    }
    echo '</ul>' >> "${REPORT_FILE}"
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 12: Arjun ──────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="arjun" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:code" style="color:var(--kp-accent2)"></span>
    <h3>Parameter Discovery</h3><span class="step-badge">12/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_ARJUN}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-arjun)</div>' >> "${REPORT_FILE}"
else
    echo '<pre class="kp-pre">'"$(json_content "${OUT_DIR}/arjun.json")"'</pre>' >> "${REPORT_FILE}"
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 13-16: Vulns ───────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="vulns" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:warning" style="color:var(--kp-accent2)"></span>
    <h3>Vulnerability Findings</h3><span class="step-badge">13–16/18</span>
  </div>
  <div class="kp-card-body">
    <ul uk-accordion>
HTMLEOF

if [[ "${SKIP_XSS}" == "true" ]]; then
    echo '<li><a class="uk-accordion-title" href="#">Dalfox XSS</a><div class="uk-accordion-content"><div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-xss)</div></div></li>' >> "${REPORT_FILE}"
else
    echo '<li class="uk-open"><a class="uk-accordion-title" href="#">Dalfox XSS ('"${XSS_COUNT}"' findings)</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/dalfox.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
fi

if [[ "${SKIP_SQLMAP}" == "true" ]]; then
    echo '<li><a class="uk-accordion-title" href="#">SQLMap</a><div class="uk-accordion-content"><div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-sqlmap)</div></div></li>' >> "${REPORT_FILE}"
else
    echo '<li><a class="uk-accordion-title" href="#">SQLMap ('"${SQLI_COUNT}"' injectable)</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/sqlmap_console.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
fi

if [[ "${SKIP_OSV}" == "true" ]]; then
    echo '<li><a class="uk-accordion-title" href="#">OSV-Scanner</a><div class="uk-accordion-content"><div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-osv)</div></div></li>' >> "${REPORT_FILE}"
else
    echo '<li><a class="uk-accordion-title" href="#">OSV-Scanner (Dependency Vulnerabilities)</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/osv_scanner.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
fi

if [[ "${SKIP_NUCLEI}" == "true" ]]; then
    echo '<li><a class="uk-accordion-title" href="#">Nuclei</a><div class="uk-accordion-content"><div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-nuclei)</div></div></li>' >> "${REPORT_FILE}"
else
    echo '<li><a class="uk-accordion-title" href="#">Nuclei ('"${NUCLEI_COUNT}"' findings)</a><div class="uk-accordion-content"><pre class="kp-pre">'"$(file_content "${OUT_DIR}/nuclei.txt")"'</pre></div></li>' >> "${REPORT_FILE}"
fi

echo '    </ul>' >> "${REPORT_FILE}"
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 17: Bot Blocker ────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="bots" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:ban" style="color:var(--kp-accent2)"></span>
    <h3>Nginx Bad Bot Blocker Validation</h3><span class="step-badge">17/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_BOTBLOCKER}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-botblocker)</div>' >> "${REPORT_FILE}"
else
    if [[ -s "${OUT_DIR}/botblocker_test.txt" ]]; then
        SUMMARY_BLOCK=$(grep -A 10 '^SUMMARY' "${OUT_DIR}/botblocker_test.txt" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' || true)
        echo "<p style='margin-bottom:12px;'><span uk-icon='icon:check-circle'></span> Block rate: <strong style='color:var(--kp-green);'>${BOT_BLOCK_RATE}</strong></p><pre class='kp-pre'>${SUMMARY_BLOCK}</pre>" >> "${REPORT_FILE}"
        echo '<details style="margin-top:12px;"><summary style="cursor:pointer;color:var(--kp-muted);font-size:0.85rem;">Full bot blocker test output</summary><pre class="kp-pre" style="margin-top:8px;">'"$(file_content "${OUT_DIR}/botblocker_test.txt")"'</pre></details>' >> "${REPORT_FILE}"
    else
        echo '<pre class="kp-pre">(no output)</pre>' >> "${REPORT_FILE}"
    fi
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── 18: ZAP ────────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
<div id="zap" class="kp-card">
  <div class="kp-card-header">
    <span uk-icon="icon:bolt" style="color:var(--kp-accent2)"></span>
    <h3>OWASP ZAP Active Scan</h3><span class="step-badge">18/18</span>
  </div>
  <div class="kp-card-body">
HTMLEOF
if [[ "${SKIP_ZAP}" == "true" ]]; then
    echo '<div class="skipped-badge"><span uk-icon="icon:minus-circle;ratio:0.85"></span> Skipped (--skip-zap)</div>' >> "${REPORT_FILE}"
else
    if [[ -s "${OUT_DIR}/zap_report.html" ]]; then
        echo '<p><a href="zap_report.html" class="uk-button" style="background:var(--kp-accent);color:#fff;border:none;padding:8px 18px;border-radius:4px;" target="_blank"><span uk-icon="icon:bolt"></span> Open Full ZAP Report</a></p><p style="color:var(--kp-muted);font-size:0.85rem;margin-top:8px;">ZAP produces a standalone HTML report. Click above to open it.</p>' >> "${REPORT_FILE}"
    else
        echo '<pre class="kp-pre">(no output — ZAP may have timed out or failed)</pre>' >> "${REPORT_FILE}"
    fi
fi
echo '  </div></div>' >> "${REPORT_FILE}"

# ── Close ──────────────────────────────────────────────────────────────────
cat >> "${REPORT_FILE}" <<HTMLEOF
</div>

<footer>
  Generated by <a href="https://github.com/kpirnie/webscanner" target="_blank">KP WebScanner</a>
  &nbsp;·&nbsp; <a href="https://kevinpirnie.com" target="_blank">kevinpirnie.com</a>
  &nbsp;·&nbsp; ${TIMESTAMP}
</footer>
</body>
</html>
HTMLEOF

ok "HTML report → ${REPORT_FILE}"

# -----------------------------------------------------------------------------
# Final Summary
# -----------------------------------------------------------------------------
section "Complete — $(date)"

FILES=(
    whatweb.txt httpx.txt shodan.txt censys.txt
    subdomains.txt subdomains_live.txt
    dns.txt ports.txt nmap.txt nmap.xml
    testssl.txt testssl.json
    observatory.json
    nikto.txt nikto.json
    wpscan.txt wpscan.json
    endpoints.txt gobuster.txt ffuf.json
    arjun.json dalfox.txt
    sqlmap_console.txt
    osv_scanner.txt osv_scanner.json
    botblocker_test.txt
    nuclei.txt nuclei.json
    zap_report.html
    report.html
)

if [[ -n "${OUTPUT_PATH}" ]]; then
    echo -e "\n${BOLD}Results: ${OUT_DIR}${RESET}"
    for f in "${FILES[@]}"; do
        fp="${OUT_DIR}/${f}"
        if [[ -f "${fp}" && -s "${fp}" ]]; then
            SIZE=$(du -sh "${fp}" | cut -f1)
            echo -e "  ${GREEN}✓${RESET} ${f} ${CYAN}(${SIZE})${RESET}"
        fi
    done
    if [[ -d "${OUT_DIR}/sqlmap" ]]; then
        echo -e "  ${GREEN}✓${RESET} sqlmap/ ${CYAN}(dir)${RESET}"
    fi
    echo -e "\n  ${BOLD}${GREEN}→ Open report.html for full results${RESET}"
else
    [[ -s "${OUT_DIR}/shodan.txt" ]]          && { echo -e "\n${BOLD}── Shodan ───────────${RESET}"; cat "${OUT_DIR}/shodan.txt"; }
    [[ -s "${OUT_DIR}/censys.txt" ]]          && { echo -e "\n${BOLD}── Censys ───────────${RESET}"; cat "${OUT_DIR}/censys.txt"; }
    [[ -s "${OUT_DIR}/httpx.txt" ]]           && { echo -e "\n${BOLD}── Fingerprint ──────${RESET}"; cat "${OUT_DIR}/httpx.txt"; }
    [[ -s "${OUT_DIR}/ports.txt" ]]           && { echo -e "\n${BOLD}── Open Ports ───────${RESET}"; cat "${OUT_DIR}/ports.txt"; }
    [[ -s "${OUT_DIR}/nmap.txt" ]]            && { echo -e "\n${BOLD}── Nmap Services ────${RESET}"; grep -E "^[0-9]+/|SCRIPT OUTPUT|^Host" "${OUT_DIR}/nmap.txt" | head -50 || true; }
    [[ -s "${OUT_DIR}/testssl.txt" ]]         && { echo -e "\n${BOLD}── SSL Issues ───────${RESET}"; grep -E "WARN|CRITICAL|NOT ok" "${OUT_DIR}/testssl.txt" || echo "  None"; }
    [[ -s "${OUT_DIR}/observatory.json" ]]    && { echo -e "\n${BOLD}── HTTP Headers ─────${RESET}"; jq -r '.scan | "Grade: \(.grade) | Score: \(.score)"' "${OUT_DIR}/observatory.json" 2>/dev/null || cat "${OUT_DIR}/observatory.json"; }
    [[ -s "${OUT_DIR}/nikto.txt" ]]           && { echo -e "\n${BOLD}── Nikto ────────────${RESET}"; grep "^+" "${OUT_DIR}/nikto.txt" || echo "  None"; }
    [[ -s "${OUT_DIR}/wpscan.txt" ]]          && { echo -e "\n${BOLD}── WPScan ───────────${RESET}"; grep -E "\[!\]|\[\+\]" "${OUT_DIR}/wpscan.txt" || echo "  None"; }
    [[ -s "${OUT_DIR}/arjun.json" ]]          && { echo -e "\n${BOLD}── Arjun Params ─────${RESET}"; jq -r '.[] | .url + " → " + (.params | join(", "))' "${OUT_DIR}/arjun.json" 2>/dev/null || cat "${OUT_DIR}/arjun.json"; }
    [[ -s "${OUT_DIR}/dalfox.txt" ]]          && { echo -e "\n${BOLD}── Dalfox XSS ───────${RESET}"; grep -E "VULN|WEAK|POC" "${OUT_DIR}/dalfox.txt" || echo "  None found"; }
    [[ -s "${OUT_DIR}/sqlmap_console.txt" ]]  && { echo -e "\n${BOLD}── SQLMap ───────────${RESET}"; grep -E "injectable|Parameter|Type:" "${OUT_DIR}/sqlmap_console.txt" || echo "  None found"; }
    [[ -s "${OUT_DIR}/osv_scanner.txt" ]]     && { echo -e "\n${BOLD}── OSV Dependencies ─${RESET}"; grep -E "CRITICAL|HIGH|MEDIUM" "${OUT_DIR}/osv_scanner.txt" || echo "  None found"; }
    [[ -s "${OUT_DIR}/botblocker_test.txt" ]] && { echo -e "\n${BOLD}── Bot Blocker ──────${RESET}"; grep -E "SUMMARY|blocked:|positives:|rate:" "${OUT_DIR}/botblocker_test.txt" || true; }
    [[ -s "${OUT_DIR}/nuclei.txt" ]]          && { echo -e "\n${BOLD}── Nuclei ───────────${RESET}"; cat "${OUT_DIR}/nuclei.txt"; }
    [[ -s "${OUT_DIR}/gobuster.txt" ]]        && { echo -e "\n${BOLD}── Paths ────────────${RESET}"; head -50 "${OUT_DIR}/gobuster.txt"; }
fi