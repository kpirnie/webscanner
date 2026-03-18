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
  -o PATH             Write results to /output/PATH (requires volume mount)
                      Omit to print summary to stdout
  --skip-zap          Skip OWASP ZAP
  --skip-brute        Skip gobuster + ffuf
  --skip-nikto        Skip nikto
  --skip-sqlmap       Skip sqlmap
  --severity LEVEL    Nuclei severity (default: low,medium,high,critical)
  --help              Show this help

EOF
    exit 0
}

# -----------------------------------------------------------------------------
# Args
# -----------------------------------------------------------------------------
[[ $# -lt 1 || "$1" == "--help" ]] && usage

TARGET_RAW="$1"; shift

OUTPUT_PATH=""
SKIP_ZAP=false
SKIP_BRUTE=false
SKIP_NIKTO=false
SKIP_SQLMAP=false
SEVERITY="low,medium,high,critical"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o)             OUTPUT_PATH="$2"; shift ;;
        --skip-zap)     SKIP_ZAP=true ;;
        --skip-brute)   SKIP_BRUTE=true ;;
        --skip-nikto)   SKIP_NIKTO=true ;;
        --skip-sqlmap)  SKIP_SQLMAP=true ;;
        --severity)     SEVERITY="$2"; shift ;;
        --help)         usage ;;
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
section "1/13 — Fingerprinting"

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

# -----------------------------------------------------------------------------
# 2 — Subdomain enumeration
# -----------------------------------------------------------------------------
section "2/13 — Subdomain Enumeration"

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

# -----------------------------------------------------------------------------
# 3 — DNS
# -----------------------------------------------------------------------------
section "3/13 — DNS Enumeration"

info "dnsx..."
echo "${TARGET_HOST}" | dnsx \
    -a -aaaa -cname -mx -ns -txt -resp \
    -o "${OUT_DIR}/dns.txt" 2>&1 \
    | tee "${OUT_DIR}/dnsx_console.txt" || true
ok "dnsx done"

# -----------------------------------------------------------------------------
# 4 — Ports
# -----------------------------------------------------------------------------
section "4/13 — Port Scanning"

info "naabu (top 1000)..."
naabu -host "${TARGET_HOST}" -top-ports 1000 \
    -o "${OUT_DIR}/ports.txt" 2>&1 \
    | tee "${OUT_DIR}/naabu_console.txt" || true
ok "naabu done"

# -----------------------------------------------------------------------------
# 5 — SSL/TLS
# -----------------------------------------------------------------------------
section "5/13 — SSL/TLS Analysis"

info "testssl.sh..."
testssl.sh \
    --logfile "${OUT_DIR}/testssl.txt" \
    --jsonfile "${OUT_DIR}/testssl.json" \
    --severity LOW --quiet \
    "${TARGET_URI}" 2>&1 \
    | tee "${OUT_DIR}/testssl_console.txt" || true
ok "testssl.sh done"

# -----------------------------------------------------------------------------
# 6 — Mozilla HTTP Observatory
# -----------------------------------------------------------------------------
section "6/13 — HTTP Security Headers (Mozilla Observatory)"

info "observatory..."
if command -v observatory &>/dev/null; then
    observatory "${TARGET_HOST}" --format json \
        > "${OUT_DIR}/observatory.json" 2>&1 || true
    observatory "${TARGET_HOST}" --format report --zero \
        > "${OUT_DIR}/observatory.txt" 2>&1 || true
    ok "observatory done"
else
    # Fallback: call the MDN API directly
    info "observatory CLI not found, querying MDN API..."
    curl -sf "https://observatory-api.mdn.mozilla.net/api/v2/scan?host=${TARGET_HOST}" \
        -o "${OUT_DIR}/observatory.json" 2>/dev/null || true
    ok "observatory done (API fallback)"
fi

# -----------------------------------------------------------------------------
# 6 — Nikto
# -----------------------------------------------------------------------------
section "7/13 — Nikto"

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
    warn "nikto skipped (--skip-nikto)"
fi

# -----------------------------------------------------------------------------
# 8 — CMS Scanning (WordPress / Drupal / Joomla — auto-detected)
# -----------------------------------------------------------------------------
section "8/13 — CMS Scanning"

IS_WORDPRESS=false
IS_DRUPAL=false
IS_JOOMLA=false

# Detect from httpx and whatweb output
grep -qi "wordpress" "${OUT_DIR}/httpx.txt"  2>/dev/null && IS_WORDPRESS=true
grep -qi "wordpress" "${OUT_DIR}/whatweb.txt" 2>/dev/null && IS_WORDPRESS=true
grep -qi "drupal"    "${OUT_DIR}/httpx.txt"  2>/dev/null && IS_DRUPAL=true
grep -qi "drupal"    "${OUT_DIR}/whatweb.txt" 2>/dev/null && IS_DRUPAL=true
grep -qi "joomla"    "${OUT_DIR}/httpx.txt"  2>/dev/null && IS_JOOMLA=true
grep -qi "joomla"    "${OUT_DIR}/whatweb.txt" 2>/dev/null && IS_JOOMLA=true

# WordPress → WPScan
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

# Drupal → droopescan
if [[ "${IS_DRUPAL}" == "true" ]]; then
    info "Drupal detected — running droopescan..."
    droopescan scan drupal -u "${TARGET_URI}" \
        --output-format json \
        > "${OUT_DIR}/droopescan.json" 2>&1 || true
    droopescan scan drupal -u "${TARGET_URI}" \
        > "${OUT_DIR}/droopescan.txt" 2>&1 || true
    ok "droopescan done"
else
    warn "Drupal not detected — skipping droopescan"
fi

# Joomla → JoomScan
if [[ "${IS_JOOMLA}" == "true" ]]; then
    info "Joomla detected — running JoomScan..."
    joomscan \
        --url "${TARGET_URI}" \
        --output "${OUT_DIR}/joomscan.txt" 2>&1 \
        | tee "${OUT_DIR}/joomscan_console.txt" || true
    ok "JoomScan done"
else
    warn "Joomla not detected — skipping JoomScan"
fi

[[ "${IS_WORDPRESS}" == "false" && "${IS_DRUPAL}" == "false" && "${IS_JOOMLA}" == "false" ]] && \
    info "No known CMS detected — all CMS scanners skipped"

# -----------------------------------------------------------------------------
# 8 — Endpoint discovery
# -----------------------------------------------------------------------------
section "9/13 — Endpoint Discovery"

info "katana..."
katana -u "${TARGET_URI}" -depth 3 -js-crawl \
    -o "${OUT_DIR}/endpoints.txt" 2>&1 \
    | tee "${OUT_DIR}/katana_console.txt" || true
ok "katana done"

if [[ "${SKIP_BRUTE}" == "false" ]]; then
    if [[ -n "${WORDLIST}" ]]; then
        info "gobuster..."
        gobuster dir -u "${TARGET_URI}" -w "${WORDLIST}" \
            -o "${OUT_DIR}/gobuster.txt" -k --timeout 10s 2>&1 \
            | tee "${OUT_DIR}/gobuster_console.txt" || true
        ok "gobuster done"

        info "ffuf..."
        ffuf -u "${TARGET_URI}/FUZZ" -w "${WORDLIST}" \
            -o "${OUT_DIR}/ffuf.json" -of json \
            -mc 200,201,204,301,302,307,401,403 -timeout 10 2>&1 \
            | tee "${OUT_DIR}/ffuf_console.txt" || true
        ok "ffuf done"
    else
        warn "No wordlist found — skipping gobuster and ffuf"
    fi
else
    warn "Brute-forcing skipped (--skip-brute)"
fi

# -----------------------------------------------------------------------------
# 10 — SQLMap
# -----------------------------------------------------------------------------
section "10/13 — SQLMap (SQL Injection)"

info "sqlmap — crawling target for injection points..."
if [[ "${SKIP_SQLMAP}" == "false" ]]; then
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

    # If katana found endpoints, feed them in too
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
# 8 — Nuclei
# -----------------------------------------------------------------------------
section "11/13 — Nuclei"

info "Updating templates..."
nuclei -update-templates -silent 2>/dev/null || true

info "nuclei..."
nuclei -u "${TARGET_URI}" \
    -o "${OUT_DIR}/nuclei.txt" \
    -je "${OUT_DIR}/nuclei.json" \
    -severity "${SEVERITY}" -stats 2>&1 \
    | tee "${OUT_DIR}/nuclei_console.txt" || true
ok "nuclei done"

# -----------------------------------------------------------------------------
# 9 — ZAP
# -----------------------------------------------------------------------------
section "12/13 — OWASP ZAP"

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
# Summary
# -----------------------------------------------------------------------------
section "Complete — $(date)"

FILES=(
    whatweb.txt httpx.txt subdomains.txt subdomains_live.txt
    dns.txt ports.txt testssl.txt testssl.json
    observatory.txt observatory.json
    nikto.txt nikto.json
    wpscan.txt wpscan.json
    droopescan.txt droopescan.json
    joomscan.txt
    endpoints.txt gobuster.txt ffuf.json
    sqlmap_console.txt
    nuclei.txt nuclei.json
    zap_report.html
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
    # sqlmap writes its own subdirectory
    if [[ -d "${OUT_DIR}/sqlmap" ]]; then
        echo -e "  ${GREEN}✓${RESET} sqlmap/ ${CYAN}(dir)${RESET}"
    fi
else
    # stdout summary
    [[ -s "${OUT_DIR}/httpx.txt" ]]         && { echo -e "\n${BOLD}── Fingerprint ──────${RESET}"; cat "${OUT_DIR}/httpx.txt"; }
    [[ -s "${OUT_DIR}/ports.txt" ]]         && { echo -e "\n${BOLD}── Open Ports ───────${RESET}"; cat "${OUT_DIR}/ports.txt"; }
    [[ -s "${OUT_DIR}/testssl.txt" ]]       && { echo -e "\n${BOLD}── SSL Issues ───────${RESET}"; grep -E "WARN|CRITICAL|NOT ok" "${OUT_DIR}/testssl.txt" || echo "  None"; }
    [[ -s "${OUT_DIR}/observatory.txt" ]]   && { echo -e "\n${BOLD}── HTTP Headers ─────${RESET}"; cat "${OUT_DIR}/observatory.txt"; }
    [[ -s "${OUT_DIR}/nikto.txt" ]]         && { echo -e "\n${BOLD}── Nikto ────────────${RESET}"; grep "^+" "${OUT_DIR}/nikto.txt" || echo "  None"; }
    [[ -s "${OUT_DIR}/wpscan.txt" ]]        && { echo -e "\n${BOLD}── WPScan ───────────${RESET}"; grep -E "\[!\]|\[\+\]" "${OUT_DIR}/wpscan.txt" || echo "  None"; }
    [[ -s "${OUT_DIR}/droopescan.txt" ]]    && { echo -e "\n${BOLD}── Droopescan ───────${RESET}"; cat "${OUT_DIR}/droopescan.txt"; }
    [[ -s "${OUT_DIR}/joomscan.txt" ]]      && { echo -e "\n${BOLD}── JoomScan ─────────${RESET}"; grep -E "^\[" "${OUT_DIR}/joomscan.txt" || echo "  None"; }
    [[ -s "${OUT_DIR}/sqlmap_console.txt" ]] && { echo -e "\n${BOLD}── SQLMap ───────────${RESET}"; grep -E "injectable|Parameter|Type:" "${OUT_DIR}/sqlmap_console.txt" || echo "  None found"; }
    [[ -s "${OUT_DIR}/nuclei.txt" ]]        && { echo -e "\n${BOLD}── Nuclei ───────────${RESET}"; cat "${OUT_DIR}/nuclei.txt"; }
    [[ -s "${OUT_DIR}/gobuster.txt" ]]      && { echo -e "\n${BOLD}── Paths ────────────${RESET}"; head -50 "${OUT_DIR}/gobuster.txt"; }
fi
