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
section "1/18 — Fingerprinting"

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
section "2/18 — Passive Recon (Shodan & Censys)"

TARGET_IP=$(dig +short "${TARGET_HOST}" | grep -E '^[0-9]+\.' | head -1)

# Shodan
if [[ -n "${SHODAN_API_KEY:-}" ]]; then
    info "Shodan lookup..."
    if [[ -n "${TARGET_IP}" ]]; then
        shodan host "${TARGET_IP}" > "${OUT_DIR}/shodan.txt" 2>&1 || true
        ok "Shodan done → ${OUT_DIR}/shodan.txt"
    else
        warn "Could not resolve ${TARGET_HOST} for Shodan"
    fi
else
    warn "SHODAN_API_KEY not set — skipping Shodan (free key at shodan.io)"
fi

# Censys
if [[ -n "${CENSYS_API_ID:-}" && -n "${CENSYS_API_SECRET:-}" ]]; then
    info "Censys lookup..."
    export CENSYS_API_ID CENSYS_API_SECRET
    censys view "${TARGET_IP:-${TARGET_HOST}}" \
        > "${OUT_DIR}/censys.txt" 2>&1 || true
    ok "Censys done → ${OUT_DIR}/censys.txt"
else
    warn "CENSYS_API_ID/CENSYS_API_SECRET not set — skipping Censys (free at censys.io)"
fi

section "3/18 — Subdomain Enumeration"

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
section "4/18 — DNS Enumeration"

info "dnsx..."
echo "${TARGET_HOST}" | dnsx \
    -a -aaaa -cname -mx -ns -txt -resp \
    -o "${OUT_DIR}/dns.txt" 2>&1 \
    | tee "${OUT_DIR}/dnsx_console.txt" || true
ok "dnsx done"

# -----------------------------------------------------------------------------
# 4 — Ports
# -----------------------------------------------------------------------------
section "5/18 — Port Scanning"

info "naabu (top 1000)..."
naabu -host "${TARGET_HOST}" -top-ports 1000 \
    -o "${OUT_DIR}/ports.txt" 2>&1 \
    | tee "${OUT_DIR}/naabu_console.txt" || true
ok "naabu done"

# -----------------------------------------------------------------------------
# 6 — Nmap deep service scan (runs against ports naabu discovered)
# -----------------------------------------------------------------------------
section "6/18 — Nmap Service & Script Scan"

info "nmap — service detection and NSE vuln scripts..."
if [[ -s "${OUT_DIR}/ports.txt" ]]; then
    # Extract just the port numbers from naabu output
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

# -----------------------------------------------------------------------------
# 7 — SSL/TLS
# -----------------------------------------------------------------------------
section "7/18 — SSL/TLS Analysis"

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
section "8/18 — HTTP Security Headers (Mozilla Observatory)"

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
    warn "nikto skipped (--skip-nikto)"
fi

# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# CMS Scanning (WordPress — WPScan; Drupal/Joomla — detected and logged)
# -----------------------------------------------------------------------------
section "10/18 — CMS Scanning"

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

# Drupal / Joomla — log detection; coverage handled by Nuclei + ZAP
[[ "${IS_DRUPAL}" == "true" ]]  && warn "Drupal detected — covered by Nuclei templates and ZAP active scan"
[[ "${IS_JOOMLA}" == "true" ]]  && warn "Joomla detected — covered by Nuclei templates and ZAP active scan"
[[ "${IS_WORDPRESS}" == "false" && "${IS_DRUPAL}" == "false" && "${IS_JOOMLA}" == "false" ]] && \
    info "No known CMS detected"

# -----------------------------------------------------------------------------
# 8 — Endpoint discovery
# -----------------------------------------------------------------------------
section "11/18 — Endpoint Discovery"

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
# -----------------------------------------------------------------------------
# 10 — Arjun (Hidden parameter discovery)
# -----------------------------------------------------------------------------
section "12/18 — Arjun (Parameter Discovery)"

info "arjun — discovering hidden parameters..."
if [[ -s "${OUT_DIR}/endpoints.txt" ]]; then
    head -50 "${OUT_DIR}/endpoints.txt" > "${OUT_DIR}/arjun_targets.txt"
    arjun -i "${OUT_DIR}/arjun_targets.txt" \
        -oJ "${OUT_DIR}/arjun.json" \
        -t 5 --stable \
        2>&1 | tee "${OUT_DIR}/arjun_console.txt" || true
else
    arjun -u "${TARGET_URI}" \
        -oJ "${OUT_DIR}/arjun.json" \
        -t 5 --stable \
        2>&1 | tee "${OUT_DIR}/arjun_console.txt" || true
fi
ok "arjun done"

# -----------------------------------------------------------------------------
# 11 — Dalfox (XSS scanning)
# -----------------------------------------------------------------------------
section "13/18 — Dalfox (XSS Scanning)"

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

# -----------------------------------------------------------------------------
# 12 — SQLMap (SQL Injection)
# -----------------------------------------------------------------------------
section "14/18 — SQLMap (SQL Injection)"

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

section "15/18 — OSV-Scanner (Dependency Vulnerabilities)"

info "osv-scanner — checking for exposed dependency files..."
OSV_DIR="${OUT_DIR}/osv_scan"
mkdir -p "${OSV_DIR}"

# Download any exposed dependency/lockfiles found by katana
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

# Also try common exposed paths directly
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

section "16/18 — Nuclei"

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
section "17/18 — Nginx Bad Bot Blocker Validation"

# Tests whether nginx-ultimate-bad-bot-blocker is correctly blocking bad
# user-agents, fake Googlebots, and bad referrers, and NOT blocking good bots.
# Lists fetched live from: mitchellkrogza/nginx-ultimate-bad-bot-blocker
# A non-2xx/3xx response (or connection refused/reset) = correctly blocked.

REPO_RAW="https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists"
SAMPLE_SIZE=20
BOT_REPORT="${OUT_DIR}/botblocker_test.txt"
BLOCKED=0
ALLOWED=0
FP=0  # false positives (good bots that got blocked)

# How we determine "blocked": curl non-2xx/3xx HTTP code, or connection error
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
    # 2xx or 3xx = allowed through; anything else (444, 403, 0, empty) = blocked
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

# ── Bad User-Agents ──────────────────────────────────────────────────────────
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
        # Ensure referrer has a scheme
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
        # --interface spoofing requires root and may not work in all environments
        # Fall back to X-Forwarded-For header injection test
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
echo "═══════════════════════════════════════════════════"
echo "SUMMARY"
echo "  Correctly blocked: ${BLOCKED}"
echo "  Not blocked:       ${ALLOWED}"
echo "  False positives:   ${FP}"
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
# Summary
# -----------------------------------------------------------------------------
section "Complete — $(date)"

FILES=(
    whatweb.txt httpx.txt shodan.txt censys.txt
    subdomains.txt subdomains_live.txt
    dns.txt ports.txt nmap.txt nmap.xml
    testssl.txt testssl.json
    observatory.txt observatory.json
    nikto.txt nikto.json
    wpscan.txt wpscan.json
    endpoints.txt gobuster.txt ffuf.json
    arjun.json dalfox.txt
    sqlmap_console.txt
    osv_scanner.txt osv_scanner.json
    botblocker_test.txt
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
    [[ -s "${OUT_DIR}/shodan.txt" ]]         && { echo -e "\n${BOLD}── Shodan ───────────${RESET}"; cat "${OUT_DIR}/shodan.txt"; }
    [[ -s "${OUT_DIR}/censys.txt" ]]         && { echo -e "\n${BOLD}── Censys ───────────${RESET}"; cat "${OUT_DIR}/censys.txt"; }
    [[ -s "${OUT_DIR}/httpx.txt" ]]          && { echo -e "\n${BOLD}── Fingerprint ──────${RESET}"; cat "${OUT_DIR}/httpx.txt"; }
    [[ -s "${OUT_DIR}/ports.txt" ]]          && { echo -e "\n${BOLD}── Open Ports ───────${RESET}"; cat "${OUT_DIR}/ports.txt"; }
    [[ -s "${OUT_DIR}/nmap.txt" ]]           && { echo -e "\n${BOLD}── Nmap Services ────${RESET}"; grep -E "^[0-9]+/|SCRIPT OUTPUT|^Host" "${OUT_DIR}/nmap.txt" | head -50 || true; }
    [[ -s "${OUT_DIR}/testssl.txt" ]]        && { echo -e "\n${BOLD}── SSL Issues ───────${RESET}"; grep -E "WARN|CRITICAL|NOT ok" "${OUT_DIR}/testssl.txt" || echo "  None"; }
    [[ -s "${OUT_DIR}/observatory.txt" ]]    && { echo -e "\n${BOLD}── HTTP Headers ─────${RESET}"; cat "${OUT_DIR}/observatory.txt"; }
    [[ -s "${OUT_DIR}/nikto.txt" ]]          && { echo -e "\n${BOLD}── Nikto ────────────${RESET}"; grep "^+" "${OUT_DIR}/nikto.txt" || echo "  None"; }
    [[ -s "${OUT_DIR}/wpscan.txt" ]]         && { echo -e "\n${BOLD}── WPScan ───────────${RESET}"; grep -E "\[!\]|\[\+\]" "${OUT_DIR}/wpscan.txt" || echo "  None"; }
    [[ -s "${OUT_DIR}/arjun.json" ]]         && { echo -e "\n${BOLD}── Arjun Params ─────${RESET}"; jq -r '.[] | .url + " → " + (.params | join(", "))' "${OUT_DIR}/arjun.json" 2>/dev/null || cat "${OUT_DIR}/arjun.json"; }
    [[ -s "${OUT_DIR}/dalfox.txt" ]]         && { echo -e "\n${BOLD}── Dalfox XSS ───────${RESET}"; grep -E "VULN|WEAK|POC" "${OUT_DIR}/dalfox.txt" || echo "  None found"; }
    [[ -s "${OUT_DIR}/sqlmap_console.txt" ]] && { echo -e "\n${BOLD}── SQLMap ───────────${RESET}"; grep -E "injectable|Parameter|Type:" "${OUT_DIR}/sqlmap_console.txt" || echo "  None found"; }
    [[ -s "${OUT_DIR}/osv_scanner.txt" ]]    && { echo -e "\n${BOLD}── OSV Dependencies ─${RESET}"; grep -E "CRITICAL|HIGH|MEDIUM" "${OUT_DIR}/osv_scanner.txt" || echo "  None found"; }
    [[ -s "${OUT_DIR}/botblocker_test.txt" ]] && { echo -e "\n${BOLD}── Bot Blocker ──────${RESET}"; grep -E "SUMMARY|blocked:|positives:|rate:" "${OUT_DIR}/botblocker_test.txt" || true; }
    [[ -s "${OUT_DIR}/nuclei.txt" ]]         && { echo -e "\n${BOLD}── Nuclei ───────────${RESET}"; cat "${OUT_DIR}/nuclei.txt"; }
    [[ -s "${OUT_DIR}/gobuster.txt" ]]       && { echo -e "\n${BOLD}── Paths ────────────${RESET}"; head -50 "${OUT_DIR}/gobuster.txt"; }
fi