#!/usr/bin/env bash
set -euo pipefail

run_soft() {
    local label="$1"; shift

    if ! "$@"; then
        echo "[!] $label FAILED (skipping)" >&2
    fi
}


########################################
# PROFESSIONAL RECON PIPELINE
#
# This script automates recon by combining a wide set of tools:
#
#   - subfinder       : subdomain enumeration
#   - httpx           : probing, status codes, redirects
#   - katana          : advanced crawler (JS-aware)
#   - gospider        : additional crawling
#   - waybackurls     : fetch historical URLs
#   - LinkFinder      : extract endpoints from JS
#   - SecretFinder    : find tokens/secrets in JS files
#   - nuclei          : template-based vulnerability scanning
#   - ParamSpider     : discover parameters
#   - ffuf            : directory/file fuzzing
#   - SecurityTrails  : domain information API
#   - Shodan          : internet-wide device search
#   - Censys/ZoomEye   : internet-wide search engines
#   - VirusTotal      : threat intelligence and URL analysis
########################################

# -------------------------------------------------------
# DİQQƏT: Aşağıdakı yollar şəxsi istifadəçiyə məxsusdur.
# Bu hissədəki dəyişənlərə sizin öz sisteminizdə alətlərin yerləşdiyi
# PATH-ları yazmalısınız.
#
# Əgər bu alətlər başqa qovluqda yerləşirsə, sadəcə həmin yolları 
# uyğun olaraq dəyişin.
# -------------------------------------------------------
LINKFINDER="/usr/local/bin/linkfinder"
SECRETFINDER="/usr/bin/python3 /home/mrk4z1m0v/SecretFinder/SecretFinder.py"
NUCLEI_TEMPLATES="$HOME/.local/nuclei-templates"

# API keys (must be set before use)
SHODAN_API_KEY="YOUR_API_KEY"
CENSYS_PAT="YOUR_API_KEY"
ZOOMEYE_API_KEY="YOUR_API_KEY"
VIRUSTOTAL_API_KEY="YOUR_API_KEY"
SECURITYTRAILS_API_KEY="YOUR_API_KEY"

# -------------------------------------------------------
# Basic argument check
# -------------------------------------------------------
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 example.com"
    exit 1
fi

DOMAIN="$1"

# -------------------------------------------------------
# Ensure required tools are installed
# -------------------------------------------------------
REQUIRED_CMDS=(subfinder httpx katana gospider waybackurls python3 nuclei paramspider ffuf)
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[!] Required tool not found: $cmd"
        echo "    Please install it and re-run."
        exit 1
    fi
done

# -------------------------------------------------------
# Auto-detect LinkFinder if installed
# -------------------------------------------------------
LINKFINDER="$(command -v linkfinder || true)"

if [[ -z "$LINKFINDER" ]]; then
    echo "[!] LinkFinder not found. Install it via:"
    echo "    pip install linkfinder"
else
    echo "[+] LinkFinder found at: $LINKFINDER"
fi

# Secondary check (common pattern in production scripts)
if [[ -z "$LINKFINDER" ]]; then
    echo "[!] LinkFinder not found. Install using: pip install linkfinder"
else
    echo "[+] LinkFinder OK: $LINKFINDER"
fi

# -------------------------------------------------------
# Check SecretFinder script path
# -------------------------------------------------------
# DİQQƏT: Bu yol şəxsi istifadəçiyə məxsusdur.
# Siz SecretFinder-i haraya klon etmisinizsə: 
#   /home/<istifadəçi_adı>/SecretFinder/SecretFinder.py
# həmin yeri bura yazmalısınız.
if [[ ! -f "/home/mrk4z1m0v/SecretFinder/SecretFinder.py" ]]; then
    echo "[!] SecretFinder script not found."
else
    echo "[+] SecretFinder OK."
fi

# -------------------------------------------------------
# Create output directory structure
# -------------------------------------------------------
TS="$(date +%F_%H-%M-%S)"
OUTDIR="recon_${DOMAIN}_${TS}"

# 1) One folder for all raw output
ALL_RAW_DIR="${OUTDIR}/all_raw"
mkdir -p "$ALL_RAW_DIR"

# Aliases for compatibility with existing logic
RAW_DIR="$ALL_RAW_DIR"
HOSTS_DIR="$ALL_RAW_DIR"
URLS_DIR="$ALL_RAW_DIR"

# 2) Separate raw JS files
JS_RAW_DIR="${OUTDIR}/js_all_raw"
mkdir -p "$JS_RAW_DIR"

# 3) Clean pentest-ready assets directory
ASSETS_DIR="${OUTDIR}/assets"
JS_ASSETS_DIR="${ASSETS_DIR}/js_assets"
JS_DIR="$JS_ASSETS_DIR"

# 4) FUZZ and SCAN results also stored in raw folder
FUZZ_DIR="$ALL_RAW_DIR"
SCANS_DIR="$ALL_RAW_DIR"
FINDINGS_DIR="$ASSETS_DIR"

mkdir -p "$ASSETS_DIR" "$JS_DIR"



# -------------------------------------------------------
# Result files (main summary + full output)
# -------------------------------------------------------
MAIN_RESULTS="${OUTDIR}/main_results.txt"
ALL_RESULTS="${OUTDIR}/all_results.txt"

# Clear them
> "$MAIN_RESULTS"
> "$ALL_RESULTS"

echo "[*] Output directory: $OUTDIR"
echo "[*] Main results: $MAIN_RESULTS"
echo "[*] All results: $ALL_RESULTS"
echo

# -------------------------------------------------------
# Utility: write results to both main and full logs
# -------------------------------------------------------
log_to_files() {
    echo "$1" >> "$ALL_RESULTS"
    if [[ "$2" == "main" ]]; then
        echo "$1" >> "$MAIN_RESULTS"
    fi
}

# -------------------------------------------------------
# === SUBDOMAIN ENUMERATION ===
# -------------------------------------------------------
add_section() {
    local section_name="$1"
    local include_in_main="${2:-true}"
    
    local separator="========================================"
    local header="=== $section_name ==="
    
    echo "$separator" >> "$ALL_RESULTS"
    echo "$header" >> "$ALL_RESULTS"
    echo "$separator" >> "$ALL_RESULTS"
    echo "" >> "$ALL_RESULTS"
    
    if [[ "$include_in_main" == "true" ]]; then
        echo "$separator" >> "$MAIN_RESULTS"
        echo "$header" >> "$MAIN_RESULTS"
        echo "$separator" >> "$MAIN_RESULTS"
        echo "" >> "$MAIN_RESULTS"
    fi
}

# ------------------------------------------------------------
# Keeps a maximum of 2 URLs per content-length to reduce false positives.
# This prevents multiple "duplicate" URLs with the same response size from cluttering results.
# ------------------------------------------------------------
filter_by_content_length() {
    local input_file="$1"
    local output_file="$2"
    local tmp_httpx="$(mktemp)"

    # Skip if input file is empty
    if [[ ! -s "$input_file" ]]; then
        echo "[!] $input_file boşdur, filter_by_content_length skip."
        return 0
    fi

    echo "[*] Reducing false positives by response length for: $input_file"

     # Probe URLs with httpx to get status codes and content-length
    httpx -silent -follow-redirects \
          -timeout 10 \
          -mc 200,301,302,307,308,401,403 \
          -cl \
          -l "$input_file" > "$tmp_httpx" 2>/dev/null || true

    # httpx output format:
    # URL [status] [content-length] [content-type] ...
    # We keep a maximum of 2 URLs per content-length
    awk '
    {
        url = $1
        cl  = ""

        # Field-lar içindən [rəqəm] olanı CL kimi götürək
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^\[[0-9]+\]$/) {
                gsub(/\[/, "", $i)
                gsub(/\]/, "", $i)
                cl = $i
            }
        }

        # CL tapa bilməsək – ehtiyat üçün saxlayırıq
        if (cl == "") {
            print url
            next
        }

        if (cnt[cl] < 2) {
            cnt[cl]++
            print url
        }
        # əks halda (cnt[cl] >= 2) – həmin CL üçün artıq kifayət edir, skip
    }' "$tmp_httpx" > "$output_file"

    rm -f "$tmp_httpx"
}

########################################
# 1) SUBDOMAIN DISCOVERY
########################################

echo "[*] Step 1: Enumerating subdomains with subfinder..."
subfinder -d "$DOMAIN" -silent | sort -u > "${RAW_DIR}/subdomains_all.txt"

# Additional subdomain sources
echo "[*] Step 1b: Checking CIRT.sh for subdomains..."
run_soft "CIRT.sh subdomains" \
    curl -s "https://cirt.net/domains?q=$DOMAIN" \
    | grep -oP '[a-zA-Z0-9.-]+\.'"$DOMAIN" 2>/dev/null \
    | sort -u >> "${RAW_DIR}/subdomains_all.txt" || true

# Remove duplicates
sort -u "${RAW_DIR}/subdomains_all.txt" -o "${RAW_DIR}/subdomains_all.txt"

# Count total subdomains found
SUBCOUNT="$(wc -l < "${RAW_DIR}/subdomains_all.txt" || echo 0)"
echo "    [+] Total subdomains found: ${SUBCOUNT}"

# Log all subdomains to all_results
add_section "ALL SUBDOMAINS (RAW)" "false"
cat "${RAW_DIR}/subdomains_all.txt" >> "$ALL_RESULTS"
echo "" >> "$ALL_RESULTS"

if [[ "$SUBCOUNT" -eq 0 ]]; then
    echo "[!] No subdomains found. Exiting."
    exit 0
fi

########################################
# 2) LIVE HOST DISCOVERY
########################################

echo
echo "[*] Step 2: Probing subdomains with httpx..."

# Probe all subdomains with httpx to get live hosts and extra info
httpx \
    -l "${RAW_DIR}/subdomains_all.txt" \
    -silent \
    -follow-redirects \
    -http2 \
    -timeout 10 \
    -sc -cl -ct -ip -server -td -location \
    -mc 200,201,202,204,301,302,307,308,401,403 \
    | tee "${HOSTS_DIR}/live_subdomains_httpx_full.txt" >/dev/null

# Extract only live hosts (2xx/3xx/401/403)
cut -d' ' -f1 "${HOSTS_DIR}/live_subdomains_httpx_full.txt" \
    | sort -u > "${HOSTS_DIR}/live_subdomains.txt"

LIVECOUNT="$(wc -l < "${HOSTS_DIR}/live_subdomains.txt" || echo 0)"
echo "    [+] Live subdomains (2xx/3xx): ${LIVECOUNT}"

# Copy clean host list to assets for later use
cp "${HOSTS_DIR}/live_subdomains.txt" "${ASSETS_DIR}/live_subdomains.txt" 2>/dev/null || true

# Log live subdomains to main results
add_section "LIVE SUBDOMAINS (2xx/3xx STATUS)" "true"
cat "${HOSTS_DIR}/live_subdomains.txt" >> "$MAIN_RESULTS"


# Log full httpx output to all results
add_section "FULL HTTPX RESULTS (STATUS + REDIRECTS)" "false"
cat "${HOSTS_DIR}/live_subdomains_httpx_full.txt" >> "$ALL_RESULTS"
echo "" >> "$ALL_RESULTS"

if [[ "$LIVECOUNT" -eq 0 ]]; then
    echo "[!] No live subdomains found. Exiting."
    exit 0
fi

########################################
# 3) URL DISCOVERY
########################################

echo
echo "[*] Step 3: Crawling live hosts with katana (timeout: 300s)..."
timeout 300 katana -silent \
       -list "${HOSTS_DIR}/live_subdomains.txt" \
       -jc \
       -d 3 \
       -o "${URLS_DIR}/urls_katana.txt" || echo "[!] Katana timeout or error"

echo "[*] Step 4: Extra crawling with gospider (timeout: 300s)..."
timeout 300 gospider -S "${HOSTS_DIR}/live_subdomains.txt" \
             -d 2 \
             -r \
             -a \
             -w \
             -q \
             -o "${URLS_DIR}/gospider_raw" >/dev/null 2>&1 || echo "[!] Gospider timeout"


filter_by_fingerprint() {
    local input_file="$1"
    local output_file="$2"
    local tmp_httpx
    tmp_httpx="$(mktemp)"

    if [[ ! -s "$input_file" ]]; then
        echo "[!] $input_file boşdur, filter_by_fingerprint skip."
        return 0
    fi

    echo "[*] Reducing false positives by response fingerprint for: $input_file"

    # Probe URLs with httpx and extract:
    #   - status code
    #   - content-length
    #   - SHA256 hash (response body hash)
    httpx -silent -follow-redirects \
          -timeout 10 \
          -mc 200,201,202,204,301,302,307,308,401,403 \
          -sc -cl -hash sha256 \
          -l "$input_file" > "$tmp_httpx" 2>/dev/null || true

    
    # Example httpx output:
    #   https://site.com [200] [1234] [sha256:abcdef...]
    #
    # Logic:
    #   - If hash exists → use it as fingerprint (strongest).
    #   - Otherwise use (status + content-length).
    #   - Otherwise use content-length only.
    #   - Keep max 2 URLs per fingerprint bucket.
    awk '
    {
        url = $1
        sc = ""
        cl = ""
        hash = ""

        # field-lərin içindən status, cl və hash-i çıxarırıq
        for (i = 2; i <= NF; i++) {
            if ($i ~ /^\[[0-9]{3}\]$/) {
                sc = $i
            } else if ($i ~ /^\[[0-9]+\]$/) {
                cl = $i
            } else if ($i ~ /\[sha256:[0-9a-fA-F]+\]/) {
                hash = $i
            }
        }

        gsub(/[\[\]]/, "", sc)
        gsub(/[\[\]]/, "", cl)
        gsub(/\[sha256:/, "", hash)
        gsub(/\]/, "", hash)

        key = ""

        if (hash != "") {
            key = "H|" hash               # eyni hash = eyni content
        } else if (sc != "" && cl != "") {
            key = "SC_CL|" sc "|" cl      # eyni status + eyni CL
        } else if (cl != "") {
            key = "CL|" cl
        } else {
            # hash və CL tapa bilməsək, bu URL-i saxlayırıq
            print url
            next
        }

        if (count[key] < 2) {
            count[key]++
            print url
        }
        # 3-cü, 4-cü və s. eyni content-lər atılır
    }' "$tmp_httpx" > "$output_file"

    rm -f "$tmp_httpx"
}


# Extract URLs from all gospider output files inside the directory
# Grep recursively (-r), extract URLs and deduplicate
if [[ -d "${URLS_DIR}/gospider_raw" ]]; then
    grep -rohP '(http|https)://[^\s"]+' "${URLS_DIR}/gospider_raw" 2>/dev/null \
        | sort -u > "${URLS_DIR}/urls_gospider.txt" || true
fi

echo "[*] Step 5: Pulling historical URLs from waybackurls..."
echo "$DOMAIN" | waybackurls | sort -u > "${URLS_DIR}/urls_wayback.txt"

# Merge URLs from katana, gospider and wayback
echo "[*] Step 6: Combining and deduplicating URLs..."
cat "${URLS_DIR}/urls_katana.txt" \
    "${URLS_DIR}/urls_gospider.txt" \
    "${URLS_DIR}/urls_wayback.txt" 2>/dev/null \
    | sort -u > "${URLS_DIR}/urls_all.txt"

# Remove development/junk noise (webpack, dev-tools, hot reload endpoints, etc.)
# If grep fails, fall back to full list
grep -Ev 'node_modules/|webpack/|react-devtools|sockjs-node|hot-update|__webpack_hmr|webpack-dev-server|browser-sync' \
    "${URLS_DIR}/urls_all.txt" > "${URLS_DIR}/urls_clean.txt" || cp "${URLS_DIR}/urls_all.txt" "${URLS_DIR}/urls_clean.txt"

URLCOUNT="$(wc -l < "${URLS_DIR}/urls_clean.txt" || echo 0)"
echo "    [+] Total unique URLs (clean): ${URLCOUNT}"

# Add full results to the ALL_RESULTS log
add_section "ALL DISCOVERED URLS" "false"
cat "${URLS_DIR}/urls_all.txt" >> "$ALL_RESULTS"
echo "" >> "$ALL_RESULTS"

# Add *active* URLs to the MAIN results (JS excluded later)
add_section "ACTIVE URLS (FROM LIVE HOSTS)" "true"
cat "${URLS_DIR}/urls_katana.txt" "${URLS_DIR}/urls_gospider.txt" 2>/dev/null \
    | grep -Ev 'node_modules/|webpack/|react-devtools|sockjs-node|hot-update|__webpack_hmr|webpack-dev-server|browser-sync' \
    | sort -u >> "$MAIN_RESULTS"
echo "" >> "$MAIN_RESULTS"

# Remove media/static assets: images, videos, fonts, CSS, map files, etc.
grep -Ev '\.(png|jpe?g|gif|svg|ico|webp|bmp|tiff?|mp4|mp3|avi|mov|mkv|webm|woff2?|ttf|eot|otf|css|map)(\?|$)' \
    "${URLS_DIR}/urls_clean.txt" > "${ASSETS_DIR}/url_tmp.txt" || true

# Remove .js endpoints to get pure crawlable endpoints
grep -Ev '\.js(\?|$| )' "${ASSETS_DIR}/url_tmp.txt" > "${ASSETS_DIR}/url.txt" || true
rm -f "${ASSETS_DIR}/url_tmp.txt"

# Extract URLs that contain parameters (?param=) → used for XSS/SSRF/Open Redirect testing
grep '\?' "${ASSETS_DIR}/url.txt" | sort -u > "${ASSETS_DIR}/url_params.txt" || true

# Identify critical endpoints (auth, API, admin, upload, login, token, redirect, etc.)
CRIT_PATTERN='(/api/|/auth|/login|/signin|/logout|/admin|/config|/debug|/upload|/callback|/redirect|/token|/oauth|/profile|/account)'

# Extract critical endpoints
grep -Ei "$CRIT_PATTERN" "${ASSETS_DIR}/url.txt" | sort -u > "${ASSETS_DIR}/endpoint.txt" || true

# Extract all endpoints (URLs with at least 1 path segment)
awk -F/ 'NF > 3' "${ASSETS_DIR}/url.txt" | sort -u > "${ASSETS_DIR}/endpoint_all_tmp.txt" || true

# Add non-critical endpoints into endpoint.txt
grep -vxF -f "${ASSETS_DIR}/endpoint.txt" \
    "${ASSETS_DIR}/endpoint_all_tmp.txt" >> "${ASSETS_DIR}/endpoint.txt" || true

rm -f "${ASSETS_DIR}/endpoint_all_tmp.txt"

# Apply fingerprint filtering to endpoints (keep max 2 URLs per fingerprint)
if [[ -s "${ASSETS_DIR}/endpoint.txt" ]]; then
    filter_by_fingerprint "${ASSETS_DIR}/endpoint.txt" "${ASSETS_DIR}/endpoint_filtered.txt"
    mv "${ASSETS_DIR}/endpoint_filtered.txt" "${ASSETS_DIR}/endpoint.txt"
fi

########################################
# GLOBAL URL FILTER (3-layer architecture)
########################################
echo "[*] Running global response fingerprint filter on URL corpus..."

# Filter main cleaned URL list
if [[ -s "${ASSETS_DIR}/url.txt" ]]; then
    filter_by_fingerprint "${ASSETS_DIR}/url.txt" "${ASSETS_DIR}/url_filtered.txt"
    mv "${ASSETS_DIR}/url_filtered.txt" "${ASSETS_DIR}/url.txt"
fi

# Filter entire cleaned URL corpus
if [[ -s "${URLS_DIR}/urls_clean.txt" ]]; then
    filter_by_fingerprint "${URLS_DIR}/urls_clean.txt" "${URLS_DIR}/urls_clean_filtered.txt"
    mv "${URLS_DIR}/urls_clean_filtered.txt" "${URLS_DIR}/urls_clean.txt"
fi

# Filter Katana crawler URLs
if [[ -s "${URLS_DIR}/urls_katana.txt" ]]; then
    filter_by_fingerprint "${URLS_DIR}/urls_katana.txt" "${URLS_DIR}/urls_katana_filtered.txt"
    mv "${URLS_DIR}/urls_katana_filtered.txt" "${URLS_DIR}/urls_katana.txt"
fi

# Filter Gospider URLs
if [[ -s "${URLS_DIR}/urls_gospider.txt" ]]; then
    filter_by_fingerprint "${URLS_DIR}/urls_gospider.txt" "${URLS_DIR}/urls_gospider_filtered.txt"
    mv "${URLS_DIR}/urls_gospider_filtered.txt" "${URLS_DIR}/urls_gospider.txt"
fi

########################################
# 4) JS ANALYSIS
########################################

if [[ "$URLCOUNT" -eq 0 ]]; then
    echo "[!] No URLs collected. Skipping JS analysis."
    exit 0
fi

echo
echo "[*] Step 7: Extracting JS files from URL corpus..."
grep -Ei '\.js(\?|$| )' "${URLS_DIR}/urls_clean.txt" \
    | grep -Ev 'node_modules/|webpack/|react-devtools|sockjs-node|hot-update|__webpack_hmr' \
    | sort -u > "${JS_DIR}/js_files.txt" || true

JSCOUNT="$(wc -l < "${JS_DIR}/js_files.txt" 2>/dev/null || echo 0)"
echo "    [+] Unique JS files (initial): ${JSCOUNT}"

# Add JS files to the report
add_section "JAVASCRIPT FILES" "true"
if [[ -s "${JS_DIR}/js_files.txt" ]]; then
    cat "${JS_DIR}/js_files.txt" >> "$MAIN_RESULTS"
    cat "${JS_DIR}/js_files.txt" >> "$ALL_RESULTS"
else
    echo "No JS files found." >> "$MAIN_RESULTS"
    echo "No JS files found." >> "$ALL_RESULTS"
fi
echo "" >> "$MAIN_RESULTS"
echo "" >> "$ALL_RESULTS"

# Recursive JS analysis using LinkFinder + SecretFinder
if [[ "$JSCOUNT" -gt 0 ]]; then
    echo "[*] Step 8–9: Recursive JS analysis (LinkFinder + SecretFinder)..."


    ENDPOINTS_RAW="${JS_RAW_DIR}/js_endpoints_raw.txt"
    SECRETS_RAW="${JS_RAW_DIR}/js_secrets_raw.txt"
    PROCESSED="${JS_RAW_DIR}/js_files_processed.txt"
    JS_BATCH="${JS_RAW_DIR}/js_batch.txt"
    JS_NEW="${JS_RAW_DIR}/js_new_found.txt"

    > "$ENDPOINTS_RAW"
    > "$SECRETS_RAW"
    > "$PROCESSED"

# Identify JS files not yet processed
    while true; do
        
        if [[ -s "$PROCESSED" ]]; then
            grep -vxF -f "$PROCESSED" "${JS_DIR}/js_files.txt" 2>/dev/null > "$JS_BATCH" || true
        else
            cp "${JS_DIR}/js_files.txt" "$JS_BATCH" 2>/dev/null || true
        fi

        BATCH_COUNT="$(wc -l < "$JS_BATCH" 2>/dev/null || echo 0)"
        [[ "$BATCH_COUNT" -eq 0 ]] && break

        echo "  [+] New JS batch to scan: $BATCH_COUNT"

        while read -r js_url; do
            [[ -z "$js_url" ]] && continue

            echo "  [-] $js_url" >> "$ENDPOINTS_RAW"
            "$LINKFINDER" -i "$js_url" -o cli 2>/dev/null >> "$ENDPOINTS_RAW" || true

            echo >> "$ENDPOINTS_RAW"

            echo "  [-] $js_url" >> "$SECRETS_RAW"
            $SECRETFINDER -i "$js_url" -o cli 2>/dev/null >> "$SECRETS_RAW" || true
            echo >> "$SECRETS_RAW"

            echo "$js_url" >> "$PROCESSED"
        done < "$JS_BATCH"

            # Extract new JS URLs from raw LinkFinder output
        grep -oP 'https?://[^\s"<>]+' "$ENDPOINTS_RAW" 2>/dev/null \
            | grep -Ei '\.js(\?|$| )' \
            | sort -u > "$JS_NEW" || true

          # Add new JS files to processing list
        if [[ -s "$JS_NEW" ]]; then
            grep -vxF -f "${JS_DIR}/js_files.txt" "$JS_NEW" >> "${JS_DIR}/js_files.txt" || true
            sort -u "${JS_DIR}/js_files.txt" -o "${JS_DIR}/js_files.txt"
        else
            break
        fi
    done

    # Extract non-JS endpoints
    grep -oP 'https?://[^\s"<>]+' "$ENDPOINTS_RAW" 2>/dev/null \
        | grep -Ev '\.js(\?|$| )' \
        | sort -u > "${JS_DIR}/js_url.txt" || true

    # Remove static/media assets
    grep -Ev '\.(png|jpe?g|gif|svg|ico|webp|bmp|tiff?|mp4|mp3|avi|mov|mkv|webm|woff2?|ttf|eot|otf|css|map)(\?|$)' \
        "${JS_DIR}/js_url.txt" | sort -u > "${JS_DIR}/js_endpoints.txt" || true

    # JS secrets and tokens
    grep -Ei '(/api/|/auth|/login|/signin|/logout|/admin|/config|/debug|/upload|/callback|/redirect|/token|/oauth|/profile|/account)' \
        "${JS_DIR}/js_endpoints.txt" | sort -u > "${JS_DIR}/js_api.txt" || true

    grep -Ei 'secret|api[_-]?key|token|bearer|password|passwd|access[_-]?key' "$SECRETS_RAW" 2>/dev/null \
    | grep -Ev '^\s*\[-\]|node_modules/|webpack/|react-devtools|sockjs-node|hot-update|__webpack_hmr' \
    | sort -u > "${JS_DIR}/js_secret_key.txt" || true

    # Apply fingerprint filtering on JS endpoints
if [[ -s "${JS_DIR}/js_endpoints.txt" ]]; then
    filter_by_fingerprint "${JS_DIR}/js_endpoints.txt" "${JS_DIR}/js_endpoints_filtered.txt"
    mv "${JS_DIR}/js_endpoints_filtered.txt" "${JS_DIR}/js_endpoints.txt"
fi

    # Add cleaned JS results to reports
    add_section "JS ENDPOINTS (CLEAN)" "true"
    if [[ -s "${JS_DIR}/js_endpoints.txt" ]]; then
        cat "${JS_DIR}/js_endpoints.txt" >> "$MAIN_RESULTS"
        cat "${JS_DIR}/js_endpoints.txt" >> "$ALL_RESULTS"
    else
        echo "No JS endpoints found." >> "$MAIN_RESULTS"
        echo "No JS endpoints found." >> "$ALL_RESULTS"
    fi
    echo "" >> "$MAIN_RESULTS"
    echo "" >> "$ALL_RESULTS"

    add_section "JS SECRETS/TOKENS (CLEAN)" "true"
    if [[ -s "${JS_DIR}/js_secret_key.txt" ]]; then
        cat "${JS_DIR}/js_secret_key.txt" >> "$MAIN_RESULTS"
        cat "${JS_DIR}/js_secret_key.txt" >> "$ALL_RESULTS"
    else
        echo "No JS secrets found." >> "$MAIN_RESULTS"
        echo "No JS secrets found." >> "$ALL_RESULTS"
    fi
    echo "" >> "$MAIN_RESULTS"
    echo "" >> "$ALL_RESULTS"
fi



########################################
# 5) ADVANCED SEARCH PATTERNS
########################################

echo
echo "[*] Step 10: Running advanced search patterns..."

# Search for configuration files and other sensitive endpoints
echo "[*] Searching for configuration files and sensitive endpoints..."
PATTERNS=(
    "inurl:conf|inurl:env|inurl:cgi|inurl:bin|inurl:etc|inurl:root|inurl:sql|inurl:backup|inurl:admin|inurl:php|inurl:config|inurl:database|inurl:db|inurl:credentials|inurl:passwd|inurl:password|inurl:secret|inurl:key|ext:json|ext:xml|ext:yml|ext:ini|ext:env|ext:bak|ext:backup|ext:old|ext:swp"
    "inurl:login|inurl:signin|intitle:login|intitle:signin|inurl:secure|inurl:admin|inurl:administrator|inurl:auth|inurl:account|inurl:user|intitle:admin|intitle:dashboard"
    "inurl:api|inurl:rest|inurl:v1|inurl:v2|inurl:v3|inurl:graphql|inurl:soap|inurl:auth|inurl:token|inurl:endpoint|inurl:service"
    "inurl:demo|inurl:dev|inurl:staging|inurl:test|inurl:sandbox|inurl:preview|inurl:uat|inurl:beta|inurl:internal|inurl:mock"
    "ext:log|ext:txt|ext:csv|ext:conf|ext:cnf|ext:ini|ext:env|ext:sh|ext:bak|ext:backup|ext:old|ext:sql|ext:json|ext:xml"
    "inurl:wp-|inurl:wp-content|inurl:plugins|inurl:uploads|inurl:themes|inurl:joomla|inurl:drupal|inurl:modules|inurl:sites"
    "inurl:include|inurl:dir|inurl:detail=|inurl:file=|inurl:folder=|inurl:inc=|inurl:page=|inurl:path=|inurl:module=|inurl:view=|inurl:download=|inurl:source=|inurl:document="
    "inurl:redirectUrl=http|inurl:redir|inurl:url|inurl:redirect|inurl:return|inurl:src=http|inurl:next|inurl:target|inurl:goto|inurl:callback|inurl:uri"
)

> "${FINDINGS_DIR}/sensitive_patterns.txt"
for pattern in "${PATTERNS[@]}"; do
    grep -E "$pattern" "${URLS_DIR}/urls_all.txt" 2>/dev/null >> "${FINDINGS_DIR}/sensitive_patterns.txt" || true
done

# WordPress specific endpoints
WP_ENDPOINTS=(
    "wp-admin.php" "wp-config.php" "wp-content/uploads" "wp-load" "wp-signup.php"
    "wp-json" "wp-includes" "index.php" "wp-login.php" "wp-links-opml.php"
    "wp-activate.php" "wp-blog-header.php" "wp-cron.php" "wp-links.php"
    "wp-mail.php" "xmlrpc.php" "wp-settings.php" "wp-trackback.php"
)

> "${FINDINGS_DIR}/wordpress_endpoints.txt"
for endpoint in "${WP_ENDPOINTS[@]}"; do
    grep "$endpoint" "${URLS_DIR}/urls_all.txt" 2>/dev/null >> "${FINDINGS_DIR}/wordpress_endpoints.txt" || true
done

# Log search pattern results
add_section "SENSITIVE PATTERNS AND ENDPOINTS" "true"
if [[ -s "${FINDINGS_DIR}/sensitive_patterns.txt" ]]; then
    echo "=== Sensitive Patterns ===" >> "$MAIN_RESULTS"
    cat "${FINDINGS_DIR}/sensitive_patterns.txt" >> "$MAIN_RESULTS"
    echo "" >> "$MAIN_RESULTS"
    
    echo "=== Sensitive Patterns ===" >> "$ALL_RESULTS"
    cat "${FINDINGS_DIR}/sensitive_patterns.txt" >> "$ALL_RESULTS"
    echo "" >> "$ALL_RESULTS"
fi

if [[ -s "${FINDINGS_DIR}/wordpress_endpoints.txt" ]]; then
    echo "=== WordPress Endpoints ===" >> "$MAIN_RESULTS"
    cat "${FINDINGS_DIR}/wordpress_endpoints.txt" >> "$MAIN_RESULTS"
    echo "" >> "$MAIN_RESULTS"
    
    echo "=== WordPress Endpoints ===" >> "$ALL_RESULTS"
    cat "${FINDINGS_DIR}/wordpress_endpoints.txt" >> "$ALL_RESULTS"
    echo "" >> "$ALL_RESULTS"
fi

########################################
# 6) FUZZING WITH FFUF
########################################

echo
echo "[*] Step 11: Directory fuzzing with ffuf..."

if [[ -s "${HOSTS_DIR}/live_subdomains.txt" ]]; then
    # Simple directory fuzzing on first 5 live hosts
    head -5 "${HOSTS_DIR}/live_subdomains.txt" | while read -r host; do
        echo "  [-] Fuzzing: $host"
        ffuf -u "${host}/FUZZ" -w /usr/share/wordlists/dirb/common.txt \
            -mc 200,301,302,403 \
            -o "${FUZZ_DIR}/ffuf_$(echo "$host" | sed 's|https\?://||' | tr '/' '_').json" \
            -of json \
            -s >/dev/null 2>&1 || true
    done
fi


########################################
# 12) Nuclei background scanning (SECURITY SCANNING)
########################################

echo
echo "[*] Step 12: Launching Nuclei vulnerability scanning in background..."

NUCLEI_INPUT="${URLS_DIR}/urls_all.txt"
NUCLEI_OUTPUT="${ASSETS_DIR}/nuclei.txt"
NUCLEI_LOG="${ASSETS_DIR}/nuclei_console.log"

if [[ -s "$NUCLEI_INPUT" ]]; then

# Run Nuclei scan with medium, high, and critical severity levels
    nuclei -l "$NUCLEI_INPUT" \
           -t "$NUCLEI_TEMPLATES" \
           -o "$NUCLEI_OUTPUT" \
           -severity medium,high,critical \
           -c 80 \
           -rate-limit 50 \
           -stats \
           > "$NUCLEI_LOG" 2>&1 &

    NUCLEI_PID=$!
    echo "    [+] Nuclei is running in background (PID: $NUCLEI_PID)"
    echo "    [+] Output file: $NUCLEI_OUTPUT"
    echo "    [+] Live log:    $NUCLEI_LOG"

    # Optional: Nuclei bitəndə xəbərdarlıq etsin
    (
        wait $NUCLEI_PID
        echo "[+] Nuclei finished! Results saved to $NUCLEI_OUTPUT"
    ) &
else
    echo "[!] No URLs for Nuclei scan, skipping..."
fi



########################################
# 13) Parameter discovery with ParamSpider
########################################
echo "[*] Step 13: Running ParamSpider for parameter discovery..."
run_soft "ParamSpider" \
    paramspider --domain "$DOMAIN" --output "${SCANS_DIR}/paramspider_results.txt" >/dev/null 2>&1

# Log security scan results
add_section "SECURITY SCAN RESULTS" "true"
if [[ -s "${SCANS_DIR}/nuclei_results.txt" ]]; then
    echo "=== Nuclei Vulnerability Scan Results ===" >> "$MAIN_RESULTS"
    cat "${SCANS_DIR}/nuclei_results.txt" >> "$MAIN_RESULTS"
    echo "" >> "$MAIN_RESULTS"
    
    echo "=== Nuclei Vulnerability Scan Results ===" >> "$ALL_RESULTS"
    cat "${SCANS_DIR}/nuclei_results.txt" >> "$ALL_RESULTS"
    echo "" >> "$ALL_RESULTS"
fi

if [[ -s "${SCANS_DIR}/paramspider_results.txt" ]]; then
    echo "=== Parameter Discovery Results ===" >> "$MAIN_RESULTS"
    cat "${SCANS_DIR}/paramspider_results.txt" >> "$MAIN_RESULTS"
    echo "" >> "$MAIN_RESULTS"
    
    echo "=== Parameter Discovery Results ===" >> "$ALL_RESULTS"
    cat "${SCANS_DIR}/paramspider_results.txt" >> "$ALL_RESULTS"
    echo "" >> "$ALL_RESULTS"
fi

########################################
# 8) EXTERNAL INTEL GATHERING
########################################

echo
echo "[*] Step 14: Gathering external intelligence..."

# Query Shodan for information using advanced search filters
echo "[*] Querying Shodan..."
SHODAN_RESULTS="${SCANS_DIR}/shodan_combined.txt"
> "$SHODAN_RESULTS"

if command -v shodan >/dev/null 2>&1 && [[ "$SHODAN_API_KEY" != "your-shodan-api-key" ]]; then
    run_soft "Shodan init" shodan init "$SHODAN_API_KEY"
    run_soft "Shodan host lookup" shodan host "$DOMAIN" >> "$SHODAN_RESULTS" 2>&1
   

    # Run advanced Shodan search queries
    echo "=== Advanced Shodan Queries ===" >> "$SHODAN_RESULTS"
    shodan search "ssl.cert.subject.CN:\"$DOMAIN\" http.title:\"index of/\"" --limit 10 >> "$SHODAN_RESULTS" 2>&1 || true
    shodan search "http.title:\"admin\" OR http.title:\"control panel\" OR \"phpMyAdmin\" port:8080,80,443" --limit 10 >> "$SHODAN_RESULTS" 2>&1 || true
    shodan search "\"Docker Registry HTTP API\" -\"UNAUTHORIZED\"" --limit 5 >> "$SHODAN_RESULTS" 2>&1 || true
    shodan search "\"authentication disabled\" \"RFB 003.008\"" --limit 5 >> "$SHODAN_RESULTS" 2>&1 || true
    shodan search "\"Set-Cookie: mongo-express=\" \"200 OK\"" --limit 5 >> "$SHODAN_RESULTS" 2>&1 || true
fi

# Query Censys for host information
echo "[*] Querying Censys..."
if [[ "$CENSYS_PAT" != "" ]]; then
    curl -s -H "Authorization: Bearer $CENSYS_PAT" \
         "https://search.censys.io/api/v2/hosts/search?q=$DOMAIN" \
         > "${SCANS_DIR}/censys_info.json"
fi


# Query VirusTotal for domain intelligence
echo "[*] Querying VirusTotal..."
if [[ "$VIRUSTOTAL_API_KEY" != "your-virustotal-api-key" ]]; then
    curl -s -X GET "https://www.virustotal.com/api/v3/domains/$DOMAIN" \
         -H "x-apikey: $VIRUSTOTAL_API_KEY" > "${SCANS_DIR}/virustotal_info.json" 2>&1 || true
fi

# Query SecurityTrails for domain and subdomain information
if [[ "$SECURITYTRAILS_API_KEY" != "" ]]; then
    echo "[*] Querying SecurityTrails..."
    curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" \
        "https://api.securitytrails.com/v1/domain/$DOMAIN" \
        > "${ASSETS_DIR}/securitytrails_info.json"

    # Fetch subdomains from SecurityTrails
    curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" \
        "https://api.securitytrails.com/v1/domain/$DOMAIN/subdomains" \
        > "${ASSETS_DIR}/securitytrails_subdomains.json"
fi


# Log external intelligence results
add_section "EXTERNAL INTELLIGENCE & DORKING RESULTS" "true"
if [[ -s "$SHODAN_RESULTS" ]]; then
    echo "=== Shodan Intelligence ===" >> "$MAIN_RESULTS"
    cat "$SHODAN_RESULTS" >> "$MAIN_RESULTS"
    echo "" >> "$MAIN_RESULTS"
    
    echo "=== Shodan Intelligence ===" >> "$ALL_RESULTS"
    cat "$SHODAN_RESULTS" >> "$ALL_RESULTS"
    echo "" >> "$ALL_RESULTS"
fi

if [[ -s "${SCANS_DIR}/censys_info.json" ]]; then
    echo "=== Censys Intelligence (raw JSON) ===" >> "$ALL_RESULTS"
    cat "${SCANS_DIR}/censys_info.json" >> "$ALL_RESULTS"
    echo "" >> "$ALL_RESULTS"
fi

########################################
# 9) DOCKER & KUBERNETES SCANNING
########################################

echo
echo "[*] Step 15: Scanning for Docker & Kubernetes misconfigurations..."

# Detect Docker-related endpoints
DOCKER_K8S_WORDS=(
    # Docker general
    "docker"
    "dockerfile"
    "dockerfiles"
    "dockerfile.dev"
    "docker-compose"
    "compose"
    "docker-compose.yml"
    "docker-compose.yaml"
    "container"
    "containers"
    "image"
    "images"
    "registry"
    "docker-service"
    "docker-daemon"
    "docker-config"

    # Docker environments
    "docker/dev"
    "docker/test"
    "docker/stage"
    "docker/prod"

    # Docker components
    "build"
    "deploy"
    "volumes"
    "volume"
    "network"
    "networks"
    "env"
    "environment"
    "configs"
    "config"
    "secrets"

    # Kubernetes general
    "k8s"
    "kubernetes"
    "cluster"
    "clusters"
    "pod"
    "pods"
    "node"
    "nodes"
    "deployment"
    "deployments"
    "statefulset"
    "daemonset"
    "replicaset"
    "jobs"
    "cronjob"
    "rollout"

    # Kubernetes resources
    "namespace"
    "namespaces"
    "service"
    "services"
    "svc"
    "ingress"
    "ingresses"
    "configmap"
    "configmaps"
    "secret"
    "secrets"
    "persistentvolume"
    "persistentvolumeclaim"
    "storageclass"

    # Kubernetes manifests
    "deployment.yaml"
    "service.yaml"
    "ingress.yaml"
    "configmap.yaml"
    "secret.yaml"
    "pod.yaml"
    "statefulset.yaml"

    # Monitoring / Observability
    "metrics"
    "monitoring"
    "observability"
    "grafana"
    "prometheus"
    "loki"
    "jaeger"

    # DevOps CI/CD related to containers
    "docker-build"
    "container-build"
    "pipeline"
    "ci"
    "cd"
    "artifact"
    "artifacts"
)



> "${FINDINGS_DIR}/docker_findings.txt"
for pattern in "${DOCKER_PATTERNS[@]}"; do
    grep "$pattern" "${URLS_DIR}/urls_all.txt" 2>/dev/null >> "${FINDINGS_DIR}/docker_findings.txt" || true

done

# Detect Kubernetes-related endpoints and files
K8S_PATTERNS=(
    # Kubernetes keywords
    "kubernetes"
    "k8s"
    "kube"
    "kubeconfig"
    "kube-system"
    "kubelet"
    "kube-proxy"
    "kubeadm"

    # API / manifests
    "apiVersion:"
    "kind:"
    "metadata:"
    "spec:"
    "containers:"
    "initContainers:"
    "volumes:"
    "volumeMounts:"
    "serviceAccount"
    "serviceAccountName"

    # Kubernetes resources
    "Deployment"
    "StatefulSet"
    "DaemonSet"
    "ReplicaSet"
    "Job"
    "CronJob"
    "Pod"
    "Namespace"
    "Service"
    "Ingress"
    "ConfigMap"
    "Secret"
    "PersistentVolume"
    "PersistentVolumeClaim"
    "StorageClass"

    # Manifest filenames
    "deployment.yaml"
    "deployment.yml"
    "service.yaml"
    "ingress.yaml"
    "configmap.yaml"
    "secret.yaml"
    "statefulset.yaml"
    "pod.yaml"
    "kustomization.yaml"

    # Helm charts
    "Chart.yaml"
    "values.yaml"
    "templates/"
    "helm"
    "helmfile"

    # Operators / CRDs
    "CustomResourceDefinition"
    "crd"
    "operator"
    "controller"
    "reconciler"

    # Observability & dashboard
    "kubernetes dashboard"
    "prometheus"
    "grafana"
    "metrics-server"
    "metrics.k8s.io"

    # DevOps infra
    "k8s-dev"
    "k8s-staging"
    "k8s-prod"
    "dev-cluster"
    "test-cluster"
    "prod-cluster"
)


> "${FINDINGS_DIR}/kubernetes_findings.txt"
for pattern in "${K8S_PATTERNS[@]}"; do
    grep -r "$pattern" "${URLS_DIR}/urls_all.txt" 2>/dev/null >> "${FINDINGS_DIR}/kubernetes_findings.txt" || true
done

# Log infrastructure-related findings
add_section "INFRASTRUCTURE FINDINGS" "true"
if [[ -s "${FINDINGS_DIR}/docker_findings.txt" ]]; then
    echo "=== Docker Misconfigurations ===" >> "$MAIN_RESULTS"
    cat "${FINDINGS_DIR}/docker_findings.txt" >> "$MAIN_RESULTS"
    echo "" >> "$MAIN_RESULTS"
    
    echo "=== Docker Misconfigurations ===" >> "$ALL_RESULTS"
    cat "${FINDINGS_DIR}/docker_findings.txt" >> "$ALL_RESULTS"
    echo "" >> "$ALL_RESULTS"
fi

if [[ -s "${FINDINGS_DIR}/kubernetes_findings.txt" ]]; then
    echo "=== Kubernetes Misconfigurations ===" >> "$MAIN_RESULTS"
    cat "${FINDINGS_DIR}/kubernetes_findings.txt" >> "$MAIN_RESULTS"
    echo "" >> "$MAIN_RESULTS"
    
    echo "=== Kubernetes Misconfigurations ===" >> "$ALL_RESULTS"
    cat "${FINDINGS_DIR}/kubernetes_findings.txt" >> "$ALL_RESULTS"
    echo "" >> "$ALL_RESULTS"
fi

########################################
# 10) FINAL SUMMARY AND REPORT ORGANIZATION
########################################

echo
echo "[*] Step 16: Generating final reports..."

# Add headers to both main and all-results files
{
    echo "========================================"
    echo "         COMPREHENSIVE RECON REPORT"
    echo "                 Domain: $DOMAIN"
    echo "               Generated: $(date)"
    echo "========================================"
    echo ""
} | tee -a "$MAIN_RESULTS" "$ALL_RESULTS" >/dev/null

# Table of contents for main results
{
    echo "TABLE OF CONTENTS (Main Results)"
    echo "1. Live Subdomains"
    echo "2. Active URLs" 
    echo "3. JavaScript Files"
    echo "4. JS Endpoints"
    echo "5. JS Secrets/Tokens"
    echo "6. Sensitive Patterns & Endpoints"
    echo "7. Security Scan Results"
    echo "8. External Intelligence"
    echo "9. Infrastructure Findings"
    echo ""
    echo "========================================"
    echo ""
} >> "$MAIN_RESULTS"

# Table of contents for all results
{
    echo "TABLE OF CONTENTS (All Results)"
    echo "1. All Subdomains (Raw)"
    echo "2. Full HTTPX Results"
    echo "3. All Discovered URLs"
    echo "4. Live Subdomains"
    echo "5. Active URLs"
    echo "6. JavaScript Files"
    echo "7. JS Endpoints"
    echo "8. JS Secrets/Tokens"
    echo "9. Sensitive Patterns & Endpoints"
    echo "10. Security Scan Results"
    echo "11. External Intelligence"
    echo "12. Infrastructure Findings"
    echo ""
    echo "========================================"
    echo ""
} >> "$ALL_RESULTS"

# Display final statistics
MAIN_SIZE=$(du -h "$MAIN_RESULTS" | cut -f1)
ALL_SIZE=$(du -h "$ALL_RESULTS" | cut -f1)

echo
echo "========================================"
echo " RECON COMPLETED SUCCESSFULLY! THANKS MRK4Z1M0V"
echo "========================================"
echo " Domain: $DOMAIN"
echo " Output directory: $OUTDIR"
echo ""
echo " MAIN RESULTS: $MAIN_RESULTS"
echo "   - Size: $MAIN_SIZE"
echo "   - Contains: Filtered, relevant findings"
echo "   - Organized by category"
echo ""
echo " ALL RESULTS: $ALL_RESULTS"  
echo "   - Size: $ALL_SIZE"
echo "   - Contains: All raw data + findings"
echo "   - Comprehensive collection"
echo ""
echo " Summary:"
echo " - Subdomains: $SUBCOUNT total, $LIVECOUNT live"
echo " - URLs: $URLCOUNT discovered"
echo " - JS Files: $JSCOUNT found"
echo "========================================"
echo "[*] MRK4Z1M0V"
echo "========================================"
