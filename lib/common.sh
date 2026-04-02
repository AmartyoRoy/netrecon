#!/bin/bash
# ============================================================
# NetRecon — Common Library
# Shared functions used by all modules
# ============================================================
# Sourced by modules, not executed directly.
# ============================================================

# Prevent double-sourcing
[[ -n "${_NETRECON_COMMON_LOADED:-}" ]] && return 0
_NETRECON_COMMON_LOADED=1

# ---- Color Codes ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ---- Logging Functions ----
_log_ts() { echo -e "${DIM}$(date '+%Y-%m-%d %H:%M:%S')${NC}"; }

log()     { echo -e "$(_log_ts) ${CYAN}[INFO]${NC}  $1" | tee -a "${LOGFILE:-/dev/null}"; }
warn()    { echo -e "$(_log_ts) ${YELLOW}[WARN]${NC}  $1" | tee -a "${LOGFILE:-/dev/null}"; }
success() { echo -e "$(_log_ts) ${GREEN}[OK]${NC}    $1" | tee -a "${LOGFILE:-/dev/null}"; }
error()   { echo -e "$(_log_ts) ${RED}[ERROR]${NC} $1" | tee -a "${LOGFILE:-/dev/null}"; }
header()  { echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}" | tee -a "${LOGFILE:-/dev/null}"
            echo -e "${BOLD} $1${NC}" | tee -a "${LOGFILE:-/dev/null}"
            echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}\n" | tee -a "${LOGFILE:-/dev/null}"; }
separator() { echo -e "${DIM}───────────────────────────────────────────────────────────${NC}" | tee -a "${LOGFILE:-/dev/null}"; }

# ---- Directory Resolution ----
# Find project root (where netrecon.sh lives)
find_project_root() {
    local dir="$(cd "$(dirname "${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}")" && pwd)"
    while [ "$dir" != "/" ]; do
        [ -f "${dir}/netrecon.sh" ] && { echo "$dir"; return 0; }
        dir="$(dirname "$dir")"
    done
    echo "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
}

PROJECT_ROOT="${PROJECT_ROOT:-$(find_project_root)}"
CONFIG_DIR="${PROJECT_ROOT}/config"
MODULES_DIR="${PROJECT_ROOT}/modules"
LIB_DIR="${PROJECT_ROOT}/lib"

# ---- Configuration Loading ----
load_config() {
    local config_file="$1"
    if [ -f "${CONFIG_DIR}/${config_file}" ]; then
        source "${CONFIG_DIR}/${config_file}"
        return 0
    else
        warn "Config file not found: ${config_file}"
        return 1
    fi
}

# ---- Target Loading ----
# Loads targets from config/targets.conf into associative array TARGETS
declare -gA TARGETS
load_targets() {
    local targets_file="${CONFIG_DIR}/targets.conf"

    if [ ! -f "$targets_file" ]; then
        error "Targets file not found: ${targets_file}"
        error "Copy config/targets.conf.example to config/targets.conf and define your targets."
        return 1
    fi

    while IFS='=' read -r site cidr; do
        # Skip comments and empty lines
        [[ "$site" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$site" ]] && continue
        site=$(echo "$site" | tr -d '[:space:]')
        cidr=$(echo "$cidr" | tr -d '[:space:]')
        [[ -z "$site" || -z "$cidr" ]] && continue

        # Validate CIDR format
        if [[ "$cidr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            TARGETS["$site"]="$cidr"
        else
            warn "Invalid CIDR format for site '${site}': ${cidr} — skipping"
        fi
    done < "$targets_file"

    if [ ${#TARGETS[@]} -eq 0 ]; then
        error "No valid targets found in ${targets_file}"
        return 1
    fi

    return 0
}

# List all loaded target sites
list_targets() {
    for site in "${!TARGETS[@]}"; do
        echo "${site}=${TARGETS[$site]}"
    done | sort
}

# Get CIDR for a specific site
get_cidr() {
    local site=$1
    echo "${TARGETS[$site]:-}"
}

# ---- Engagement Directory ----
# Sets up output directory for current engagement
ENGAGEMENT_DIR=""
setup_engagement_dir() {
    local name="${1:-engagement}"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    ENGAGEMENT_DIR="${PROJECT_ROOT}/engagements/${name}_${timestamp}"

    mkdir -p "$ENGAGEMENT_DIR"

    # Create per-site subdirectories
    for site in "${!TARGETS[@]}"; do
        mkdir -p "${ENGAGEMENT_DIR}/${site}"/{nmap,enum,vulns,evidence}
    done

    # Store engagement metadata
    cat > "${ENGAGEMENT_DIR}/metadata.txt" << EOF
Engagement: ${name}
Started: $(date)
Operator: $(whoami)@$(hostname)
Source IP: $(ip -4 addr show 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}' || echo "unknown")
Targets:
$(list_targets | sed 's/^/  /')
EOF

    LOGFILE="${ENGAGEMENT_DIR}/netrecon.log"
    export ENGAGEMENT_DIR LOGFILE

    success "Engagement directory: ${ENGAGEMENT_DIR}"
    return 0
}

# Use an existing engagement directory (for resuming)
use_engagement_dir() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        error "Engagement directory not found: ${dir}"
        return 1
    fi
    ENGAGEMENT_DIR="$dir"
    LOGFILE="${ENGAGEMENT_DIR}/netrecon.log"
    export ENGAGEMENT_DIR LOGFILE

    # Ensure per-site dirs exist
    for site in "${!TARGETS[@]}"; do
        mkdir -p "${ENGAGEMENT_DIR}/${site}"/{nmap,enum,vulns,evidence}
    done

    log "Resuming engagement: ${ENGAGEMENT_DIR}"
    return 0
}

# ---- Helper Functions ----

# Get site output directory
site_dir() {
    local site=$1
    echo "${ENGAGEMENT_DIR}/${site}"
}

# Get live hosts file for a site
live_hosts_file() {
    local site=$1
    echo "${ENGAGEMENT_DIR}/${site}/live_hosts.txt"
}

# Count live hosts for a site
count_live_hosts() {
    local site=$1
    local hostfile=$(live_hosts_file "$site")
    if [ -s "$hostfile" ]; then
        wc -l < "$hostfile"
    else
        echo "0"
    fi
}

# Check if a site has live hosts
has_live_hosts() {
    local site=$1
    local hostfile=$(live_hosts_file "$site")
    [ -s "$hostfile" ]
}

# Get nmap timing for a site (can be overridden per-site)
get_timing() {
    local site=$1
    # Check if site-specific timing is set
    local var="TIMING_${site^^}"
    if [ -n "${!var:-}" ]; then
        echo "${!var}"
    else
        echo "${DEFAULT_TIMING:--T3}"
    fi
}

# Check if a command/tool exists
check_tool() {
    local tool=$1
    command -v "$tool" &>/dev/null
}

# Require a tool (exit if missing)
require_tool() {
    local tool=$1
    local install_hint="${2:-}"
    if ! check_tool "$tool"; then
        error "Required tool not found: ${tool}"
        [ -n "$install_hint" ] && error "Install with: ${install_hint}"
        return 1
    fi
}

# Run a command with timing info
timed_run() {
    local description="$1"
    shift
    local start=$(date +%s)
    log "Starting: ${description}"

    "$@"
    local exit_code=$?

    local end=$(date +%s)
    local elapsed=$(( end - start ))
    local min=$(( elapsed / 60 ))
    local sec=$(( elapsed % 60 ))

    if [ $exit_code -eq 0 ]; then
        success "${description} completed in ${min}m ${sec}s"
    else
        warn "${description} finished with exit code ${exit_code} in ${min}m ${sec}s"
    fi

    return $exit_code
}

# ---- Nmap Output Parsing ----

# Extract live hosts from gnmap file
extract_hosts_gnmap() {
    local gnmap_file=$1
    if [ -f "$gnmap_file" ]; then
        grep "Status: Up" "$gnmap_file" | awk '{print $2}' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n
    fi
}

# Extract hosts with specific port open from gnmap
extract_hosts_with_port() {
    local gnmap_file=$1
    local port=$2
    if [ -f "$gnmap_file" ]; then
        grep "${port}/open" "$gnmap_file" | awk '{print $2}' | sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n
    fi
}

# Parse nmap output into a readable per-host summary
parse_nmap_summary() {
    local nmap_base=$1   # Base path without extension
    local output=$2      # Output file
    local title=$3       # Section title

    {
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║  ${title}"
        echo "║  Generated: $(date)"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo ""

        if [ -f "${nmap_base}.gnmap" ]; then
            echo "--- OPEN PORTS PER HOST ---"
            echo ""
            grep "Ports:" "${nmap_base}.gnmap" | while IFS= read -r line; do
                local ip=$(echo "$line" | awk '{print $2}')
                echo "Host: ${ip}"
                echo "  PORT      STATE   SERVICE          VERSION"
                echo "$line" | sed 's/.*Ports: //' | tr ',' '\n' | \
                    awk -F'/' '{printf "  %-9s %-7s %-16s %s\n", $1, $3, $5, $7}'
                echo ""
            done

            local total=$(grep -c "^Host:" "${nmap_base}.gnmap" 2>/dev/null || echo "0")
            local with_ports=$(grep -c "Ports:" "${nmap_base}.gnmap" 2>/dev/null || echo "0")
            echo "--- STATISTICS ---"
            echo "Total hosts scanned: ${total}"
            echo "Hosts with open ports: ${with_ports}"
        else
            echo "(no gnmap output file found)"
        fi
        echo ""
    } > "$output"
}

# ---- Validation ----

# Validate site name exists in targets
validate_site() {
    local site=$1
    if [[ -v "TARGETS[$site]" ]]; then
        return 0
    else
        error "Unknown site: ${site}. Available: ${!TARGETS[*]}"
        return 1
    fi
}

# Validate target_site argument (site name or 'all')
validate_target_arg() {
    local target=$1
    if [ "$target" == "all" ]; then
        return 0
    else
        validate_site "$target"
    fi
}

# Iterate over target sites (handles 'all' or specific site)
for_each_site() {
    local target=$1
    local fn=$2

    if [[ "$target" == "all" ]]; then
        local sorted_sites
        mapfile -t sorted_sites < <(printf '%s\n' "${!TARGETS[@]}" | sort)
        for site in "${sorted_sites[@]}"; do
            "$fn" "$site"
        done
    else
        "$fn" "$target"
    fi
}

# ---- Preflight Check Template ----
run_preflight() {
    local module_name=$1
    shift
    local required_tools=("$@")

    header "PREFLIGHT: ${module_name}"

    # Check engagement dir
    if [ -z "$ENGAGEMENT_DIR" ] || [ ! -d "$ENGAGEMENT_DIR" ]; then
        error "No engagement directory set. Run setup first."
        return 1
    fi
    success "Engagement dir: ${ENGAGEMENT_DIR}"

    # Check required tools
    local tools_ok=true
    for tool in "${required_tools[@]}"; do
        if check_tool "$tool"; then
            success "Tool found: ${tool}"
        else
            error "Tool missing: ${tool}"
            tools_ok=false
        fi
    done

    if [ "$tools_ok" = false ]; then
        error "Missing required tools. Install them and retry."
        return 1
    fi

    return 0
}
