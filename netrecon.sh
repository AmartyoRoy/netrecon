#!/bin/bash
# ============================================================
# NetRecon — Main Orchestrator
# Modular Internal Network Penetration Test Automation
# ============================================================
#
# USAGE:
#   ./netrecon.sh <command> [options]
#
# COMMANDS:
#   init <name>          Create a new engagement
#   resume <dir>         Resume an existing engagement
#   run <phase> [site]   Run a specific phase (1-7, or 'all')
#   status               Show engagement status
#   help                 Show this help
#
# EXAMPLES:
#   ./netrecon.sh init acme-internal
#   ./netrecon.sh run all
#   ./netrecon.sh run 2 hq
#   ./netrecon.sh run all --skip-phase6
#   ./netrecon.sh resume ./engagements/acme-internal_20260402/
#
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PROJECT_ROOT="$SCRIPT_DIR"

source "${SCRIPT_DIR}/lib/common.sh"

# ---- Argument Parsing ----
COMMAND="${1:-help}"
shift || true

SKIP_PHASE6=false
PHASE6_IFACE=""
PHASE6_DURATION=""
PHASE6_PACKETS=""
TARGET_SITE="all"
ENGAGEMENT_NAME=""
RESUME_DIR=""

parse_args() {
    for arg in "$@"; do
        case $arg in
            --skip-phase6)       SKIP_PHASE6=true ;;
            --phase6-interface=*) PHASE6_IFACE="${arg#*=}" ;;
            --phase6-duration=*)  PHASE6_DURATION="${arg#*=}" ;;
            --phase6-packets=*)   PHASE6_PACKETS="${arg#*=}" ;;
            -h|--help)            show_help; exit 0 ;;
            *)
                # First positional arg depends on command
                if [ -z "$ENGAGEMENT_NAME" ] && [ "$COMMAND" == "init" ]; then
                    ENGAGEMENT_NAME="$arg"
                elif [ -z "$RESUME_DIR" ] && [ "$COMMAND" == "resume" ]; then
                    RESUME_DIR="$arg"
                elif [[ "$arg" =~ ^[0-9]+$ ]] || [ "$arg" == "all" ]; then
                    # Could be phase number or site name
                    if [[ "$arg" =~ ^[0-9]+$ ]]; then
                        PHASE_NUM="$arg"
                    else
                        TARGET_SITE="$arg"
                    fi
                else
                    TARGET_SITE="$arg"
                fi
                ;;
        esac
    done
}

show_help() {
    echo ""
    echo -e "${BOLD}NetRecon — Internal Network Pentest Automation${NC}"
    echo ""
    echo "USAGE:"
    echo "  ./netrecon.sh <command> [options]"
    echo ""
    echo "COMMANDS:"
    echo "  init <name>            Create a new engagement"
    echo "  resume <dir>           Resume an existing engagement"
    echo "  run <phase> [site]     Run phase: 1,2,3,4,6,7,all"
    echo "  status                 Show engagement status"
    echo "  help                   Show this help"
    echo ""
    echo "OPTIONS:"
    echo "  --skip-phase6          Skip passive traffic capture"
    echo "  --phase6-interface=X   Capture interface (default: eth0)"
    echo "  --phase6-duration=X    Capture duration in seconds (default: 600)"
    echo ""
    echo "EXAMPLES:"
    echo "  ./netrecon.sh init mytest"
    echo "  ./netrecon.sh run all"
    echo "  ./netrecon.sh run 2 hq"
    echo "  ./netrecon.sh run all --skip-phase6"
    echo ""
}

show_banner() {
    echo ""
    echo -e "${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║   ${CYAN}NetRecon${NC}${BOLD} — Internal Network Pentest Automation         ║${NC}"
    echo -e "${BOLD}║   Non-intrusive • Modular • Rate-limited                  ║${NC}"
    echo -e "${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ---- Preflight ----
run_preflight_checks() {
    echo -e "${CYAN}[PREFLIGHT]${NC} Checking prerequisites..."

    # Check modules exist
    local modules_ok=true
    for m in 01_discovery 02_port_scan 03_snmp_enum 04_vuln_scan 06_protocol_analysis 07_report; do
        if [ -f "${MODULES_DIR}/${m}.sh" ]; then
            echo -e "${GREEN}  ✓${NC} ${m}.sh"
        else
            echo -e "${RED}  ✗${NC} ${m}.sh MISSING"
            modules_ok=false
        fi
    done

    # Check required tools
    echo ""
    echo -e "${CYAN}[PREFLIGHT]${NC} Checking tools..."
    for tool in nmap; do
        if check_tool "$tool"; then
            echo -e "${GREEN}  ✓${NC} ${tool}"
        else
            echo -e "${RED}  ✗${NC} ${tool} NOT FOUND (required)"
            return 1
        fi
    done
    for tool in tshark tcpdump onesixtyone snmpwalk ssh-audit snmp-check arp-scan; do
        if check_tool "$tool"; then
            echo -e "${GREEN}  ✓${NC} ${tool}"
        else
            echo -e "${YELLOW}  ⚠${NC} ${tool} (optional — will use fallbacks)"
        fi
    done

    # Check live hosts per site
    echo ""
    echo -e "${CYAN}[PREFLIGHT]${NC} Target sites..."
    for site in $(echo "${!TARGETS[@]}" | tr ' ' '\n' | sort); do
        local cidr=${TARGETS[$site]}
        if has_live_hosts "$site"; then
            local count=$(count_live_hosts "$site")
            echo -e "${GREEN}  ✓${NC} ${site^^} (${cidr}) — ${count} live hosts"
        else
            echo -e "${YELLOW}  ⚠${NC} ${site^^} (${cidr}) — no live hosts yet"
        fi
    done
    echo ""
}

# ---- Phase Runner ----
run_phase() {
    local phase=$1
    local target=$2
    local phase_start=$(date +%s)
    local phase_name=""
    local script=""

    case $phase in
        1) phase_name="Phase 1: Host Discovery";           script="01_discovery.sh" ;;
        2) phase_name="Phase 2: Port Scanning";             script="02_port_scan.sh" ;;
        3) phase_name="Phase 3: SNMP Enumeration";          script="03_snmp_enum.sh" ;;
        4) phase_name="Phase 4: Vulnerability Scanning";    script="04_vuln_scan.sh" ;;
        6) phase_name="Phase 6: Protocol Analysis";         script="06_protocol_analysis.sh" ;;
        7) phase_name="Phase 7: Report Generation";         script="07_report.sh" ;;
        *) error "Unknown phase: $phase"; return 1 ;;
    esac

    echo ""
    echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD} ${phase_name}${NC}"
    echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo ""

    local script_path="${MODULES_DIR}/${script}"
    if [ ! -f "$script_path" ]; then
        error "Module not found: ${script_path}"
        return 1
    fi

    # Build args for protocol analysis
    local extra_args=()
    if [ "$phase" == "6" ]; then
        [ -n "$PHASE6_IFACE" ] && extra_args+=("$PHASE6_IFACE")
        [ -n "$PHASE6_DURATION" ] && extra_args+=("$PHASE6_DURATION")
        [ -n "$PHASE6_PACKETS" ] && extra_args+=("$PHASE6_PACKETS")
        bash "$script_path" "${extra_args[@]}" 2>&1 | tee -a "${LOGFILE:-/dev/null}"
    elif [ "$phase" == "7" ]; then
        bash "$script_path" 2>&1 | tee -a "${LOGFILE:-/dev/null}"
    else
        bash "$script_path" "$target" 2>&1 | tee -a "${LOGFILE:-/dev/null}"
    fi

    local exit_code=${PIPESTATUS[0]}
    local phase_end=$(date +%s)
    local elapsed=$(( phase_end - phase_start ))
    local min=$(( elapsed / 60 ))
    local sec=$(( elapsed % 60 ))

    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}[OK]${NC} ${phase_name} completed in ${min}m ${sec}s"
    else
        echo -e "${RED}[FAIL]${NC} ${phase_name} failed (exit ${exit_code}) in ${min}m ${sec}s"
        if [ "${CONTINUE_ON_ERROR:-true}" == "true" ]; then
            echo -e "${YELLOW}Continuing with remaining phases...${NC}"
        else
            return $exit_code
        fi
    fi
}

# ---- Commands ----
cmd_init() {
    local name="${ENGAGEMENT_NAME:-engagement}"

    show_banner
    log "Initializing new engagement: ${name}"

    # Load targets
    load_targets || exit 1
    log "Loaded ${#TARGETS[@]} target site(s):"
    list_targets | while read -r line; do log "  $line"; done

    # Set up directory structure
    setup_engagement_dir "$name"

    echo ""
    success "Engagement ready! Next steps:"
    echo "  1. Run:  ./netrecon.sh resume ${ENGAGEMENT_DIR}"
    echo "  2. Then: ./netrecon.sh run all"
    echo ""
}

cmd_resume() {
    local dir="${RESUME_DIR}"

    if [ -z "$dir" ]; then
        # Find most recent engagement
        dir=$(ls -dt "${PROJECT_ROOT}/engagements/"*/ 2>/dev/null | head -1)
        if [ -z "$dir" ]; then
            error "No engagements found. Run './netrecon.sh init <name>' first."
            exit 1
        fi
        log "Auto-resuming most recent engagement: ${dir}"
    fi

    show_banner
    load_targets || exit 1
    use_engagement_dir "$dir"

    echo ""
    success "Engagement resumed: ${ENGAGEMENT_DIR}"
    echo "  Run: ./netrecon.sh run all"
    echo ""
}

cmd_run() {
    local phase="${PHASE_NUM:-all}"
    local target="$TARGET_SITE"

    show_banner

    # Ensure engagement is set up
    if [ -z "${ENGAGEMENT_DIR:-}" ] || [ ! -d "${ENGAGEMENT_DIR:-/nonexistent}" ]; then
        # Try auto-resume
        load_targets || exit 1
        local dir=$(ls -dt "${PROJECT_ROOT}/engagements/"*/ 2>/dev/null | head -1)
        if [ -n "$dir" ]; then
            use_engagement_dir "$dir"
        else
            error "No engagement found. Run './netrecon.sh init <name>' first."
            exit 1
        fi
    fi

    load_targets || exit 1

    echo -e "  Target:       ${GREEN}${target}${NC}"
    echo -e "  Phase:        ${phase}"
    echo -e "  Skip Phase 6: ${SKIP_PHASE6}"
    echo -e "  Engagement:   ${ENGAGEMENT_DIR}"
    echo ""

    run_preflight_checks

    echo -e "${BOLD}Starting in ${PREFLIGHT_WAIT:-5} seconds... Press Ctrl+C to abort.${NC}"
    sleep ${PREFLIGHT_WAIT:-5}

    local start_time=$(date +%s)

    if [ "$phase" == "all" ]; then
        run_phase 1 "$target"
        run_phase 2 "$target"
        run_phase 3 "$target"
        run_phase 4 "$target"

        # Phase 5 (WiFi) — always manual
        echo ""
        echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW} PHASE 5: WiFi Assessment — SKIPPED (requires manual run)${NC}"
        echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
        echo ""

        if [ "$SKIP_PHASE6" == "false" ]; then
            run_phase 6 "$target"
        else
            echo -e "${YELLOW} PHASE 6: Protocol Analysis — SKIPPED (--skip-phase6)${NC}"
        fi

        run_phase 7 "$target"
    else
        run_phase "$phase" "$target"
    fi

    # Final summary
    local end_time=$(date +%s)
    local total=$(( end_time - start_time ))
    local hours=$(( total / 3600 ))
    local mins=$(( (total % 3600) / 60 ))
    local secs=$(( total % 60 ))

    echo ""
    echo -e "${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║   ALL PHASES COMPLETE                                     ║${NC}"
    echo -e "${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Runtime:      ${hours}h ${mins}m ${secs}s"
    echo -e "  Engagement:   ${ENGAGEMENT_DIR}"
    echo -e "  Log:          ${LOGFILE:-N/A}"
    echo ""

    # List key output files
    echo -e "  ${BOLD}Key Output Files:${NC}"
    for site in $(echo "${!TARGETS[@]}" | tr ' ' '\n' | sort); do
        echo -e "  ${CYAN}${site^^}:${NC}"
        [ -f "$(site_dir "$site")/vulns/VULNERABILITY_SUMMARY.txt" ] && echo "    ├── vulns/VULNERABILITY_SUMMARY.txt"
        [ -f "$(site_dir "$site")/enum/SNMP_FINDINGS_SUMMARY.txt" ] && echo "    ├── enum/SNMP_FINDINGS_SUMMARY.txt"
        [ -f "$(site_dir "$site")/nmap/network_device_ports_SUMMARY.txt" ] && echo "    └── nmap/network_device_ports_SUMMARY.txt"
    done

    echo ""
    echo -e "  ${BOLD}Consolidated Reports:${NC}"
    ls -1t "${ENGAGEMENT_DIR}"/NETRECON_REPORT_*.txt 2>/dev/null | head -1 | while read f; do
        echo "    ├── $(basename "$f")"
    done
    ls -1t "${ENGAGEMENT_DIR}"/NETRECON_FINDINGS_*.csv 2>/dev/null | head -1 | while read f; do
        echo "    └── $(basename "$f")"
    done
    echo ""
    echo -e "${GREEN}Done! Review the report and customize before presenting.${NC}"
}

cmd_status() {
    show_banner
    load_targets || exit 1

    local dir=$(ls -dt "${PROJECT_ROOT}/engagements/"*/ 2>/dev/null | head -1)
    if [ -z "$dir" ]; then
        warn "No engagements found."
        return
    fi

    use_engagement_dir "$dir"

    echo -e "${BOLD}Engagement Status${NC}"
    echo ""

    for site in $(echo "${!TARGETS[@]}" | tr ' ' '\n' | sort); do
        local sd="$(site_dir "$site")"
        echo -e "  ${CYAN}${site^^}${NC} (${TARGETS[$site]})"

        # Discovery
        if has_live_hosts "$site"; then
            echo -e "    ${GREEN}✓${NC} Discovery:  $(count_live_hosts "$site") hosts"
        else
            echo -e "    ${RED}✗${NC} Discovery:  not run"
        fi

        # Port scan
        if ls "${sd}/nmap/tcp_top1000"*.gnmap &>/dev/null; then
            echo -e "    ${GREEN}✓${NC} Port Scan:  complete"
        else
            echo -e "    ${RED}✗${NC} Port Scan:  not run"
        fi

        # SNMP
        if [ -f "${sd}/enum/SNMP_FINDINGS_SUMMARY.txt" ]; then
            echo -e "    ${GREEN}✓${NC} SNMP Enum:  complete"
        else
            echo -e "    ${RED}✗${NC} SNMP Enum:  not run"
        fi

        # Vulns
        if [ -f "${sd}/vulns/VULNERABILITY_SUMMARY.txt" ]; then
            echo -e "    ${GREEN}✓${NC} Vuln Scan:  complete"
        else
            echo -e "    ${RED}✗${NC} Vuln Scan:  not run"
        fi

        echo ""
    done

    # Report
    if ls "${ENGAGEMENT_DIR}"/NETRECON_REPORT_*.txt &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Report generated"
    else
        echo -e "  ${RED}✗${NC} Report not yet generated"
    fi
    echo ""
}

# ---- Main Dispatch ----
parse_args "$@"

case $COMMAND in
    init)    cmd_init ;;
    resume)  cmd_resume ;;
    run)     cmd_run ;;
    status)  cmd_status ;;
    help|-h|--help) show_help ;;
    *)       error "Unknown command: $COMMAND"; show_help; exit 1 ;;
esac
