#!/bin/bash
# ============================================================
# NetRecon — Module 01: Host Discovery
# Phase 1: ARP Scan, Ping Sweep, TCP SYN Probes
# ============================================================
# Discovers live hosts on target subnets using multiple methods
# for maximum coverage. Results are stored in live_hosts.txt
# per site for use by all subsequent modules.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

# Load configurations
load_config "ports.conf"
load_config "scan_tuning.conf"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ---- Phase 1.1: ARP Scan (local subnets only) ----
run_arp_discovery() {
    local site=$1
    local cidr=$(get_cidr "$site")

    if ! has_live_hosts "$site" || [ "${FORCE_RESCAN:-false}" == "true" ]; then
        log "Phase 1.1: ARP Discovery — ${site^^} (${cidr})"
    else
        log "Skipping ARP discovery for ${site^^} — live_hosts.txt already exists (use FORCE_RESCAN=true to override)"
        return 0
    fi

    local outdir="$(site_dir "$site")/nmap"
    mkdir -p "$outdir"

    # ARP scan is Layer 2 only — fast and reliable on local subnets
    if check_tool "arp-scan"; then
        log "  Running arp-scan on ${cidr}..."
        timed_run "ARP scan ${site^^}" \
            sudo arp-scan --interface="${CAPTURE_INTERFACE:-eth0}" "$cidr" 2>&1 \
            | tee "${outdir}/arp_scan_${TIMESTAMP}.txt" \
            | tee -a "${LOGFILE:-/dev/null}"

        # Extract IPs from arp-scan output
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "${outdir}/arp_scan_${TIMESTAMP}.txt" \
            | sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n \
            >> "$(live_hosts_file "$site")" 2>/dev/null || true
    else
        warn "arp-scan not found — skipping Layer 2 discovery"
    fi
}

# ---- Phase 1.2: ICMP + TCP SYN Ping Sweep ----
run_ping_sweep() {
    local site=$1
    local cidr=$(get_cidr "$site")
    local timing=$(get_timing "$site")
    local outdir="$(site_dir "$site")/nmap"

    mkdir -p "$outdir"
    log "Phase 1.2: Nmap Host Discovery — ${site^^} (${cidr})"

    # Combined discovery: ICMP echo + TCP SYN on common ports + UDP probes
    timed_run "Host discovery ${site^^}" \
        sudo nmap -sn \
        -PE -PP -PM \
        -PS${DISCOVERY_TCP_PORTS} \
        -PU${DISCOVERY_UDP_PORTS} \
        ${timing} --max-rate=${DISCOVERY_RATE} \
        "$cidr" \
        -oA "${outdir}/host_discovery_${TIMESTAMP}"

    # Extract live hosts from gnmap
    if [ -f "${outdir}/host_discovery_${TIMESTAMP}.gnmap" ]; then
        extract_hosts_gnmap "${outdir}/host_discovery_${TIMESTAMP}.gnmap" \
            >> "$(live_hosts_file "$site")"
    fi
}

# ---- Consolidate and Deduplicate ----
consolidate_hosts() {
    local site=$1
    local hostfile=$(live_hosts_file "$site")

    if [ -s "$hostfile" ]; then
        # Deduplicate and sort numerically
        sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n "$hostfile" -o "$hostfile"
        local count=$(wc -l < "$hostfile")
        success "${site^^}: ${count} live hosts discovered"
    else
        warn "${site^^}: No live hosts found"
    fi
}

# ---- Discovery Summary ----
generate_discovery_summary() {
    local site=$1
    local summary="$(site_dir "$site")/nmap/DISCOVERY_SUMMARY.txt"

    {
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║  HOST DISCOVERY SUMMARY — ${site^^}"
        echo "║  Generated: $(date)"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo ""

        local hostfile=$(live_hosts_file "$site")
        if [ -s "$hostfile" ]; then
            local count=$(wc -l < "$hostfile")
            echo "Live hosts discovered: ${count}"
            echo ""
            echo "--- HOST LIST ---"
            cat "$hostfile"
        else
            echo "No live hosts discovered."
        fi
        echo ""
    } > "$summary"

    success "Discovery summary: ${summary}"
}

# ---- Aggressive: OS Detection ----
run_os_detection() {
    local site=$1
    local hostfile=$(live_hosts_file "$site")

    if [[ ! -s "$hostfile" ]]; then
        return
    fi

    if ! is_aggressive; then
        return
    fi

    local outdir="$(site_dir "$site")/nmap"
    local hostcount=$(wc -l < "$hostfile")
    log "Phase 1.3 [AGGRESSIVE]: OS Detection — ${site^^} (${hostcount} hosts)"

    timed_run "OS detection ${site^^}" \
        sudo nmap -O --osscan-guess \
        $(aggressive_timing "$site") --max-rate=$(aggressive_rate ${DISCOVERY_RATE}) \
        -iL "$hostfile" \
        -oA "${outdir}/os_detection_${TIMESTAMP}"

    success "OS detection complete for ${site^^}"
}

# ---- Main Execution ----
run_discovery() {
    local site=$1

    separator
    header "MODULE 01: HOST DISCOVERY — ${site^^}"

    # Clear previous live_hosts if force rescan
    if [[ "${FORCE_RESCAN:-false}" == "true" ]]; then
        > "$(live_hosts_file "$site")"
    fi

    run_arp_discovery "$site"
    run_ping_sweep "$site"
    consolidate_hosts "$site"
    run_os_detection "$site"
    generate_discovery_summary "$site"

    separator
}

# Entry point
main() {
    require_tool "nmap" "apt install nmap" || exit 1

    local target="${1:-all}"
    validate_target_arg "$target" || exit 1

    header "NETRECON — Phase 1: Host Discovery"

    for_each_site "$target" run_discovery

    echo ""
    success "Phase 1: Host Discovery complete"
}

# Only run main if executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [ -z "${ENGAGEMENT_DIR:-}" ]; then
        error "ENGAGEMENT_DIR not set. Run this module via netrecon.sh or set up first."
        exit 1
    fi
    main "$@"
fi
