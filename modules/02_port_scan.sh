#!/bin/bash
# ============================================================
# NetRecon — Module 02: Port Scanning
# Phase 2.1: TCP Top 1000
# Phase 2.2: Network Infrastructure Targeted Ports
# Phase 2.3: UDP Critical Ports
# ============================================================
# Performs comprehensive port enumeration with version detection.
# Rate-limited and timed per engagement parameters.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

load_config "ports.conf"
load_config "scan_tuning.conf"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ---- Phase 2.1: TCP Top 1000 ----
run_tcp_top1000() {
    local site=$1
    local timing=$(get_timing "$site")
    local hostfile=$(live_hosts_file "$site")
    local outdir="$(site_dir "$site")/nmap"

    if [ ! -s "$hostfile" ]; then
        warn "No live hosts for ${site^^} — skipping TCP top 1000"
        return
    fi

    local hostcount=$(wc -l < "$hostfile")
    log "Phase 2.1: TCP Top 1000 — ${site^^} (${hostcount} hosts)"

    mkdir -p "$outdir"

    timed_run "TCP top 1000 scan ${site^^}" \
        sudo nmap -sS -sV ${timing} --max-rate=${TCP_SCAN_RATE} --open \
        --top-ports 1000 \
        -iL "$hostfile" \
        -oA "${outdir}/tcp_top1000_${TIMESTAMP}"

    parse_nmap_summary "${outdir}/tcp_top1000_${TIMESTAMP}" \
        "${outdir}/tcp_top1000_SUMMARY.txt" \
        "TCP Top 1000 Ports — ${site^^}"

    success "Phase 2.1 complete for ${site^^}"
}

# ---- Phase 2.2: Network Infrastructure Ports ----
run_infra_ports() {
    local site=$1
    local timing=$(get_timing "$site")
    local hostfile=$(live_hosts_file "$site")
    local outdir="$(site_dir "$site")/nmap"

    if [ ! -s "$hostfile" ]; then
        warn "No live hosts for ${site^^} — skipping infrastructure ports"
        return
    fi

    local hostcount=$(wc -l < "$hostfile")
    log "Phase 2.2: Network Infrastructure Ports — ${site^^} (${hostcount} hosts)"

    mkdir -p "$outdir"

    timed_run "Infrastructure ports scan ${site^^}" \
        sudo nmap -sS -sV ${timing} --max-rate=${TCP_SCAN_RATE} --open \
        -p ${INFRA_TCP_PORTS} \
        -iL "$hostfile" \
        -oA "${outdir}/network_device_ports_${TIMESTAMP}"

    parse_nmap_summary "${outdir}/network_device_ports_${TIMESTAMP}" \
        "${outdir}/network_device_ports_SUMMARY.txt" \
        "Network Infrastructure Ports — ${site^^}"

    success "Phase 2.2 complete for ${site^^}"
}

# ---- Phase 2.3: UDP Critical Ports ----
run_udp_critical() {
    local site=$1
    local timing=$(get_timing "$site")
    local hostfile=$(live_hosts_file "$site")
    local outdir="$(site_dir "$site")/nmap"

    if [ ! -s "$hostfile" ]; then
        warn "No live hosts for ${site^^} — skipping UDP scan"
        return
    fi

    local hostcount=$(wc -l < "$hostfile")
    log "Phase 2.3: UDP Critical Ports — ${site^^} (${hostcount} hosts)"
    warn "UDP scans are slow. This may take a while..."

    mkdir -p "$outdir"

    timed_run "UDP critical ports scan ${site^^}" \
        sudo nmap -sU -sV ${timing} --max-rate=${UDP_SCAN_RATE} --open \
        -p ${CRITICAL_UDP_PORTS} \
        -iL "$hostfile" \
        -oA "${outdir}/udp_critical_${TIMESTAMP}"

    parse_nmap_summary "${outdir}/udp_critical_${TIMESTAMP}" \
        "${outdir}/udp_critical_SUMMARY.txt" \
        "UDP Critical Ports — ${site^^}"

    success "Phase 2.3 complete for ${site^^}"
}

# ---- Run all port scans for a site ----
run_port_scan() {
    local site=$1

    separator
    header "MODULE 02: PORT SCANNING — ${site^^}"

    run_tcp_top1000 "$site"
    run_infra_ports "$site"
    run_udp_critical "$site"

    separator
}

# Entry point
main() {
    require_tool "nmap" "apt install nmap" || exit 1

    local target="${1:-all}"
    validate_target_arg "$target" || exit 1

    header "NETRECON — Phase 2: Port Scanning"

    for_each_site "$target" run_port_scan

    echo ""
    success "Phase 2: Port Scanning complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [ -z "${ENGAGEMENT_DIR:-}" ]; then
        error "ENGAGEMENT_DIR not set. Run this module via netrecon.sh or set up first."
        exit 1
    fi
    main "$@"
fi
