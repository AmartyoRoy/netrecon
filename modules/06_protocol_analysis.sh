#!/bin/bash
# ============================================================
# NetRecon — Module 06: Network Protocol Analysis
# Phase 6.1: Passive Traffic Capture
# Phase 6.2: Protocol Analysis with tshark
# ============================================================
# Phase 5 (WiFi) is left manual — requires physical adapter.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

load_config "scan_tuning.conf"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

CAPTURE_INTERFACE="${1:-${CAPTURE_INTERFACE:-eth0}}"
CAPTURE_DURATION="${2:-${CAPTURE_DURATION:-600}}"
CAPTURE_PACKET_LIMIT="${3:-${CAPTURE_PACKET_LIMIT:-200000}}"

build_capture_filter() {
    local filter=""
    for site in "${!TARGETS[@]}"; do
        local cidr=${TARGETS[$site]}
        [ -n "$filter" ] && filter="${filter} or net ${cidr}" || filter="net ${cidr}"
    done
    echo "$filter"
}

run_passive_capture() {
    header "MODULE 06: PASSIVE PROTOCOL ANALYSIS"
    log "Interface: ${CAPTURE_INTERFACE} | Duration: ${CAPTURE_DURATION}s | Max Packets: ${CAPTURE_PACKET_LIMIT}"

    EVIDENCE_DIR="${ENGAGEMENT_DIR}/evidence_${TIMESTAMP}"
    mkdir -p "$EVIDENCE_DIR"

    local capture_filter=$(build_capture_filter)
    FULL_PCAP="${EVIDENCE_DIR}/full_capture.pcap"

    log "Phase 6.1: Starting passive traffic capture..."
    sudo timeout ${CAPTURE_DURATION} tcpdump -i ${CAPTURE_INTERFACE} \
        -w "$FULL_PCAP" -c ${CAPTURE_PACKET_LIMIT} "${capture_filter}" \
        2>&1 | tee -a "${LOGFILE:-/dev/null}" &
    local full_pid=$!

    local insecure_pcap="${EVIDENCE_DIR}/insecure_protocols.pcap"
    sudo timeout ${CAPTURE_DURATION} tcpdump -i ${CAPTURE_INTERFACE} \
        -w "$insecure_pcap" 'port 23 or port 21 or port 69 or port 161 or port 514 or port 80' \
        2>&1 | tee -a "${LOGFILE:-/dev/null}" &
    local insecure_pid=$!

    log "Captures running (PIDs: ${full_pid}, ${insecure_pid}). Waiting ${CAPTURE_DURATION}s..."
    wait $full_pid 2>/dev/null || true
    wait $insecure_pid 2>/dev/null || true
    success "Passive capture complete"
}

run_protocol_analysis() {
    require_tool "tshark" "apt install tshark" || return 1
    log "Phase 6.2: Protocol Analysis"
    local ad="${EVIDENCE_DIR}/analysis"
    mkdir -p "$ad"

    log "  [6.2.1] Cleartext protocols..."
    tshark -r "$FULL_PCAP" -Y "telnet or ftp or http.request or snmp" \
        -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info \
        -E header=y -E separator='|' 2>/dev/null > "${ad}/cleartext_protocols.txt" || true

    log "  [6.2.2] DTP frames..."
    tshark -r "$FULL_PCAP" -Y "dtp" \
        -T fields -e frame.number -e eth.src -e dtp.tlv_type -e _ws.col.Info \
        -E header=y -E separator='|' 2>/dev/null > "${ad}/dtp_frames.txt" || true

    log "  [6.2.3] STP frames..."
    tshark -r "$FULL_PCAP" -Y "stp" \
        -T fields -e frame.number -e eth.src -e stp.root.hw -e stp.bridge.hw -e stp.root.cost \
        -E header=y -E separator='|' 2>/dev/null > "${ad}/stp_frames.txt" || true

    log "  [6.2.4] CDP/LLDP frames..."
    tshark -r "$FULL_PCAP" -Y "cdp or lldp" \
        -T fields -e frame.number -e eth.src -e cdp.deviceid -e cdp.platform \
        -e cdp.software_version -e cdp.portid -e lldp.tlv.system.name -e lldp.tlv.system.desc \
        -E header=y -E separator='|' 2>/dev/null > "${ad}/cdp_lldp_info.txt" || true

    log "  [6.2.5] HSRP/VRRP frames..."
    tshark -r "$FULL_PCAP" -Y "hsrp or vrrp" \
        -T fields -e frame.number -e ip.src -e ip.dst -e hsrp.state -e hsrp.auth_data \
        -e vrrp.auth_type -e _ws.col.Info \
        -E header=y -E separator='|' 2>/dev/null > "${ad}/fhrp_frames.txt" || true

    log "  [6.2.6] DHCP traffic..."
    tshark -r "$FULL_PCAP" -Y "dhcp" \
        -T fields -e frame.number -e eth.src -e dhcp.type -e dhcp.ip.your \
        -e dhcp.option.dhcp_server_id -e dhcp.option.domain_name \
        -E header=y -E separator='|' 2>/dev/null > "${ad}/dhcp_traffic.txt" || true

    log "  [6.2.7] Credential leakage..."
    tshark -r "$FULL_PCAP" \
        -Y "http.authorization or ftp.request.command == USER or ftp.request.command == PASS or telnet" \
        -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info \
        -E header=y -E separator='|' 2>/dev/null > "${ad}/potential_credentials.txt" || true

    log "  [6.2.8] Protocol distribution..."
    tshark -r "$FULL_PCAP" -z io,phs -q 2>/dev/null > "${ad}/protocol_hierarchy.txt" || true

    log "  [6.2.9] Conversation stats..."
    tshark -r "$FULL_PCAP" -z conv,ip -q 2>/dev/null > "${ad}/ip_conversations.txt" || true
}

# Helper: count lines in file, default 0
_fc() { wc -l < "$1" 2>/dev/null || echo "0"; }

generate_protocol_summary() {
    local s="${EVIDENCE_DIR}/PROTOCOL_ANALYSIS_SUMMARY.txt"
    local ad="${EVIDENCE_DIR}/analysis"
    {
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║  NETWORK PROTOCOL ANALYSIS FINDINGS"
        echo "║  Interface: ${CAPTURE_INTERFACE} | Duration: ${CAPTURE_DURATION}s"
        echo "║  Generated: $(date)"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo ""
        local checks=("cleartext_protocols.txt:🔴 CLEARTEXT PROTOCOL TRAFFIC"
                       "dtp_frames.txt:🟡 DTP FRAMES (VLAN Hopping Risk)"
                       "cdp_lldp_info.txt:🟡 CDP/LLDP DEVICE INFO LEAKAGE"
                       "fhrp_frames.txt:🟡 HSRP/VRRP (First-Hop Redundancy)"
                       "stp_frames.txt:ℹ  SPANNING TREE PROTOCOL"
                       "potential_credentials.txt:🔴 POTENTIAL CREDENTIAL LEAKAGE")
        for entry in "${checks[@]}"; do
            local file="${entry%%:*}"
            local title="${entry#*:}"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "$title"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            local c=$(_fc "${ad}/${file}")
            if [ "$c" -gt 1 ]; then
                echo "  ⚠ ${c} frames captured. Details: analysis/${file}"
                head -20 "${ad}/${file}"
            else
                echo "  ✓ None observed"
            fi
            echo ""
        done
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "📊 PROTOCOL DISTRIBUTION"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        cat "${ad}/protocol_hierarchy.txt" 2>/dev/null || echo "  (not available)"
        echo ""
    } > "$s"
    success "Protocol analysis summary: ${s}"

    log "Distributing evidence to per-site directories..."
    for site in "${!TARGETS[@]}"; do
        local se="$(site_dir "$site")/evidence"
        mkdir -p "$se"
        cp -r "${EVIDENCE_DIR}/analysis" "$se/" 2>/dev/null || true
        cp "$s" "$se/" 2>/dev/null || true
    done
}

main() {
    require_tool "tcpdump" "apt install tcpdump" || exit 1
    header "NETRECON — Phase 6: Passive Protocol Analysis"
    run_passive_capture
    run_protocol_analysis
    generate_protocol_summary
    echo ""
    success "Phase 6: Protocol Analysis complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    [ -z "${ENGAGEMENT_DIR:-}" ] && { error "ENGAGEMENT_DIR not set."; exit 1; }
    main "$@"
fi
