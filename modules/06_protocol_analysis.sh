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

# ---- Aggressive: Active Protocol Probing ----
run_aggressive_protocol_checks() {
    if ! is_aggressive; then
        return
    fi

    require_tool "tshark" "apt install tshark" || return 1
    log "Phase 6.3 [AGGRESSIVE]: Active Protocol Analysis"
    local ad="${EVIDENCE_DIR}/analysis"

    # LLMNR / NBNS / mDNS — name resolution poisoning vectors
    log "  [6.3.1] LLMNR/NBNS/mDNS poisoning vectors..."
    tshark -r "$FULL_PCAP" -Y "llmnr or nbns or mdns" \
        -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol \
        -e dns.qry.name -e _ws.col.Info \
        -E header=y -E separator='|' 2>/dev/null > "${ad}/llmnr_nbns_mdns.txt" || true

    # WPAD detection
    log "  [6.3.2] WPAD broadcast detection..."
    tshark -r "$FULL_PCAP" -Y "dns.qry.name contains \"wpad\" or http.host contains \"wpad\"" \
        -T fields -e frame.number -e ip.src -e ip.dst -e dns.qry.name -e http.host \
        -E header=y -E separator='|' 2>/dev/null > "${ad}/wpad_detection.txt" || true

    # ARP anomalies (gratuitous ARP, ARP storms, duplicate IPs)
    log "  [6.3.3] ARP anomaly detection..."
    tshark -r "$FULL_PCAP" -Y "arp.duplicate-address-detected or arp.opcode == 2" \
        -T fields -e frame.number -e arp.src.hw_mac -e arp.src.proto_ipv4 \
        -e arp.dst.proto_ipv4 -e _ws.col.Info \
        -E header=y -E separator='|' 2>/dev/null > "${ad}/arp_anomalies.txt" || true

    # DTP VLAN hopping feasibility
    log "  [6.3.4] DTP VLAN hopping feasibility..."
    local dtp_count=$(_fc "${ad}/dtp_frames.txt")
    if [[ "$dtp_count" -gt 1 ]]; then
        warn "DTP frames detected — VLAN hopping may be feasible"
        echo "⚠ DTP frames detected (${dtp_count} frames). Trunk negotiation is possible." \
            > "${ad}/vlan_hopping_feasibility.txt"
        echo "Recommendation: Enable 'switchport nonegotiate' on all access ports." \
            >> "${ad}/vlan_hopping_feasibility.txt"
    fi

    # SNMPv1/v2c cleartext community strings in traffic
    log "  [6.3.5] SNMP cleartext community strings in traffic..."
    tshark -r "$FULL_PCAP" -Y "snmp" \
        -T fields -e frame.number -e ip.src -e ip.dst -e snmp.community \
        -E header=y -E separator='|' 2>/dev/null > "${ad}/snmp_cleartext.txt" || true

    success "Phase 6.3 aggressive protocol analysis complete"
}

# ---- Update summary for aggressive findings ----
append_aggressive_summary() {
    if ! is_aggressive; then
        return
    fi

    local s="${EVIDENCE_DIR}/PROTOCOL_ANALYSIS_SUMMARY.txt"
    local ad="${EVIDENCE_DIR}/analysis"

    {
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🔴 AGGRESSIVE MODE — ADDITIONAL FINDINGS"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""

        local aggressive_checks=(
            "llmnr_nbns_mdns.txt:🔴 LLMNR/NBNS/mDNS POISONING VECTORS"
            "wpad_detection.txt:🔴 WPAD BROADCAST DETECTION"
            "arp_anomalies.txt:🟡 ARP ANOMALIES"
            "snmp_cleartext.txt:🟡 SNMP CLEARTEXT COMMUNITIES IN TRAFFIC"
            "vlan_hopping_feasibility.txt:🔴 VLAN HOPPING FEASIBILITY"
        )
        for entry in "${aggressive_checks[@]}"; do
            local file="${entry%%:*}"
            local title="${entry#*:}"
            echo "$title:"
            local c=$(_fc "${ad}/${file}")
            if [[ "$c" -gt 1 ]]; then
                echo "  ⚠ ${c} events captured. Details: analysis/${file}"
                head -10 "${ad}/${file}" 2>/dev/null | sed 's/^/  /'
            elif [[ -s "${ad}/${file}" ]]; then
                cat "${ad}/${file}" | sed 's/^/  /'
            else
                echo "  ✓ None observed"
            fi
            echo ""
        done
    } >> "$s"
}

main() {
    require_tool "tcpdump" "apt install tcpdump" || exit 1
    if is_aggressive; then
        header "NETRECON — Phase 6: Protocol Analysis [AGGRESSIVE]"
    else
        header "NETRECON — Phase 6: Passive Protocol Analysis"
    fi
    run_passive_capture
    run_protocol_analysis
    generate_protocol_summary
    run_aggressive_protocol_checks
    append_aggressive_summary
    echo ""
    success "Phase 6: Protocol Analysis complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    [ -z "${ENGAGEMENT_DIR:-}" ] && { error "ENGAGEMENT_DIR not set."; exit 1; }
    main "$@"
fi
