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

load_config "ports.conf"
load_config "scan_tuning.conf"

# TARGETS must be loaded before this module runs.
# When invoked via orchestrator, load_targets is called in cmd_run.
# When invoked standalone, the caller must have exported TARGETS.
# Guard: if TARGETS is empty, attempt to load them.
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    load_targets || { error "Cannot proceed without targets."; exit 1; }
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Positional args ($1/$2/$3) are interface/duration/packets, NOT site name.
# The orchestrator passes these via extra_args (line 225-228 of netrecon.sh).
CAPTURE_INTERFACE="${1:-${CAPTURE_INTERFACE:-eth0}}"
CAPTURE_DURATION="${2:-${CAPTURE_DURATION:-600}}"
CAPTURE_PACKET_LIMIT="${3:-${CAPTURE_PACKET_LIMIT:-200000}}"
CAPTURE_MAX_SIZE_MB="${CAPTURE_MAX_SIZE_MB:-500}"

# ---- Interface Validation ----
validate_interface() {
    local iface="$1"
    if ! ip link show "$iface" &>/dev/null; then
        error "Interface '${iface}' not found. Available interfaces:"
        ip -o link show | awk -F': ' '{print "  " $2}' | tee -a "${LOGFILE:-/dev/null}"
        return 1
    fi
}

build_capture_filter() {
    local filter=""
    for site in "${!TARGETS[@]}"; do
        local cidr="${TARGETS[$site]}"
        [ -n "$filter" ] && filter="${filter} or net ${cidr}" || filter="net ${cidr}"
    done
    if [[ -z "$filter" ]]; then
        error "No targets loaded — cannot build capture filter. Aborting capture."
        return 1
    fi
    echo "$filter"
}

run_passive_capture() {
    header "MODULE 06: PASSIVE PROTOCOL ANALYSIS"
    log "Interface: ${CAPTURE_INTERFACE} | Duration: ${CAPTURE_DURATION}s | Max Packets: ${CAPTURE_PACKET_LIMIT}"

    validate_interface "${CAPTURE_INTERFACE}" || return 1

    EVIDENCE_DIR="${ENGAGEMENT_DIR}/evidence_${TIMESTAMP}"
    mkdir -p "$EVIDENCE_DIR"

    local capture_filter
    capture_filter=$(build_capture_filter) || return 1
    FULL_PCAP="${EVIDENCE_DIR}/full_capture.pcap"

    log "Phase 6.1: Starting passive traffic capture..."

    # tcpdump -C expects an integer (MB). Validate it.
    if ! [[ "${CAPTURE_MAX_SIZE_MB}" =~ ^[0-9]+$ ]]; then
        warn "CAPTURE_MAX_SIZE_MB='${CAPTURE_MAX_SIZE_MB}' is not a valid integer, defaulting to 500"
        CAPTURE_MAX_SIZE_MB=500
    fi

    # When -C is used, tcpdump appends a numeric suffix to the filename.
    # With -W 1, it creates: full_capture.pcap (no suffix for first file, or pcap0 on some versions).
    # To avoid confusion, we do NOT use -C/-W when size limit is 0 (disabled).
    local tcpdump_size_opts=()
    if [[ "${CAPTURE_MAX_SIZE_MB}" -gt 0 ]]; then
        tcpdump_size_opts=(-C "${CAPTURE_MAX_SIZE_MB}" -W 1)
    fi

    sudo timeout "${CAPTURE_DURATION}" tcpdump -i "${CAPTURE_INTERFACE}" \
        -w "$FULL_PCAP" -c "${CAPTURE_PACKET_LIMIT}" \
        "${tcpdump_size_opts[@]}" \
        "${capture_filter}" \
        2>>"${LOGFILE:-/dev/null}" &
    local full_pid=$!

    local insecure_pcap="${EVIDENCE_DIR}/insecure_protocols.pcap"
    local insecure_filter="(${capture_filter}) and (port 23 or port 21 or port 69 or port 161 or port 514 or port 80)"
    sudo timeout "${CAPTURE_DURATION}" tcpdump -i "${CAPTURE_INTERFACE}" \
        -w "$insecure_pcap" "${insecure_filter}" \
        2>>"${LOGFILE:-/dev/null}" &
    local insecure_pid=$!

    log "Captures running (PIDs: ${full_pid}, ${insecure_pid}). Waiting up to ${CAPTURE_DURATION}s..."

    # Progress indicator
    local elapsed=0
    local interval=30
    while kill -0 "$full_pid" 2>/dev/null && [[ $elapsed -lt $CAPTURE_DURATION ]]; do
        sleep $interval
        elapsed=$((elapsed + interval))
        # pcap might not exist yet if no matching traffic; guard with -f
        if [[ -f "$FULL_PCAP" ]]; then
            local pcap_size
            pcap_size=$(du -sh "$FULL_PCAP" 2>/dev/null | awk '{print $1}')
            log "  Capture progress: ${elapsed}/${CAPTURE_DURATION}s | PCAP size: ${pcap_size:-0B}"
        else
            log "  Capture progress: ${elapsed}/${CAPTURE_DURATION}s | PCAP size: 0B (no matching traffic yet)"
        fi
    done

    wait $full_pid 2>/dev/null || true
    wait $insecure_pid 2>/dev/null || true
    success "Passive capture complete"
}

run_protocol_analysis() {
    require_tool "tshark" "apt install tshark" || return 1

    if [[ ! -s "$FULL_PCAP" ]]; then
        warn "Capture file is empty or missing: ${FULL_PCAP}"
        warn "Skipping protocol analysis — check interface and permissions."
        return 1
    fi

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

# Count data lines in a tshark output file (subtracts header).
# For files that don't have a tshark header (e.g. rogue_dhcp_detection.txt,
# vlan_hopping_feasibility.txt), we check if the file was generated by tshark
# by looking for the separator character, but for simplicity we just subtract 1
# and floor at 0 — worst case we under-report by 1 for non-tshark files,
# which is harmless because those files use the -s (size) check path in the summary.
_fc() {
    if [[ ! -f "$1" ]]; then
        echo "0"
        return
    fi
    local total
    total=$(wc -l < "$1" 2>/dev/null || echo "0")
    # Strip leading whitespace that wc may produce on some systems
    total="${total// /}"
    total=$((total - 1))
    [[ $total -lt 0 ]] && total=0
    echo "$total"
}

generate_protocol_summary() {
    local s="${EVIDENCE_DIR}/PROTOCOL_ANALYSIS_SUMMARY.txt"
    local ad="${EVIDENCE_DIR}/analysis"

    # Guard: if analysis dir doesn't exist (capture failed + returned early),
    # generate a minimal summary noting the failure.
    if [[ ! -d "$ad" ]]; then
        {
            echo "╔════════════════════════════════════════════════════════════╗"
            echo "║  NETWORK PROTOCOL ANALYSIS FINDINGS"
            echo "║  Interface: ${CAPTURE_INTERFACE} | Duration: ${CAPTURE_DURATION}s"
            echo "║  Generated: $(date)"
            echo "╚════════════════════════════════════════════════════════════╝"
            echo ""
            echo "⚠ No analysis data — capture or analysis phase failed."
            echo "  Check the log for errors: ${LOGFILE:-N/A}"
        } > "$s"
        warn "Protocol analysis summary (empty): ${s}"
        return
    fi

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
                       "potential_credentials.txt:🔴 POTENTIAL CREDENTIAL LEAKAGE"
                       "dhcp_traffic.txt:ℹ  DHCP TRAFFIC")
        for entry in "${checks[@]}"; do
            local file="${entry%%:*}"
            local title="${entry#*:}"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "$title"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            if [[ ! -f "${ad}/${file}" ]]; then
                echo "  ✓ None observed (no data file)"
            else
                local c=$(_fc "${ad}/${file}")
                if [ "$c" -gt 0 ]; then
                    echo "  ⚠ ${c} frames captured. Details: analysis/${file}"
                    head -20 "${ad}/${file}"
                else
                    echo "  ✓ None observed"
                fi
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
        return 0
    fi

    require_tool "tshark" "apt install tshark" || return 1

    if [[ ! -s "$FULL_PCAP" ]]; then
        warn "No capture data for aggressive analysis — skipping"
        return 0
    fi

    log "Phase 6.3 [AGGRESSIVE]: Active Protocol Analysis"
    local ad="${EVIDENCE_DIR}/analysis"
    mkdir -p "$ad"

    # LLMNR / NBNS / mDNS — name resolution poisoning vectors
    log "  [6.3.1] LLMNR/NBNS/mDNS poisoning vectors..."
    tshark -r "$FULL_PCAP" -Y "llmnr or nbns or mdns" \
        -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol \
        -e dns.qry.name -e _ws.col.Info \
        -E header=y -E separator='|' 2>/dev/null > "${ad}/llmnr_nbns_mdns.txt" || true

    # WPAD detection
    log "  [6.3.2] WPAD broadcast detection..."
    tshark -r "$FULL_PCAP" -Y 'dns.qry.name contains "wpad" or http.host contains "wpad"' \
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
    if [[ "$dtp_count" -gt 0 ]]; then
        warn "DTP frames detected — VLAN hopping may be feasible"
        {
            echo "⚠ DTP frames detected (${dtp_count} frames). Trunk negotiation is possible."
            echo "Recommendation: Enable 'switchport nonegotiate' on all access ports."
        } > "${ad}/vlan_hopping_feasibility.txt"
    fi

    # SNMPv1/v2c cleartext community strings in traffic
    log "  [6.3.5] SNMP cleartext community strings in traffic..."
    tshark -r "$FULL_PCAP" -Y "snmp" \
        -T fields -e frame.number -e ip.src -e ip.dst -e snmp.community \
        -E header=y -E separator='|' 2>/dev/null > "${ad}/snmp_cleartext.txt" || true

    # Rogue DHCP server detection
    log "  [6.3.6] Rogue DHCP server detection..."
    tshark -r "$FULL_PCAP" -Y "dhcp.option.dhcp_server_id" \
        -T fields -e dhcp.option.dhcp_server_id \
        -E separator='|' 2>/dev/null | sort -u > "${ad}/dhcp_servers_unique.txt" || true

    # dhcp_servers_unique.txt has no tshark header (fields piped through sort -u),
    # so count lines directly — do NOT use _fc which subtracts 1.
    local dhcp_server_count=0
    if [[ -f "${ad}/dhcp_servers_unique.txt" ]]; then
        dhcp_server_count=$(wc -l < "${ad}/dhcp_servers_unique.txt" 2>/dev/null || echo "0")
        dhcp_server_count="${dhcp_server_count// /}"
    fi

    if [[ "$dhcp_server_count" -gt 1 ]]; then
        warn "Multiple DHCP servers detected (${dhcp_server_count}) — potential rogue DHCP!"
        {
            echo "⚠ Multiple DHCP servers detected on the network segment:"
            sed 's/^/  - /' < "${ad}/dhcp_servers_unique.txt"
            echo ""
            echo "Recommendation: Verify each server is authorized. Enable DHCP snooping."
        } > "${ad}/rogue_dhcp_detection.txt"
    elif [[ "$dhcp_server_count" -eq 1 ]]; then
        log "    Single DHCP server found: $(cat "${ad}/dhcp_servers_unique.txt")"
    else
        log "    No DHCP server IDs observed in capture."
    fi

    # IPv6 Router Advertisement / DHCPv6 analysis
    log "  [6.3.7] IPv6 RA/DHCPv6 analysis..."
    tshark -r "$FULL_PCAP" -Y "icmpv6.type == 134 or dhcpv6" \
        -T fields -e frame.number -e ipv6.src -e ipv6.dst -e _ws.col.Protocol -e _ws.col.Info \
        -E header=y -E separator='|' 2>/dev/null > "${ad}/ipv6_ra_dhcpv6.txt" || true
    local ipv6_count=$(_fc "${ad}/ipv6_ra_dhcpv6.txt")
    if [[ "$ipv6_count" -gt 0 ]]; then
        warn "IPv6 Router Advertisements or DHCPv6 detected (${ipv6_count} frames) — RA spoofing risk"
    fi

    success "Phase 6.3 aggressive protocol analysis complete"
}

# ---- Update summary for aggressive findings ----
append_aggressive_summary() {
    if ! is_aggressive; then
        return 0
    fi

    local s="${EVIDENCE_DIR}/PROTOCOL_ANALYSIS_SUMMARY.txt"
    local ad="${EVIDENCE_DIR}/analysis"

    # Guard: summary file must exist
    if [[ ! -f "$s" ]]; then
        warn "Summary file missing — cannot append aggressive findings"
        return 0
    fi

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
            "rogue_dhcp_detection.txt:🔴 ROGUE DHCP SERVER DETECTION"
            "ipv6_ra_dhcpv6.txt:🟡 IPv6 ROUTER ADVERTISEMENTS / DHCPv6"
        )
        for entry in "${aggressive_checks[@]}"; do
            local file="${entry%%:*}"
            local title="${entry#*:}"
            echo "$title:"
            if [[ ! -f "${ad}/${file}" ]]; then
                echo "  ✓ None observed"
            else
                local c=$(_fc "${ad}/${file}")
                if [[ "$c" -gt 0 ]]; then
                    echo "  ⚠ ${c} events captured. Details: analysis/${file}"
                    head -10 "${ad}/${file}" 2>/dev/null | sed 's/^/  /'
                elif [[ -s "${ad}/${file}" ]]; then
                    # File has content but _fc says 0 (non-tshark file like rogue_dhcp_detection.txt)
                    sed 's/^/  /' < "${ad}/${file}"
                else
                    echo "  ✓ None observed"
                fi
            fi
            echo ""
        done
    } >> "$s"
}

main() {
    require_tool "tcpdump" "apt install tcpdump" || exit 1

    # Phase 6 operates at the interface level, not per-site.
    # Accept but ignore target argument for orchestrator compatibility.

    if is_aggressive; then
        header "NETRECON — Phase 6: Protocol Analysis [AGGRESSIVE]"
    else
        header "NETRECON — Phase 6: Passive Protocol Analysis"
    fi

    run_passive_capture
    local capture_rc=$?

    # Even if capture returned non-zero (bad interface, empty filter), attempt
    # to generate a summary so the orchestrator's status check and report
    # module always find PROTOCOL_ANALYSIS_SUMMARY.txt.
    if [[ $capture_rc -ne 0 ]]; then
        warn "Capture phase failed (rc=${capture_rc}). Generating empty summary."
        EVIDENCE_DIR="${EVIDENCE_DIR:-${ENGAGEMENT_DIR}/evidence_${TIMESTAMP}}"
        mkdir -p "$EVIDENCE_DIR"
        FULL_PCAP="${FULL_PCAP:-${EVIDENCE_DIR}/full_capture.pcap}"
        generate_protocol_summary
        return $capture_rc
    fi

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
