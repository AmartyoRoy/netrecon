#!/bin/bash
# ============================================================
# NetRecon — Module 03: SNMP Enumeration
# Phase 3.1: Community String Discovery
# Phase 3.2: SNMP Walk (automated for discovered strings)
# ============================================================
# Tests default/common community strings against SNMP-responding
# hosts, then walks discovered strings for device intelligence.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

load_config "ports.conf"
load_config "scan_tuning.conf"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# SNMP OIDs for structured walks
declare -A SNMP_OIDS
SNMP_OIDS=(
    ["system"]="1.3.6.1.2.1.1"
    ["interfaces"]="1.3.6.1.2.1.2"
    ["arp_table"]="1.3.6.1.2.1.4.22"
    ["routing_table"]="1.3.6.1.2.1.4.21"
    ["vlans_cisco"]="1.3.6.1.4.1.9.9.46"
    ["ip_addresses"]="1.3.6.1.2.1.4.20"
    ["tcp_connections"]="1.3.6.1.2.1.6.13"
)

# ---- Extract SNMP-responding hosts from prior scans ----
extract_snmp_hosts() {
    local site=$1
    local snmp_hosts_file="$(site_dir "$site")/enum/snmp_hosts.txt"
    mkdir -p "$(site_dir "$site")/enum"

    > "$snmp_hosts_file"

    # From UDP scan results
    for f in "$(site_dir "$site")/nmap/udp_critical"*.nmap; do
        [ -f "$f" ] && grep -B10 "161/open" "$f" 2>/dev/null \
            | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "$snmp_hosts_file" 2>/dev/null || true
    done

    # From network device ports scan
    for f in "$(site_dir "$site")/nmap/network_device_ports"*.nmap; do
        [ -f "$f" ] && grep -B10 "161/open" "$f" 2>/dev/null \
            | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "$snmp_hosts_file" 2>/dev/null || true
    done

    # From TCP top 1000
    for f in "$(site_dir "$site")/nmap/tcp_top1000"*.nmap; do
        [ -f "$f" ] && grep -B10 "161/open" "$f" 2>/dev/null \
            | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "$snmp_hosts_file" 2>/dev/null || true
    done

    # Deduplicate
    if [ -s "$snmp_hosts_file" ]; then
        sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n "$snmp_hosts_file" -o "$snmp_hosts_file"
    fi

    # Fallback: try all live hosts if no SNMP-specific hosts found
    if [ ! -s "$snmp_hosts_file" ]; then
        if has_live_hosts "$site"; then
            warn "${site^^}: No SNMP-open hosts from prior scans. Trying all live hosts."
            cp "$(live_hosts_file "$site")" "$snmp_hosts_file"
        fi
    fi

    echo "$snmp_hosts_file"
}

# ---- Phase 3.1: Community String Discovery ----
run_snmp_community_scan() {
    local site=$1
    local snmp_hosts_file=$(extract_snmp_hosts "$site")
    local community_file="${CONFIG_DIR}/snmp_communities.txt"

    if [ ! -s "$snmp_hosts_file" ]; then
        warn "${site^^}: No hosts to scan for SNMP — skipping"
        return
    fi

    if [ ! -f "$community_file" ]; then
        error "SNMP community strings file not found: ${community_file}"
        return
    fi

    local hostcount=$(wc -l < "$snmp_hosts_file")
    log "Phase 3.1: SNMP Community String Scan — ${site^^} (${hostcount} hosts)"

    local enumdir="$(site_dir "$site")/enum"

    # Method 1: onesixtyone (fast brute)
    if check_tool "onesixtyone"; then
        log "  Running onesixtyone for ${site^^}..."
        timed_run "onesixtyone ${site^^}" \
            onesixtyone -c "$community_file" -i "$snmp_hosts_file" 2>&1 \
            | tee "${enumdir}/snmp_communities_found.txt" \
            | tee -a "${LOGFILE:-/dev/null}"
    else
        warn "onesixtyone not found — using nmap snmp-brute as fallback"
    fi

    # Method 2: nmap SNMP info scripts
    log "  Running nmap SNMP info scripts for ${site^^}..."
    timed_run "SNMP nmap info ${site^^}" \
        sudo nmap -sU -p 161 --open \
        --script=snmp-info,snmp-sysdescr \
        -iL "$snmp_hosts_file" \
        -oA "${enumdir}/snmp_nmap_info_${TIMESTAMP}"

    success "Phase 3.1 complete for ${site^^}"
}

# ---- Phase 3.2: SNMP Walk ----
run_snmp_walk() {
    local site=$1
    local communities_file="$(site_dir "$site")/enum/snmp_communities_found.txt"

    if [ ! -s "$communities_file" ]; then
        warn "${site^^}: No SNMP communities found — skipping SNMP walk"
        return
    fi

    if ! check_tool "snmpwalk"; then
        warn "snmpwalk not found — skipping SNMP walks"
        return
    fi

    log "Phase 3.2: SNMP Walk — ${site^^}"
    mkdir -p "$(site_dir "$site")/enum/snmp_walks"

    # Parse onesixtyone output: IP [community] description
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3} \[[^]]+\]' "$communities_file" 2>/dev/null | \
    while IFS= read -r match; do
        local ip=$(echo "$match" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
        local community=$(echo "$match" | grep -oP '\[\K[^\]]+')
        local ip_safe=$(echo "$ip" | tr '.' '_')
        local walkdir="$(site_dir "$site")/enum/snmp_walks"

        log "  Walking SNMP on ${ip} with community '${community}'..."

        # Per-host summary file
        local host_summary="${walkdir}/${ip_safe}_full_walk.txt"
        {
            echo "╔════════════════════════════════════════════════════════════╗"
            echo "║  SNMP Walk Summary: ${ip}"
            echo "║  Community String: ${community}"
            echo "║  Date: $(date)"
            echo "╚════════════════════════════════════════════════════════════╝"
        } > "$host_summary"

        for oid_name in "${!SNMP_OIDS[@]}"; do
            local oid=${SNMP_OIDS[$oid_name]}
            local outfile="${walkdir}/${ip_safe}_${oid_name}.txt"

            echo ""  >> "$host_summary"
            echo "--- ${oid_name^^} (OID: ${oid}) ---" >> "$host_summary"

            timeout ${SNMP_WALK_TIMEOUT} snmpwalk -v2c -c "$community" "$ip" "$oid" 2>&1 \
                | tee "$outfile" >> "$host_summary" || {
                echo "(timeout or error)" >> "$host_summary"
                warn "snmpwalk timed out for ${ip} OID ${oid_name}"
            }
        done

        # Also try snmp-check if available
        if check_tool "snmp-check"; then
            log "  Running snmp-check on ${ip}..."
            timeout ${SNMP_CHECK_TIMEOUT} snmp-check -c "$community" "$ip" 2>&1 \
                | tee "${walkdir}/${ip_safe}_snmpcheck.txt" \
                | tee -a "${LOGFILE:-/dev/null}" || true
        fi

        success "SNMP walk complete for ${ip}"
    done
}

# ---- Generate SNMP Findings Summary ----
generate_snmp_summary() {
    local site=$1
    local summary="$(site_dir "$site")/enum/SNMP_FINDINGS_SUMMARY.txt"
    local enumdir="$(site_dir "$site")/enum"

    {
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║  SNMP ENUMERATION FINDINGS — ${site^^}"
        echo "║  Generated: $(date)"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo ""

        # Community strings found
        echo "--- COMMUNITY STRINGS DISCOVERED ---"
        if [ -s "${enumdir}/snmp_communities_found.txt" ]; then
            cat "${enumdir}/snmp_communities_found.txt"
        else
            echo "(none found)"
        fi
        echo ""

        # System descriptions
        echo "--- DEVICE SYSTEM DESCRIPTIONS ---"
        for f in "${enumdir}/snmp_walks/"*_system.txt; do
            if [ -f "$f" ]; then
                local ip=$(basename "$f" | sed 's/_system.txt//' | tr '_' '.')
                echo ""
                echo "Host: ${ip}"
                grep -i "sysDescr\|sysName\|sysLocation\|sysContact\|sysUpTime" "$f" 2>/dev/null || true
            fi
        done
        echo ""

        # Interface counts
        echo "--- NETWORK INTERFACES PER DEVICE ---"
        for f in "${enumdir}/snmp_walks/"*_interfaces.txt; do
            if [ -f "$f" ]; then
                local ip=$(basename "$f" | sed 's/_interfaces.txt//' | tr '_' '.')
                local iface_count=$(grep -c "ifDescr" "$f" 2>/dev/null || echo "0")
                echo "  ${ip}: ${iface_count} interfaces"
            fi
        done
        echo ""

        # ARP tables (additional host discovery)
        echo "--- ADDITIONAL HOSTS DISCOVERED VIA ARP TABLES ---"
        for f in "${enumdir}/snmp_walks/"*_arp_table.txt; do
            if [ -f "$f" ]; then
                grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$f" 2>/dev/null | sort -u || true
            fi
        done
        echo ""
    } > "$summary"

    success "SNMP summary: ${summary}"
}

# ---- Run all SNMP tasks for a site ----
run_snmp_enum() {
    local site=$1

    separator
    header "MODULE 03: SNMP ENUMERATION — ${site^^}"

    run_snmp_community_scan "$site"
    run_snmp_walk "$site"
    generate_snmp_summary "$site"

    separator
}

# Entry point
main() {
    local target="${1:-all}"
    validate_target_arg "$target" || exit 1

    header "NETRECON — Phase 3: SNMP Enumeration"

    for_each_site "$target" run_snmp_enum

    echo ""
    success "Phase 3: SNMP Enumeration complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [ -z "${ENGAGEMENT_DIR:-}" ]; then
        error "ENGAGEMENT_DIR not set. Run this module via netrecon.sh or set up first."
        exit 1
    fi
    main "$@"
fi
