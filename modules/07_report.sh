#!/bin/bash
# ============================================================
# NetRecon — Module 07: Report Generator
# Consolidates all findings into structured final report + CSV
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

load_config "ports.conf"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="${ENGAGEMENT_DIR}/NETRECON_REPORT_${TIMESTAMP}.txt"
REPORT_CSV="${ENGAGEMENT_DIR}/NETRECON_FINDINGS_${TIMESTAMP}.csv"

# ---- Report Header ----
write_header() {
    if is_aggressive; then
        cat > "$REPORT_FILE" << 'HEADER'
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║       INTERNAL NETWORK PENETRATION TEST REPORT                     ║
║       NetRecon — Aggressive Assessment                             ║
║       ⚠ INTRUSIVE TESTING PERFORMED                                ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝

HEADER
    else
        cat > "$REPORT_FILE" << 'HEADER'
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║       INTERNAL NETWORK PENETRATION TEST REPORT                     ║
║       NetRecon — Non-Intrusive Assessment                          ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝

HEADER
    fi

    cat >> "$REPORT_FILE" << EOF
Report Generated: $(date)
Report File: ${REPORT_FILE}
Engagement Dir: ${ENGAGEMENT_DIR}
Scan Mode: ${SCAN_MODE^^}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. EXECUTIVE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scope:
EOF

    for site in $(echo "${!TARGETS[@]}" | tr ' ' '\n' | sort); do
        local cidr=${TARGETS[$site]}
        printf "  %-8s %s\n" "${site^^}" "$cidr" >> "$REPORT_FILE"
    done

    if is_aggressive; then
        cat >> "$REPORT_FILE" << EOF

Testing Type: Aggressive (Discovery, Enumeration, Vulnerability ID, Exploit Validation, Credential Testing)
Testing Approach: Includes brute-force, vulnerability exploitation scripts, active protocol probing

EOF
    else
        cat >> "$REPORT_FILE" << EOF

Testing Type: Non-Intrusive (Discovery, Enumeration, Vulnerability ID)
Testing Approach: No exploits, no brute-force, no DoS

EOF
    fi
}

# ---- Host Discovery Summary ----
write_host_summary() {
    echo "" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"
    echo "1.1 HOST DISCOVERY SUMMARY" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    printf "  %-8s %-22s %-12s\n" "SITE" "CIDR" "LIVE HOSTS" >> "$REPORT_FILE"
    printf "  %-8s %-22s %-12s\n" "--------" "----------------------" "----------" >> "$REPORT_FILE"

    local total=0
    for site in $(echo "${!TARGETS[@]}" | tr ' ' '\n' | sort); do
        local count=$(count_live_hosts "$site")
        total=$((total + count))
        printf "  %-8s %-22s %-12s\n" "${site^^}" "${TARGETS[$site]}" "$count" >> "$REPORT_FILE"
    done
    printf "  %-8s %-22s %-12s\n" "" "TOTAL" "$total" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

# ---- Device Inventory ----
write_device_inventory() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"
    echo "2. NETWORK DEVICE INVENTORY" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"

    for site in $(echo "${!TARGETS[@]}" | tr ' ' '\n' | sort); do
        echo "" >> "$REPORT_FILE"
        echo "  ┌─────────────────────────────────────────────────────────" >> "$REPORT_FILE"
        echo "  │ ${site^^} — Device Inventory" >> "$REPORT_FILE"
        echo "  └─────────────────────────────────────────────────────────" >> "$REPORT_FILE"

        local found=false
        for f in "$(site_dir "$site")/nmap/"*.nmap; do
            [ -f "$f" ] && { found=true; break; }
        done

        if $found; then
            for f in "$(site_dir "$site")/nmap/"*.nmap; do
                [ -f "$f" ] && awk '
                /^Nmap scan report for/ {
                    if (ip != "") print ""
                    ip = $NF; gsub(/[()]/, "", ip)
                    printf "  IP: %-18s", ip
                }
                /^MAC Address:/ {
                    mac = $3; vendor = ""
                    for (i=4; i<=NF; i++) vendor = vendor " " $i
                    printf "  MAC: %-20s %s", mac, vendor
                }
                /open/ && !/^#/ && !/Nmap/ && !/Host/ {
                    gsub(/^[[:space:]]+/, "")
                    if ($0 ~ /^[0-9]+\//) printf "\n    %s", $0
                }
                END { if (ip != "") print "" }
                ' "$f" >> "$REPORT_FILE" 2>/dev/null || true
            done
        else
            echo "    (no scan data available)" >> "$REPORT_FILE"
        fi
    done
}

# ---- Open Port Summary ----
write_port_summary() {
    echo "" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"
    echo "3. OPEN PORT SUMMARY" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"

    for site in $(echo "${!TARGETS[@]}" | tr ' ' '\n' | sort); do
        echo "" >> "$REPORT_FILE"
        echo "  ┌── ${site^^} — Open Ports Distribution" >> "$REPORT_FILE"
        local tmpfile=$(mktemp)
        for f in "$(site_dir "$site")/nmap/"*.gnmap; do
            [ -f "$f" ] && grep "Ports:" "$f" 2>/dev/null | \
                sed 's/.*Ports: //' | tr ',' '\n' | \
                awk -F'/' '{if ($2=="open") print $1"/"$3" ("$5")"}' >> "$tmpfile" 2>/dev/null || true
        done
        if [ -s "$tmpfile" ]; then
            echo "  Most common open ports:" >> "$REPORT_FILE"
            sort "$tmpfile" | uniq -c | sort -rn | head -20 | \
                awk '{printf "    %4d hosts — %s\n", $1, substr($0, index($0,$2))}' >> "$REPORT_FILE"
        else
            echo "    (no port data)" >> "$REPORT_FILE"
        fi
        rm -f "$tmpfile"
    done
}

# ---- Vulnerability Findings ----
write_vuln_findings() {
    echo "" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"
    echo "4. VULNERABILITY FINDINGS" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"

    for site in $(echo "${!TARGETS[@]}" | tr ' ' '\n' | sort); do
        echo "" >> "$REPORT_FILE"
        echo "  ╔═══ ${site^^} VULNERABILITIES" >> "$REPORT_FILE"
        local vs="$(site_dir "$site")/vulns/VULNERABILITY_SUMMARY.txt"
        if [ -f "$vs" ]; then
            sed 's/^/  /' "$vs" >> "$REPORT_FILE"
        else
            echo "    (not yet completed)" >> "$REPORT_FILE"
        fi
    done
}

# ---- SNMP Findings ----
write_snmp_findings() {
    echo "" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"
    echo "5. SNMP ENUMERATION FINDINGS" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"

    for site in $(echo "${!TARGETS[@]}" | tr ' ' '\n' | sort); do
        echo "" >> "$REPORT_FILE"
        echo "  --- ${site^^} ---" >> "$REPORT_FILE"
        local sf="$(site_dir "$site")/enum/SNMP_FINDINGS_SUMMARY.txt"
        if [ -f "$sf" ]; then
            sed 's/^/  /' "$sf" >> "$REPORT_FILE"
        else
            echo "    (not yet completed)" >> "$REPORT_FILE"
        fi
    done
}

# ---- Protocol Analysis ----
write_protocol_findings() {
    echo "" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"
    echo "6. NETWORK PROTOCOL ANALYSIS" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"

    local ps=$(ls -t "${ENGAGEMENT_DIR}"/evidence_*/PROTOCOL_ANALYSIS_SUMMARY.txt 2>/dev/null | head -1)
    if [ -n "$ps" ] && [ -f "$ps" ]; then
        sed 's/^/  /' "$ps" >> "$REPORT_FILE"
    else
        echo "  (not yet completed)" >> "$REPORT_FILE"
    fi
}

# ---- Brute Force / Credential Testing (Aggressive only) ----
write_brute_findings() {
    if ! is_aggressive; then
        return
    fi

    echo "" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"
    echo "6.5 CREDENTIAL TESTING FINDINGS [AGGRESSIVE]" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"

    for site in $(echo "${!TARGETS[@]}" | tr ' ' '\n' | sort); do
        echo "" >> "$REPORT_FILE"
        echo "  --- ${site^^} ---" >> "$REPORT_FILE"
        local bf="$(site_dir "$site")/vulns/brute/BRUTE_FORCE_SUMMARY.txt"
        if [[ -f "$bf" ]]; then
            sed 's/^/  /' "$bf" >> "$REPORT_FILE"
        else
            echo "    (not yet completed)" >> "$REPORT_FILE"
        fi
    done
}

# ---- Recommendations ----
write_recommendations() {
    echo "" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"
    echo "7. RECOMMENDATIONS (AUTO-GENERATED)" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "  NOTE: Review and customize before final report." >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    local n=1

    # Dynamic recommendations based on scan findings
    for site in "${!TARGETS[@]}"; do
        for f in "$(site_dir "$site")/vulns/telnet_check"*.nmap; do
            [ -f "$f" ] && grep -q "23/open" "$f" 2>/dev/null && {
                echo "  ${n}. [CRITICAL] Disable Telnet — replace with SSH v2" >> "$REPORT_FILE"
                n=$((n+1)); break 2
            }
        done
    done

    for site in "${!TARGETS[@]}"; do
        [ -f "$(site_dir "$site")/enum/snmp_communities_found.txt" ] && \
            grep -qi "public\|private" "$(site_dir "$site")/enum/snmp_communities_found.txt" 2>/dev/null && {
            echo "  ${n}. [CRITICAL] Change default SNMP community strings; migrate to SNMPv3" >> "$REPORT_FILE"
            n=$((n+1)); break
        }
    done

    for site in "${!TARGETS[@]}"; do
        for f in "$(site_dir "$site")/vulns/cisco_smart_install"*.nmap; do
            [ -f "$f" ] && grep -q "4786/open" "$f" 2>/dev/null && {
                echo "  ${n}. [CRITICAL] Disable Cisco Smart Install (CVE-2018-0171)" >> "$REPORT_FILE"
                n=$((n+1)); break 2
            }
        done
    done

    # Standard recommendations
    cat >> "$REPORT_FILE" << EOF
  ${n}. [HIGH] Enforce HTTPS for all management interfaces
  $((n+1)). [HIGH] Review network segmentation and management VLAN ACLs
  $((n+2)). [MEDIUM] Harden SSH — disable CBC ciphers, weak KEX
  $((n+3)). [MEDIUM] Disable CDP/LLDP on user-facing ports
  $((n+4)). [MEDIUM] Enable BPDU Guard + switchport nonegotiate on access ports
  $((n+5)). [LOW] Implement NTP authentication
  $((n+6)). [LOW] Cross-reference firmware versions with vendor advisories

EOF
}

# ---- Tool Versions ----
write_environment() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"
    echo "8. TESTING ENVIRONMENT" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "  Tool Versions:" >> "$REPORT_FILE"
    nmap --version 2>/dev/null | head -2 | sed 's/^/    /' >> "$REPORT_FILE" || echo "    nmap: N/A" >> "$REPORT_FILE"
    echo "  OS:" >> "$REPORT_FILE"
    cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | sed 's/^/    /' >> "$REPORT_FILE" || echo "    (unknown)" >> "$REPORT_FILE"
    uname -a 2>/dev/null | sed 's/^/    /' >> "$REPORT_FILE" || true
    echo "" >> "$REPORT_FILE"
}

# ---- CSV Generation ----
generate_csv() {
    log "Generating CSV findings..."
    echo "Site,Severity,Finding,Affected_Host,Port,Details" > "$REPORT_CSV"

    for site in "${!TARGETS[@]}"; do
        local sd="$(site_dir "$site")"
        for f in "${sd}/vulns/telnet_check"*.gnmap; do
            [ -f "$f" ] && grep "23/open" "$f" 2>/dev/null | \
                awk -v s="${site^^}" '{print s",Critical,Telnet Enabled,"$2",23,Unencrypted management"}' >> "$REPORT_CSV" || true
        done
        for f in "${sd}/vulns/cisco_smart_install"*.gnmap; do
            [ -f "$f" ] && grep "4786/open" "$f" 2>/dev/null | \
                awk -v s="${site^^}" '{print s",Critical,Cisco Smart Install,"$2",4786,CVE-2018-0171"}' >> "$REPORT_CSV" || true
        done
        for f in "${sd}/vulns/http_enum"*.gnmap; do
            [ -f "$f" ] && grep "80/open" "$f" 2>/dev/null | \
                awk -v s="${site^^}" '{print s",High,HTTP Management,"$2",80,Unencrypted web mgmt"}' >> "$REPORT_CSV" || true
        done
        if [ -f "${sd}/enum/snmp_communities_found.txt" ]; then
            grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}.*\[public\]' "${sd}/enum/snmp_communities_found.txt" 2>/dev/null | \
                awk -v s="${site^^}" -F'[' '{gsub(/ /,"",$1); print s",Critical,Default SNMP (public),"$1",161,Default read community"}' >> "$REPORT_CSV" || true
        fi

        # Aggressive-only CSV entries
        if is_aggressive; then
            # SMB vulnerabilities (EternalBlue etc)
            for f in "${sd}/vulns/smb_vulns"*.gnmap; do
                [[ -f "$f" ]] && grep "445/open" "$f" 2>/dev/null | \
                    awk -v s="${site^^}" '{print s",Critical,SMB Vulnerability,"$2",445,MS17-010/MS08-067 check"}' >> "$REPORT_CSV" || true
            done
            # RDP vulnerabilities
            for f in "${sd}/vulns/rdp_checks"*.gnmap; do
                [[ -f "$f" ]] && grep "3389/open" "$f" 2>/dev/null | \
                    awk -v s="${site^^}" '{print s",High,RDP Exposed,"$2",3389,MS12-020 check"}' >> "$REPORT_CSV" || true
            done
            # Brute force successes
            for f in "${sd}/vulns/brute/"*.nmap; do
                [[ -f "$f" ]] && grep -i "Valid credentials\|Login succeeded" "$f" 2>/dev/null | \
                    awk -v s="${site^^}" '{print s",Critical,Default Credentials,N/A,N/A,"$0}' >> "$REPORT_CSV" || true
            done
            # SNMP write access
            if [[ -f "${sd}/enum/snmp_write_access.txt" ]]; then
                awk -v s="${site^^}" '{print s",Critical,SNMP Write Access,N/A,161,"$0}' \
                    "${sd}/enum/snmp_write_access.txt" >> "$REPORT_CSV" || true
            fi
        fi
    done
}

# ---- Footer ----
write_footer() {
    echo "" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"
    echo "END OF REPORT" >> "$REPORT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "This report was auto-generated by NetRecon." >> "$REPORT_FILE"
    echo "Review and supplement with manual analysis before presenting." >> "$REPORT_FILE"
}

# Entry point
main() {
    header "NETRECON — Phase 7: Report Generation"
    log "Generating consolidated report..."

    write_header
    write_host_summary
    write_device_inventory
    write_port_summary
    write_vuln_findings
    write_snmp_findings
    write_protocol_findings
    write_brute_findings
    write_recommendations
    write_environment
    write_footer
    generate_csv

    echo ""
    success "Report:  ${REPORT_FILE}"
    success "CSV:     ${REPORT_CSV}"
    echo "Lines in report: $(wc -l < "$REPORT_FILE")"
    echo "CSV entries:     $(wc -l < "$REPORT_CSV")"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    [ -z "${ENGAGEMENT_DIR:-}" ] && { error "ENGAGEMENT_DIR not set."; exit 1; }
    main "$@"
fi
