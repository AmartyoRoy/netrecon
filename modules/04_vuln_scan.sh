#!/bin/bash
# ============================================================
# NetRecon — Module 04: Vulnerability Scanning
# Phase 4.1: NSE Safe Scripts
# Phase 4.2: Targeted Vulnerability Checks
# Phase 4.3: SSH Audit
# ============================================================
# ALL NON-INTRUSIVE — no exploits, no brute force, no DoS.
# Uses nmap NSE "safe" category and targeted security checks.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

load_config "ports.conf"
load_config "scan_tuning.conf"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ---- Phase 4.1: NSE Safe Scripts ----
run_nse_safe() {
    local site=$1
    local timing=$(get_timing "$site")
    local hostfile=$(live_hosts_file "$site")

    if [ ! -s "$hostfile" ]; then
        warn "No live hosts for ${site^^} — skipping NSE safe scan"
        return
    fi

    local hostcount=$(wc -l < "$hostfile")
    log "Phase 4.1: NSE Safe Scripts — ${site^^} (${hostcount} hosts)"

    local vulndir="$(site_dir "$site")/vulns"
    mkdir -p "$vulndir"

    timed_run "NSE safe scan ${site^^}" \
        sudo nmap -sV --script="safe and not dos and not exploit and not brute and not fuzzer" \
        ${timing} --max-rate=${NSE_SCAN_RATE} \
        -iL "$hostfile" \
        -oA "${vulndir}/nse_safe_scan_${TIMESTAMP}"

    success "Phase 4.1 NSE safe scan complete for ${site^^}"
}

# ---- Phase 4.2: Targeted Vulnerability Checks ----
run_targeted_vulns() {
    local site=$1
    local timing=$(get_timing "$site")
    local hostfile=$(live_hosts_file "$site")

    if [ ! -s "$hostfile" ]; then
        warn "No live hosts for ${site^^} — skipping targeted checks"
        return
    fi

    log "Phase 4.2: Targeted Vulnerability Checks — ${site^^}"
    local vulndir="$(site_dir "$site")/vulns"
    mkdir -p "$vulndir"

    # 4.2.1: Cisco Smart Install (CVE-2018-0171)
    log "  [4.2.1] Checking Cisco Smart Install (port 4786)..."
    timed_run "Cisco Smart Install check ${site^^}" \
        sudo nmap -p 4786 --open --script=cisco-smart-install \
        ${timing} -iL "$hostfile" \
        -oA "${vulndir}/cisco_smart_install_${TIMESTAMP}"

    # 4.2.2: SSL/TLS Issues on management interfaces
    log "  [4.2.2] Checking SSL/TLS issues on management ports..."
    timed_run "SSL/TLS checks ${site^^}" \
        sudo nmap -p ${SSL_PORTS} --open \
        --script=ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,ssl-dh-params,ssl-known-key \
        ${timing} --max-rate=${VULN_SCAN_RATE} \
        -iL "$hostfile" \
        -oA "${vulndir}/ssl_checks_${TIMESTAMP}"

    # 4.2.3: HTTP Enumeration (banners, titles — no fuzzing)
    log "  [4.2.3] Enumerating HTTP management interfaces..."
    timed_run "HTTP enumeration ${site^^}" \
        sudo nmap -p ${WEB_PORTS} --open \
        --script=http-title,http-server-header,http-robots.txt,http-headers,http-methods,http-favicon \
        ${timing} --max-rate=${VULN_SCAN_RATE} \
        -iL "$hostfile" \
        -oA "${vulndir}/http_enum_${TIMESTAMP}"

    # 4.2.4: Telnet Check (presence = critical finding)
    log "  [4.2.4] Checking for Telnet services..."
    timed_run "Telnet check ${site^^}" \
        sudo nmap -p 23 --open \
        --script=telnet-ntlm-info,telnet-encryption \
        ${timing} -iL "$hostfile" \
        -oA "${vulndir}/telnet_check_${TIMESTAMP}"

    # 4.2.5: NTP Checks
    log "  [4.2.5] Checking NTP configuration..."
    timed_run "NTP check ${site^^}" \
        sudo nmap -sU -p 123 --open \
        --script=ntp-info,ntp-monlist \
        ${timing} --max-rate=${UDP_SCAN_RATE} \
        -iL "$hostfile" \
        -oA "${vulndir}/ntp_check_${TIMESTAMP}"

    # 4.2.6: DNS Checks
    log "  [4.2.6] Checking DNS services..."
    timed_run "DNS check ${site^^}" \
        sudo nmap -sU -p 53 --open \
        --script=dns-recursion,dns-service-discovery,dns-nsid \
        ${timing} --max-rate=${UDP_SCAN_RATE} \
        -iL "$hostfile" \
        -oA "${vulndir}/dns_check_${TIMESTAMP}"

    success "Phase 4.2 targeted checks complete for ${site^^}"
}

# ---- Phase 4.3: SSH Audit ----
run_ssh_audit() {
    local site=$1
    local timing=$(get_timing "$site")
    local hostfile=$(live_hosts_file "$site")

    if [ ! -s "$hostfile" ]; then
        warn "No live hosts for ${site^^} — skipping SSH audit"
        return
    fi

    log "Phase 4.3: SSH Audit — ${site^^}"
    local vulndir="$(site_dir "$site")/vulns"

    # Nmap SSH scripts
    timed_run "SSH nmap audit ${site^^}" \
        sudo nmap -p 22 --open \
        --script=ssh2-enum-algos,ssh-auth-methods,ssh-hostkey \
        ${timing} -iL "$hostfile" \
        -oA "${vulndir}/ssh_audit_nmap_${TIMESTAMP}"

    # Detailed ssh-audit tool (if installed)
    if check_tool "ssh-audit"; then
        log "  Running detailed ssh-audit tool..."
        mkdir -p "${vulndir}/ssh_audit_detail"

        # Extract SSH hosts from nmap results
        if [ -f "${vulndir}/ssh_audit_nmap_${TIMESTAMP}.gnmap" ]; then
            grep "22/open" "${vulndir}/ssh_audit_nmap_${TIMESTAMP}.gnmap" 2>/dev/null | \
                awk '{print $2}' | while read -r ip; do
                log "  ssh-audit ${ip}..."
                timeout ${SSH_AUDIT_TIMEOUT} ssh-audit "$ip" 2>&1 \
                    | tee "${vulndir}/ssh_audit_detail/${ip//./_}.txt" || true
            done
        fi
    else
        warn "ssh-audit tool not installed. Install with: pip3 install ssh-audit"
    fi

    success "Phase 4.3 SSH audit complete for ${site^^}"
}

# ---- Generate Vulnerability Summary Report ----
generate_vuln_summary() {
    local site=$1
    local vulndir="$(site_dir "$site")/vulns"
    local summary="${vulndir}/VULNERABILITY_SUMMARY.txt"

    {
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║  VULNERABILITY SCAN FINDINGS — ${site^^}"
        echo "║  Generated: $(date)"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo ""

        # ---- CRITICAL FINDINGS ----
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🔴 CRITICAL FINDINGS"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""

        # Cisco Smart Install
        echo "[CRITICAL] Cisco Smart Install (CVE-2018-0171):"
        for f in "${vulndir}/cisco_smart_install"*.nmap; do
            [ -f "$f" ] && {
                local count=$(grep -c "4786/open" "$f" 2>/dev/null || echo "0")
                if [ "$count" -gt 0 ]; then
                    echo "  ⚠ FOUND: ${count} host(s) with port 4786 OPEN"
                    grep -B5 "4786/open" "$f" | grep "report for" | awk '{print "    - " $NF}'
                else
                    echo "  ✓ Not found (port 4786 closed on all hosts)"
                fi
            }
        done
        echo ""

        # Telnet
        echo "[CRITICAL] Telnet Services Enabled:"
        for f in "${vulndir}/telnet_check"*.nmap; do
            [ -f "$f" ] && {
                local count=$(grep -c "23/open" "$f" 2>/dev/null || echo "0")
                if [ "$count" -gt 0 ]; then
                    echo "  ⚠ FOUND: ${count} host(s) with Telnet OPEN"
                    grep -B5 "23/open" "$f" | grep "report for" | awk '{print "    - " $NF}'
                else
                    echo "  ✓ No Telnet services found"
                fi
            }
        done
        echo ""

        # Heartbleed
        echo "[CRITICAL] SSL Heartbleed (CVE-2014-0160):"
        for f in "${vulndir}/ssl_checks"*.nmap; do
            [ -f "$f" ] && {
                if grep -qi "VULNERABLE.*heartbleed" "$f" 2>/dev/null; then
                    echo "  ⚠ FOUND: Heartbleed vulnerable hosts:"
                    grep -B20 "heartbleed" "$f" | grep "report for" | awk '{print "    - " $NF}'
                else
                    echo "  ✓ No Heartbleed vulnerability found"
                fi
            }
        done
        echo ""

        # ---- HIGH FINDINGS ----
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🟠 HIGH FINDINGS"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""

        # Weak SSL/TLS
        echo "[HIGH] Weak SSL/TLS Configurations:"
        for f in "${vulndir}/ssl_checks"*.nmap; do
            [ -f "$f" ] && {
                if grep -qiE "SSLv3|TLSv1\.0|TLSv1\.1" "$f" 2>/dev/null; then
                    echo "  ⚠ Deprecated TLS versions found:"
                    grep -iE "SSLv3|TLSv1\.0 |TLSv1\.1 " "$f" | head -20
                fi
                if grep -qi "RC4\|DES\|EXPORT\|NULL" "$f" 2>/dev/null; then
                    echo "  ⚠ Weak ciphers found:"
                    grep -i "RC4\|DES\|EXPORT\|NULL" "$f" | head -20
                fi
                if ! grep -qiE "SSLv3|TLSv1\.0|TLSv1\.1|RC4|DES|EXPORT|NULL" "$f" 2>/dev/null; then
                    echo "  ✓ No critically weak SSL/TLS configurations found"
                fi
            }
        done
        echo ""

        # HTTP unencrypted management
        echo "[HIGH] HTTP (unencrypted) Management Interfaces:"
        for f in "${vulndir}/http_enum"*.nmap; do
            [ -f "$f" ] && {
                local count=$(grep -c "80/open" "$f" 2>/dev/null || echo "0")
                if [ "$count" -gt 0 ]; then
                    echo "  ⚠ FOUND: ${count} host(s) with HTTP (port 80) management"
                    grep -A2 "http-title" "$f" 2>/dev/null | head -30 || true
                fi
            }
        done
        echo ""

        # ---- MEDIUM FINDINGS ----
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🟡 MEDIUM FINDINGS"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""

        # Weak SSH Algorithms
        echo "[MEDIUM] SSH Weak Algorithms:"
        for f in "${vulndir}/ssh_audit_nmap"*.nmap; do
            [ -f "$f" ] && {
                if grep -qiE "cbc|arcfour|sha1|diffie-hellman-group1|diffie-hellman-group-exchange-sha1" "$f" 2>/dev/null; then
                    echo "  ⚠ Weak SSH algorithms detected:"
                    grep -iE "cbc|arcfour|sha1|diffie-hellman-group1" "$f" | head -20
                else
                    echo "  ✓ No critically weak SSH algorithms found"
                fi
            }
        done
        echo ""

        # NTP
        echo "[MEDIUM] NTP Configuration Issues:"
        for f in "${vulndir}/ntp_check"*.nmap; do
            [ -f "$f" ] && {
                if grep -qi "monlist" "$f" 2>/dev/null; then
                    echo "  ⚠ NTP monlist enabled (amplification risk):"
                    grep -B5 "monlist" "$f" | grep "report for" | awk '{print "    - " $NF}'
                fi
            }
        done
        echo ""

        # DNS recursion
        echo "[MEDIUM] DNS Recursion Enabled:"
        for f in "${vulndir}/dns_check"*.nmap; do
            [ -f "$f" ] && {
                if grep -qi "recursion.*enabled" "$f" 2>/dev/null; then
                    echo "  ⚠ DNS recursion enabled on:"
                    grep -B10 "recursion" "$f" | grep "report for" | awk '{print "    - " $NF}'
                fi
            }
        done
        echo ""

        # ---- DEVICE INVENTORY ----
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "📋 WEB MANAGEMENT INTERFACE INVENTORY"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        for f in "${vulndir}/http_enum"*.nmap; do
            [ -f "$f" ] && {
                awk '/^Nmap scan report for/{ip=$NF} /http-title:/{print ip " -> " $0}' "$f" 2>/dev/null || true
            }
        done
        echo ""

        # ---- SSL CERTIFICATES ----
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🔒 SSL CERTIFICATE SUMMARY"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        for f in "${vulndir}/ssl_checks"*.nmap; do
            [ -f "$f" ] && {
                awk '/^Nmap scan report for/{ip=$NF}
                     /Subject:/{print ip ": " $0}
                     /Not valid after/{print "  Expires: " $0}
                     /Self-signed/{print "  ⚠ SELF-SIGNED CERTIFICATE"}' "$f" 2>/dev/null || true
            }
        done
        echo ""
    } > "$summary"

    success "Vulnerability summary: ${summary}"
}

# ---- Aggressive: Vuln + Exploit NSE ----
run_nse_aggressive() {
    local site=$1

    if ! is_aggressive; then
        return
    fi

    local timing=$(aggressive_timing "$site")
    local hostfile=$(live_hosts_file "$site")

    if [[ ! -s "$hostfile" ]]; then
        return
    fi

    local hostcount=$(wc -l < "$hostfile")
    log "Phase 4.4 [AGGRESSIVE]: Vuln+Exploit NSE — ${site^^} (${hostcount} hosts)"

    local vulndir="$(site_dir "$site")/vulns"
    mkdir -p "$vulndir"

    # Vuln category (includes exploit validation, NOT dos)
    timed_run "NSE vuln+exploit ${site^^}" \
        sudo nmap -sV --script="vuln and not dos" \
        ${timing} --max-rate=$(aggressive_rate ${VULN_SCAN_RATE}) \
        -iL "$hostfile" \
        -oA "${vulndir}/nse_vuln_exploit_${TIMESTAMP}"

    success "Phase 4.4 aggressive NSE scan complete for ${site^^}"
}

# ---- Aggressive: SMB Vulnerability Checks ----
run_smb_checks() {
    local site=$1

    if ! is_aggressive; then
        return
    fi

    local hostfile=$(live_hosts_file "$site")
    if [[ ! -s "$hostfile" ]]; then
        return
    fi

    log "Phase 4.5 [AGGRESSIVE]: SMB Vulnerability Checks — ${site^^}"
    local vulndir="$(site_dir "$site")/vulns"

    # EternalBlue (MS17-010)
    timed_run "SMB MS17-010 check ${site^^}" \
        sudo nmap -p 445 --open \
        --script=smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-ms10-054 \
        $(aggressive_timing "$site") -iL "$hostfile" \
        -oA "${vulndir}/smb_vulns_${TIMESTAMP}"

    # SMB enumeration
    timed_run "SMB enum ${site^^}" \
        sudo nmap -p 139,445 --open \
        --script=smb-enum-shares,smb-enum-users,smb-os-discovery,smb-protocols \
        $(aggressive_timing "$site") -iL "$hostfile" \
        -oA "${vulndir}/smb_enum_${TIMESTAMP}"

    success "Phase 4.5 SMB checks complete for ${site^^}"
}

# ---- Aggressive: RDP Checks ----
run_rdp_checks() {
    local site=$1

    if ! is_aggressive; then
        return
    fi

    local hostfile=$(live_hosts_file "$site")
    if [[ ! -s "$hostfile" ]]; then
        return
    fi

    log "Phase 4.6 [AGGRESSIVE]: RDP Vulnerability Checks — ${site^^}"
    local vulndir="$(site_dir "$site")/vulns"

    timed_run "RDP vuln check ${site^^}" \
        sudo nmap -p 3389 --open \
        --script=rdp-vuln-ms12-020,rdp-enum-encryption,rdp-ntlm-info \
        $(aggressive_timing "$site") -iL "$hostfile" \
        -oA "${vulndir}/rdp_checks_${TIMESTAMP}"

    success "Phase 4.6 RDP checks complete for ${site^^}"
}

# ---- Aggressive: searchsploit integration ----
run_searchsploit() {
    local site=$1

    if ! is_aggressive; then
        return
    fi

    if ! check_tool "searchsploit"; then
        warn "searchsploit not found — skipping exploit-db lookup"
        return
    fi

    log "Phase 4.7 [AGGRESSIVE]: searchsploit — ${site^^}"
    local vulndir="$(site_dir "$site")/vulns"

    # Find nmap XML files and search exploit-db
    for f in "$(site_dir "$site")/nmap/"*.xml "${vulndir}/"*.xml; do
        if [[ -f "$f" ]]; then
            log "  Searching exploits for $(basename "$f")..."
            searchsploit --nmap "$f" 2>/dev/null \
                | tee -a "${vulndir}/searchsploit_results_${TIMESTAMP}.txt" || true
        fi
    done

    success "Phase 4.7 searchsploit complete for ${site^^}"
}

# ---- Run all vuln tasks for a site ----
run_vuln_scan() {
    local site=$1

    separator
    header "MODULE 04: VULNERABILITY SCANNING — ${site^^}"

    run_nse_safe "$site"
    run_targeted_vulns "$site"
    run_ssh_audit "$site"
    run_nse_aggressive "$site"
    run_smb_checks "$site"
    run_rdp_checks "$site"
    run_searchsploit "$site"
    generate_vuln_summary "$site"

    separator
}

# Entry point
main() {
    require_tool "nmap" "apt install nmap" || exit 1

    local target="${1:-all}"
    validate_target_arg "$target" || exit 1

    header "NETRECON — Phase 4: Vulnerability Scanning"

    for_each_site "$target" run_vuln_scan

    echo ""
    success "Phase 4: Vulnerability Scanning complete"
    success "Check each site's vulns/VULNERABILITY_SUMMARY.txt"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [ -z "${ENGAGEMENT_DIR:-}" ]; then
        error "ENGAGEMENT_DIR not set. Run this module via netrecon.sh or set up first."
        exit 1
    fi
    main "$@"
fi
