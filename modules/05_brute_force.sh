#!/bin/bash
# ============================================================
# NetRecon — Module 05: Credential Testing (Brute Force)
# Phase 5.1: Default Credential Checks
# Phase 5.2: Service-Specific Brute Force
# Phase 5.3: Anonymous/Null Session Checks
# ============================================================
# AGGRESSIVE MODE ONLY — this module performs active credential
# testing against discovered services. Only runs when
# SCAN_MODE=aggressive.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

load_config "ports.conf"
load_config "scan_tuning.conf"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CREDS_FILE="${CONFIG_DIR}/brute_creds.txt"

# ---- Guard: Aggressive only ----
check_aggressive_mode() {
    if ! is_aggressive; then
        error "Module 05 (Brute Force) only runs in aggressive mode."
        error "Use: ./netrecon.sh run all --mode=aggressive"
        return 1
    fi
    return 0
}

# ---- Extract hosts with specific service ----
get_service_hosts() {
    local site=$1
    local port=$2
    local sd="$(site_dir "$site")"

    # Check gnmap files for hosts with this port open
    for f in "${sd}/nmap/"*.gnmap "${sd}/vulns/"*.gnmap; do
        [[ -f "$f" ]] && grep "${port}/open" "$f" 2>/dev/null | awk '{print $2}'
    done | sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n
}

# ---- Phase 5.1: Default Credential Checks (nmap) ----
run_default_cred_checks() {
    local site=$1
    local hostfile=$(live_hosts_file "$site")

    if [[ ! -s "$hostfile" ]]; then
        warn "No live hosts for ${site^^} — skipping credential checks"
        return
    fi

    log "Phase 5.1 [AGGRESSIVE]: Default Credential Checks — ${site^^}"
    local brutedir="$(site_dir "$site")/vulns/brute"
    mkdir -p "$brutedir"

    # SSH default credentials
    local ssh_hosts=$(get_service_hosts "$site" "22")
    if [[ -n "$ssh_hosts" ]]; then
        local ssh_list="${brutedir}/ssh_targets.txt"
        echo "$ssh_hosts" > "$ssh_list"
        local count=$(wc -l < "$ssh_list")
        log "  [5.1.1] SSH brute — ${count} targets"

        timed_run "SSH brute ${site^^}" \
            sudo nmap -p 22 --open \
            --script=ssh-brute \
            --script-args="userdb=${CREDS_FILE},passdb=${CREDS_FILE},brute.threads=${BRUTE_FORCE_THREADS},brute.firstonly=true" \
            $(aggressive_timing "$site") \
            -iL "$ssh_list" \
            -oA "${brutedir}/ssh_brute_${TIMESTAMP}" || true

        success "SSH brute complete for ${site^^}"
    fi

    # FTP default credentials + anonymous
    local ftp_hosts=$(get_service_hosts "$site" "21")
    if [[ -n "$ftp_hosts" ]]; then
        local ftp_list="${brutedir}/ftp_targets.txt"
        echo "$ftp_hosts" > "$ftp_list"
        local count=$(wc -l < "$ftp_list")
        log "  [5.1.2] FTP brute + anonymous check — ${count} targets"

        timed_run "FTP brute ${site^^}" \
            sudo nmap -p 21 --open \
            --script=ftp-brute,ftp-anon \
            --script-args="userdb=${CREDS_FILE},passdb=${CREDS_FILE},brute.threads=${BRUTE_FORCE_THREADS},brute.firstonly=true" \
            $(aggressive_timing "$site") \
            -iL "$ftp_list" \
            -oA "${brutedir}/ftp_brute_${TIMESTAMP}" || true

        success "FTP brute complete for ${site^^}"
    fi

    # Telnet default credentials
    local telnet_hosts=$(get_service_hosts "$site" "23")
    if [[ -n "$telnet_hosts" ]]; then
        local telnet_list="${brutedir}/telnet_targets.txt"
        echo "$telnet_hosts" > "$telnet_list"
        local count=$(wc -l < "$telnet_list")
        log "  [5.1.3] Telnet brute — ${count} targets"

        timed_run "Telnet brute ${site^^}" \
            sudo nmap -p 23 --open \
            --script=telnet-brute \
            --script-args="userdb=${CREDS_FILE},passdb=${CREDS_FILE},brute.threads=${BRUTE_FORCE_THREADS},brute.firstonly=true" \
            $(aggressive_timing "$site") \
            -iL "$telnet_list" \
            -oA "${brutedir}/telnet_brute_${TIMESTAMP}" || true

        success "Telnet brute complete for ${site^^}"
    fi
}

# ---- Phase 5.2: HTTP Default Account Checks ----
run_http_default_accounts() {
    local site=$1
    local hostfile=$(live_hosts_file "$site")

    if [[ ! -s "$hostfile" ]]; then
        return
    fi

    log "Phase 5.2 [AGGRESSIVE]: HTTP Default Accounts — ${site^^}"
    local brutedir="$(site_dir "$site")/vulns/brute"
    mkdir -p "$brutedir"

    # Check web management interfaces for default credentials
    timed_run "HTTP default accounts ${site^^}" \
        sudo nmap -p ${WEB_PORTS} --open \
        --script=http-default-accounts,http-auth-finder \
        $(aggressive_timing "$site") --max-rate=$(aggressive_rate ${VULN_SCAN_RATE}) \
        -iL "$hostfile" \
        -oA "${brutedir}/http_default_accounts_${TIMESTAMP}" || true

    success "Phase 5.2 HTTP default accounts check complete for ${site^^}"
}

# ---- Phase 5.3: SMB Null Session + Guest Access ----
run_smb_null_session() {
    local site=$1

    local smb_hosts=$(get_service_hosts "$site" "445")
    if [[ -z "$smb_hosts" ]]; then
        return
    fi

    log "Phase 5.3 [AGGRESSIVE]: SMB Null/Guest Session — ${site^^}"
    local brutedir="$(site_dir "$site")/vulns/brute"
    mkdir -p "$brutedir"
    local smb_list="${brutedir}/smb_targets.txt"
    echo "$smb_hosts" > "$smb_list"
    local count=$(wc -l < "$smb_list")
    log "  Testing ${count} SMB hosts for null/guest access"

    timed_run "SMB null session ${site^^}" \
        sudo nmap -p 139,445 --open \
        --script=smb-enum-shares,smb-enum-users,smb-ls \
        --script-args="smbusername='',smbpassword=''" \
        $(aggressive_timing "$site") \
        -iL "$smb_list" \
        -oA "${brutedir}/smb_null_session_${TIMESTAMP}" || true

    # Guest access
    timed_run "SMB guest access ${site^^}" \
        sudo nmap -p 139,445 --open \
        --script=smb-enum-shares \
        --script-args="smbusername='guest',smbpassword=''" \
        $(aggressive_timing "$site") \
        -iL "$smb_list" \
        -oA "${brutedir}/smb_guest_${TIMESTAMP}" || true

    success "Phase 5.3 SMB null/guest check complete for ${site^^}"
}

# ---- Generate Brute Force Summary ----
generate_brute_summary() {
    local site=$1
    local brutedir="$(site_dir "$site")/vulns/brute"
    local summary="${brutedir}/BRUTE_FORCE_SUMMARY.txt"

    if [[ ! -d "$brutedir" ]]; then
        return
    fi

    {
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║  CREDENTIAL TESTING FINDINGS — ${site^^}"
        echo "║  Mode: AGGRESSIVE"
        echo "║  Generated: $(date)"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo ""

        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🔴 VALID CREDENTIALS FOUND"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""

        local found=false
        for f in "${brutedir}/"*.nmap; do
            [[ -f "$f" ]] && {
                if grep -qi "Valid credentials\|Login succeeded\|brute.*success\|Anonymous.*allowed" "$f" 2>/dev/null; then
                    found=true
                    echo "  File: $(basename "$f")"
                    grep -iA2 "Valid credentials\|Login succeeded\|brute.*success\|Anonymous.*allowed" "$f" 2>/dev/null \
                        | sed 's/^/    /'
                    echo ""
                fi
            }
        done

        if [[ "$found" == "false" ]]; then
            echo "  ✓ No default/weak credentials found"
        fi
        echo ""

        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🟡 SMB NULL/GUEST SESSION RESULTS"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""

        for f in "${brutedir}/smb_null"*.nmap "${brutedir}/smb_guest"*.nmap; do
            [[ -f "$f" ]] && {
                if grep -qi "READ\|WRITE\|enum" "$f" 2>/dev/null; then
                    echo "  ⚠ Accessible shares found in $(basename "$f"):"
                    grep -iA5 "smb-enum-shares\|smb-ls" "$f" 2>/dev/null \
                        | head -30 | sed 's/^/    /'
                else
                    echo "  ✓ No null/guest access in $(basename "$f")"
                fi
                echo ""
            }
        done

        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "📋 HTTP DEFAULT ACCOUNT RESULTS"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""

        for f in "${brutedir}/http_default"*.nmap; do
            [[ -f "$f" ]] && {
                if grep -qi "default.*account\|credentials" "$f" 2>/dev/null; then
                    echo "  ⚠ Default accounts found:"
                    grep -iA3 "default.*account\|credentials" "$f" 2>/dev/null \
                        | head -20 | sed 's/^/    /'
                else
                    echo "  ✓ No default HTTP accounts found"
                fi
                echo ""
            }
        done
        echo ""
    } > "$summary"

    success "Brute force summary: ${summary}"
}

# ---- Run all brute force tasks for a site ----
run_brute_force() {
    local site=$1

    separator
    header "MODULE 05: CREDENTIAL TESTING [AGGRESSIVE] — ${site^^}"

    run_default_cred_checks "$site"
    run_http_default_accounts "$site"
    run_smb_null_session "$site"
    generate_brute_summary "$site"

    separator
}

# Entry point
main() {
    check_aggressive_mode || exit 1
    require_tool "nmap" "apt install nmap" || exit 1

    local target="${1:-all}"
    validate_target_arg "$target" || exit 1

    header "NETRECON — Phase 5: Credential Testing [AGGRESSIVE]"

    for_each_site "$target" run_brute_force

    echo ""
    success "Phase 5: Credential Testing complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ -z "${ENGAGEMENT_DIR:-}" ]]; then
        error "ENGAGEMENT_DIR not set. Run this module via netrecon.sh or set up first."
        exit 1
    fi
    main "$@"
fi
