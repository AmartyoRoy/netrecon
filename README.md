# NetRecon

**Modular Internal Network Penetration Test Automation**

NetRecon automates non-intrusive internal network assessments. It handles host discovery, port scanning, SNMP enumeration, vulnerability identification, passive protocol analysis, and consolidated report generation — all from a single CLI.

## Features

- **Modular architecture** — run individual phases or the full pipeline
- **Multi-site support** — define targets in a config file, scan them all or individually
- **Non-intrusive** — no exploits, no brute force, no DoS. Uses only `safe` NSE category
- **Rate-limited** — configurable timing and packet rates per engagement sensitivity
- **Per-site output** — clean directory structure with summaries at every level
- **Auto-generated reports** — structured TXT report + CSV findings spreadsheet
- **Resumable engagements** — pick up where you left off

## Quick Start

```bash
# 1. Clone / copy to your Kali machine
git clone <repo> && cd netrecon

# 2. Configure your targets
cp config/targets.conf.example config/targets.conf
# Edit targets.conf with your site names and CIDRs

# 3. Initialize an engagement
sudo ./netrecon.sh init my-assessment

# 4. Resume and run all phases
sudo ./netrecon.sh resume
sudo ./netrecon.sh run all

# Or run specific phases / sites
sudo ./netrecon.sh run 1           # Discovery only
sudo ./netrecon.sh run 2 site_a    # Port scan a specific site only
sudo ./netrecon.sh run all --skip-phase6
```

## Phases

| Phase | Module | Description |
|-------|--------|-------------|
| 1 | `01_discovery.sh` | ARP scan + ICMP/TCP/UDP host discovery |
| 2 | `02_port_scan.sh` | TCP top-1000, infrastructure ports, UDP critical |
| 3 | `03_snmp_enum.sh` | Community string brute + automated SNMP walks |
| 4 | `04_vuln_scan.sh` | NSE safe scripts, SSL/TLS, Cisco SMI, Telnet, SSH audit |
| 5 | *(manual)* | WiFi assessment — requires physical adapter |
| 6 | `06_protocol_analysis.sh` | Passive capture + tshark protocol analysis |
| 7 | `07_report.sh` | Consolidated report + CSV findings generator |

## Directory Structure

```
netrecon/
├── netrecon.sh                  # Main orchestrator
├── config/
│   ├── targets.conf.example     # Target template (copy → targets.conf)
│   ├── ports.conf               # Port lists for each scan type
│   ├── scan_tuning.conf         # Timing, rate limits, timeouts
│   └── snmp_communities.txt     # Community string wordlist
├── lib/
│   └── common.sh                # Shared functions & utilities
├── modules/
│   ├── 01_discovery.sh          # Host discovery
│   ├── 02_port_scan.sh          # Port scanning
│   ├── 03_snmp_enum.sh          # SNMP enumeration
│   ├── 04_vuln_scan.sh          # Vulnerability scanning
│   ├── 06_protocol_analysis.sh  # Passive protocol analysis
│   └── 07_report.sh             # Report generation
└── engagements/                 # Created per engagement (gitignored)
    └── <name>_<timestamp>/
        ├── metadata.txt
        ├── netrecon.log
        ├── NETRECON_REPORT_*.txt
        ├── NETRECON_FINDINGS_*.csv
        └── <site>/
            ├── live_hosts.txt
            ├── nmap/  enum/  vulns/  evidence/
            └── *_SUMMARY.txt
```

## Configuration

### `config/targets.conf`
```
# SITE_NAME=CIDR
hq=192.168.1.0/24
branch_ny=10.10.10.0/24
datacenter=172.16.0.0/24
dmz=10.20.0.0/24
```

### `config/scan_tuning.conf`
Key settings:
- `DEFAULT_TIMING` — nmap timing template (default: `-T3`)
- `*_RATE` — packets per second for each scan type
- `CAPTURE_DURATION` — passive capture window in seconds
- `CONTINUE_ON_ERROR` — keep going if a phase fails

## Requirements

**Required:**
- `nmap` — core scanning engine

**Optional (enhances results):**
- `tshark` / `tcpdump` — protocol analysis (Phase 6)
- `onesixtyone` — fast SNMP community brute
- `snmpwalk` / `snmp-check` — SNMP walks
- `ssh-audit` — detailed SSH algorithm audit
- `arp-scan` — Layer 2 host discovery

## Key Output Files

| File | What's In It |
|------|-------------|
| `NETRECON_REPORT_*.txt` | Full consolidated report |
| `NETRECON_FINDINGS_*.csv` | Spreadsheet-ready findings |
| `<site>/vulns/VULNERABILITY_SUMMARY.txt` | Per-site vulns by severity |
| `<site>/enum/SNMP_FINDINGS_SUMMARY.txt` | SNMP community strings & device info |
| `<site>/nmap/*_SUMMARY.txt` | Per-scan port summaries |

## Safety

- Rate-limited scans with configurable `-T` timing
- **No** exploit, brute, DOS, or fuzzer NSE categories
- Timeouts on all external tool calls
- Preflight checks with confirmation prompt
- Full execution logging

> **Always notify SOC/NOC before scanning and have authorization documentation ready.**

## License

MIT License — see [LICENSE](LICENSE)
