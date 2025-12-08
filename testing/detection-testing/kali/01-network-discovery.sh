#!/bin/bash
#
# Network Discovery Testing Script
# Generates network scanning events for detection testing
#
# Triggers:
# - Firewall logs
# - IDS/IPS alerts
# - Sysmon Event 3 (Network Connection)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Default values
TARGET=""
LOG_FILE="/tmp/network-discovery-$(date +%Y%m%d_%H%M%S).log"
DELAY=2

# Functions
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "$msg" | tee -a "$LOG_FILE"
}

banner() {
    echo -e "${CYAN}"
    echo "============================================================"
    echo "  Network Discovery Detection Test"
    echo "============================================================"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 -t <target> [-d delay]"
    echo ""
    echo "Options:"
    echo "  -t    Target network (e.g., 192.168.1.0/24 or single IP)"
    echo "  -d    Delay between tests in seconds (default: 2)"
    echo ""
    echo "Example:"
    echo "  $0 -t 192.168.1.0/24"
    echo "  $0 -t 192.168.1.100 -d 5"
    exit 1
}

check_tools() {
    local tools=("nmap" "ping" "arping" "nbtscan")
    local missing=()

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}[WARN] Missing tools: ${missing[*]}${NC}"
        echo "Install with: apt install nmap nbtscan arping"
    fi
}

# Parse arguments
while getopts "t:d:h" opt; do
    case $opt in
        t) TARGET="$OPTARG" ;;
        d) DELAY="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$TARGET" ]; then
    usage
fi

# Main
banner

echo -e "${YELLOW}"
echo "WARNING: This script performs network scanning."
echo "Only use in authorized test environments!"
echo -e "${NC}"
echo ""
read -p "Continue? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    echo "Cancelled by user"
    exit 0
fi

log "${CYAN}Starting Network Discovery Tests${NC}"
log "Target: $TARGET"
log "Log file: $LOG_FILE"
echo ""

check_tools

# =============================================================================
# Test 1: ICMP Ping Sweep
# =============================================================================
echo -e "${GREEN}[TEST 1] ICMP Ping Sweep${NC}"
log "[TEST 1] ICMP Ping Sweep"

if command -v nmap &> /dev/null; then
    log "Running: nmap -sn $TARGET"
    nmap -sn "$TARGET" 2>&1 | tee -a "$LOG_FILE"
else
    log "nmap not available, using ping"
    if [[ "$TARGET" == *"/"* ]]; then
        log "Cannot ping sweep without nmap"
    else
        ping -c 3 "$TARGET" 2>&1 | tee -a "$LOG_FILE"
    fi
fi

sleep "$DELAY"

# =============================================================================
# Test 2: ARP Discovery
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 2] ARP Discovery${NC}"
log "[TEST 2] ARP Discovery"

if command -v arping &> /dev/null && [[ "$TARGET" != *"/"* ]]; then
    log "Running: arping -c 3 $TARGET"
    arping -c 3 "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
else
    log "arping not available or target is network range"
fi

sleep "$DELAY"

# =============================================================================
# Test 3: NetBIOS Discovery
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 3] NetBIOS Name Discovery${NC}"
log "[TEST 3] NetBIOS Discovery"

if command -v nbtscan &> /dev/null; then
    log "Running: nbtscan $TARGET"
    nbtscan "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
else
    log "nbtscan not available"
fi

sleep "$DELAY"

# =============================================================================
# Test 4: TCP SYN Discovery
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 4] TCP SYN Discovery (common ports)${NC}"
log "[TEST 4] TCP SYN Discovery"

if command -v nmap &> /dev/null; then
    log "Running: nmap -sS -p 22,80,135,139,443,445,3389 --open $TARGET"
    sudo nmap -sS -p 22,80,135,139,443,445,3389 --open "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
else
    log "nmap not available"
fi

sleep "$DELAY"

# =============================================================================
# Test 5: UDP Discovery
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 5] UDP Discovery (DNS, SNMP, NTP)${NC}"
log "[TEST 5] UDP Discovery"

if command -v nmap &> /dev/null; then
    log "Running: nmap -sU -p 53,123,161 --open $TARGET"
    sudo nmap -sU -p 53,123,161 --open "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
else
    log "nmap not available"
fi

sleep "$DELAY"

# =============================================================================
# Test 6: OS Detection (generates more traffic)
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 6] OS Detection Attempt${NC}"
log "[TEST 6] OS Detection"

if command -v nmap &> /dev/null; then
    # Only run on single host
    if [[ "$TARGET" != *"/"* ]]; then
        log "Running: nmap -O $TARGET"
        sudo nmap -O "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
    else
        log "OS detection skipped for network range (too noisy)"
    fi
else
    log "nmap not available"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${GREEN}  Network Discovery Tests Complete!${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

log "Tests completed at $(date)"
echo ""
echo -e "${YELLOW}Verification:${NC}"
echo "1. Check target firewall logs for connection attempts"
echo "2. Check Sysmon Event 3 for network connections"
echo "3. Grafana query: {job=\"windows_sysmon\"} |~ \"$(hostname -I | awk '{print $1}')\""
echo ""
echo "Log saved to: $LOG_FILE"
