#!/bin/bash
#
# Port Scanning Detection Testing Script
# Tests various scanning techniques for detection validation
#
# Triggers:
# - IDS/IPS port scan alerts
# - Firewall connection logs
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
LOG_FILE="/tmp/port-scanning-$(date +%Y%m%d_%H%M%S).log"
DELAY=3

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "$msg" | tee -a "$LOG_FILE"
}

banner() {
    echo -e "${CYAN}"
    echo "============================================================"
    echo "  Port Scanning Detection Test"
    echo "============================================================"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 -t <target_ip> [-d delay]"
    echo ""
    echo "Options:"
    echo "  -t    Target IP address (single host)"
    echo "  -d    Delay between tests in seconds (default: 3)"
    echo ""
    exit 1
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

# Validate single IP
if [[ "$TARGET" == *"/"* ]]; then
    echo -e "${RED}Error: Please specify single IP, not network range${NC}"
    exit 1
fi

banner

echo -e "${YELLOW}"
echo "WARNING: This script performs intensive port scanning."
echo "This WILL trigger IDS/IPS alerts!"
echo "Only use in authorized test environments!"
echo -e "${NC}"
echo ""
read -p "Continue? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    echo "Cancelled by user"
    exit 0
fi

log "${CYAN}Starting Port Scanning Tests${NC}"
log "Target: $TARGET"
log "Log file: $LOG_FILE"
echo ""

# Check for nmap
if ! command -v nmap &> /dev/null; then
    echo -e "${RED}Error: nmap is required but not installed${NC}"
    echo "Install with: apt install nmap"
    exit 1
fi

# =============================================================================
# Test 1: TCP Connect Scan (noisy but common)
# =============================================================================
echo -e "${GREEN}[TEST 1] TCP Connect Scan (-sT)${NC}"
log "[TEST 1] TCP Connect Scan"

log "Running: nmap -sT -p 1-1000 $TARGET"
nmap -sT -p 1-1000 "$TARGET" 2>&1 | tee -a "$LOG_FILE"

sleep "$DELAY"

# =============================================================================
# Test 2: TCP SYN Scan (stealthier)
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 2] TCP SYN Scan (-sS)${NC}"
log "[TEST 2] TCP SYN Scan"

log "Running: nmap -sS -p 1-1000 $TARGET"
sudo nmap -sS -p 1-1000 "$TARGET" 2>&1 | tee -a "$LOG_FILE"

sleep "$DELAY"

# =============================================================================
# Test 3: TCP FIN Scan (evasion technique)
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 3] TCP FIN Scan (-sF)${NC}"
log "[TEST 3] TCP FIN Scan"

log "Running: nmap -sF -p 21,22,23,25,80,443,445,3389 $TARGET"
sudo nmap -sF -p 21,22,23,25,80,443,445,3389 "$TARGET" 2>&1 | tee -a "$LOG_FILE"

sleep "$DELAY"

# =============================================================================
# Test 4: TCP NULL Scan
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 4] TCP NULL Scan (-sN)${NC}"
log "[TEST 4] TCP NULL Scan"

log "Running: nmap -sN -p 21,22,23,25,80,443,445,3389 $TARGET"
sudo nmap -sN -p 21,22,23,25,80,443,445,3389 "$TARGET" 2>&1 | tee -a "$LOG_FILE"

sleep "$DELAY"

# =============================================================================
# Test 5: TCP XMAS Scan
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 5] TCP XMAS Scan (-sX)${NC}"
log "[TEST 5] TCP XMAS Scan"

log "Running: nmap -sX -p 21,22,23,25,80,443,445,3389 $TARGET"
sudo nmap -sX -p 21,22,23,25,80,443,445,3389 "$TARGET" 2>&1 | tee -a "$LOG_FILE"

sleep "$DELAY"

# =============================================================================
# Test 6: Version Detection
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 6] Service Version Detection (-sV)${NC}"
log "[TEST 6] Service Version Detection"

log "Running: nmap -sV --version-intensity 5 -p 22,80,135,139,443,445,3389 $TARGET"
nmap -sV --version-intensity 5 -p 22,80,135,139,443,445,3389 "$TARGET" 2>&1 | tee -a "$LOG_FILE"

sleep "$DELAY"

# =============================================================================
# Test 7: Aggressive Scan
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 7] Aggressive Scan (-A)${NC}"
log "[TEST 7] Aggressive Scan"

log "Running: nmap -A -p 22,80,135,139,443,445,3389 $TARGET"
sudo nmap -A -p 22,80,135,139,443,445,3389 "$TARGET" 2>&1 | tee -a "$LOG_FILE"

sleep "$DELAY"

# =============================================================================
# Test 8: UDP Scan (slow)
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 8] UDP Scan (-sU)${NC}"
log "[TEST 8] UDP Scan"

log "Running: nmap -sU --top-ports 20 $TARGET"
sudo nmap -sU --top-ports 20 "$TARGET" 2>&1 | tee -a "$LOG_FILE"

sleep "$DELAY"

# =============================================================================
# Test 9: Script Scan (vuln detection)
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 9] NSE Script Scan${NC}"
log "[TEST 9] NSE Script Scan"

log "Running: nmap --script=default,vuln -p 445 $TARGET"
sudo nmap --script=default,vuln -p 445 "$TARGET" 2>&1 | tee -a "$LOG_FILE"

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${GREEN}  Port Scanning Tests Complete!${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

log "Tests completed at $(date)"
echo ""
echo -e "${YELLOW}Detection Verification:${NC}"
echo ""
echo "1. IDS Alerts:"
echo "   - Check Snort/Suricata for port scan alerts"
echo ""
echo "2. Windows Firewall:"
echo "   {job=\"windows_firewall\"} |= \"DROP\""
echo ""
echo "3. Sysmon Network Connections:"
echo "   {job=\"windows_sysmon\", event_id=\"3\"}"
echo ""
echo "4. Expected alert types:"
echo "   - Port scan detected"
echo "   - Multiple connection attempts"
echo "   - Service enumeration"
echo ""
echo "Log saved to: $LOG_FILE"
