#!/bin/bash
#
# SMB/Windows Enumeration Testing Script
# Tests SMB enumeration techniques for detection validation
#
# Triggers:
# - Event 4625: Failed Logon
# - Event 5140-5145: Network Share Access
# - Event 4776: Credential Validation
# - Sysmon Event 3: Network Connection
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
USERNAME="guest"
PASSWORD=""
DOMAIN=""
LOG_FILE="/tmp/smb-enum-$(date +%Y%m%d_%H%M%S).log"
DELAY=2

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "$msg" | tee -a "$LOG_FILE"
}

banner() {
    echo -e "${CYAN}"
    echo "============================================================"
    echo "  SMB/Windows Enumeration Detection Test"
    echo "============================================================"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 -t <target_ip> [-u username] [-p password] [-d domain]"
    echo ""
    echo "Options:"
    echo "  -t    Target IP address"
    echo "  -u    Username (default: guest)"
    echo "  -p    Password (default: empty)"
    echo "  -d    Domain (optional)"
    echo ""
    exit 1
}

check_tools() {
    local tools=("smbclient" "rpcclient" "enum4linux" "crackmapexec" "nbtscan")
    local missing=()

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}[WARN] Missing tools: ${missing[*]}${NC}"
    fi
}

# Parse arguments
while getopts "t:u:p:d:h" opt; do
    case $opt in
        t) TARGET="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        d) DOMAIN="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$TARGET" ]; then
    usage
fi

banner

echo -e "${YELLOW}"
echo "WARNING: This script performs SMB enumeration."
echo "This will generate authentication events!"
echo "Only use in authorized test environments!"
echo -e "${NC}"
echo ""
read -p "Continue? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    echo "Cancelled by user"
    exit 0
fi

log "${CYAN}Starting SMB Enumeration Tests${NC}"
log "Target: $TARGET"
log "Username: $USERNAME"
log "Log file: $LOG_FILE"
echo ""

check_tools

# Build credential string
if [ -n "$DOMAIN" ]; then
    CRED_STR="$DOMAIN/$USERNAME"
else
    CRED_STR="$USERNAME"
fi

# =============================================================================
# Test 1: NetBIOS Name Query
# =============================================================================
echo -e "${GREEN}[TEST 1] NetBIOS Name Query${NC}"
log "[TEST 1] NetBIOS Name Query"

if command -v nbtscan &> /dev/null; then
    log "Running: nbtscan $TARGET"
    nbtscan "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
fi

if command -v nmblookup &> /dev/null; then
    log "Running: nmblookup -A $TARGET"
    nmblookup -A "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
fi

sleep "$DELAY"

# =============================================================================
# Test 2: SMB Null Session
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 2] SMB Null Session Attempt${NC}"
log "[TEST 2] SMB Null Session"

if command -v smbclient &> /dev/null; then
    log "Running: smbclient -N -L //$TARGET"
    smbclient -N -L "//$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
fi

sleep "$DELAY"

# =============================================================================
# Test 3: Share Enumeration
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 3] Share Enumeration${NC}"
log "[TEST 3] Share Enumeration"

if command -v smbclient &> /dev/null; then
    if [ -n "$PASSWORD" ]; then
        log "Running: smbclient -U $CRED_STR%[REDACTED] -L //$TARGET"
        smbclient -U "$CRED_STR%$PASSWORD" -L "//$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
    else
        log "Running: smbclient -U $CRED_STR -N -L //$TARGET"
        smbclient -U "$CRED_STR" -N -L "//$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
    fi
fi

sleep "$DELAY"

# =============================================================================
# Test 4: RPC Enumeration
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 4] RPC User/Group Enumeration${NC}"
log "[TEST 4] RPC Enumeration"

if command -v rpcclient &> /dev/null; then
    log "Running: rpcclient -U '' -N $TARGET -c 'enumdomusers'"
    rpcclient -U "" -N "$TARGET" -c "enumdomusers" 2>&1 | tee -a "$LOG_FILE" || true

    log "Running: rpcclient -U '' -N $TARGET -c 'enumdomgroups'"
    rpcclient -U "" -N "$TARGET" -c "enumdomgroups" 2>&1 | tee -a "$LOG_FILE" || true

    log "Running: rpcclient -U '' -N $TARGET -c 'lsaenumsid'"
    rpcclient -U "" -N "$TARGET" -c "lsaenumsid" 2>&1 | tee -a "$LOG_FILE" || true
fi

sleep "$DELAY"

# =============================================================================
# Test 5: enum4linux Full Enumeration
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 5] enum4linux Full Enumeration${NC}"
log "[TEST 5] enum4linux"

if command -v enum4linux &> /dev/null; then
    log "Running: enum4linux -a $TARGET"
    enum4linux -a "$TARGET" 2>&1 | head -100 | tee -a "$LOG_FILE" || true
elif command -v enum4linux-ng &> /dev/null; then
    log "Running: enum4linux-ng -A $TARGET"
    enum4linux-ng -A "$TARGET" 2>&1 | head -100 | tee -a "$LOG_FILE" || true
fi

sleep "$DELAY"

# =============================================================================
# Test 6: CrackMapExec Enumeration
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 6] CrackMapExec SMB Enumeration${NC}"
log "[TEST 6] CrackMapExec"

if command -v crackmapexec &> /dev/null; then
    log "Running: crackmapexec smb $TARGET --shares"
    crackmapexec smb "$TARGET" --shares 2>&1 | tee -a "$LOG_FILE" || true

    log "Running: crackmapexec smb $TARGET --users"
    crackmapexec smb "$TARGET" --users 2>&1 | tee -a "$LOG_FILE" || true

    log "Running: crackmapexec smb $TARGET --groups"
    crackmapexec smb "$TARGET" --groups 2>&1 | tee -a "$LOG_FILE" || true
elif command -v netexec &> /dev/null; then
    log "Running: netexec smb $TARGET --shares"
    netexec smb "$TARGET" --shares 2>&1 | tee -a "$LOG_FILE" || true
fi

sleep "$DELAY"

# =============================================================================
# Test 7: SMB Version Detection
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 7] SMB Version Detection${NC}"
log "[TEST 7] SMB Version"

if command -v nmap &> /dev/null; then
    log "Running: nmap --script smb-protocols -p 445 $TARGET"
    nmap --script smb-protocols -p 445 "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
fi

sleep "$DELAY"

# =============================================================================
# Test 8: SMB Security Scan
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 8] SMB Security Scan${NC}"
log "[TEST 8] SMB Security"

if command -v nmap &> /dev/null; then
    log "Running: nmap --script smb-security-mode -p 445 $TARGET"
    nmap --script smb-security-mode -p 445 "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true

    log "Running: nmap --script smb2-security-mode -p 445 $TARGET"
    nmap --script smb2-security-mode -p 445 "$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${GREEN}  SMB Enumeration Tests Complete!${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

log "Tests completed at $(date)"
echo ""
echo -e "${YELLOW}Detection Verification:${NC}"
echo ""
echo "1. Failed Logon Events (4625):"
echo "   {job=\"windows_auth\"} |= \"4625\""
echo ""
echo "2. Share Access Events (5140-5145):"
echo "   {job=\"windows_shares\"} |~ \"514[0-5]\""
echo ""
echo "3. Credential Validation (4776):"
echo "   {job=\"windows_auth\"} |= \"4776\""
echo ""
echo "4. Network Connections (Sysmon 3):"
echo "   {job=\"windows_sysmon\", event_id=\"3\"} |= \"445\""
echo ""
echo "Log saved to: $LOG_FILE"
