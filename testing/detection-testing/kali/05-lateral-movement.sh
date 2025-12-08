#!/bin/bash
#
# Lateral Movement Testing Script
# Tests remote execution techniques for detection validation
#
# Triggers:
# - Event 4624: Successful Logon (Type 3, 10)
# - Event 4648: Explicit Credentials
# - Event 4688: Process Create
# - Event 7045: Service Installed
# - Sysmon Event 1: Process Create
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
USERNAME=""
PASSWORD=""
DOMAIN=""
LOG_FILE="/tmp/lateral-movement-$(date +%Y%m%d_%H%M%S).log"
DELAY=3

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "$msg" | tee -a "$LOG_FILE"
}

banner() {
    echo -e "${CYAN}"
    echo "============================================================"
    echo "  Lateral Movement Detection Test"
    echo "============================================================"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 -t <target_ip> -u <username> -p <password> [-d domain]"
    echo ""
    echo "Options:"
    echo "  -t    Target IP address"
    echo "  -u    Username with admin rights on target"
    echo "  -p    Password"
    echo "  -d    Domain (optional)"
    echo ""
    echo "NOTE: This test requires VALID credentials with admin access"
    exit 1
}

check_tools() {
    local tools=("impacket-psexec" "impacket-wmiexec" "impacket-smbexec" "crackmapexec" "evil-winrm")
    local missing=()

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}[WARN] Missing tools: ${missing[*]}${NC}"
        echo "Install with: apt install impacket-scripts evil-winrm"
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

if [ -z "$TARGET" ] || [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
    usage
fi

banner

echo -e "${YELLOW}"
echo "WARNING: This script performs lateral movement techniques."
echo "This will:"
echo "  - Create remote services"
echo "  - Execute commands on target"
echo "  - Generate authentication events"
echo ""
echo "Only use with VALID AUTHORIZATION!"
echo -e "${NC}"
echo ""
read -p "Continue? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    echo "Cancelled by user"
    exit 0
fi

log "${CYAN}Starting Lateral Movement Tests${NC}"
log "Target: $TARGET"
log "Username: $USERNAME"
log "Log file: $LOG_FILE"
echo ""

check_tools

# Build credential string
if [ -n "$DOMAIN" ]; then
    CRED_STR="$DOMAIN/$USERNAME:$PASSWORD"
    IMPACKET_CRED="$DOMAIN/$USERNAME:$PASSWORD@$TARGET"
else
    CRED_STR="$USERNAME:$PASSWORD"
    IMPACKET_CRED="$USERNAME:$PASSWORD@$TARGET"
fi

# =============================================================================
# Test 1: PsExec (creates service PSEXESVC)
# =============================================================================
echo -e "${GREEN}[TEST 1] PsExec Remote Execution${NC}"
log "[TEST 1] PsExec"

if command -v impacket-psexec &> /dev/null; then
    log "Running: impacket-psexec $IMPACKET_CRED 'cmd /c whoami'"
    echo "whoami" | timeout 30 impacket-psexec "$IMPACKET_CRED" 2>&1 | tee -a "$LOG_FILE" || true
elif command -v psexec.py &> /dev/null; then
    echo "whoami" | timeout 30 psexec.py "$IMPACKET_CRED" 2>&1 | tee -a "$LOG_FILE" || true
else
    log "impacket-psexec not available"
fi

sleep "$DELAY"

# =============================================================================
# Test 2: WMI Execution
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 2] WMI Remote Execution${NC}"
log "[TEST 2] WMI Execution"

if command -v impacket-wmiexec &> /dev/null; then
    log "Running: impacket-wmiexec $IMPACKET_CRED 'whoami'"
    echo "whoami" | timeout 30 impacket-wmiexec "$IMPACKET_CRED" 2>&1 | tee -a "$LOG_FILE" || true
elif command -v wmiexec.py &> /dev/null; then
    echo "whoami" | timeout 30 wmiexec.py "$IMPACKET_CRED" 2>&1 | tee -a "$LOG_FILE" || true
else
    log "impacket-wmiexec not available"
fi

sleep "$DELAY"

# =============================================================================
# Test 3: SMBExec (file-based)
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 3] SMBExec Remote Execution${NC}"
log "[TEST 3] SMBExec"

if command -v impacket-smbexec &> /dev/null; then
    log "Running: impacket-smbexec $IMPACKET_CRED 'whoami'"
    echo "whoami" | timeout 30 impacket-smbexec "$IMPACKET_CRED" 2>&1 | tee -a "$LOG_FILE" || true
elif command -v smbexec.py &> /dev/null; then
    echo "whoami" | timeout 30 smbexec.py "$IMPACKET_CRED" 2>&1 | tee -a "$LOG_FILE" || true
else
    log "impacket-smbexec not available"
fi

sleep "$DELAY"

# =============================================================================
# Test 4: WinRM Execution
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 4] WinRM Remote Execution${NC}"
log "[TEST 4] WinRM"

if command -v evil-winrm &> /dev/null; then
    log "Running: evil-winrm -i $TARGET -u $USERNAME -p [REDACTED] -c 'whoami'"
    echo "whoami" | timeout 30 evil-winrm -i "$TARGET" -u "$USERNAME" -p "$PASSWORD" 2>&1 | tee -a "$LOG_FILE" || true
else
    log "evil-winrm not available"
fi

sleep "$DELAY"

# =============================================================================
# Test 5: DCOM Execution
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 5] DCOM Remote Execution${NC}"
log "[TEST 5] DCOM"

if command -v impacket-dcomexec &> /dev/null; then
    log "Running: impacket-dcomexec $IMPACKET_CRED 'whoami'"
    echo "whoami" | timeout 30 impacket-dcomexec "$IMPACKET_CRED" 2>&1 | tee -a "$LOG_FILE" || true
elif command -v dcomexec.py &> /dev/null; then
    echo "whoami" | timeout 30 dcomexec.py "$IMPACKET_CRED" 2>&1 | tee -a "$LOG_FILE" || true
else
    log "impacket-dcomexec not available"
fi

sleep "$DELAY"

# =============================================================================
# Test 6: CrackMapExec Command Execution
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 6] CrackMapExec Execution${NC}"
log "[TEST 6] CrackMapExec"

if command -v crackmapexec &> /dev/null; then
    log "Running: crackmapexec smb $TARGET -u $USERNAME -p [REDACTED] -x 'whoami'"
    crackmapexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" -x "whoami" 2>&1 | tee -a "$LOG_FILE" || true

    log "Running: crackmapexec smb $TARGET -u $USERNAME -p [REDACTED] -X 'Get-Process | Select -First 3'"
    crackmapexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" -X "Get-Process | Select -First 3" 2>&1 | tee -a "$LOG_FILE" || true
elif command -v netexec &> /dev/null; then
    netexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" -x "whoami" 2>&1 | tee -a "$LOG_FILE" || true
else
    log "crackmapexec/netexec not available"
fi

sleep "$DELAY"

# =============================================================================
# Test 7: Scheduled Task Creation
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 7] Remote Scheduled Task${NC}"
log "[TEST 7] Scheduled Task"

if command -v impacket-atexec &> /dev/null; then
    log "Running: impacket-atexec $IMPACKET_CRED 'whoami'"
    timeout 30 impacket-atexec "$IMPACKET_CRED" "whoami" 2>&1 | tee -a "$LOG_FILE" || true
elif command -v atexec.py &> /dev/null; then
    timeout 30 atexec.py "$IMPACKET_CRED" "whoami" 2>&1 | tee -a "$LOG_FILE" || true
else
    log "impacket-atexec not available"
fi

sleep "$DELAY"

# =============================================================================
# Test 8: Remote Service Creation
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 8] Remote Service Creation${NC}"
log "[TEST 8] Service Creation"

if command -v impacket-services &> /dev/null; then
    log "Listing remote services..."
    timeout 30 impacket-services "$IMPACKET_CRED" list 2>&1 | head -20 | tee -a "$LOG_FILE" || true
elif command -v services.py &> /dev/null; then
    timeout 30 services.py "$IMPACKET_CRED" list 2>&1 | head -20 | tee -a "$LOG_FILE" || true
else
    log "impacket-services not available"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${GREEN}  Lateral Movement Tests Complete!${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

log "Tests completed at $(date)"
echo ""
echo -e "${YELLOW}Detection Verification:${NC}"
echo ""
echo "1. Network Logon Events (4624 Type 3):"
echo "   {job=\"windows_auth\"} |= \"4624\" |= \"Logon Type:.*3\""
echo ""
echo "2. Explicit Credential Use (4648):"
echo "   {job=\"windows_auth\"} |= \"4648\""
echo ""
echo "3. Service Installation (7045):"
echo "   {job=\"windows_services\"} |= \"7045\""
echo ""
echo "4. Process Creation (4688):"
echo "   {job=\"windows_process\"} |= \"4688\" |= \"PSEXE\""
echo ""
echo "5. Sysmon Process (Event 1):"
echo "   {job=\"windows_sysmon\", event_id=\"1\"}"
echo ""
echo "6. WMI Activity:"
echo "   {job=\"windows_sysmon\"} |= \"WmiPrvSE\""
echo ""
echo "Log saved to: $LOG_FILE"
