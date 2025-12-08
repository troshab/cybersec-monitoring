#!/bin/bash
#
# Persistence Simulation Testing Script
# Tests persistence technique detection from remote attacker perspective
#
# Triggers:
# - Event 7045: Service Installed
# - Event 4698: Scheduled Task Created
# - Event 4697: Security Service Install
# - Registry modification events
# - Sysmon Events 12, 13 (Registry)
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
LOG_FILE="/tmp/persistence-sim-$(date +%Y%m%d_%H%M%S).log"
DELAY=3

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "$msg" | tee -a "$LOG_FILE"
}

banner() {
    echo -e "${CYAN}"
    echo "============================================================"
    echo "  Persistence Simulation Detection Test"
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
    local tools=("impacket-smbexec" "impacket-wmiexec" "crackmapexec" "smbclient")
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

if [ -z "$TARGET" ] || [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
    usage
fi

banner

echo -e "${YELLOW}"
echo "WARNING: This script simulates persistence techniques."
echo "This will:"
echo "  - Create services on target (then remove)"
echo "  - Create scheduled tasks (then remove)"
echo "  - Modify registry entries (then revert)"
echo ""
echo "All changes are CLEANED UP after testing!"
echo "Only use with VALID AUTHORIZATION!"
echo -e "${NC}"
echo ""
read -p "Continue? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    echo "Cancelled by user"
    exit 0
fi

log "${CYAN}Starting Persistence Simulation Tests${NC}"
log "Target: $TARGET"
log "Username: $USERNAME"
log "Log file: $LOG_FILE"
echo ""

check_tools

# Build credential string
if [ -n "$DOMAIN" ]; then
    IMPACKET_CRED="$DOMAIN/$USERNAME:$PASSWORD@$TARGET"
    CME_DOMAIN="-d $DOMAIN"
else
    IMPACKET_CRED="$USERNAME:$PASSWORD@$TARGET"
    CME_DOMAIN=""
fi

# Test service name
TEST_SVC="TestPersistSvc"
TEST_TASK="TestPersistTask"

# =============================================================================
# Test 1: Remote Service Creation (Event 7045)
# =============================================================================
echo -e "${GREEN}[TEST 1] Remote Service Creation${NC}"
log "[TEST 1] Remote Service Creation"

if command -v crackmapexec &> /dev/null; then
    # Create service
    log "Creating test service: $TEST_SVC"
    crackmapexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" $CME_DOMAIN \
        -x "sc create $TEST_SVC binPath= \"cmd.exe /c echo test\" start= demand" 2>&1 | tee -a "$LOG_FILE" || true

    sleep 2

    # Cleanup
    log "Removing test service: $TEST_SVC"
    crackmapexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" $CME_DOMAIN \
        -x "sc delete $TEST_SVC" 2>&1 | tee -a "$LOG_FILE" || true
elif command -v netexec &> /dev/null; then
    netexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" $CME_DOMAIN \
        -x "sc create $TEST_SVC binPath= \"cmd.exe /c echo test\" start= demand" 2>&1 | tee -a "$LOG_FILE" || true
    sleep 2
    netexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" $CME_DOMAIN \
        -x "sc delete $TEST_SVC" 2>&1 | tee -a "$LOG_FILE" || true
else
    log "crackmapexec/netexec not available"
fi

sleep "$DELAY"

# =============================================================================
# Test 2: Suspicious Service Path (PowerShell)
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 2] Suspicious Service (PowerShell path)${NC}"
log "[TEST 2] Suspicious PowerShell Service"

SUSPICIOUS_SVC="TestSuspiciousSvc"

if command -v crackmapexec &> /dev/null; then
    log "Creating suspicious service with PowerShell"
    crackmapexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" $CME_DOMAIN \
        -x "sc create $SUSPICIOUS_SVC binPath= \"powershell.exe -nop -w hidden -c Get-Date\" start= demand" 2>&1 | tee -a "$LOG_FILE" || true

    sleep 2

    log "Removing suspicious service"
    crackmapexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" $CME_DOMAIN \
        -x "sc delete $SUSPICIOUS_SVC" 2>&1 | tee -a "$LOG_FILE" || true
fi

sleep "$DELAY"

# =============================================================================
# Test 3: Scheduled Task Creation (Event 4698)
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 3] Remote Scheduled Task Creation${NC}"
log "[TEST 3] Scheduled Task Creation"

if command -v crackmapexec &> /dev/null; then
    log "Creating scheduled task: $TEST_TASK"
    crackmapexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" $CME_DOMAIN \
        -x "schtasks /create /tn $TEST_TASK /tr \"cmd.exe /c echo test\" /sc once /st 23:59 /ru SYSTEM /f" 2>&1 | tee -a "$LOG_FILE" || true

    sleep 2

    log "Removing scheduled task: $TEST_TASK"
    crackmapexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" $CME_DOMAIN \
        -x "schtasks /delete /tn $TEST_TASK /f" 2>&1 | tee -a "$LOG_FILE" || true
fi

sleep "$DELAY"

# =============================================================================
# Test 4: Registry Run Key Persistence
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 4] Registry Run Key Persistence${NC}"
log "[TEST 4] Registry Run Key"

REG_VALUE="TestPersistence"

if command -v crackmapexec &> /dev/null; then
    log "Adding Run key entry"
    crackmapexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" $CME_DOMAIN \
        -x "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v $REG_VALUE /t REG_SZ /d \"cmd.exe /c echo test\" /f" 2>&1 | tee -a "$LOG_FILE" || true

    sleep 2

    log "Removing Run key entry"
    crackmapexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" $CME_DOMAIN \
        -x "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v $REG_VALUE /f" 2>&1 | tee -a "$LOG_FILE" || true
fi

sleep "$DELAY"

# =============================================================================
# Test 5: WMI Event Subscription (Advanced Persistence)
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 5] WMI Event Subscription Query${NC}"
log "[TEST 5] WMI Event Subscription"

if command -v impacket-wmiexec &> /dev/null; then
    log "Querying WMI event subscriptions (detection test)"
    echo 'wmic /namespace:\\root\subscription path __EventFilter get Name' | \
        timeout 30 impacket-wmiexec "$IMPACKET_CRED" 2>&1 | tee -a "$LOG_FILE" || true

    echo 'wmic /namespace:\\root\subscription path CommandLineEventConsumer get Name' | \
        timeout 30 impacket-wmiexec "$IMPACKET_CRED" 2>&1 | tee -a "$LOG_FILE" || true
else
    log "impacket-wmiexec not available"
fi

sleep "$DELAY"

# =============================================================================
# Test 6: Startup Folder Persistence
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 6] Startup Folder Persistence${NC}"
log "[TEST 6] Startup Folder"

if command -v smbclient &> /dev/null && [ -n "$PASSWORD" ]; then
    STARTUP_PATH="Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"

    log "Checking startup folder access"
    echo "ls \"$STARTUP_PATH\"" | \
        smbclient "//$TARGET/C\$" -U "$USERNAME%$PASSWORD" 2>&1 | tee -a "$LOG_FILE" || true
else
    log "smbclient not available or no password"
fi

sleep "$DELAY"

# =============================================================================
# Test 7: COM Hijacking Query
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 7] COM Hijacking Detection${NC}"
log "[TEST 7] COM Hijacking Query"

if command -v crackmapexec &> /dev/null; then
    log "Querying COM objects in HKCU"
    crackmapexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" $CME_DOMAIN \
        -x "reg query \"HKCU\\Software\\Classes\\CLSID\" /s 2>nul | findstr /i \"InprocServer32\" | head -10" 2>&1 | tee -a "$LOG_FILE" || true
fi

sleep "$DELAY"

# =============================================================================
# Test 8: User Account Creation
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 8] Remote User Account Creation${NC}"
log "[TEST 8] User Creation"

TEST_USER="TestPersistUser"

if command -v crackmapexec &> /dev/null; then
    log "Creating test user: $TEST_USER"
    crackmapexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" $CME_DOMAIN \
        -x "net user $TEST_USER P@ssw0rd123! /add" 2>&1 | tee -a "$LOG_FILE" || true

    sleep 2

    log "Adding to administrators"
    crackmapexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" $CME_DOMAIN \
        -x "net localgroup Administrators $TEST_USER /add" 2>&1 | tee -a "$LOG_FILE" || true

    sleep 2

    log "Removing test user"
    crackmapexec smb "$TARGET" -u "$USERNAME" -p "$PASSWORD" $CME_DOMAIN \
        -x "net user $TEST_USER /delete" 2>&1 | tee -a "$LOG_FILE" || true
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${GREEN}  Persistence Simulation Tests Complete!${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

log "Tests completed at $(date)"
echo ""
echo -e "${YELLOW}Detection Verification:${NC}"
echo ""
echo "1. Service Installation (7045):"
echo "   {job=\"windows_services\"} |= \"7045\" |~ \"TestPersist|Suspicious\""
echo ""
echo "2. Scheduled Task Creation (4698):"
echo "   {job=\"windows_persistence\"} |= \"4698\""
echo ""
echo "3. Security Service Install (4697):"
echo "   {job=\"windows_persistence\"} |= \"4697\""
echo ""
echo "4. Registry Modification (Sysmon 12, 13):"
echo "   {job=\"windows_sysmon\"} |~ \"event_id=\\\"1[23]\\\"\" |= \"Run\""
echo ""
echo "5. User Account Events (4720, 4732):"
echo "   {job=\"windows_accounts\"} |~ \"4720|4732\" |= \"TestPersist\""
echo ""
echo "6. Suspicious Binaries in Services:"
echo "   {job=\"windows_services\"} |~ \"powershell|cmd.*hidden\""
echo ""
echo "Log saved to: $LOG_FILE"
