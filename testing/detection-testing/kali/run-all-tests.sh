#!/bin/bash
#
# Kali Detection Testing - Master Script
# Runs all detection tests sequentially
#
# Usage: ./run-all-tests.sh -t <target_ip> [-u username] [-p password] [-d delay]
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Default values
TARGET=""
USERNAME=""
PASSWORD=""
DOMAIN=""
DELAY=10
SKIP_TESTS=""
LOG_FILE="/tmp/kali-tests-$(date +%Y%m%d_%H%M%S).log"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

banner() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'
 ██╗  ██╗ █████╗ ██╗     ██╗    ████████╗███████╗███████╗████████╗███████╗
 ██║ ██╔╝██╔══██╗██║     ██║    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝
 █████╔╝ ███████║██║     ██║       ██║   █████╗  ███████╗   ██║   ███████╗
 ██╔═██╗ ██╔══██║██║     ██║       ██║   ██╔══╝  ╚════██║   ██║   ╚════██║
 ██║  ██╗██║  ██║███████╗██║       ██║   ███████╗███████║   ██║   ███████║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝       ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝
EOF
    echo -e "${NC}"
    echo -e "${MAGENTA}  Detection Testing Suite - Attack Simulation${NC}"
    echo ""
}

usage() {
    echo "Usage: $0 -t <target_ip> [options]"
    echo ""
    echo "Required:"
    echo "  -t    Target IP address"
    echo ""
    echo "Optional:"
    echo "  -u    Username (required for tests 5-6)"
    echo "  -p    Password (required for tests 5-6)"
    echo "  -D    Domain"
    echo "  -d    Delay between tests in seconds (default: 10)"
    echo "  -s    Skip tests (comma-separated, e.g., 5,6)"
    echo ""
    echo "Examples:"
    echo "  $0 -t 192.168.1.100"
    echo "  $0 -t 192.168.1.100 -u admin -p 'P@ssw0rd' -d 30"
    echo "  $0 -t 192.168.1.100 -s 5,6"
    echo ""
    exit 1
}

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "$msg" | tee -a "$LOG_FILE"
}

run_test() {
    local num=$1
    local name=$2
    local script=$3
    local args=$4

    echo ""
    echo -e "${MAGENTA}************************************************************${NC}"
    echo -e "${MAGENTA}  TEST $num: $name${NC}"
    echo -e "${MAGENTA}************************************************************${NC}"
    echo ""

    if [[ ",$SKIP_TESTS," == *",$num,"* ]]; then
        echo -e "${YELLOW}[SKIP] Test $num skipped by user${NC}"
        return 0
    fi

    if [ -f "$SCRIPT_DIR/$script" ]; then
        log "Starting: $script"
        bash "$SCRIPT_DIR/$script" $args <<< "y" || true
        log "Completed: $script"
    else
        echo -e "${RED}[ERROR] Script not found: $script${NC}"
        return 1
    fi
}

# Parse arguments
while getopts "t:u:p:D:d:s:h" opt; do
    case $opt in
        t) TARGET="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        D) DOMAIN="$OPTARG" ;;
        d) DELAY="$OPTARG" ;;
        s) SKIP_TESTS="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$TARGET" ]; then
    usage
fi

banner

echo -e "${YELLOW}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                         WARNING                                   ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  This script performs security testing including:                ║"
echo "║    - Network scanning and enumeration                            ║"
echo "║    - Password attacks and brute force                            ║"
echo "║    - Lateral movement techniques                                 ║"
echo "║    - Persistence mechanism testing                               ║"
echo "║                                                                   ║"
echo "║  Only use with EXPLICIT AUTHORIZATION!                           ║"
echo "║  For testing environments ONLY!                                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

read -p "Do you have authorization to test $TARGET? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    echo "Cancelled by user"
    exit 0
fi

# Start time
START_TIME=$(date +%s)

log "${CYAN}Starting Kali Detection Test Suite${NC}"
log "Target: $TARGET"
log "Log file: $LOG_FILE"
log "Skip tests: ${SKIP_TESTS:-none}"
echo ""

# =============================================================================
# Test Matrix
# =============================================================================
echo -e "${CYAN}Test Plan:${NC}"
echo "  1. Network Discovery    - ICMP, ARP, NetBIOS scanning"
echo "  2. Port Scanning        - TCP/UDP port enumeration"
echo "  3. SMB Enumeration      - Windows share/user enumeration"
echo "  4. Credential Attacks   - Password spraying, brute force"
echo "  5. Lateral Movement     - PsExec, WMI, WinRM (requires creds)"
echo "  6. Persistence Sim      - Service, task, registry (requires creds)"
echo ""

# Check if credentials provided for advanced tests
if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
    echo -e "${YELLOW}[NOTE] Username/password not provided.${NC}"
    echo -e "${YELLOW}       Tests 5-6 (lateral movement, persistence) will be skipped.${NC}"
    SKIP_TESTS="${SKIP_TESTS:+$SKIP_TESTS,}5,6"
    echo ""
fi

sleep 2

# =============================================================================
# Run Tests
# =============================================================================

# Test 1: Network Discovery
run_test 1 "Network Discovery" "01-network-discovery.sh" "-t $TARGET"
echo -e "${GRAY}Waiting $DELAY seconds before next test...${NC}"
sleep "$DELAY"

# Test 2: Port Scanning
run_test 2 "Port Scanning" "02-port-scanning.sh" "-t $TARGET"
echo -e "${GRAY}Waiting $DELAY seconds before next test...${NC}"
sleep "$DELAY"

# Test 3: SMB Enumeration
run_test 3 "SMB Enumeration" "03-smb-enumeration.sh" "-t $TARGET"
echo -e "${GRAY}Waiting $DELAY seconds before next test...${NC}"
sleep "$DELAY"

# Test 4: Credential Attacks
run_test 4 "Credential Attacks" "04-credential-attacks.sh" "-t $TARGET"
echo -e "${GRAY}Waiting $DELAY seconds before next test...${NC}"
sleep "$DELAY"

# Test 5: Lateral Movement (requires credentials)
if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
    CRED_ARGS="-t $TARGET -u $USERNAME -p $PASSWORD"
    [ -n "$DOMAIN" ] && CRED_ARGS="$CRED_ARGS -d $DOMAIN"
    run_test 5 "Lateral Movement" "05-lateral-movement.sh" "$CRED_ARGS"
    sleep "$DELAY"
fi

# Test 6: Persistence Simulation (requires credentials)
if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
    run_test 6 "Persistence Simulation" "06-persistence-simulation.sh" "$CRED_ARGS"
fi

# =============================================================================
# Summary
# =============================================================================
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
DURATION_MIN=$((DURATION / 60))
DURATION_SEC=$((DURATION % 60))

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  All Tests Complete!${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo ""

log "Test suite completed"
log "Duration: ${DURATION_MIN}m ${DURATION_SEC}s"

echo -e "${CYAN}Summary:${NC}"
echo "  Target:   $TARGET"
echo "  Duration: ${DURATION_MIN}m ${DURATION_SEC}s"
echo "  Log:      $LOG_FILE"
echo ""

echo -e "${YELLOW}Grafana Verification Queries:${NC}"
echo ""
echo "1. All events from Kali IP:"
echo "   {host=~\".*\"} |~ \"$(hostname -I | awk '{print $1}')\""
echo ""
echo "2. Failed authentication attempts:"
echo "   {job=\"windows_auth\"} |= \"4625\""
echo ""
echo "3. Network connections to target:"
echo "   {job=\"windows_sysmon\", event_id=\"3\"}"
echo ""
echo "4. New services created:"
echo "   {job=\"windows_services\"} |= \"7045\""
echo ""
echo "5. Scheduled tasks:"
echo "   {job=\"windows_persistence\"} |= \"4698\""
echo ""
echo "6. Account changes:"
echo "   {job=\"windows_accounts\"} |~ \"4720|4732\""
echo ""

echo -e "${GREEN}Test suite finished at $(date)${NC}"
echo ""
