#!/bin/bash
# =============================================================================
# Linux Security Tests - Run All
# =============================================================================
# Запускає всі тести для перевірки моніторингу Linux
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo -e "${MAGENTA}============================================================${NC}"
echo -e "${MAGENTA}  Linux Security Detection Tests${NC}"
echo -e "${MAGENTA}============================================================${NC}"
echo ""

echo -e "${CYAN}Директорія тестів: $SCRIPT_DIR${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}УВАГА: Деякі тести потребують root прав.${NC}"
    echo -e "${YELLOW}Для повного тестування запустіть: sudo $0${NC}"
    echo ""
fi

# Check for sshpass
if ! command -v sshpass &> /dev/null; then
    echo -e "${YELLOW}УВАГА: sshpass не встановлено. Встановіть: apt install sshpass${NC}"
    echo ""
fi

read -p "Продовжити тестування? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Скасовано."
    exit 0
fi

echo ""
echo -e "${CYAN}Початок тестування...${NC}"
echo ""

# =============================================================================
# Run tests
# =============================================================================

TESTS=(
    "01-test-authentication.sh:Authentication Tests (SSH, su, sudo)"
    "02-test-user-management.sh:User Management Tests (useradd, groupadd)"
    "03-test-sudo-activity.sh:Sudo Activity Tests"
    "04-test-persistence.sh:Persistence Tests (cron, systemd)"
)

PASSED=0
FAILED=0

for test_entry in "${TESTS[@]}"; do
    IFS=':' read -r test_file test_name <<< "$test_entry"
    test_path="$SCRIPT_DIR/$test_file"

    echo ""
    echo -e "${MAGENTA}============================================================${NC}"
    echo -e "${MAGENTA}  $test_name${NC}"
    echo -e "${MAGENTA}============================================================${NC}"

    if [[ -f "$test_path" ]]; then
        chmod +x "$test_path"

        if bash "$test_path"; then
            echo -e "${GREEN}[PASS]${NC} $test_name"
            ((PASSED++))
        else
            echo -e "${RED}[FAIL]${NC} $test_name"
            ((FAILED++))
        fi
    else
        echo -e "${YELLOW}[SKIP]${NC} $test_file не знайдено"
    fi

    echo ""
    read -p "Натисніть Enter для продовження..." -r
done

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${MAGENTA}============================================================${NC}"
echo -e "${MAGENTA}  Підсумок тестування${NC}"
echo -e "${MAGENTA}============================================================${NC}"
echo ""
echo -e "  Пройдено: ${GREEN}$PASSED${NC}"
echo -e "  Провалено: ${RED}$FAILED${NC}"
echo ""

echo -e "${CYAN}Перевірка в Grafana:${NC}"
echo "  1. Відкрийте http://10.0.1.2:3000"
echo "  2. Перейдіть в Explore → Loki"
echo "  3. Запити:"
echo ""
echo '     {job="auth"} |~ "Failed|authentication failure"'
echo '     {job="auth"} |~ "useradd|userdel|usermod"'
echo '     {job="auth"} |= "sudo:"'
echo '     {job="syslog"} |= "CRON"'
echo ""

echo -e "${CYAN}Дашборд:${NC}"
echo "  Перейдіть в Dashboard → Linux Security"
echo ""
