#!/bin/bash
# =============================================================================
# Linux User Management Test Script
# =============================================================================
# Генерує події управління користувачами
# Аналог Windows Event ID 4720, 4726, 4732, 4733
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[TEST]${NC} $1"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }

echo ""
echo "============================================================"
echo "  Linux User Management Test"
echo "============================================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "Цей скрипт потрібно запускати від root"
    echo "Використайте: sudo $0"
    exit 1
fi

TEST_USER="testmonuser"
TEST_GROUP="testmongroup"

# =============================================================================
# Cleanup existing test objects
# =============================================================================
log_info "Очистка існуючих тестових об'єктів..."
userdel -r "$TEST_USER" 2>/dev/null || true
groupdel "$TEST_GROUP" 2>/dev/null || true

# =============================================================================
# Test 1: Create User (аналог 4720)
# =============================================================================
log_info "Test 1: Створення користувача (useradd)..."

useradd -m -c "Test Monitoring User" -s /bin/bash "$TEST_USER"
echo "$TEST_USER:TestP@ssw0rd!" | chpasswd

log_success "Користувач '$TEST_USER' створено"

sleep 1

# =============================================================================
# Test 2: Create Group (аналог 4731)
# =============================================================================
log_info "Test 2: Створення групи (groupadd)..."

groupadd "$TEST_GROUP"

log_success "Група '$TEST_GROUP' створена"

sleep 1

# =============================================================================
# Test 3: Add User to Group (аналог 4732)
# =============================================================================
log_info "Test 3: Додавання користувача до групи..."

usermod -aG "$TEST_GROUP" "$TEST_USER"

log_success "Користувач доданий до групи '$TEST_GROUP'"

sleep 1

# =============================================================================
# Test 4: Add User to sudo Group (CRITICAL - аналог 4732 до Administrators)
# =============================================================================
log_info "Test 4: Додавання до sudo групи (CRITICAL!)..."

usermod -aG sudo "$TEST_USER"

log_warn "КРИТИЧНО: Користувач доданий до sudo групи!"

sleep 1

# =============================================================================
# Test 5: Modify User (аналог 4738)
# =============================================================================
log_info "Test 5: Зміна параметрів користувача..."

usermod -c "Modified Test User" "$TEST_USER"
chage -M 90 "$TEST_USER"  # Set password expiry

log_success "Параметри користувача змінено"

sleep 1

# =============================================================================
# Test 6: Lock/Unlock User (аналог 4725, 4722)
# =============================================================================
log_info "Test 6: Блокування/розблокування користувача..."

passwd -l "$TEST_USER"
log_success "Користувач заблокований"

sleep 1

passwd -u "$TEST_USER"
log_success "Користувач розблокований"

sleep 1

# =============================================================================
# Test 7: Password Change (аналог 4724)
# =============================================================================
log_info "Test 7: Зміна пароля..."

echo "$TEST_USER:NewP@ssw0rd123!" | chpasswd

log_success "Пароль змінено"

sleep 1

# =============================================================================
# Test 8: Remove from sudo (аналог 4733)
# =============================================================================
log_info "Test 8: Видалення з sudo групи..."

gpasswd -d "$TEST_USER" sudo

log_success "Користувач видалений з sudo групи"

sleep 1

# =============================================================================
# Cleanup
# =============================================================================
log_info "Очистка тестових об'єктів..."

userdel -r "$TEST_USER" 2>/dev/null || true
log_success "Користувач видалений (аналог 4726)"

groupdel "$TEST_GROUP" 2>/dev/null || true
log_success "Група видалена (аналог 4734)"

# =============================================================================
# Verification
# =============================================================================
echo ""
echo "============================================================"
echo -e "${GREEN}  Тест завершено!${NC}"
echo "============================================================"
echo ""
echo -e "${CYAN}Перевірка подій:${NC}"
echo ""

# Check auth.log for user management events
if [[ -f /var/log/auth.log ]]; then
    echo -e "${YELLOW}Події управління користувачами в auth.log:${NC}"
    grep -E "useradd|userdel|groupadd|groupdel|usermod|passwd|chage" /var/log/auth.log | tail -15
fi

echo ""
echo -e "${YELLOW}Loki запити для перевірки:${NC}"
echo '  {job="auth"} |~ "useradd|userdel|usermod"'
echo '  {job="auth"} |~ "groupadd|groupdel|gpasswd"'
echo '  {job="auth"} |= "sudo"'
echo '  {job="auth"} |= "password changed"'
echo ""
