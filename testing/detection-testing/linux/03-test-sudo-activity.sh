#!/bin/bash
# =============================================================================
# Linux Sudo Activity Test Script
# =============================================================================
# Генерує події sudo для тестування моніторингу
# Аналог Windows Event ID 4672 (Special Privileges)
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
echo "  Linux Sudo Activity Test"
echo "============================================================"
echo ""

# =============================================================================
# Test 1: Normal sudo commands
# =============================================================================
log_info "Test 1: Звичайні sudo команди..."

sudo whoami
sudo id
sudo ls /root > /dev/null 2>&1 || true

log_success "Звичайні sudo команди виконано"

# =============================================================================
# Test 2: Sudo with different users
# =============================================================================
log_info "Test 2: Sudo як інший користувач..."

sudo -u nobody whoami 2>/dev/null || true
sudo -u www-data id 2>/dev/null || true

log_success "Sudo як інший користувач"

# =============================================================================
# Test 3: Suspicious sudo commands
# =============================================================================
log_info "Test 3: Підозрілі sudo команди..."

# Читання shadow файлу
sudo cat /etc/shadow > /dev/null 2>&1 || true
log_warn "Читання /etc/shadow"

# Зміна файлів в /etc
sudo touch /tmp/test_etc_access
log_info "Доступ до системних файлів"

# Запуск bash як root
sudo bash -c "echo 'Root shell test'" 2>/dev/null || true
log_warn "Root shell через sudo bash"

# =============================================================================
# Test 4: sudo -i / sudo su
# =============================================================================
log_info "Test 4: Інтерактивний root shell..."

# Ці команди записуються як підозрілі
sudo bash -c "whoami && pwd"

log_warn "sudo bash виконано"

# =============================================================================
# Test 5: Sudoers file access
# =============================================================================
log_info "Test 5: Доступ до sudoers..."

sudo cat /etc/sudoers > /dev/null 2>&1 || true
sudo ls -la /etc/sudoers.d/ > /dev/null 2>&1 || true

log_warn "Доступ до sudoers файлів"

# =============================================================================
# Test 6: Failed sudo (if not root)
# =============================================================================
if [[ $EUID -ne 0 ]]; then
    log_info "Test 6: Невдалі sudo спроби..."

    # Спроба команди без прав
    echo "wrongpassword" | sudo -S -k cat /etc/shadow 2>/dev/null || true

    log_success "Невдала sudo спроба згенерована"
fi

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

# Check auth.log for sudo events
if [[ -f /var/log/auth.log ]]; then
    sudo_count=$(grep -c "sudo:" /var/log/auth.log 2>/dev/null | tail -1 || echo "0")
    echo -e "  Sudo events in auth.log: ${GREEN}$sudo_count${NC}"

    echo ""
    echo -e "${YELLOW}Останні 10 sudo подій:${NC}"
    grep "sudo:" /var/log/auth.log | tail -10
fi

echo ""
echo -e "${YELLOW}Loki запити для перевірки:${NC}"
echo '  {job="auth"} |= "sudo:"'
echo '  {job="auth"} |~ "sudo.*COMMAND"'
echo '  {job="auth"} |= "NOT allowed"'
echo '  {job="auth"} |~ "sudo.*(shadow|sudoers|passwd)"'
echo ""
