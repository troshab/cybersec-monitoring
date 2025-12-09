#!/bin/bash
# =============================================================================
# Linux Authentication Test Script
# =============================================================================
# Генерує події автентифікації для тестування моніторингу
# Аналог Windows Event ID 4624, 4625
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
echo "  Linux Authentication Test"
echo "============================================================"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    log_warn "Запущено від root - деякі тести пропущені"
fi

# =============================================================================
# Test 1: Failed SSH Login Attempts
# =============================================================================
log_info "Test 1: Генерація невдалих SSH входів..."

for i in {1..5}; do
    log_info "Спроба $i/5..."
    # Спроба SSH з неправильним паролем до localhost
    sshpass -p "wrongpassword" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
        nonexistent_user@localhost exit 2>/dev/null || true
    sleep 0.5
done

log_success "5 невдалих SSH спроб (перевірте /var/log/auth.log)"

# =============================================================================
# Test 2: Failed su Attempts
# =============================================================================
log_info "Test 2: Невдалі спроби su..."

for i in {1..3}; do
    echo "wrongpassword" | su - nonexistent_user 2>/dev/null || true
done

log_success "3 невдалі su спроби згенеровано"

# =============================================================================
# Test 3: sudo with wrong password
# =============================================================================
log_info "Test 3: Невдалі спроби sudo..."

# Це потребує інтерактивного вводу, тому просто логуємо
for i in {1..3}; do
    echo "wrongpassword" | sudo -S ls /root 2>/dev/null || true
done

log_success "sudo спроби згенеровано"

# =============================================================================
# Test 4: PAM Authentication
# =============================================================================
log_info "Test 4: PAM authentication events..."

# Login спроба через login command
echo "testuser:wrongpassword" | timeout 2 login 2>/dev/null || true

log_success "PAM події згенеровано"

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

# Check auth.log
if [[ -f /var/log/auth.log ]]; then
    failed_count=$(grep -c "Failed password\|authentication failure" /var/log/auth.log 2>/dev/null | tail -1 || echo "0")
    echo -e "  Failed logins in auth.log: ${GREEN}$failed_count${NC}"

    echo ""
    echo -e "${YELLOW}Останні 10 подій автентифікації:${NC}"
    grep -E "sshd|su|sudo|login" /var/log/auth.log | tail -10
fi

echo ""
echo -e "${YELLOW}Loki запити для перевірки:${NC}"
echo '  {job="auth"} |= "Failed"'
echo '  {job="auth"} |~ "authentication failure|Failed password"'
echo '  {job="auth", host="monitoring-server"}'
echo ""
