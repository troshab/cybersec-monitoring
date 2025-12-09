#!/bin/bash
# =============================================================================
# Linux Persistence Test Script
# =============================================================================
# Генерує події persistence механізмів
# Аналог Windows Event ID 4698 (Scheduled Task), 7045 (Service)
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
echo "  Linux Persistence Mechanisms Test"
echo "============================================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "Цей скрипт потрібно запускати від root"
    echo "Використайте: sudo $0"
    exit 1
fi

TEST_USER="testcronuser"

# =============================================================================
# Test 1: Create Cron Job (аналог Scheduled Task - 4698)
# =============================================================================
log_info "Test 1: Створення cron job (аналог 4698)..."

# Створення тестового cron job
echo "*/5 * * * * root echo 'Test cron job' >> /tmp/test_cron.log" > /etc/cron.d/test_security_cron

log_warn "Cron job створено в /etc/cron.d/"

# User crontab
crontab -l > /tmp/old_crontab 2>/dev/null || true
(crontab -l 2>/dev/null; echo "*/10 * * * * echo 'User cron test'") | crontab -

log_success "User crontab змінено"

sleep 1

# =============================================================================
# Test 2: Create at Job
# =============================================================================
log_info "Test 2: Створення at job..."

if command -v at &> /dev/null; then
    echo "echo 'at job test'" | at now + 1 hour 2>/dev/null || true
    log_success "at job створено"
else
    log_info "at не встановлено - пропущено"
fi

# =============================================================================
# Test 3: Create Systemd Timer (Modern Cron)
# =============================================================================
log_info "Test 3: Створення systemd timer..."

# Створення простого service + timer
cat > /etc/systemd/system/test-security.service << 'EOF'
[Unit]
Description=Test Security Service

[Service]
Type=oneshot
ExecStart=/bin/echo "Test systemd service"
EOF

cat > /etc/systemd/system/test-security.timer << 'EOF'
[Unit]
Description=Test Security Timer

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable test-security.timer 2>/dev/null || true

log_warn "Systemd timer створено"

sleep 1

# =============================================================================
# Test 4: Modify /etc/rc.local (Legacy persistence)
# =============================================================================
log_info "Test 4: Модифікація rc.local..."

if [[ -f /etc/rc.local ]]; then
    cp /etc/rc.local /etc/rc.local.bak
    echo "# Test security entry" >> /etc/rc.local
    log_warn "rc.local модифіковано"
else
    echo "#!/bin/bash" > /etc/rc.local
    echo "# Test security entry" >> /etc/rc.local
    chmod +x /etc/rc.local
    log_warn "rc.local створено"
fi

# =============================================================================
# Test 5: SSH Authorized Keys (Common persistence)
# =============================================================================
log_info "Test 5: SSH authorized_keys modification..."

# Створення тестового користувача для SSH key
useradd -m "$TEST_USER" 2>/dev/null || true
mkdir -p /home/$TEST_USER/.ssh
echo "# Test SSH key entry - security test" >> /home/$TEST_USER/.ssh/authorized_keys
chmod 700 /home/$TEST_USER/.ssh
chmod 600 /home/$TEST_USER/.ssh/authorized_keys
chown -R $TEST_USER:$TEST_USER /home/$TEST_USER/.ssh

log_warn "SSH authorized_keys модифіковано"

# =============================================================================
# Test 6: Bashrc/Profile modification
# =============================================================================
log_info "Test 6: Модифікація shell profile..."

echo "# Test security entry - bashrc" >> /home/$TEST_USER/.bashrc
echo "# Test security entry - profile" >> /etc/profile.d/test_security.sh

log_warn "Shell profiles модифіковано"

# =============================================================================
# Cleanup
# =============================================================================
log_info "Очистка тестових об'єктів..."

# Remove cron jobs
rm -f /etc/cron.d/test_security_cron
crontab /tmp/old_crontab 2>/dev/null || crontab -r 2>/dev/null || true
rm -f /tmp/old_crontab

# Remove systemd timer
systemctl disable test-security.timer 2>/dev/null || true
rm -f /etc/systemd/system/test-security.service
rm -f /etc/systemd/system/test-security.timer
systemctl daemon-reload

# Restore rc.local
if [[ -f /etc/rc.local.bak ]]; then
    mv /etc/rc.local.bak /etc/rc.local
else
    rm -f /etc/rc.local
fi

# Remove test user
userdel -r "$TEST_USER" 2>/dev/null || true

# Remove profile
rm -f /etc/profile.d/test_security.sh

log_success "Тестові об'єкти видалено"

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

# Check various logs
echo -e "${YELLOW}Cron події:${NC}"
grep -E "cron|CRON" /var/log/syslog 2>/dev/null | tail -5 || echo "  No cron events found"

echo ""
echo -e "${YELLOW}Systemd події:${NC}"
journalctl -u test-security.timer --no-pager 2>/dev/null | tail -5 || echo "  No systemd events found"

echo ""
echo -e "${YELLOW}Loki запити для перевірки:${NC}"
echo '  {job="syslog"} |= "CRON"'
echo '  {job="syslog"} |~ "crontab|anacron"'
echo '  {job="auth"} |~ "useradd|authorized_keys"'
echo '  {job="syslog"} |= "systemd"'
echo ""
