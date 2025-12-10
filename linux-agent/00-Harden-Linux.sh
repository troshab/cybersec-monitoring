#!/bin/bash
#
# Central hardening script for Linux systems (Debian/Ubuntu)
#
# Applies basic security hardening:
# - SSH hardening
# - Firewall (ufw)
# - Kernel security parameters
# - Service hardening
# - Audit rules
#
# Usage: sudo ./00-Harden-Linux.sh
#
# Options:
#   --skip-firewall   Skip firewall configuration
#   --skip-ssh        Skip SSH hardening
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging functions
log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

# Check root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root (sudo)"
    exit 1
fi

# Parse arguments
SKIP_FIREWALL=false
SKIP_SSH=false

for arg in "$@"; do
    case $arg in
        --skip-firewall) SKIP_FIREWALL=true ;;
        --skip-ssh) SKIP_SSH=true ;;
        *) log_warning "Unknown option: $arg" ;;
    esac
done

echo ""
echo "================================================================"
echo "  Linux System Hardening"
echo "================================================================"
echo ""
echo "This script will apply:"
echo "  1. Kernel security parameters (sysctl)"
echo "  2. SSH hardening (if not skipped)"
echo "  3. Firewall configuration (ufw, if not skipped)"
echo "  4. Service hardening"
echo "  5. Audit rules"
echo ""

RESULTS=()

# =============================================================================
# Step 1: Kernel Security Parameters
# =============================================================================
echo ""
echo "=== Step 1/5: Kernel Security Parameters ==="

log_info "Configuring sysctl security parameters..."

cat > /etc/sysctl.d/99-security.conf << 'EOF'
# Network security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# IPv6 (disable if not needed, otherwise harden)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Kernel hardening
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.dmesg_restrict = 1

# Filesystem
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF

sysctl -p /etc/sysctl.d/99-security.conf > /dev/null 2>&1
log_success "Kernel parameters configured"
RESULTS+=("Kernel Parameters:OK")

# =============================================================================
# Step 2: SSH Hardening
# =============================================================================
echo ""
echo "=== Step 2/5: SSH Hardening ==="

if [ "$SKIP_SSH" = false ]; then
    log_info "Hardening SSH configuration..."

    # Backup original config
    if [ ! -f /etc/ssh/sshd_config.bak ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    fi

    # Create hardened SSH config
    cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
# Hardened SSH Configuration

# Disable root login
PermitRootLogin no

# Disable password authentication (use keys)
# Uncomment if you have SSH keys configured:
# PasswordAuthentication no
# PubkeyAuthentication yes

# Protocol and encryption
Protocol 2
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Disable insecure options
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no

# Session security
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 3

# Logging
LogLevel VERBOSE
SyslogFacility AUTH
EOF

    # Test SSH config before restarting
    if sshd -t 2>/dev/null; then
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
        log_success "SSH hardened"
        RESULTS+=("SSH Hardening:OK")
    else
        log_error "SSH config test failed - reverting"
        rm -f /etc/ssh/sshd_config.d/99-hardening.conf
        RESULTS+=("SSH Hardening:FAIL")
    fi
else
    log_warning "SSH hardening skipped (--skip-ssh)"
    RESULTS+=("SSH Hardening:SKIP")
fi

# =============================================================================
# Step 3: Firewall (ufw)
# =============================================================================
echo ""
echo "=== Step 3/5: Firewall Configuration ==="

if [ "$SKIP_FIREWALL" = false ]; then
    log_info "Configuring firewall (ufw)..."

    # Install ufw if not present
    if ! command -v ufw &> /dev/null; then
        apt-get update -qq && apt-get install -y -qq ufw
    fi

    # Reset and configure
    ufw --force reset > /dev/null 2>&1

    # Default policies
    ufw default deny incoming > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1

    # Allow SSH (important!)
    ufw allow ssh > /dev/null 2>&1

    # Enable logging
    ufw logging medium > /dev/null 2>&1

    # Enable firewall
    ufw --force enable > /dev/null 2>&1

    log_success "Firewall configured (SSH allowed)"
    RESULTS+=("Firewall:OK")
else
    log_warning "Firewall configuration skipped (--skip-firewall)"
    RESULTS+=("Firewall:SKIP")
fi

# =============================================================================
# Step 4: Service Hardening
# =============================================================================
echo ""
echo "=== Step 4/5: Service Hardening ==="

log_info "Disabling unnecessary services..."

# List of services to disable (if present)
DISABLE_SERVICES=(
    "avahi-daemon"      # mDNS
    "cups"              # Printing (if not needed)
    "rpcbind"           # NFS RPC
    "nfs-server"        # NFS server
    "bluetooth"         # Bluetooth
    "telnet"            # Telnet
    "rsh"               # Remote shell
)

for svc in "${DISABLE_SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        log_success "Disabled: $svc"
    fi
done

log_success "Service hardening complete"
RESULTS+=("Service Hardening:OK")

# =============================================================================
# Step 5: Audit Rules
# =============================================================================
echo ""
echo "=== Step 5/5: Audit Rules ==="

log_info "Configuring audit rules..."

# Install auditd if not present
if ! command -v auditd &> /dev/null; then
    apt-get update -qq && apt-get install -y -qq auditd audispd-plugins
fi

# Create audit rules
cat > /etc/audit/rules.d/99-hardening.rules << 'EOF'
# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode (1=printk, 2=panic)
-f 1

# Monitor time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-w /etc/localtime -p wa -k time-change

# Monitor user/group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor network configuration
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/sysctl.conf -p wa -k network
-w /etc/sysctl.d/ -p wa -k network

# Monitor login files
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Monitor sudo usage
-w /etc/sudoers -p wa -k sudo
-w /etc/sudoers.d/ -p wa -k sudo

# Monitor SSH config
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

# Monitor cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron

# Privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged

# File deletion
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=unset -k delete

# Make configuration immutable (must be last)
-e 2
EOF

# Restart auditd
systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
log_success "Audit rules configured"
RESULTS+=("Audit Rules:OK")

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "================================================================"
echo "  Linux Hardening Summary"
echo "================================================================"
echo ""

SUCCESS_COUNT=0
TOTAL_COUNT=${#RESULTS[@]}

for result in "${RESULTS[@]}"; do
    NAME="${result%%:*}"
    STATUS="${result##*:}"

    case $STATUS in
        OK)
            echo -e "  ${GREEN}[OK]${NC} $NAME"
            ((SUCCESS_COUNT++))
            ;;
        FAIL)
            echo -e "  ${RED}[FAIL]${NC} $NAME"
            ;;
        SKIP)
            echo -e "  ${YELLOW}[SKIP]${NC} $NAME"
            ((SUCCESS_COUNT++))
            ;;
    esac
done

echo ""
echo "Result: $SUCCESS_COUNT/$TOTAL_COUNT steps completed successfully"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC}"
echo "  - Review SSH config before disabling password auth"
echo "  - Add firewall rules for your services (ufw allow <port>)"
echo "  - Reboot recommended to apply all kernel parameters"
echo ""
