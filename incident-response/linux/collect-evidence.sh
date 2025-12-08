#!/bin/bash
#
# Linux Evidence Collection for CERT-UA
# Based on UAC (Unix-like Artifacts Collector) methodology
#
# Usage: sudo ./collect-evidence.sh [output_path]
#
# CERT-UA Contact:
# - Email: cert@cert.gov.ua
# - Phone: +380 44 281 88 25
# - Web: https://cert.gov.ua
#

set -e

# =============================================================================
# Configuration
# =============================================================================
VERSION="1.0"
HOSTNAME=$(hostname)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_PATH="${1:-/tmp/Evidence_${HOSTNAME}_${TIMESTAMP}}"
LOG_FILE="${OUTPUT_PATH}/collection.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# Functions
# =============================================================================
log() {
    local level="$1"
    local msg="$2"
    local ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[${ts}] [${level}] ${msg}"
    echo "[${ts}] [${level}] ${msg}" >> "$LOG_FILE"
}

log_info()    { log "INFO" "$1"; }
log_success() { log "${GREEN}SUCCESS${NC}" "$1"; }
log_warning() { log "${YELLOW}WARNING${NC}" "$1"; }
log_error()   { log "${RED}ERROR${NC}" "$1"; }

create_folder() {
    local folder="$OUTPUT_PATH/$1"
    mkdir -p "$folder"
    echo "$folder"
}

safe_copy() {
    local src="$1"
    local dst="$2"
    if [ -e "$src" ]; then
        cp -rL "$src" "$dst" 2>/dev/null && log_success "Copied: $src" || log_warning "Partial copy: $src"
    else
        log_warning "Not found: $src"
    fi
}

# =============================================================================
# Check privileges
# =============================================================================
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Usage: sudo $0 [output_path]"
    exit 1
fi

# =============================================================================
# Banner
# =============================================================================
clear
echo -e "${CYAN}"
echo "============================================================"
echo "  Linux Evidence Collection for CERT-UA"
echo "  Version: $VERSION"
echo "============================================================"
echo -e "${NC}"

cat << 'EOF'
 ██████╗███████╗██████╗ ████████╗    ██╗   ██╗ █████╗
██╔════╝██╔════╝██╔══██╗╚══██╔══╝    ██║   ██║██╔══██╗
██║     █████╗  ██████╔╝   ██║       ██║   ██║███████║
██║     ██╔══╝  ██╔══██╗   ██║       ██║   ██║██╔══██║
╚██████╗███████╗██║  ██║   ██║       ╚██████╔╝██║  ██║
 ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝        ╚═════╝ ╚═╝  ╚═╝
EOF

echo ""
echo -e "Target: ${CYAN}$HOSTNAME${NC}"
echo -e "Output: ${CYAN}$OUTPUT_PATH${NC}"
echo ""

read -p "Start evidence collection? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    echo "Cancelled by user"
    exit 0
fi

# =============================================================================
# Initialize
# =============================================================================
START_TIME=$(date +%s)
mkdir -p "$OUTPUT_PATH"
touch "$LOG_FILE"

log_info "Evidence collection started"
log_info "Hostname: $HOSTNAME"
log_info "User: $(whoami)"
log_info "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"

# =============================================================================
# 1. VOLATILE DATA (collect first!)
# =============================================================================
echo ""
echo -e "${CYAN}[1/8] Collecting VOLATILE DATA...${NC}"
VOLATILE_PATH=$(create_folder "01_Volatile")

# Running processes
log_info "Collecting running processes..."
ps auxwww > "$VOLATILE_PATH/ps_aux.txt" 2>/dev/null
ps -ef > "$VOLATILE_PATH/ps_ef.txt" 2>/dev/null
pstree -p > "$VOLATILE_PATH/pstree.txt" 2>/dev/null

# Process details
for pid in /proc/[0-9]*; do
    if [ -d "$pid" ]; then
        pid_num=$(basename "$pid")
        {
            echo "=== PID: $pid_num ==="
            echo "Cmdline: $(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ')"
            echo "Exe: $(readlink -f "$pid/exe" 2>/dev/null)"
            echo "Cwd: $(readlink -f "$pid/cwd" 2>/dev/null)"
        } >> "$VOLATILE_PATH/process_details.txt"
    fi
done

# Network connections
log_info "Collecting network connections..."
ss -tulpan > "$VOLATILE_PATH/ss_tulpan.txt" 2>/dev/null
netstat -tulpan > "$VOLATILE_PATH/netstat_tulpan.txt" 2>/dev/null || true
lsof -i -n -P > "$VOLATILE_PATH/lsof_network.txt" 2>/dev/null || true

# Network routes
ip route > "$VOLATILE_PATH/ip_route.txt" 2>/dev/null
ip addr > "$VOLATILE_PATH/ip_addr.txt" 2>/dev/null

# ARP cache
ip neigh > "$VOLATILE_PATH/arp_cache.txt" 2>/dev/null
arp -a > "$VOLATILE_PATH/arp_a.txt" 2>/dev/null || true

# DNS resolver
cat /etc/resolv.conf > "$VOLATILE_PATH/resolv.conf" 2>/dev/null

# Open files
lsof > "$VOLATILE_PATH/lsof_all.txt" 2>/dev/null &
LSOF_PID=$!

# Logged in users
who > "$VOLATILE_PATH/who.txt" 2>/dev/null
w > "$VOLATILE_PATH/w.txt" 2>/dev/null
last -50 > "$VOLATILE_PATH/last.txt" 2>/dev/null
lastlog > "$VOLATILE_PATH/lastlog.txt" 2>/dev/null

# =============================================================================
# 2. SYSTEM LOGS
# =============================================================================
echo ""
echo -e "${CYAN}[2/8] Collecting SYSTEM LOGS...${NC}"
LOGS_PATH=$(create_folder "02_Logs")

# Auth logs
safe_copy "/var/log/auth.log" "$LOGS_PATH/"
safe_copy "/var/log/auth.log.1" "$LOGS_PATH/"
safe_copy "/var/log/secure" "$LOGS_PATH/"
safe_copy "/var/log/secure-*" "$LOGS_PATH/"

# Syslog
safe_copy "/var/log/syslog" "$LOGS_PATH/"
safe_copy "/var/log/syslog.1" "$LOGS_PATH/"
safe_copy "/var/log/messages" "$LOGS_PATH/"
safe_copy "/var/log/messages-*" "$LOGS_PATH/"

# Audit logs
safe_copy "/var/log/audit/audit.log" "$LOGS_PATH/"
safe_copy "/var/log/audit/audit.log.1" "$LOGS_PATH/"

# Kernel logs
safe_copy "/var/log/kern.log" "$LOGS_PATH/"
safe_copy "/var/log/dmesg" "$LOGS_PATH/"
dmesg > "$LOGS_PATH/dmesg_current.txt" 2>/dev/null

# Cron logs
safe_copy "/var/log/cron" "$LOGS_PATH/"
safe_copy "/var/log/cron.log" "$LOGS_PATH/"

# Package manager logs
safe_copy "/var/log/dpkg.log" "$LOGS_PATH/"
safe_copy "/var/log/apt/history.log" "$LOGS_PATH/"
safe_copy "/var/log/yum.log" "$LOGS_PATH/"
safe_copy "/var/log/dnf.log" "$LOGS_PATH/"

# SSH logs
safe_copy "/var/log/ssh*" "$LOGS_PATH/"

# Fail2ban
safe_copy "/var/log/fail2ban.log" "$LOGS_PATH/"

# Journalctl export (last 7 days)
log_info "Exporting journalctl..."
journalctl --since "7 days ago" > "$LOGS_PATH/journal_7days.txt" 2>/dev/null || true
journalctl -u sshd > "$LOGS_PATH/journal_sshd.txt" 2>/dev/null || true
journalctl -u sudo > "$LOGS_PATH/journal_sudo.txt" 2>/dev/null || true

# =============================================================================
# 3. USER ARTIFACTS
# =============================================================================
echo ""
echo -e "${CYAN}[3/8] Collecting USER ARTIFACTS...${NC}"
USERS_PATH=$(create_folder "03_Users")

# System users
cat /etc/passwd > "$USERS_PATH/passwd" 2>/dev/null
cat /etc/shadow > "$USERS_PATH/shadow" 2>/dev/null
cat /etc/group > "$USERS_PATH/group" 2>/dev/null
cat /etc/sudoers > "$USERS_PATH/sudoers" 2>/dev/null
cat /etc/sudoers.d/* > "$USERS_PATH/sudoers.d.txt" 2>/dev/null

# Per-user artifacts
for user_home in /home/* /root; do
    if [ -d "$user_home" ]; then
        username=$(basename "$user_home")
        user_folder=$(create_folder "03_Users/$username")

        # Shell history
        safe_copy "$user_home/.bash_history" "$user_folder/"
        safe_copy "$user_home/.zsh_history" "$user_folder/"
        safe_copy "$user_home/.sh_history" "$user_folder/"
        safe_copy "$user_home/.history" "$user_folder/"

        # SSH
        safe_copy "$user_home/.ssh/authorized_keys" "$user_folder/"
        safe_copy "$user_home/.ssh/known_hosts" "$user_folder/"
        safe_copy "$user_home/.ssh/config" "$user_folder/"

        # Bash config
        safe_copy "$user_home/.bashrc" "$user_folder/"
        safe_copy "$user_home/.bash_profile" "$user_folder/"
        safe_copy "$user_home/.profile" "$user_folder/"

        # Cron
        crontab -u "$username" -l > "$user_folder/crontab.txt" 2>/dev/null || true

        # Recently used
        safe_copy "$user_home/.local/share/recently-used.xbel" "$user_folder/"

        # Gnome Keyring (existence check)
        [ -d "$user_home/.local/share/keyrings" ] && log_info "Found keyring for $username"
    fi
done

# =============================================================================
# 4. SCHEDULED TASKS
# =============================================================================
echo ""
echo -e "${CYAN}[4/8] Collecting SCHEDULED TASKS...${NC}"
TASKS_PATH=$(create_folder "04_ScheduledTasks")

# System crontabs
safe_copy "/etc/crontab" "$TASKS_PATH/"
safe_copy "/etc/cron.d" "$TASKS_PATH/"
safe_copy "/etc/cron.daily" "$TASKS_PATH/"
safe_copy "/etc/cron.hourly" "$TASKS_PATH/"
safe_copy "/etc/cron.weekly" "$TASKS_PATH/"
safe_copy "/etc/cron.monthly" "$TASKS_PATH/"

# User crontabs
safe_copy "/var/spool/cron/crontabs" "$TASKS_PATH/"
safe_copy "/var/spool/cron" "$TASKS_PATH/spool_cron"

# Systemd timers
systemctl list-timers --all > "$TASKS_PATH/systemd_timers.txt" 2>/dev/null

# At jobs
atq > "$TASKS_PATH/at_queue.txt" 2>/dev/null || true
safe_copy "/var/spool/at" "$TASKS_PATH/"

# =============================================================================
# 5. SERVICES & STARTUP
# =============================================================================
echo ""
echo -e "${CYAN}[5/8] Collecting SERVICES & STARTUP...${NC}"
SERVICES_PATH=$(create_folder "05_Services")

# Systemd services
systemctl list-unit-files > "$SERVICES_PATH/systemd_units.txt" 2>/dev/null
systemctl list-units --type=service > "$SERVICES_PATH/systemd_services.txt" 2>/dev/null
systemctl list-units --failed > "$SERVICES_PATH/systemd_failed.txt" 2>/dev/null

# Init.d
ls -la /etc/init.d/ > "$SERVICES_PATH/initd_list.txt" 2>/dev/null
safe_copy "/etc/init.d" "$SERVICES_PATH/"

# RC scripts
ls -la /etc/rc*.d/ > "$SERVICES_PATH/rc_list.txt" 2>/dev/null

# Startup
safe_copy "/etc/rc.local" "$SERVICES_PATH/"

# =============================================================================
# 6. NETWORK CONFIG
# =============================================================================
echo ""
echo -e "${CYAN}[6/8] Collecting NETWORK CONFIG...${NC}"
NETWORK_PATH=$(create_folder "06_Network")

# Network interfaces
ifconfig -a > "$NETWORK_PATH/ifconfig.txt" 2>/dev/null || true
ip link > "$NETWORK_PATH/ip_link.txt" 2>/dev/null

# Firewall rules
iptables -L -n -v > "$NETWORK_PATH/iptables.txt" 2>/dev/null || true
iptables-save > "$NETWORK_PATH/iptables_save.txt" 2>/dev/null || true
ip6tables -L -n -v > "$NETWORK_PATH/ip6tables.txt" 2>/dev/null || true
nft list ruleset > "$NETWORK_PATH/nftables.txt" 2>/dev/null || true
ufw status verbose > "$NETWORK_PATH/ufw_status.txt" 2>/dev/null || true

# Hosts
safe_copy "/etc/hosts" "$NETWORK_PATH/"
safe_copy "/etc/hosts.allow" "$NETWORK_PATH/"
safe_copy "/etc/hosts.deny" "$NETWORK_PATH/"

# Network config
safe_copy "/etc/network/interfaces" "$NETWORK_PATH/"
safe_copy "/etc/netplan" "$NETWORK_PATH/"
safe_copy "/etc/NetworkManager" "$NETWORK_PATH/"

# SSH config
safe_copy "/etc/ssh/sshd_config" "$NETWORK_PATH/"
safe_copy "/etc/ssh/ssh_config" "$NETWORK_PATH/"

# =============================================================================
# 7. INSTALLED SOFTWARE
# =============================================================================
echo ""
echo -e "${CYAN}[7/8] Collecting INSTALLED SOFTWARE...${NC}"
SOFTWARE_PATH=$(create_folder "07_Software")

# Debian/Ubuntu
dpkg -l > "$SOFTWARE_PATH/dpkg_list.txt" 2>/dev/null || true
apt list --installed > "$SOFTWARE_PATH/apt_installed.txt" 2>/dev/null || true

# RHEL/CentOS
rpm -qa > "$SOFTWARE_PATH/rpm_list.txt" 2>/dev/null || true
yum list installed > "$SOFTWARE_PATH/yum_installed.txt" 2>/dev/null || true

# Kernel modules
lsmod > "$SOFTWARE_PATH/lsmod.txt" 2>/dev/null

# SUID/SGID binaries
find / -perm -4000 -o -perm -2000 2>/dev/null | head -200 > "$SOFTWARE_PATH/suid_sgid.txt"

# =============================================================================
# 8. SYSTEM INFO
# =============================================================================
echo ""
echo -e "${CYAN}[8/8] Collecting SYSTEM INFO...${NC}"
INFO_PATH=$(create_folder "08_SystemInfo")

# System info
uname -a > "$INFO_PATH/uname.txt" 2>/dev/null
cat /etc/os-release > "$INFO_PATH/os_release.txt" 2>/dev/null
cat /etc/*release > "$INFO_PATH/all_release.txt" 2>/dev/null
hostnamectl > "$INFO_PATH/hostnamectl.txt" 2>/dev/null || true

# Hardware
lscpu > "$INFO_PATH/lscpu.txt" 2>/dev/null
free -h > "$INFO_PATH/memory.txt" 2>/dev/null
df -h > "$INFO_PATH/disk_usage.txt" 2>/dev/null
lsblk > "$INFO_PATH/lsblk.txt" 2>/dev/null
fdisk -l > "$INFO_PATH/fdisk.txt" 2>/dev/null
mount > "$INFO_PATH/mounts.txt" 2>/dev/null

# Boot info
cat /proc/cmdline > "$INFO_PATH/cmdline.txt" 2>/dev/null
uptime > "$INFO_PATH/uptime.txt" 2>/dev/null

# Environment
env > "$INFO_PATH/environment.txt" 2>/dev/null

# Wait for lsof to complete
wait $LSOF_PID 2>/dev/null || true

# =============================================================================
# Finalize
# =============================================================================
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

log_info "Collection completed in $DURATION seconds"

# Create archive
echo ""
echo -e "${CYAN}Creating archive...${NC}"

ARCHIVE_NAME="Evidence_${HOSTNAME}_${TIMESTAMP}.tar.gz"
ARCHIVE_PATH="/tmp/$ARCHIVE_NAME"

tar -czf "$ARCHIVE_PATH" -C "$(dirname "$OUTPUT_PATH")" "$(basename "$OUTPUT_PATH")"

# Calculate hash
HASH=$(sha256sum "$ARCHIVE_PATH" | cut -d' ' -f1)
log_info "Archive created: $ARCHIVE_PATH"
log_info "SHA256: $HASH"

# Create report
cat > "$OUTPUT_PATH/COLLECTION_REPORT.txt" << EOF
Evidence Collection Report
==========================
Hostname: $HOSTNAME
Collected by: $(whoami)
Start time: $(date -d "@$START_TIME" '+%Y-%m-%d %H:%M:%S')
End time: $(date -d "@$END_TIME" '+%Y-%m-%d %H:%M:%S')
Duration: $DURATION seconds

Archive: $ARCHIVE_NAME
SHA256: $HASH

CERT-UA Contact:
- Email: cert@cert.gov.ua
- Phone: +380 44 281 88 25
- Web: https://cert.gov.ua
EOF

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  COLLECTION COMPLETE${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "Evidence folder: ${CYAN}$OUTPUT_PATH${NC}"
echo -e "Archive: ${CYAN}$ARCHIVE_PATH${NC}"
echo ""
echo -e "SHA256: ${YELLOW}$HASH${NC}"
echo ""
echo "Next steps:"
echo "1. Copy archive to external drive"
echo "2. Encrypt with GPG: gpg -c $ARCHIVE_NAME"
echo "3. Contact CERT-UA: cert@cert.gov.ua"
echo "4. Provide password via phone: +380 44 281 88 25"
echo ""
