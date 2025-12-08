#!/bin/bash
#
# Linux Agent Installation Script
# Встановлення моніторингу на Linux системах
#
# Підтримка:
#   - Ubuntu 20.04+, 22.04+, 24.04
#   - Debian 11+, 12
#   - RHEL/CentOS/Rocky 8+, 9
#   - Kali Linux
#
# Компоненти:
#   - Promtail (logs → Loki)
#   - Node Exporter (metrics → Prometheus)
#   - Auditd (системний аудит)
#   - Osquery (опціонально, для FleetDM)
#

set -e

# =============================================================================
# Кольори та функції виводу
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${CYAN}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

banner() {
    echo ""
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo ""
}

# =============================================================================
# Параметри за замовчуванням
# =============================================================================
LOKI_URL=""
FLEET_URL=""
FLEET_SECRET=""
PROMTAIL_VERSION="2.9.3"
NODE_EXPORTER_VERSION="1.7.0"
OSQUERY_VERSION="5.12.1"
SKIP_AUDITD=false
SKIP_OSQUERY=false
INSTALL_DIR="/opt/monitoring"
CONFIG_DIR="/etc/monitoring"

# =============================================================================
# Парсинг аргументів
# =============================================================================
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Required:
  --loki-url URL          URL сервера Loki (наприклад: http://192.168.1.100:3100)

Optional:
  --fleet-url URL         URL FleetDM сервера
  --fleet-secret SECRET   FleetDM enrollment secret
  --skip-auditd           Пропустити налаштування auditd
  --skip-osquery          Пропустити встановлення osquery
  --promtail-version VER  Версія Promtail (default: $PROMTAIL_VERSION)
  --node-exporter-version VER  Версія Node Exporter (default: $NODE_EXPORTER_VERSION)
  -h, --help              Показати цю довідку

Examples:
  $0 --loki-url "http://192.168.1.100:3100"
  $0 --loki-url "http://loki:3100" --fleet-url "https://fleet:8080" --fleet-secret "abc123"

EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --loki-url)
            LOKI_URL="$2"
            shift 2
            ;;
        --fleet-url)
            FLEET_URL="$2"
            shift 2
            ;;
        --fleet-secret)
            FLEET_SECRET="$2"
            shift 2
            ;;
        --skip-auditd)
            SKIP_AUDITD=true
            shift
            ;;
        --skip-osquery)
            SKIP_OSQUERY=true
            shift
            ;;
        --promtail-version)
            PROMTAIL_VERSION="$2"
            shift 2
            ;;
        --node-exporter-version)
            NODE_EXPORTER_VERSION="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Невідомий параметр: $1"
            usage
            ;;
    esac
done

if [ -z "$LOKI_URL" ]; then
    log_error "Параметр --loki-url обов'язковий!"
    usage
fi

# =============================================================================
# Перевірка root
# =============================================================================
if [ "$EUID" -ne 0 ]; then
    log_error "Запустіть скрипт від root (sudo)"
    exit 1
fi

# =============================================================================
# Визначення дистрибутива
# =============================================================================
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
        DISTRO_LIKE=$ID_LIKE
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    else
        DISTRO="unknown"
    fi

    log_info "Виявлено: $DISTRO $DISTRO_VERSION"
}

# =============================================================================
# Встановлення залежностей
# =============================================================================
install_dependencies() {
    banner "Встановлення залежностей"

    case $DISTRO in
        ubuntu|debian|kali)
            apt-get update
            apt-get install -y curl wget unzip jq auditd audispd-plugins
            ;;
        rhel|centos|rocky|almalinux|fedora)
            if command -v dnf &> /dev/null; then
                dnf install -y curl wget unzip jq audit
            else
                yum install -y curl wget unzip jq audit
            fi
            ;;
        *)
            log_warning "Невідомий дистрибутив, спроба встановлення..."
            ;;
    esac

    log_success "Залежності встановлено"
}

# =============================================================================
# Створення директорій
# =============================================================================
create_directories() {
    log_info "Створення директорій..."

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p /var/log/monitoring
    mkdir -p /var/lib/promtail

    log_success "Директорії створено"
}

# =============================================================================
# Встановлення Promtail
# =============================================================================
install_promtail() {
    banner "Встановлення Promtail v$PROMTAIL_VERSION"

    local ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="arm"
            ;;
    esac

    local PROMTAIL_URL="https://github.com/grafana/loki/releases/download/v${PROMTAIL_VERSION}/promtail-linux-${ARCH}.zip"

    log_info "Завантаження Promtail..."
    cd /tmp
    wget -q "$PROMTAIL_URL" -O promtail.zip
    unzip -o promtail.zip
    mv "promtail-linux-$ARCH" "$INSTALL_DIR/promtail"
    chmod +x "$INSTALL_DIR/promtail"
    rm -f promtail.zip

    log_success "Promtail завантажено"

    # Конфігурація
    log_info "Створення конфігурації Promtail..."

    local HOSTNAME=$(hostname)

    cat > "$CONFIG_DIR/promtail.yml" << EOF
# Promtail Configuration for Linux
# Generated: $(date)

server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /var/lib/promtail/positions.yaml

clients:
  - url: ${LOKI_URL}/loki/api/v1/push
    batchwait: 1s
    batchsize: 1048576

scrape_configs:
  # Syslog
  - job_name: syslog
    static_configs:
      - targets:
          - localhost
        labels:
          job: syslog
          host: ${HOSTNAME}
          __path__: /var/log/syslog
    pipeline_stages:
      - regex:
          expression: '^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+(?P<process>\S+):\s+(?P<message>.*)$'
      - labels:
          process:

  # Auth log
  - job_name: auth
    static_configs:
      - targets:
          - localhost
        labels:
          job: auth
          host: ${HOSTNAME}
          category: authentication
          severity: high
          __path__: /var/log/auth.log
    pipeline_stages:
      - regex:
          expression: '(?i)(failed|invalid|error|denied|attack)'
      - labels:
          severity: high

  # Secure log (RHEL/CentOS)
  - job_name: secure
    static_configs:
      - targets:
          - localhost
        labels:
          job: secure
          host: ${HOSTNAME}
          category: authentication
          __path__: /var/log/secure

  # Audit log
  - job_name: audit
    static_configs:
      - targets:
          - localhost
        labels:
          job: audit
          host: ${HOSTNAME}
          category: audit
          severity: high
          __path__: /var/log/audit/audit.log
    pipeline_stages:
      - regex:
          expression: 'type=(?P<audit_type>\w+)'
      - labels:
          audit_type:

  # Kernel messages
  - job_name: kern
    static_configs:
      - targets:
          - localhost
        labels:
          job: kern
          host: ${HOSTNAME}
          category: kernel
          __path__: /var/log/kern.log

  # Dpkg/apt (Debian/Ubuntu)
  - job_name: dpkg
    static_configs:
      - targets:
          - localhost
        labels:
          job: dpkg
          host: ${HOSTNAME}
          category: packages
          __path__: /var/log/dpkg.log

  # DNF/YUM (RHEL/CentOS)
  - job_name: dnf
    static_configs:
      - targets:
          - localhost
        labels:
          job: dnf
          host: ${HOSTNAME}
          category: packages
          __path__: /var/log/dnf.log

  # SSH daemon
  - job_name: sshd
    journal:
      labels:
        job: sshd
        host: ${HOSTNAME}
        category: ssh
        severity: high
      path: /var/log/journal
    relabel_configs:
      - source_labels: ['__journal__systemd_unit']
        regex: 'sshd.service'
        action: keep

  # Sudo commands
  - job_name: sudo
    static_configs:
      - targets:
          - localhost
        labels:
          job: sudo
          host: ${HOSTNAME}
          category: privilege_escalation
          severity: critical
          __path__: /var/log/auth.log
    pipeline_stages:
      - match:
          selector: '{job="sudo"}'
          stages:
            - regex:
                expression: 'sudo:'
                source: filename

  # Cron
  - job_name: cron
    static_configs:
      - targets:
          - localhost
        labels:
          job: cron
          host: ${HOSTNAME}
          category: scheduled_tasks
          __path__: /var/log/cron.log

  # Journal (systemd)
  - job_name: journal
    journal:
      labels:
        job: journal
        host: ${HOSTNAME}
      path: /var/log/journal
    relabel_configs:
      - source_labels: ['__journal_priority']
        target_label: 'priority'
      - source_labels: ['__journal__systemd_unit']
        target_label: 'unit'
EOF

    log_success "Конфігурація Promtail створена"

    # Systemd service
    log_info "Створення systemd сервісу..."

    cat > /etc/systemd/system/promtail.service << EOF
[Unit]
Description=Promtail Log Agent
Documentation=https://grafana.com/docs/loki/latest/clients/promtail/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/promtail -config.file=${CONFIG_DIR}/promtail.yml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable promtail
    systemctl start promtail

    log_success "Promtail встановлено та запущено"
}

# =============================================================================
# Встановлення Node Exporter
# =============================================================================
install_node_exporter() {
    banner "Встановлення Node Exporter v$NODE_EXPORTER_VERSION"

    local ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="armv7"
            ;;
    esac

    local NE_URL="https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-${ARCH}.tar.gz"

    log_info "Завантаження Node Exporter..."
    cd /tmp
    wget -q "$NE_URL" -O node_exporter.tar.gz
    tar xzf node_exporter.tar.gz
    mv "node_exporter-${NODE_EXPORTER_VERSION}.linux-${ARCH}/node_exporter" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/node_exporter"
    rm -rf node_exporter.tar.gz "node_exporter-${NODE_EXPORTER_VERSION}.linux-${ARCH}"

    log_success "Node Exporter завантажено"

    # Systemd service
    log_info "Створення systemd сервісу..."

    cat > /etc/systemd/system/node_exporter.service << EOF
[Unit]
Description=Prometheus Node Exporter
Documentation=https://prometheus.io/docs/guides/node-exporter/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/node_exporter \\
    --collector.systemd \\
    --collector.processes \\
    --collector.filesystem.mount-points-exclude="^/(sys|proc|dev|host|etc)(\$|/)" \\
    --web.listen-address=":9100"
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable node_exporter
    systemctl start node_exporter

    log_success "Node Exporter встановлено (порт 9100)"
}

# =============================================================================
# Налаштування Auditd
# =============================================================================
configure_auditd() {
    if [ "$SKIP_AUDITD" = true ]; then
        log_warning "Auditd пропущено (--skip-auditd)"
        return
    fi

    banner "Налаштування Auditd"

    # Базові правила аудиту
    log_info "Створення правил аудиту..."

    cat > /etc/audit/rules.d/security.rules << 'EOF'
# Security Audit Rules for Linux
# Generated by install-agent.sh

# Remove any existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# =============================================================================
# Authentication & Authorization
# =============================================================================
# Login/logout events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Password changes
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# PAM configuration
-w /etc/pam.d/ -p wa -k pam

# SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

# =============================================================================
# Privileged Commands
# =============================================================================
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/userdel -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/groupadd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/groupdel -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# =============================================================================
# Network Configuration
# =============================================================================
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/sysconfig/network -p wa -k network
-w /etc/sysconfig/network-scripts/ -p wa -k network
-w /etc/netplan/ -p wa -k network
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network

# =============================================================================
# Systemd & Services
# =============================================================================
-w /etc/systemd/ -p wa -k systemd
-w /usr/lib/systemd/ -p wa -k systemd
-w /etc/init.d/ -p wa -k init
-w /etc/rc.local -p wa -k init

# =============================================================================
# Cron Jobs (Persistence)
# =============================================================================
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# =============================================================================
# Kernel Modules (Rootkit detection)
# =============================================================================
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# =============================================================================
# Time Changes
# =============================================================================
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# =============================================================================
# Process Execution (Suspicious)
# =============================================================================
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -F key=exec
-a always,exit -F arch=b64 -S execve -F euid=0 -F key=exec_root

# =============================================================================
# File Deletion
# =============================================================================
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# =============================================================================
# Audit Configuration (Tampering)
# =============================================================================
-w /var/log/audit/ -p wa -k audit_logs
-w /etc/audit/ -p wa -k audit_config
-w /etc/libaudit.conf -p wa -k audit_config
-w /etc/audisp/ -p wa -k audit_config

# Make config immutable (uncomment in production)
# -e 2
EOF

    # Перезавантаження auditd
    log_info "Перезавантаження auditd..."

    # auditctl -R /etc/audit/rules.d/security.rules
    service auditd restart 2>/dev/null || systemctl restart auditd

    log_success "Auditd налаштовано"
}

# =============================================================================
# Встановлення Osquery
# =============================================================================
install_osquery() {
    if [ "$SKIP_OSQUERY" = true ] || [ -z "$FLEET_URL" ]; then
        log_warning "Osquery пропущено"
        return
    fi

    if [ -z "$FLEET_SECRET" ]; then
        log_warning "FleetDM secret не вказано, osquery не встановлено"
        return
    fi

    banner "Встановлення Osquery v$OSQUERY_VERSION"

    case $DISTRO in
        ubuntu|debian|kali)
            log_info "Встановлення osquery для Debian/Ubuntu..."
            export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
            apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY
            add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
            apt-get update
            apt-get install -y osquery
            ;;
        rhel|centos|rocky|almalinux|fedora)
            log_info "Встановлення osquery для RHEL..."
            curl -L https://pkg.osquery.io/rpm/GPG | tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
            yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo
            yum-config-manager --enable osquery-s3-rpm-repo
            yum install -y osquery
            ;;
        *)
            log_warning "Автоматичне встановлення osquery не підтримується для $DISTRO"
            return
            ;;
    esac

    # Конфігурація для FleetDM
    log_info "Налаштування osquery для FleetDM..."

    mkdir -p /etc/osquery

    # Enroll secret
    echo "$FLEET_SECRET" > /etc/osquery/enroll_secret

    # Osquery flags
    cat > /etc/osquery/osquery.flags << EOF
--tls_hostname=${FLEET_URL#*://}
--tls_server_certs=/etc/osquery/fleet.crt
--enroll_secret_path=/etc/osquery/enroll_secret
--host_identifier=hostname
--enroll_tls_endpoint=/api/osquery/enroll
--config_plugin=tls
--config_tls_endpoint=/api/osquery/config
--config_refresh=10
--disable_distributed=false
--distributed_plugin=tls
--distributed_interval=10
--distributed_tls_max_attempts=3
--distributed_tls_read_endpoint=/api/osquery/distributed/read
--distributed_tls_write_endpoint=/api/osquery/distributed/write
--logger_plugin=tls
--logger_tls_endpoint=/api/osquery/log
--logger_tls_period=10
EOF

    # Спроба отримати сертифікат
    log_info "Отримання TLS сертифіката FleetDM..."
    local FLEET_HOST="${FLEET_URL#*://}"
    FLEET_HOST="${FLEET_HOST%%/*}"

    openssl s_client -connect "$FLEET_HOST" < /dev/null 2>/dev/null | openssl x509 > /etc/osquery/fleet.crt 2>/dev/null || true

    systemctl enable osqueryd
    systemctl start osqueryd

    log_success "Osquery встановлено"
}

# =============================================================================
# Налаштування Firewall
# =============================================================================
configure_firewall() {
    banner "Налаштування Firewall"

    # Node Exporter port
    if command -v ufw &> /dev/null; then
        log_info "Налаштування UFW..."
        ufw allow from any to any port 9100 proto tcp comment "Node Exporter"
        ufw allow from any to any port 9080 proto tcp comment "Promtail"
    elif command -v firewall-cmd &> /dev/null; then
        log_info "Налаштування firewalld..."
        firewall-cmd --permanent --add-port=9100/tcp
        firewall-cmd --permanent --add-port=9080/tcp
        firewall-cmd --reload
    else
        log_warning "Firewall не знайдено, налаштуйте вручну"
    fi

    log_success "Firewall налаштовано"
}

# =============================================================================
# Перевірка статусу
# =============================================================================
check_status() {
    banner "Перевірка статусу"

    echo ""
    echo "Services:"
    echo "========="

    for service in promtail node_exporter auditd osqueryd; do
        if systemctl is-active --quiet $service 2>/dev/null; then
            echo -e "  $service: ${GREEN}Running${NC}"
        else
            echo -e "  $service: ${RED}Not running${NC}"
        fi
    done

    echo ""
    echo "Ports:"
    echo "======"
    ss -tlnp | grep -E "9080|9100" || echo "  No monitoring ports detected"

    echo ""
}

# =============================================================================
# Summary
# =============================================================================
print_summary() {
    banner "Installation Complete!"

    cat << EOF
Встановлені компоненти:
  - Promtail: ${INSTALL_DIR}/promtail
  - Node Exporter: ${INSTALL_DIR}/node_exporter
  - Auditd: $(if [ "$SKIP_AUDITD" = true ]; then echo "Skipped"; else echo "Configured"; fi)
  - Osquery: $(if [ "$SKIP_OSQUERY" = true ] || [ -z "$FLEET_URL" ]; then echo "Skipped"; else echo "Configured"; fi)

Конфігурація:
  - Promtail: ${CONFIG_DIR}/promtail.yml
  - Audit rules: /etc/audit/rules.d/security.rules

Порти:
  - Node Exporter: 9100
  - Promtail: 9080

Перевірка в Grafana:
  1. Відкрийте http://<monitoring-server>:3000
  2. Перейдіть в Explore → Loki
  3. Запит: {host="$(hostname)"}

Команди управління:
  systemctl status promtail
  systemctl status node_exporter
  systemctl status auditd
  ausearch -k logins -ts recent

EOF
}

# =============================================================================
# Main
# =============================================================================
main() {
    banner "Linux Security Agent Installation"

    echo "Configuration:"
    echo "  Loki URL: $LOKI_URL"
    echo "  FleetDM: ${FLEET_URL:-Disabled}"
    echo "  Auditd: $(if [ "$SKIP_AUDITD" = true ]; then echo "Skip"; else echo "Configure"; fi)"
    echo ""

    read -p "Continue? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_warning "Cancelled by user"
        exit 0
    fi

    detect_distro
    install_dependencies
    create_directories
    install_promtail
    install_node_exporter
    configure_auditd
    install_osquery
    configure_firewall
    check_status
    print_summary
}

main "$@"
