#!/bin/bash
#
# Linux Agent Installation Script
# Встановлення моніторингу на Linux системах
#
# Підтримка:
#   - Ubuntu 20.04+, 22.04+, 24.04
#   - Debian 11+, 12, 13
#   - RHEL/CentOS/Rocky 8+, 9
#   - Kali Linux
#
# Компоненти:
#   - Grafana Alloy (logs → Loki) - replaces deprecated Promtail
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
NODE_EXPORTER_VERSION="1.7.0"
OSQUERY_VERSION="5.12.1"
SKIP_AUDITD=false
SKIP_OSQUERY=false
INSTALL_DIR="/opt/monitoring"
CONFIG_DIR="/etc/alloy"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# Парсинг аргументів
# =============================================================================
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Required:
  --loki-url URL          URL сервера Loki (наприклад: http://10.0.1.2:3100)

Optional:
  --fleet-url URL         URL FleetDM сервера
  --fleet-secret SECRET   FleetDM enrollment secret
  --skip-auditd           Пропустити налаштування auditd
  --skip-osquery          Пропустити встановлення osquery
  --node-exporter-version VER  Версія Node Exporter (default: $NODE_EXPORTER_VERSION)
  -h, --help              Показати цю довідку

Examples:
  $0 --loki-url "http://10.0.1.2:3100"
  $0 --loki-url "http://10.0.1.2:3100" --fleet-url "https://10.0.1.2:8080" --fleet-secret "abc123"

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
            apt-get install -y curl wget unzip jq auditd audispd-plugins gpg apt-transport-https
            # software-properties-common не потрібен на Debian 13+
            apt-get install -y software-properties-common 2>/dev/null || true
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
    mkdir -p /var/lib/alloy

    log_success "Директорії створено"
}

# =============================================================================
# Встановлення Grafana Alloy
# =============================================================================
install_alloy() {
    banner "Встановлення Grafana Alloy (замінює deprecated Promtail)"

    case $DISTRO in
        ubuntu|debian|kali)
            log_info "Додавання Grafana репозиторію..."
            mkdir -p /etc/apt/keyrings/
            wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor > /etc/apt/keyrings/grafana.gpg
            echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | tee /etc/apt/sources.list.d/grafana.list > /dev/null
            apt-get update
            apt-get install -y alloy
            ;;
        rhel|centos|rocky|almalinux|fedora)
            log_info "Додавання Grafana репозиторію..."
            cat > /etc/yum.repos.d/grafana.repo << 'EOF'
[grafana]
name=grafana
baseurl=https://rpm.grafana.com
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
EOF
            if command -v dnf &> /dev/null; then
                dnf install -y alloy
            else
                yum install -y alloy
            fi
            ;;
        *)
            log_error "Автоматичне встановлення Alloy не підтримується для $DISTRO"
            exit 1
            ;;
    esac

    log_success "Alloy встановлено"

    # Конфігурація
    log_info "Налаштування конфігурації Alloy..."

    # Копіюємо конфіг якщо є, або використовуємо вбудований
    if [ -f "$SCRIPT_DIR/config.alloy" ]; then
        cp "$SCRIPT_DIR/config.alloy" "$CONFIG_DIR/config.alloy"
        log_info "Використовується конфігурація з $SCRIPT_DIR/config.alloy"
    else
        # Створюємо базову конфігурацію
        cat > "$CONFIG_DIR/config.alloy" << EOF
// Grafana Alloy Configuration - Linux Agent
// Generated: $(date)

loki.write "default" {
  endpoint {
    url = "${LOKI_URL}/loki/api/v1/push"
  }
}

local.file_match "auth" {
  path_targets = [{
    __path__ = "/var/log/auth.log",
    job      = "linux_auth",
    host     = env("HOSTNAME"),
    os_type  = "linux",
  }]
}

loki.source.file "auth" {
  targets    = local.file_match.auth.targets
  forward_to = [loki.write.default.receiver]
}

local.file_match "syslog" {
  path_targets = [{
    __path__ = "/var/log/syslog",
    job      = "linux_syslog",
    host     = env("HOSTNAME"),
    os_type  = "linux",
  }]
}

loki.source.file "syslog" {
  targets    = local.file_match.syslog.targets
  forward_to = [loki.write.default.receiver]
}

local.file_match "audit" {
  path_targets = [{
    __path__ = "/var/log/audit/audit.log",
    job      = "linux_audit",
    host     = env("HOSTNAME"),
    os_type  = "linux",
  }]
}

loki.source.file "audit" {
  targets    = local.file_match.audit.targets
  forward_to = [loki.write.default.receiver]
}
EOF
    fi

    # Оновлюємо Loki URL в конфігурації
    sed -i "s|url = \"http://[^\"]*\"|url = \"${LOKI_URL}/loki/api/v1/push\"|g" "$CONFIG_DIR/config.alloy"

    # Environment config
    cat > /etc/default/alloy << 'EOF'
# Grafana Alloy configuration
ALLOY_CONFIG_FILE=/etc/alloy/config.alloy
ALLOY_STABILITY_LEVEL=generally-available
EOF

    # Права для читання логів
    usermod -a -G adm alloy 2>/dev/null || true

    systemctl daemon-reload
    systemctl enable alloy
    systemctl start alloy

    log_success "Grafana Alloy налаштовано та запущено"
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

-D
-b 8192
-f 1

# Authentication
-w /var/log/lastlog -p wa -k logins
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd

# Privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Persistence
-w /etc/cron.d/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/ -p wa -k systemd

# Kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change

# Audit logs protection
-w /var/log/audit/ -p wa -k audit_logs
-w /etc/audit/ -p wa -k audit_config
EOF

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

    banner "Встановлення Osquery"

    case $DISTRO in
        ubuntu|debian|kali)
            export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
            apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY
            add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
            apt-get update
            apt-get install -y osquery
            ;;
        rhel|centos|rocky|almalinux|fedora)
            curl -L https://pkg.osquery.io/rpm/GPG | tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
            yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo
            yum install -y osquery
            ;;
        *)
            log_warning "Автоматичне встановлення osquery не підтримується для $DISTRO"
            return
            ;;
    esac

    mkdir -p /etc/osquery
    echo "$FLEET_SECRET" > /etc/osquery/enroll_secret

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
--distributed_tls_read_endpoint=/api/osquery/distributed/read
--distributed_tls_write_endpoint=/api/osquery/distributed/write
--logger_plugin=tls
--logger_tls_endpoint=/api/osquery/log
EOF

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

    if command -v ufw &> /dev/null; then
        log_info "Налаштування UFW..."
        ufw allow from any to any port 9100 proto tcp comment "Node Exporter"
        ufw allow from any to any port 12345 proto tcp comment "Alloy UI"
    elif command -v firewall-cmd &> /dev/null; then
        log_info "Налаштування firewalld..."
        firewall-cmd --permanent --add-port=9100/tcp
        firewall-cmd --permanent --add-port=12345/tcp
        firewall-cmd --reload
    else
        log_warning "Firewall не знайдено"
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

    for service in alloy node_exporter auditd osqueryd; do
        if systemctl is-active --quiet $service 2>/dev/null; then
            echo -e "  $service: ${GREEN}Running${NC}"
        else
            echo -e "  $service: ${RED}Not running${NC}"
        fi
    done

    echo ""
    echo "Ports:"
    echo "======"
    ss -tlnp | grep -E "12345|9100" || echo "  No monitoring ports detected"

    echo ""
}

# =============================================================================
# Summary
# =============================================================================
print_summary() {
    banner "Installation Complete!"

    cat << EOF
Встановлені компоненти:
  - Grafana Alloy: /usr/bin/alloy
  - Node Exporter: ${INSTALL_DIR}/node_exporter
  - Auditd: $(if [ "$SKIP_AUDITD" = true ]; then echo "Skipped"; else echo "Configured"; fi)
  - Osquery: $(if [ "$SKIP_OSQUERY" = true ] || [ -z "$FLEET_URL" ]; then echo "Skipped"; else echo "Configured"; fi)

Конфігурація:
  - Alloy: ${CONFIG_DIR}/config.alloy
  - Audit rules: /etc/audit/rules.d/security.rules

Порти:
  - Node Exporter: 9100
  - Alloy UI: 12345

Перевірка в Grafana:
  1. Відкрийте http://<monitoring-server>:3000
  2. Перейдіть в Explore → Loki
  3. Запит: {host="$(hostname)"}

Команди управління:
  systemctl status alloy
  systemctl status node_exporter
  systemctl status auditd

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

    # Interactive prompt (skip if running non-interactively)
    if [ -t 0 ]; then
        read -p "Continue? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_warning "Cancelled by user"
            exit 0
        fi
    fi

    detect_distro
    install_dependencies
    create_directories
    install_alloy
    install_node_exporter
    configure_auditd
    install_osquery
    configure_firewall
    check_status
    print_summary
}

main "$@"
