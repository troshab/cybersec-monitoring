#!/bin/bash
# =============================================================================
# Cybersec Monitoring - Server Installation Script
# =============================================================================
# Головний скрипт встановлення серверної інфраструктури моніторингу
# Для Debian 12+ / Ubuntu 22.04+
# =============================================================================

set -e

# Кольори для виводу
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Логування
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Конфігурація
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
INSTALL_DIR="/opt/monitoring"
INVENTORY_DIR="/opt/inventory"

# Параметри за замовчуванням
SKIP_HARDENING=false
SKIP_INVENTORY=false
DRY_RUN=false
VERBOSE=false
ENV_FILE="$PROJECT_DIR/.env"

# =============================================================================
# Функції
# =============================================================================

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Головний скрипт встановлення системи моніторингу кібербезпеки.

OPTIONS:
  --env-file PATH     Шлях до .env файлу (default: ../.env)
  --skip-hardening    Пропустити hardening (для тестування)
  --skip-inventory    Не встановлювати Netdisco/FleetDM
  --dry-run           Тільки показати що буде зроблено
  --verbose           Детальний вивід
  --help              Показати цю допомогу

EXAMPLES:
  $0                              # Повне встановлення
  $0 --skip-inventory             # Без Netdisco/FleetDM
  $0 --dry-run                    # Перевірка без змін

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --env-file)
                ENV_FILE="$2"
                shift 2
                ;;
            --skip-hardening)
                SKIP_HARDENING=true
                shift
                ;;
            --skip-inventory)
                SKIP_INVENTORY=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "Невідомий параметр: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Цей скрипт потрібно запускати від root"
        log_info "Використайте: sudo $0"
        exit 1
    fi
    log_success "Запущено від root"
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Не вдалося визначити ОС"
        exit 1
    fi

    source /etc/os-release

    if [[ "$ID" != "debian" && "$ID" != "ubuntu" ]]; then
        log_error "Підтримуються тільки Debian та Ubuntu"
        exit 1
    fi

    if [[ "$ID" == "debian" && "$VERSION_ID" -lt 12 ]]; then
        log_error "Потрібна Debian 12 або новіше (поточна: $VERSION_ID)"
        exit 1
    fi

    if [[ "$ID" == "ubuntu" && "$VERSION_ID" < "22.04" ]]; then
        log_error "Потрібна Ubuntu 22.04 або новіше"
        exit 1
    fi

    log_success "ОС: $PRETTY_NAME"
}

check_env_file() {
    if [[ ! -f "$ENV_FILE" ]]; then
        log_error "Файл .env не знайдено: $ENV_FILE"
        log_info "Скопіюйте .env.example в .env та налаштуйте:"
        log_info "  cp $PROJECT_DIR/.env.example $PROJECT_DIR/.env"
        log_info "  nano $PROJECT_DIR/.env"
        exit 1
    fi

    # Завантаження змінних
    set -a
    source "$ENV_FILE"
    set +a

    # Перевірка обов'язкових змінних
    local required_vars=(
        "MONITORING_SERVER_IP"
        "GRAFANA_ADMIN_PASSWORD"
        "GRAFANA_SECRET_KEY"
    )

    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            log_error "Змінна $var не встановлена в $ENV_FILE"
            exit 1
        fi
    done

    # Перевірка чи паролі змінені
    if [[ "$GRAFANA_ADMIN_PASSWORD" == *"CHANGE_ME"* ]]; then
        log_error "Змініть GRAFANA_ADMIN_PASSWORD в $ENV_FILE"
        exit 1
    fi

    log_success "Конфігурація завантажена з $ENV_FILE"
}

check_disk_space() {
    local available_gb=$(df -BG / | tail -1 | awk '{print $4}' | tr -d 'G')
    log_info "Вільне місце на диску: ${available_gb}GB"
}

check_internet() {
    if ! ping -c 1 -W 5 8.8.8.8 &>/dev/null; then
        log_error "Немає доступу до інтернету"
        exit 1
    fi
    log_success "Інтернет доступний"
}

setup_system() {
    log_info "Налаштування системи..."

    # Встановлення hostname (якщо задано)
    if [[ -n "${MONITORING_HOSTNAME:-}" ]]; then
        hostnamectl set-hostname "$MONITORING_HOSTNAME"
        log_success "Hostname: $MONITORING_HOSTNAME"
    fi

    # Timezone
    timedatectl set-timezone "${TZ:-Europe/Kyiv}"
    log_success "Timezone: $(timedatectl show --property=Timezone --value)"

    # Оновлення системи
    log_info "Оновлення пакетів..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq

    # Встановлення базових пакетів
    log_info "Встановлення базових пакетів..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        curl \
        wget \
        git \
        htop \
        vim \
        nano \
        net-tools \
        dnsutils \
        jq \
        unzip \
        ca-certificates \
        gnupg \
        lsb-release \
        apt-transport-https

    log_success "Базові пакети встановлено"
}

setup_hardening() {
    if [[ "$SKIP_HARDENING" == true ]]; then
        log_warn "Hardening пропущено (--skip-hardening)"
        return
    fi

    log_info "Налаштування безпеки сервера..."

    # UFW Firewall
    log_info "Налаштування firewall (UFW)..."
    apt-get install -y -qq ufw

    ufw default deny incoming
    ufw default allow outgoing

    # SSH
    ufw allow from 10.0.0.0/8 to any port 22 comment "SSH internal"
    ufw allow from 172.16.0.0/12 to any port 22 comment "SSH internal"
    ufw allow from 192.168.0.0/16 to any port 22 comment "SSH internal"

    # Grafana
    ufw allow from 10.0.0.0/8 to any port "${GRAFANA_PORT:-3000}" comment "Grafana"
    ufw allow from 172.16.0.0/12 to any port "${GRAFANA_PORT:-3000}" comment "Grafana"
    ufw allow from 192.168.0.0/16 to any port "${GRAFANA_PORT:-3000}" comment "Grafana"

    # Loki (для агентів)
    ufw allow from 10.0.0.0/8 to any port "${LOKI_PORT:-3100}" comment "Loki"
    ufw allow from 172.16.0.0/12 to any port "${LOKI_PORT:-3100}" comment "Loki"
    ufw allow from 192.168.0.0/16 to any port "${LOKI_PORT:-3100}" comment "Loki"

    # Prometheus (internal)
    ufw allow from 10.0.0.0/8 to any port "${PROMETHEUS_PORT:-9090}" comment "Prometheus"
    ufw allow from 172.16.0.0/12 to any port "${PROMETHEUS_PORT:-9090}" comment "Prometheus"
    ufw allow from 192.168.0.0/16 to any port "${PROMETHEUS_PORT:-9090}" comment "Prometheus"

    # Syslog UDP
    ufw allow 514/udp comment "Syslog"

    # FleetDM (якщо не пропущено)
    if [[ "$SKIP_INVENTORY" != true ]]; then
        ufw allow from 10.0.0.0/8 to any port "${FLEET_PORT:-8080}" comment "FleetDM"
        ufw allow from 172.16.0.0/12 to any port "${FLEET_PORT:-8080}" comment "FleetDM"
        ufw allow from 192.168.0.0/16 to any port "${FLEET_PORT:-8080}" comment "FleetDM"

        ufw allow from 10.0.0.0/8 to any port "${NETDISCO_PORT:-5000}" comment "Netdisco"
        ufw allow from 172.16.0.0/12 to any port "${NETDISCO_PORT:-5000}" comment "Netdisco"
        ufw allow from 192.168.0.0/16 to any port "${NETDISCO_PORT:-5000}" comment "Netdisco"
    fi

    ufw --force enable
    log_success "Firewall налаштовано"

    # Fail2ban
    log_info "Встановлення fail2ban..."
    apt-get install -y -qq fail2ban
    systemctl enable fail2ban
    systemctl start fail2ban
    log_success "Fail2ban активовано"

    # Автоматичні оновлення безпеки
    log_info "Налаштування автоматичних оновлень..."
    apt-get install -y -qq unattended-upgrades
    dpkg-reconfigure -f noninteractive unattended-upgrades
    log_success "Автоматичні оновлення безпеки активовано"
}

install_docker() {
    log_info "Встановлення Docker..."

    # Видалення старих версій
    apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

    # Очищення старих ключів та репозиторіїв Docker
    rm -f /etc/apt/keyrings/docker.gpg /etc/apt/keyrings/docker.asc 2>/dev/null || true
    rm -f /etc/apt/sources.list.d/docker.list /etc/apt/sources.list.d/docker.sources 2>/dev/null || true

    # Додавання Docker репозиторію
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc

    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Встановлення Docker
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    # Перевірка
    docker --version
    docker compose version

    # Автозапуск
    systemctl enable docker
    systemctl start docker

    log_success "Docker встановлено"
}

create_directories() {
    log_info "Створення директорій..."

    # Monitoring stack
    mkdir -p "$INSTALL_DIR"/{data/{prometheus,loki,grafana,alertmanager},config}

    # Inventory stack
    if [[ "$SKIP_INVENTORY" != true ]]; then
        mkdir -p "$INVENTORY_DIR"/{netdisco/{logs,config,nd-site-local,pgdata},fleetdm/{certs,logs}}
    fi

    # Правильні права для Grafana (uid 472)
    chown -R 472:472 "$INSTALL_DIR/data/grafana"

    # Права для Loki
    chown -R 10001:10001 "$INSTALL_DIR/data/loki"

    # Права для FleetDM та Netdisco logs
    if [[ "$SKIP_INVENTORY" != true ]]; then
        chmod 777 "$INVENTORY_DIR/fleetdm/logs"
        chmod 777 "$INVENTORY_DIR/netdisco/logs"
    fi

    log_success "Директорії створено"
}

deploy_monitoring_stack() {
    log_info "Розгортання Monitoring Stack..."

    # Копіювання конфігурацій
    cp -r "$SCRIPT_DIR/monitoring-stack/"* "$INSTALL_DIR/config/"

    # Заміна змінних в конфігах (виключаємо alerts - там є шаблони {{ $value }})
    find "$INSTALL_DIR/config" -type f \( -name "*.yml" -o -name "*.yaml" -o -name "*.ini" \) ! -path "*/alerts/*" | while read -r file; do
        envsubst < "$file" > "$file.tmp" && mv "$file.tmp" "$file"
    done

    # Запуск
    cd "$INSTALL_DIR/config"
    docker compose up -d

    # Очікування запуску
    log_info "Очікування запуску сервісів..."
    sleep 30

    # Перевірка health
    local services=("prometheus" "loki" "grafana" "alertmanager")
    for svc in "${services[@]}"; do
        if docker ps --filter "name=$svc" --filter "status=running" | grep -q "$svc"; then
            log_success "$svc запущено"
        else
            log_error "$svc не запустився"
            docker logs "$svc" --tail 50
        fi
    done
}

deploy_inventory_stack() {
    if [[ "$SKIP_INVENTORY" == true ]]; then
        log_warn "Inventory Stack пропущено (--skip-inventory)"
        return
    fi

    log_info "Розгортання Inventory Stack..."

    # Копіювання конфігурацій
    cp -r "$SCRIPT_DIR/inventory-stack/"* "$INVENTORY_DIR/"

    # Заміна змінних
    find "$INVENTORY_DIR" -type f -name "*.yml" -o -name "*.yaml" -o -name "*.env" | while read -r file; do
        envsubst < "$file" > "$file.tmp" && mv "$file.tmp" "$file"
    done

    # Запуск
    cd "$INVENTORY_DIR"
    docker compose up -d

    log_success "Inventory Stack запущено"

    # -------------------------------------------------------------------------
    # FleetDM Auto-Setup via API
    # -------------------------------------------------------------------------
    setup_fleetdm
}

setup_fleetdm() {
    log_info "Автоматичне налаштування FleetDM..."

    local FLEET_URL="https://localhost:${FLEET_PORT:-8080}"
    local MAX_RETRIES=30
    local RETRY_INTERVAL=5

    # Очікуємо поки FleetDM стане доступним
    log_info "Очікування запуску FleetDM..."
    for i in $(seq 1 $MAX_RETRIES); do
        if curl -sk "$FLEET_URL/setup" >/dev/null 2>&1; then
            log_success "FleetDM доступний"
            break
        fi
        if [ $i -eq $MAX_RETRIES ]; then
            log_error "FleetDM не запустився після $((MAX_RETRIES * RETRY_INTERVAL)) секунд"
            log_warn "Налаштуйте FleetDM вручну: $FLEET_URL"
            return 1
        fi
        sleep $RETRY_INTERVAL
    done

    # Перевіряємо чи вже налаштований
    local SETUP_CHECK=$(curl -sk "$FLEET_URL/api/v1/setup" 2>/dev/null)
    if echo "$SETUP_CHECK" | grep -q '"setup":false'; then
        log_info "FleetDM вже налаштований"
    else
        # Виконуємо початкове налаштування через API
        log_info "Створення адміністратора FleetDM..."

        local SETUP_RESPONSE=$(curl -sk -X POST "$FLEET_URL/api/v1/setup" \
            -H 'Content-Type: application/json' \
            -d "{
                \"admin\": {
                    \"admin\": true,
                    \"email\": \"${GRAFANA_ADMIN_USER:-monadmin}@${TARGET_DOMAIN_FQDN:-lab.local}\",
                    \"name\": \"${GRAFANA_ADMIN_USER:-monadmin}\",
                    \"password\": \"${GRAFANA_ADMIN_PASSWORD:-Mon!123admin}\"
                },
                \"org_info\": {
                    \"org_name\": \"${ORGANIZATION_NAME:-LAB Training}\"
                },
                \"server_url\": \"https://${MONITORING_SERVER_IP}:${FLEET_PORT:-8080}\"
            }" 2>/dev/null)

        if echo "$SETUP_RESPONSE" | grep -q '"token"'; then
            log_success "FleetDM адміністратор створений"

            # Витягуємо токен
            local FLEET_TOKEN=$(echo "$SETUP_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

            if [ -n "$FLEET_TOKEN" ]; then
                # Отримуємо Enroll Secret
                local ENROLL_RESPONSE=$(curl -sk "$FLEET_URL/api/v1/fleet/spec/enroll_secret" \
                    -H "Authorization: Bearer $FLEET_TOKEN" 2>/dev/null)

                local ENROLL_SECRET=$(echo "$ENROLL_RESPONSE" | grep -o '"secret":"[^"]*"' | head -1 | cut -d'"' -f4)

                if [ -n "$ENROLL_SECRET" ]; then
                    # Оновлюємо .env файл
                    sed -i "s/FLEET_ENROLL_SECRET=.*/FLEET_ENROLL_SECRET=$ENROLL_SECRET/" "$ENV_FILE"
                    log_success "Fleet Enroll Secret збережено в $ENV_FILE"

                    echo ""
                    echo -e "${GREEN}============================================================${NC}"
                    echo -e "${GREEN}  FleetDM налаштовано автоматично!${NC}"
                    echo -e "${GREEN}============================================================${NC}"
                    echo ""
                    echo -e "  URL: ${CYAN}https://${MONITORING_SERVER_IP}:${FLEET_PORT:-8080}${NC}"
                    echo -e "  Логін: ${CYAN}${GRAFANA_ADMIN_USER:-monadmin}@${TARGET_DOMAIN_FQDN:-lab.local}${NC}"
                    echo -e "  Пароль: ${CYAN}${GRAFANA_ADMIN_PASSWORD:-Mon!123admin}${NC}"
                    echo ""
                    echo -e "  Enroll Secret: ${CYAN}${ENROLL_SECRET}${NC}"
                    echo ""
                else
                    log_warn "Не вдалося отримати Enroll Secret"
                fi
            fi
        else
            log_error "Помилка налаштування FleetDM: $SETUP_RESPONSE"
        fi
    fi
}

install_alloy() {
    log_info "Встановлення Grafana Alloy (замінює deprecated Promtail)..."

    # Додати Grafana репозиторій
    apt-get install -y -qq apt-transport-https wget gpg

    mkdir -p /etc/apt/keyrings/
    wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor > /etc/apt/keyrings/grafana.gpg

    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | tee /etc/apt/sources.list.d/grafana.list > /dev/null

    apt-get update -qq

    # Встановити Alloy
    apt-get install -y -qq alloy

    # Директорії
    mkdir -p /etc/alloy /var/lib/alloy
    chown -R alloy:alloy /var/lib/alloy

    # Конфігурація
    cp "$SCRIPT_DIR/alloy/config.alloy" /etc/alloy/config.alloy

    # Override для CAP_NET_BIND_SERVICE (syslog port 514)
    mkdir -p /etc/systemd/system/alloy.service.d

    cat > /etc/systemd/system/alloy.service.d/override.conf << 'EOF'
[Service]
# Allow binding to privileged ports (UDP 514 for syslog)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
EOF

    # Environment config
    cat > /etc/default/alloy << 'EOF'
# Grafana Alloy configuration
ALLOY_CONFIG_FILE=/etc/alloy/config.alloy
ALLOY_STABILITY_LEVEL=generally-available
EOF

    # Права для читання логів
    usermod -a -G adm alloy 2>/dev/null || true
    usermod -a -G docker alloy 2>/dev/null || true

    systemctl daemon-reload
    systemctl enable alloy
    systemctl start alloy

    log_success "Grafana Alloy встановлено"
}

install_node_exporter() {
    log_info "Встановлення Node Exporter..."

    local NODE_EXPORTER_VERSION="1.7.0"
    cd /tmp
    wget -q "https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz"
    tar xzf "node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz"
    cp "node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64/node_exporter" /usr/local/bin/

    # Користувач
    useradd --system --no-create-home --shell /bin/false node_exporter 2>/dev/null || true

    # Systemd сервіс
    cat > /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable node_exporter
    systemctl start node_exporter

    log_success "Node Exporter встановлено"
}

print_summary() {
    echo ""
    echo "============================================================================="
    echo -e "${GREEN}Встановлення завершено успішно!${NC}"
    echo "============================================================================="
    echo ""
    echo "Сервіси:"
    echo -e "  Grafana:      ${BLUE}http://${MONITORING_SERVER_IP}:${GRAFANA_PORT:-3000}${NC}"
    echo -e "  Prometheus:   ${BLUE}http://${MONITORING_SERVER_IP}:${PROMETHEUS_PORT:-9090}${NC}"
    echo -e "  Loki:         ${BLUE}http://${MONITORING_SERVER_IP}:${LOKI_PORT:-3100}${NC}"
    echo -e "  Alertmanager: ${BLUE}http://${MONITORING_SERVER_IP}:${ALERTMANAGER_PORT:-9093}${NC}"

    if [[ "$SKIP_INVENTORY" != true ]]; then
        echo -e "  Netdisco:     ${BLUE}http://${MONITORING_SERVER_IP}:${NETDISCO_PORT:-5000}${NC}"
        echo -e "  FleetDM:      ${BLUE}https://${MONITORING_SERVER_IP}:${FLEET_PORT:-8080}${NC}"
    fi

    echo ""
    echo "Credentials:"
    echo -e "  Grafana:      admin / ${YELLOW}(пароль з .env)${NC}"
    echo ""
    echo "Наступні кроки:"
    echo "  1. Відкрийте Grafana та змініть пароль"
    echo "  2. Перевірте datasources в Grafana"
    echo "  3. Імпортуйте дашборди"
    echo "  4. Налаштуйте сповіщення в Alertmanager"
    echo "  5. Розгорніть агенти на клієнтах"
    echo ""
    echo "Документація: $PROJECT_DIR/README.md"
    echo "============================================================================="
}

# =============================================================================
# Головна функція
# =============================================================================

main() {
    echo "============================================================================="
    echo "Cybersec Monitoring - Server Installation"
    echo "============================================================================="

    parse_args "$@"

    if [[ "$DRY_RUN" == true ]]; then
        log_warn "Режим DRY RUN - зміни не будуть внесені"
    fi

    # Перевірки
    check_root
    check_os
    check_env_file
    check_disk_space
    check_internet

    if [[ "$DRY_RUN" == true ]]; then
        log_success "Всі перевірки пройдено. Готово до встановлення."
        exit 0
    fi

    # Встановлення
    setup_system
    setup_hardening
    install_docker
    create_directories
    deploy_monitoring_stack
    deploy_inventory_stack
    install_alloy      # Grafana Alloy (замінює deprecated Promtail)
    install_node_exporter

    # Результат
    print_summary
}

main "$@"
