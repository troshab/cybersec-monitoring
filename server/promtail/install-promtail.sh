#!/bin/bash
# =============================================================================
# Promtail Installation Script for Monitoring Server
# =============================================================================
# Встановлення Promtail як native service для збору логів
# =============================================================================

set -e

# Кольори
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Конфігурація
PROMTAIL_VERSION="2.9.3"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/promtail"
DATA_DIR="/var/lib/promtail"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Перевірка root
if [[ $EUID -ne 0 ]]; then
    log_error "Запустіть від root: sudo $0"
    exit 1
fi

log_info "Встановлення Promtail v${PROMTAIL_VERSION}..."

# Завантаження
log_info "Завантаження..."
cd /tmp
wget -q "https://github.com/grafana/loki/releases/download/v${PROMTAIL_VERSION}/promtail-linux-amd64.zip" -O promtail.zip
unzip -o promtail.zip
chmod +x promtail-linux-amd64
mv promtail-linux-amd64 "${INSTALL_DIR}/promtail"

# Створення користувача
log_info "Створення системного користувача..."
useradd --system --no-create-home --shell /bin/false promtail 2>/dev/null || true

# Директорії
log_info "Створення директорій..."
mkdir -p "${CONFIG_DIR}"
mkdir -p "${DATA_DIR}"
chown promtail:promtail "${DATA_DIR}"

# Копіювання конфігурації
log_info "Копіювання конфігурації..."
if [[ -f "${SCRIPT_DIR}/promtail-server.yml" ]]; then
    cp "${SCRIPT_DIR}/promtail-server.yml" "${CONFIG_DIR}/config.yml"
else
    log_warn "Конфіг не знайдено, створюю базовий..."
    cat > "${CONFIG_DIR}/config.yml" << 'EOF'
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /var/lib/promtail/positions.yaml

clients:
  - url: http://localhost:3100/loki/api/v1/push

scrape_configs:
  - job_name: linux_syslog
    static_configs:
      - targets:
          - localhost
        labels:
          job: linux_syslog
          host: monitoring-server
          __path__: /var/log/syslog

  - job_name: linux_auth
    static_configs:
      - targets:
          - localhost
        labels:
          job: linux_auth
          host: monitoring-server
          __path__: /var/log/auth.log

  - job_name: network_syslog
    syslog:
      listen_address: 0.0.0.0:514
      listen_protocol: udp
      labels:
        job: network_syslog
    relabel_configs:
      - source_labels: ['__syslog_message_hostname']
        target_label: 'host'
EOF
fi

# Права для читання логів
log_info "Налаштування прав доступу..."
usermod -a -G adm promtail 2>/dev/null || true
usermod -a -G syslog promtail 2>/dev/null || true

# Дозвіл на низькі порти (для syslog 514)
setcap 'cap_net_bind_service=+ep' "${INSTALL_DIR}/promtail" 2>/dev/null || true

# Systemd сервіс
log_info "Створення systemd сервісу..."
cat > /etc/systemd/system/promtail.service << EOF
[Unit]
Description=Promtail Log Collector
Documentation=https://grafana.com/docs/loki/latest/clients/promtail/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=promtail
Group=promtail
ExecStart=${INSTALL_DIR}/promtail -config.file=${CONFIG_DIR}/config.yml
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}
ReadOnlyPaths=/var/log

# Capabilities for low ports
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# Запуск
log_info "Запуск сервісу..."
systemctl daemon-reload
systemctl enable promtail
systemctl start promtail

# Перевірка
sleep 2
if systemctl is-active --quiet promtail; then
    log_info "Promtail успішно встановлено та запущено!"
    log_info "Статус: $(systemctl is-active promtail)"
    log_info "Конфігурація: ${CONFIG_DIR}/config.yml"
    log_info "Дані: ${DATA_DIR}"
else
    log_error "Promtail не запустився. Перевірте логи:"
    log_error "  journalctl -u promtail -n 50"
    exit 1
fi

# Відкриття портів якщо UFW активний
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    log_info "Налаштування firewall..."
    ufw allow 514/udp comment "Syslog UDP"
    ufw allow 1514/tcp comment "Syslog TCP"
fi

log_info "Готово!"
echo ""
echo "Для перевірки:"
echo "  curl http://localhost:9080/ready"
echo "  journalctl -u promtail -f"
