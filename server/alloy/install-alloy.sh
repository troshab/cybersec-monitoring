#!/bin/bash
# =============================================================================
# Grafana Alloy Installation Script
# =============================================================================
# Встановлення Grafana Alloy для збору логів на Debian/Ubuntu
# Замінює deprecated Promtail
# =============================================================================

set -e

# Кольори
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "[INFO] $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

ALLOY_VERSION="${ALLOY_VERSION:-1.5.1}"
INSTALL_DIR="/etc/alloy"
DATA_DIR="/var/lib/alloy"

# =============================================================================
# Check if running as root
# =============================================================================
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

log_info "Installing Grafana Alloy v${ALLOY_VERSION}..."

# =============================================================================
# Add Grafana repository
# =============================================================================
log_info "Adding Grafana repository..."

apt-get install -y -qq apt-transport-https software-properties-common wget gpg

mkdir -p /etc/apt/keyrings/
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor > /etc/apt/keyrings/grafana.gpg

echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | tee /etc/apt/sources.list.d/grafana.list

apt-get update -qq

# =============================================================================
# Install Alloy
# =============================================================================
log_info "Installing Alloy package..."

apt-get install -y -qq alloy

# =============================================================================
# Create directories
# =============================================================================
mkdir -p "$INSTALL_DIR"
mkdir -p "$DATA_DIR"
chown -R alloy:alloy "$DATA_DIR"

# =============================================================================
# Copy configuration
# =============================================================================
log_info "Configuring Alloy..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/config.alloy" ]]; then
    cp "$SCRIPT_DIR/config.alloy" "$INSTALL_DIR/config.alloy"
    log_success "Configuration copied from $SCRIPT_DIR/config.alloy"
else
    log_warn "config.alloy not found in $SCRIPT_DIR, using default"
fi

# =============================================================================
# Configure systemd service
# =============================================================================
log_info "Configuring systemd service..."

# Create override for CAP_NET_BIND_SERVICE (for syslog port 514)
mkdir -p /etc/systemd/system/alloy.service.d

cat > /etc/systemd/system/alloy.service.d/override.conf << 'EOF'
[Service]
# Allow binding to privileged ports (UDP 514 for syslog)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
EOF

# Set correct config path in environment
cat > /etc/default/alloy << EOF
# Grafana Alloy configuration
ALLOY_CONFIG_FILE=/etc/alloy/config.alloy
ALLOY_STABILITY_LEVEL=generally-available
EOF

# =============================================================================
# Add alloy user to required groups
# =============================================================================
usermod -a -G adm alloy 2>/dev/null || true  # For reading system logs
usermod -a -G docker alloy 2>/dev/null || true  # For reading docker logs

# =============================================================================
# Start service
# =============================================================================
systemctl daemon-reload
systemctl enable alloy
systemctl restart alloy

# =============================================================================
# Verify installation
# =============================================================================
sleep 3

if systemctl is-active --quiet alloy; then
    log_success "Grafana Alloy installed and running!"
else
    log_error "Alloy failed to start"
    journalctl -u alloy --no-pager -n 20
    exit 1
fi

# =============================================================================
# Print summary
# =============================================================================
echo ""
echo "============================================================"
echo -e "${GREEN}Grafana Alloy installed successfully!${NC}"
echo "============================================================"
echo ""
echo "Configuration: $INSTALL_DIR/config.alloy"
echo "Data directory: $DATA_DIR"
echo ""
echo "Commands:"
echo "  systemctl status alloy     # Check status"
echo "  journalctl -u alloy -f     # View logs"
echo "  alloy fmt config.alloy     # Format config"
echo ""
echo "Web UI: http://localhost:12345 (debug interface)"
echo ""
