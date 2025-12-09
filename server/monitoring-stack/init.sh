#!/bin/bash
# =============================================================================
# Monitoring Stack - Initialization Script
# =============================================================================
# Creates directories with correct permissions
# Run this BEFORE docker compose up
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[+] Initializing Monitoring Stack...${NC}"

# =============================================================================
# Create data directories (will be created by Docker volumes, but ensure they exist)
# =============================================================================
echo -e "${YELLOW}[*] Ensuring directory structure...${NC}"

# Prometheus (UID 65534 = nobody)
mkdir -p ./prometheus/alerts

# Loki (UID 10001)
mkdir -p ./loki

# Grafana (UID 472)
mkdir -p ./grafana/{dashboards,provisioning/{alerting,dashboards,datasources}}

# Alertmanager
mkdir -p ./alertmanager

# =============================================================================
# Create .env symlink if not exists
# =============================================================================
if [[ ! -f ".env" ]]; then
    echo -e "${YELLOW}[*] Creating .env symlink...${NC}"
    ln -sf ../../.env .env
fi

echo -e "${GREEN}[+] Initialization complete!${NC}"
echo ""
echo "Now run: docker compose up -d"
