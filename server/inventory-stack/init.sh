#!/bin/bash
# =============================================================================
# Inventory Stack - Initialization Script
# =============================================================================
# Creates directories with correct permissions and generates SSL certificates
# Run this BEFORE docker compose up
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[+] Initializing Inventory Stack...${NC}"

# =============================================================================
# Netdisco directories (UID 901 = netdisco user in container)
# =============================================================================
echo -e "${YELLOW}[*] Creating Netdisco directories...${NC}"
mkdir -p ./netdisco/{postgresql,config,logs,nd-site-local}
chown -R 901:901 ./netdisco/logs ./netdisco/config ./netdisco/nd-site-local 2>/dev/null || \
    echo "    (chown skipped - run as root on Linux)"

# =============================================================================
# FleetDM certificates
# =============================================================================
CERT_DIR="./fleetdm/certs"
mkdir -p "$CERT_DIR"

if [[ ! -f "$CERT_DIR/fleet.crt" ]] || [[ ! -f "$CERT_DIR/fleet.key" ]]; then
    echo -e "${YELLOW}[*] Generating FleetDM SSL certificates...${NC}"

    # Get server IP from .env or use default
    if [[ -f "../../.env" ]]; then
        source "../../.env"
    fi
    SERVER_IP="${MONITORING_SERVER_IP:-10.0.1.2}"

    # Generate self-signed certificate
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$CERT_DIR/fleet.key" \
        -out "$CERT_DIR/fleet.crt" \
        -subj "/CN=${SERVER_IP}/O=LAB/OU=FleetDM" \
        -addext "subjectAltName=IP:${SERVER_IP},IP:127.0.0.1,DNS:localhost" \
        2>/dev/null

    chmod 644 "$CERT_DIR/fleet.crt"
    chmod 600 "$CERT_DIR/fleet.key"

    echo -e "${GREEN}[+] Certificates created for IP: ${SERVER_IP}${NC}"
else
    echo -e "${GREEN}[+] Certificates already exist${NC}"
fi

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
