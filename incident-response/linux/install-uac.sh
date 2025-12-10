#!/bin/bash
#
# UAC (Unix-like Artifacts Collector) Setup Script
#
# Downloads and configures UAC for Linux/Unix incident response.
# UAC is the standard tool for Unix forensic artifact collection.
#
# Usage: sudo ./install-uac.sh [install_path]
#
# UAC Repository: https://github.com/tclahr/uac
#
# CERT-UA Contact:
# - Email: cert@cert.gov.ua
# - Phone: +380 44 281 88 25
#

set -e

# =============================================================================
# Configuration
# =============================================================================
INSTALL_PATH="${1:-/opt/uac}"
UAC_REPO="https://github.com/tclahr/uac"
UAC_VERSION="2.9.1"  # Update as needed

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# Check privileges
# =============================================================================
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Usage: sudo $0 [install_path]"
    exit 1
fi

# =============================================================================
# Banner
# =============================================================================
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  UAC (Unix-like Artifacts Collector) Setup${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# =============================================================================
# Check dependencies
# =============================================================================
echo -e "${CYAN}[*] Checking dependencies...${NC}"

MISSING_DEPS=""

for cmd in git curl tar; do
    if ! command -v $cmd &> /dev/null; then
        MISSING_DEPS="$MISSING_DEPS $cmd"
    fi
done

if [ -n "$MISSING_DEPS" ]; then
    echo -e "${YELLOW}[!] Installing missing dependencies:$MISSING_DEPS${NC}"

    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y $MISSING_DEPS
    elif command -v yum &> /dev/null; then
        yum install -y $MISSING_DEPS
    elif command -v dnf &> /dev/null; then
        dnf install -y $MISSING_DEPS
    fi
fi

echo -e "${GREEN}[+] Dependencies OK${NC}"

# =============================================================================
# Create directory
# =============================================================================
echo -e "${CYAN}[*] Creating installation directory...${NC}"

mkdir -p "$INSTALL_PATH"
mkdir -p "$INSTALL_PATH/output"

# =============================================================================
# Download UAC
# =============================================================================
if [ -f "$INSTALL_PATH/uac" ]; then
    echo -e "${GREEN}[+] UAC already installed at $INSTALL_PATH${NC}"
    echo ""

    # Show version
    cd "$INSTALL_PATH"
    version=$("$INSTALL_PATH/uac" --version 2>&1 | head -1 || echo "Unknown")
    echo -e "Version: ${CYAN}$version${NC}"
else
    echo -e "${CYAN}[*] Downloading UAC...${NC}"

    # Method 1: Git clone (preferred)
    if command -v git &> /dev/null; then
        echo -e "${CYAN}[*] Cloning UAC repository...${NC}"
        git clone --depth 1 "$UAC_REPO" "$INSTALL_PATH/uac-repo" 2>/dev/null || true

        if [ -d "$INSTALL_PATH/uac-repo" ]; then
            cp -r "$INSTALL_PATH/uac-repo/"* "$INSTALL_PATH/"
            rm -rf "$INSTALL_PATH/uac-repo"
            echo -e "${GREEN}[+] UAC downloaded via git${NC}"
        fi
    fi

    # Method 2: Download release tarball
    if [ ! -f "$INSTALL_PATH/uac" ]; then
        echo -e "${CYAN}[*] Downloading UAC release tarball...${NC}"

        TARBALL_URL="https://github.com/tclahr/uac/releases/download/v${UAC_VERSION}/uac-${UAC_VERSION}.tar.gz"

        curl -sL "$TARBALL_URL" -o /tmp/uac.tar.gz

        if [ -f /tmp/uac.tar.gz ]; then
            tar -xzf /tmp/uac.tar.gz -C "$INSTALL_PATH" --strip-components=1
            rm /tmp/uac.tar.gz
            echo -e "${GREEN}[+] UAC downloaded from release${NC}"
        else
            echo -e "${RED}[-] Failed to download UAC${NC}"
            echo ""
            echo "Manual download:"
            echo "  1. Go to: https://github.com/tclahr/uac/releases"
            echo "  2. Download the latest release"
            echo "  3. Extract to: $INSTALL_PATH"
            exit 1
        fi
    fi
fi

# =============================================================================
# Make executable
# =============================================================================
chmod +x "$INSTALL_PATH/uac" 2>/dev/null || true

# =============================================================================
# Create collection scripts
# =============================================================================
echo -e "${CYAN}[*] Creating collection scripts...${NC}"

# Quick collection script
cat > "$INSTALL_PATH/collect-quick.sh" << 'SCRIPT'
#!/bin/bash
# UAC Quick Collection - Essential artifacts only
# Usage: sudo ./collect-quick.sh [output_path]

UAC_PATH="$(dirname "$0")"
OUTPUT_PATH="${1:-/tmp/evidence_$(hostname)_$(date +%Y%m%d_%H%M%S)}"

echo "============================================================"
echo "  UAC Quick Collection"
echo "============================================================"
echo ""
echo "Target: $(hostname)"
echo "Output: $OUTPUT_PATH"
echo ""

cd "$UAC_PATH"
./uac -p ir_triage "$OUTPUT_PATH"

echo ""
echo "Collection complete!"
echo "Output: $OUTPUT_PATH"
SCRIPT

chmod +x "$INSTALL_PATH/collect-quick.sh"
echo -e "${GREEN}[+] Created: collect-quick.sh${NC}"

# Full collection script
cat > "$INSTALL_PATH/collect-full.sh" << 'SCRIPT'
#!/bin/bash
# UAC Full Collection - Comprehensive artifacts
# Usage: sudo ./collect-full.sh [output_path]

UAC_PATH="$(dirname "$0")"
OUTPUT_PATH="${1:-/tmp/evidence_$(hostname)_$(date +%Y%m%d_%H%M%S)}"

echo "============================================================"
echo "  UAC Full Collection"
echo "============================================================"
echo ""
echo "Target: $(hostname)"
echo "Output: $OUTPUT_PATH"
echo ""
echo "This will collect comprehensive forensic artifacts."
echo "Estimated time: 15-30 minutes"
echo ""
read -p "Continue? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    echo "Cancelled"
    exit 0
fi

cd "$UAC_PATH"
./uac -p full "$OUTPUT_PATH"

echo ""
echo "Collection complete!"
echo "Output: $OUTPUT_PATH"
SCRIPT

chmod +x "$INSTALL_PATH/collect-full.sh"
echo -e "${GREEN}[+] Created: collect-full.sh${NC}"

# Memory collection script
cat > "$INSTALL_PATH/collect-memory.sh" << 'SCRIPT'
#!/bin/bash
# UAC Collection with Memory Dump
# Requires: LiME or avml for memory acquisition
# Usage: sudo ./collect-memory.sh [output_path]

UAC_PATH="$(dirname "$0")"
OUTPUT_PATH="${1:-/tmp/evidence_$(hostname)_$(date +%Y%m%d_%H%M%S)}"

echo "============================================================"
echo "  UAC Collection with Memory"
echo "============================================================"
echo ""
echo "Target: $(hostname)"
echo "Output: $OUTPUT_PATH"
echo ""

# Check for memory acquisition tool
if command -v avml &> /dev/null; then
    MEM_TOOL="avml"
elif [ -f /lib/modules/$(uname -r)/lime.ko ]; then
    MEM_TOOL="lime"
else
    echo "WARNING: No memory acquisition tool found"
    echo "Install avml or LiME for memory capture"
    echo ""
    echo "Continuing with artifact collection only..."
    MEM_TOOL=""
fi

mkdir -p "$OUTPUT_PATH"

# Capture memory first (most volatile)
if [ "$MEM_TOOL" = "avml" ]; then
    echo "[*] Capturing memory with AVML..."
    avml "$OUTPUT_PATH/memory.lime"
elif [ "$MEM_TOOL" = "lime" ]; then
    echo "[*] Capturing memory with LiME..."
    insmod /lib/modules/$(uname -r)/lime.ko "path=$OUTPUT_PATH/memory.lime format=lime"
    rmmod lime
fi

# Collect artifacts
cd "$UAC_PATH"
./uac -p full "$OUTPUT_PATH"

echo ""
echo "Collection complete!"
echo "Output: $OUTPUT_PATH"
SCRIPT

chmod +x "$INSTALL_PATH/collect-memory.sh"
echo -e "${GREEN}[+] Created: collect-memory.sh${NC}"

# =============================================================================
# Create README
# =============================================================================
cat > "$INSTALL_PATH/README.md" << 'EOF'
# UAC - Unix-like Artifacts Collector

## Installation

UAC is pre-installed in this directory. To update:
```bash
cd /opt/uac
git pull  # if cloned
# or download latest from https://github.com/tclahr/uac/releases
```

## Collection Scripts

- **collect-quick.sh** - Fast IR triage (~5-10 min)
- **collect-full.sh** - Comprehensive collection (~15-30 min)
- **collect-memory.sh** - With memory dump (requires AVML/LiME)

## Command Line Usage

### Quick IR triage:
```bash
sudo ./uac -p ir_triage /path/to/output
```

### Full collection:
```bash
sudo ./uac -p full /path/to/output
```

### Specific artifacts:
```bash
# Logs only
sudo ./uac -a logs /path/to/output

# Network and processes
sudo ./uac -a live_response/network,live_response/process /path/to/output

# Users and authentication
sudo ./uac -a system/users,logs/auth /path/to/output
```

## Key Profiles

- `ir_triage` - Incident Response triage (fast)
- `full` - Full artifact collection
- `offline` - For mounted forensic images

## Key Artifact Categories

- `live_response/` - Running processes, network, memory
- `logs/` - System logs, auth logs, audit
- `system/` - Users, groups, configs
- `applications/` - Application-specific artifacts
- `docker/` - Container artifacts
- `cloud/` - Cloud platform artifacts

## Output Structure

```
output/
├── [hostname]/
│   ├── live_response/
│   ├── logs/
│   ├── system/
│   └── ...
├── uac.log
└── uac.yaml
```

## CERT-UA Contact

After collecting evidence:
- Email: cert@cert.gov.ua
- Phone: +380 44 281 88 25
- Web: https://cert.gov.ua

## Resources

- UAC Documentation: https://github.com/tclahr/uac
- Artifact Reference: https://github.com/tclahr/uac/wiki
EOF

echo -e "${GREEN}[+] Created: README.md${NC}"

# =============================================================================
# Create symlink
# =============================================================================
if [ ! -f /usr/local/bin/uac ]; then
    ln -sf "$INSTALL_PATH/uac" /usr/local/bin/uac 2>/dev/null || true
    echo -e "${GREEN}[+] Created symlink: /usr/local/bin/uac${NC}"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  Setup Complete${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "UAC installed at: ${CYAN}$INSTALL_PATH${NC}"
echo ""
echo -e "${YELLOW}Collection scripts:${NC}"
echo "  - collect-quick.sh  (IR triage, fast)"
echo "  - collect-full.sh   (comprehensive)"
echo "  - collect-memory.sh (with memory dump)"
echo ""
echo -e "${YELLOW}Quick usage:${NC}"
echo "  cd $INSTALL_PATH"
echo "  sudo ./uac -p ir_triage /path/to/output"
echo ""
echo -e "${YELLOW}Or use collection scripts:${NC}"
echo "  sudo ./collect-quick.sh /path/to/output"
echo ""
