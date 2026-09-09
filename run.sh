#!/bin/bash
# ─── Java Packet Sniffer — Build & Run Script ─────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}"
echo "  ┌─────────────────────────────────────┐"
echo "  │   PKT-SNIFF Build & Run Script      │"
echo "  └─────────────────────────────────────┘"
echo -e "${NC}"

# Check Java
if ! command -v java &>/dev/null; then
    echo -e "${RED}[!] Java not found. Install it:${NC}"
    echo "    sudo apt install default-jdk"
    exit 1
fi

# Check Maven
if ! command -v mvn &>/dev/null; then
    echo -e "${YELLOW}[*] Maven not found. Installing...${NC}"
    sudo apt-get install -y maven 2>/dev/null || {
        echo -e "${RED}[!] Could not install Maven. Install manually:${NC}"
        echo "    sudo apt install maven"
        exit 1
    }
fi

# Check libpcap
if ! dpkg -l libpcap-dev &>/dev/null 2>&1; then
    echo -e "${YELLOW}[*] Installing libpcap-dev...${NC}"
    sudo apt-get install -y libpcap-dev 2>/dev/null
fi

# Build
echo -e "${GREEN}[*] Building...${NC}"
mvn package -q 2>/dev/null

if [[ ! -f "target/packet-sniffer.jar" ]]; then
    echo -e "${RED}[!] Build failed. Run manually: mvn package${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Build successful!${NC}"
echo ""

# Check if root
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}[!] Packet capture requires root. Running with sudo...${NC}"
    sudo java -jar target/packet-sniffer.jar
else
    java -jar target/packet-sniffer.jar
fi
