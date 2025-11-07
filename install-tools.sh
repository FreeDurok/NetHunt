#!/bin/bash
# NetHunt - Installation script for required tools on Kali Linux
# Uses Docker for Zeek (easier installation on Kali)

set -e

echo "==================================="
echo "NetHunt - Tool Installation Script"
echo "==================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "[1/6] Updating package lists..."
apt-get update -qq

echo "[2/6] Installing Docker (for Zeek)..."
if ! command -v docker &> /dev/null; then
    echo "  Installing Docker..."
    apt-get install -y docker.io
    systemctl enable docker
    systemctl start docker
    echo "  ✓ Docker installed"
else
    echo "  ✓ Docker already installed"
fi

echo "[3/6] Pulling Zeek Docker image..."
docker pull zeek/zeek:latest
echo "  ✓ Zeek image ready"

echo "[4/6] Installing Suricata (IDS/IPS)..."
apt-get install -y suricata

echo "[5/6] Installing Tshark (Wireshark CLI)..."
apt-get install -y tshark wireshark-common

echo "[6/6] Installing tcpflow (TCP stream reconstruction)..."
apt-get install -y tcpflow
echo "  ✓ tcpflow installed - ensures complete file extraction from streams"

# Add current user to docker group (if not root)
if [ -n "$SUDO_USER" ]; then
    echo ""
    echo "Adding user $SUDO_USER to docker group..."
    usermod -aG docker "$SUDO_USER"
    echo "  ✓ User added to docker group"
    echo "  ⚠️  Please log out and back in for docker group changes to take effect"
fi

echo ""
echo "==================================="
echo "Installation completed!"
echo "==================================="
echo ""
echo "Installed tools:"
echo "  - Docker: $(docker --version 2>/dev/null || echo 'Not found')"
echo "  - Zeek (Docker): $(docker images zeek/zeek --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | head -1 || echo 'Not pulled')"
echo "  - Suricata: $(which suricata 2>/dev/null || echo 'Not in PATH')"
echo "  - Tshark: $(which tshark 2>/dev/null || echo 'Not in PATH')"
echo "  - tcpflow: $(which tcpflow 2>/dev/null || echo 'Not in PATH')"
echo ""
echo "Testing Zeek Docker container..."
if docker run --rm zeek/zeek:latest --version 2>/dev/null | grep -q "zeek version"; then
    echo "  ✓ Zeek container is working!"
else
    echo "  ✗ Zeek container test failed"
fi
echo ""
echo "You can now run NetHunt with:"
echo "  python3 net-hunt.py <pcap_file> -o output_dir"
echo ""
if [ -n "$SUDO_USER" ]; then
    echo "⚠️  IMPORTANT: Log out and back in to use Docker without sudo"
fi
echo ""
