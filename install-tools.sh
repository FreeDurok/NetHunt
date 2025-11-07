#!/bin/bash
# NetHunt - Installation script for required tools on Kali Linux

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

echo "[1/4] Updating package lists..."
apt-get update -qq

echo "[2/4] Installing Zeek (Network Security Monitor)..."
apt-get install -y zeek

echo "[3/4] Installing Suricata (IDS/IPS)..."
apt-get install -y suricata

echo "[4/4] Installing Tshark (Wireshark CLI)..."
apt-get install -y tshark wireshark-common

echo ""
echo "==================================="
echo "Installation completed!"
echo "==================================="
echo ""
echo "Installed tools:"
echo "  - Zeek: $(which zeek 2>/dev/null || echo '/opt/zeek/bin/zeek')"
echo "  - Suricata: $(which suricata 2>/dev/null || echo 'Not in PATH')"
echo "  - Tshark: $(which tshark 2>/dev/null || echo 'Not in PATH')"
echo ""
echo "You can now run NetHunt with:"
echo "  python3 net-hunt.py <pcap_file> -o output_dir"
echo ""
