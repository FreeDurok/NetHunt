#!/bin/bash
# Quick test script to verify NetHunt setup

echo "==================================="
echo "NetHunt - System Check"
echo "==================================="
echo ""

echo "Checking required tools..."
echo ""

# Check Docker
if command -v docker &> /dev/null; then
    echo "✓ Docker binary found: $(docker --version)"
    if docker ps &> /dev/null; then
        echo "✓ Docker daemon is running"
        if docker images zeek/zeek --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | grep -q "zeek"; then
            echo "✓ Zeek Docker image is available"
        else
            echo "✗ Zeek Docker image not found. Run: docker pull zeek/zeek:latest"
        fi
    else
        echo "✗ Docker daemon is NOT running"
        echo "  Start it with: sudo systemctl start docker"
        echo "  Or if you just installed Docker: sudo systemctl enable --now docker"
    fi
else
    echo "✗ Docker not installed"
fi

echo ""

# Check for native Zeek
if command -v zeek &> /dev/null; then
    echo "✓ Zeek (native) found: $(zeek --version 2>&1 | head -1)"
elif [ -f "/opt/zeek/bin/zeek" ]; then
    echo "✓ Zeek (native) found: /opt/zeek/bin/zeek"
else
    echo "✗ Zeek (native) not found"
fi

echo ""

# Check Suricata
if command -v suricata &> /dev/null; then
    echo "✓ Suricata found: $(suricata --version 2>&1 | head -1)"
else
    echo "✗ Suricata not installed"
fi

echo ""

# Check Tshark
if command -v tshark &> /dev/null; then
    echo "✓ Tshark found: $(tshark --version 2>&1 | head -1)"
else
    echo "✗ Tshark not installed"
fi

echo ""
echo "==================================="
echo "Summary:"
echo "==================================="

DOCKER_OK=false
ZEEK_OK=false

if command -v docker &> /dev/null && docker ps &> /dev/null; then
    DOCKER_OK=true
fi

if command -v zeek &> /dev/null || [ -f "/opt/zeek/bin/zeek" ]; then
    ZEEK_OK=true
fi

if [ "$DOCKER_OK" = true ] || [ "$ZEEK_OK" = true ]; then
    echo "✓ System is ready to run NetHunt!"
    echo ""
    echo "Test with:"
    echo "  python3 net-hunt.py your_file.pcap -o output_dir"
else
    echo "✗ System is NOT ready"
    echo ""
    echo "You need either:"
    echo "  1. Docker running + Zeek image, OR"
    echo "  2. Native Zeek installation"
    echo ""
    echo "To install, run:"
    echo "  sudo ./install-tools.sh"
fi

echo ""
