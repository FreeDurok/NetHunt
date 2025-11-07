#!/usr/bin/env python3
"""
Test Docker checks without requiring Docker to be installed
"""

import sys
import importlib.util
from pathlib import Path

# Load net-hunt module
spec = importlib.util.spec_from_file_location("net_hunt", Path(__file__).parent / "net-hunt.py")
net_hunt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(net_hunt)

print("=== NetHunt Docker Integration Tests ===\n")

# Test 1: Check Docker availability
print("[1/3] Testing Docker check...")
docker_available = net_hunt.check_docker()
if docker_available:
    print("  ✓ Docker is available")
else:
    print("  ℹ Docker not found (expected in non-Docker environments)")

# Test 2: Check Zeek image
print("\n[2/3] Testing Zeek Docker image check...")
if docker_available:
    zeek_image_available = net_hunt.check_zeek_docker_image()
    if zeek_image_available:
        print("  ✓ Zeek Docker image found")
    else:
        print("  ℹ Zeek image not found (will be pulled on first run)")
else:
    print("  ⊘ Skipped (Docker not available)")

# Test 3: Configuration check
print("\n[3/3] Testing configuration...")
print(f"  USE_DOCKER_ZEEK: {net_hunt.USE_DOCKER_ZEEK}")
print(f"  ZEEK_DOCKER_IMAGE: {net_hunt.ZEEK_DOCKER_IMAGE}")
print("  ✓ Configuration loaded correctly")

# Summary
print("\n" + "=" * 50)
print("Test Summary:")
print("=" * 50)
if docker_available:
    print("✅ Docker is installed and accessible")
    print("   NetHunt will use Zeek via Docker automatically")
else:
    print("⚠️  Docker not installed")
    print("   To use NetHunt with Zeek analysis:")
    print("   1. Run: sudo ./install-tools.sh")
    print("   2. Or manually install: sudo apt install docker.io")
    print("   3. Pull Zeek image: docker pull zeek/zeek:latest")
    print("")
    print("   NetHunt will skip Zeek analysis if Docker is unavailable")

print("\nℹ️  NetHunt will automatically:")
print("  - Detect if Docker is available")
print("  - Pull Zeek image if needed")
print("  - Skip Zeek analysis gracefully if Docker is missing")
print("  - Continue with Suricata and Tshark analysis")
