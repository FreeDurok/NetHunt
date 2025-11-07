#!/usr/bin/env python3
"""
Test Suricata configuration generation
"""

import sys
import importlib.util
from pathlib import Path
import tempfile

# Load net-hunt module
spec = importlib.util.spec_from_file_location("net_hunt", Path(__file__).parent / "net-hunt.py")
net_hunt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(net_hunt)

print("=== NetHunt Suricata Configuration Test ===\n")

# Test configuration generation
print("[1/2] Testing Suricata YAML generation...")
with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
    temp_yaml = Path(f.name)

try:
    net_hunt.write_minimal_suricata_yaml(temp_yaml)
    print("  ✓ Configuration file generated")

    # Read and display
    print("\n[2/2] Generated configuration:")
    print("-" * 50)
    with open(temp_yaml) as f:
        config = f.read()
        print(config)
    print("-" * 50)

    # Check key elements
    checks = [
        ("eve-log", "EVE logging enabled"),
        ("http:", "HTTP logging"),
        ("dns:", "DNS logging"),
        ("tls:", "TLS logging"),
        ("files:", "File extraction"),
        ("file-store:", "File store enabled"),
    ]

    print("\nConfiguration checks:")
    for pattern, desc in checks:
        if pattern in config:
            print(f"  ✓ {desc}")
        else:
            print(f"  ✗ Missing: {desc}")

    # Check for problematic patterns
    if "fileinfo" in config:
        print("\n  ⚠️  WARNING: 'fileinfo' found - may cause compatibility issues")
    else:
        print("\n  ✓ No 'fileinfo' module (good for compatibility)")

    print("\n" + "=" * 50)
    print("✅ Configuration test completed!")
    print("=" * 50)

finally:
    # Cleanup
    if temp_yaml.exists():
        temp_yaml.unlink()
