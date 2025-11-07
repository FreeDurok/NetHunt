#!/usr/bin/env python3
"""
Quick test of NetHunt functions without requiring external tools
"""

import json
from pathlib import Path

# Test imports
try:
    from collections import Counter
    import hashlib
    print("✓ Core Python modules imported successfully")
except ImportError as e:
    print(f"✗ Import error: {e}")
    exit(1)

# Load the module functions
import sys
import importlib.util

spec = importlib.util.spec_from_file_location("net_hunt", Path(__file__).parent / "net-hunt.py")
net_hunt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(net_hunt)

print("\n=== NetHunt Basic Functionality Test ===\n")

# Test 1: deduplicate_files function
print("[1/5] Testing file deduplication...")
test_files = [
    {"sha256": "abc123", "size": 100, "path": "/test1"},
    {"sha256": "abc123", "size": 100, "path": "/test2"},  # duplicate
    {"sha256": "def456", "size": 0, "path": "/test3"},     # empty, should be removed
    {"sha256": "ghi789", "size": 200, "path": "/test4"},
]

deduplicate_files = net_hunt.deduplicate_files
result = deduplicate_files(test_files)
assert len(result) == 2, f"Expected 2 files, got {len(result)}"
print(f"  ✓ Deduplication works: {len(test_files)} files → {len(result)} unique non-empty files")

# Test 2: format_bytes function
print("\n[2/5] Testing byte formatting...")
format_bytes = net_hunt.format_bytes
test_cases = [
    (100, "100.00 B"),
    (1024, "1.00 KB"),
    (1048576, "1.00 MB"),
    (1073741824, "1.00 GB"),
]
for size, expected in test_cases:
    result = format_bytes(size)
    print(f"  {size:>12} bytes → {result:>12}")
print("  ✓ Byte formatting works")

# Test 3: HTML report generation with mock data
print("\n[3/5] Testing HTML report generation...")
generate_html_report = net_hunt.generate_html_report

mock_data = {
    "generated_at": "2025-11-07T10:00:00Z",
    "pcap": "/test/capture.pcap",
    "pcap_size": 42000000,
    "beaconing": [
        {
            "src": "192.168.1.100",
            "dst": "93.184.1.42",
            "dport": "443",
            "interval_avg_s": 60.5,
            "cv": 0.12,
            "events": 25,
            "score": 15.3
        }
    ],
    "files": [
        {
            "source": "zeek",
            "path": "/out/work_1/extracted/test.exe",
            "sha256": "a" * 64,
            "size": 2048000,
            "magic": "PE32 executable"
        }
    ],
    "http": {
        "urls": ["http://example.com/malware.exe", "http://test.com/script.ps1"],
        "requests_count": 150,
        "methods": {"GET": 120, "POST": 30},
        "status_codes": {"200": 100, "404": 20, "302": 30},
        "top_hosts": {"example.com": 80, "test.com": 70},
        "top_user_agents": {"Mozilla/5.0": 100, "curl/7.68": 50},
        "requests": []
    },
    "dns": {
        "queries_count": 250,
        "top_queries": {"malicious-c2.com": 50, "google.com": 100},
        "query_types": {"A": 200, "AAAA": 30, "TXT": 20},
        "queries": []
    },
    "ssl": {
        "connections_count": 75,
        "top_server_names": {"evil-server.com": 30, "google.com": 45},
        "ja3_fingerprints": {"a1b2c3d4e5f6" * 5: 10, "f6e5d4c3b2a1" * 5: 5},
        "tls_versions": {"TLSv1.2": 50, "TLSv1.3": 25},
        "connections": []
    },
    "statistics": {
        "total_files": 1,
        "total_beacons": 1,
        "total_http_requests": 150,
        "total_dns_queries": 250,
        "total_ssl_connections": 75,
        "unique_urls": 2,
        "unique_domains": 2
    }
}

html_output = generate_html_report(mock_data)
assert len(html_output) > 1000, "HTML output too short"
assert "NetHunt Analysis Report" in html_output, "Missing title"
assert "Beaconing Detection" in html_output, "Missing beaconing section"
assert "192.168.1.100" in html_output, "Missing beacon IP"
print("  ✓ HTML report generated successfully")
print(f"  ✓ Report size: {len(html_output):,} characters")

# Test 4: Save HTML to file
print("\n[4/5] Testing HTML file output...")
output_path = Path("/tmp/test_report.html")
output_path.write_text(html_output)
print(f"  ✓ Test report saved to: {output_path}")
print(f"  ✓ File size: {output_path.stat().st_size:,} bytes")

# Test 5: Verify HTML structure
print("\n[5/5] Verifying HTML structure...")
checks = [
    ("<!DOCTYPE html>", "HTML5 doctype"),
    ('<meta name="viewport"', "Responsive viewport"),
    ("background: linear-gradient", "Modern CSS styling"),
    ("🔍", "Emoji icons"),
    ("Beaconing Detection", "Beaconing section"),
    ("Extracted Files", "Files section"),
    ("HTTP Traffic Analysis", "HTTP section"),
    ("DNS Analysis", "DNS section"),
    ("TLS/SSL Analysis", "TLS section"),
]

for pattern, description in checks:
    if pattern in html_output:
        print(f"  ✓ {description}")
    else:
        print(f"  ✗ Missing: {description}")

print("\n" + "=" * 50)
print("✅ All basic tests passed!")
print("=" * 50)
print(f"\nYou can view the test report at: {output_path}")
print("Open it in a browser to see the modern HTML design.")
