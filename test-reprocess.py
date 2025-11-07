#!/usr/bin/env python3
"""
Quick test script to reprocess existing logs without re-running Zeek
"""

import sys
sys.path.insert(0, '.')

from nethunt.parsers import parse_http_log, parse_dns_log, parse_ssl_log
import pathlib

work_dir = pathlib.Path("out/work_1")

print("Testing log parsers...")
print(f"Working directory: {work_dir}")
print()

# Test HTTP log
http_log = work_dir / "http.log"
if http_log.exists():
    print(f"✓ Found {http_log}")
    http_data = parse_http_log(http_log)
    print(f"  URLs found: {len(http_data['urls'])}")
    print(f"  Requests: {len(http_data['requests'])}")
    print(f"  Methods: {list(http_data['methods'].keys())}")
    print(f"  Hosts: {len(http_data['hosts'])}")
    if http_data['urls']:
        print(f"  Sample URLs:")
        for url in list(http_data['urls'])[:3]:
            print(f"    - {url}")
else:
    print(f"✗ {http_log} not found")

print()

# Test DNS log
dns_log = work_dir / "dns.log"
if dns_log.exists():
    print(f"✓ Found {dns_log}")
    dns_data = parse_dns_log(dns_log)
    print(f"  Queries: {len(dns_data['queries'])}")
    print(f"  Unique domains: {len(dns_data['query_names'])}")
    if dns_data['query_names']:
        print(f"  Top domains:")
        for domain, count in list(dns_data['query_names'].items())[:5]:
            print(f"    - {domain}: {count}")
else:
    print(f"✗ {dns_log} not found")

print()

# Test SSL log
ssl_log = work_dir / "ssl.log"
if ssl_log.exists():
    print(f"✓ Found {ssl_log}")
    ssl_data = parse_ssl_log(ssl_log)
    print(f"  SSL connections: {len(ssl_data['connections'])}")
    print(f"  Unique server names: {len(ssl_data['server_names'])}")
    if ssl_data['server_names']:
        print(f"  Top servers:")
        for server, count in list(ssl_data['server_names'].items())[:5]:
            print(f"    - {server}: {count}")
else:
    print(f"✗ {ssl_log} not found")

print()

# Check extracted files
extract_dirs = [
    work_dir / "extract_files",
    work_dir / "extracted",
    work_dir / "export_http"
]

for edir in extract_dirs:
    if edir.exists():
        files = list(edir.rglob("*"))
        file_count = len([f for f in files if f.is_file()])
        print(f"✓ Found {edir.name}/ with {file_count} files")
    else:
        print(f"✗ {edir.name}/ not found")

print()
print("=" * 60)
print("Test complete! If all checks passed, the parsers are working.")
print("Run the full analysis again to regenerate the report:")
print("  python3 net-hunt.py 2025-06-13-traffic-analysis-exercise.pcap -o out/")
