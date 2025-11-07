#!/bin/bash
# Quick test script to verify NetHunt without Docker

echo "=== NetHunt Quick Test ==="
echo ""

PCAP="/home/user/NetHunt/2025-06-13-traffic-analysis-exercise.pcap"
OUT="/tmp/nethunt_test_$$"

if [ ! -f "$PCAP" ]; then
    echo "ERROR: PCAP file not found: $PCAP"
    exit 1
fi

echo "[1] Creating output directory: $OUT"
mkdir -p "$OUT"

echo "[2] Running NetHunt (without Docker, will skip Zeek)..."
cd /home/user/NetHunt
python3 net-hunt.py "$PCAP" -o "$OUT" 2>&1 | head -50

echo ""
echo "[3] Checking output..."
if [ -f "$OUT/report.json" ]; then
    echo "✓ report.json created"
    echo "Statistics:"
    python3 -c "import json; d=json.load(open('$OUT/report.json')); print('  Files:', d['statistics']['total_files']); print('  HTTP requests:', d['statistics']['total_http_requests']); print('  DNS queries:', d['statistics']['total_dns_queries'])"
else
    echo "✗ report.json NOT created"
fi

if [ -f "$OUT/report.html" ]; then
    echo "✓ report.html created ($(wc -c < $OUT/report.html) bytes)"
else
    echo "✗ report.html NOT created"
fi

echo ""
echo "[4] Work directory contents:"
ls -la "$OUT/work_1/" 2>/dev/null | head -20 || echo "  (empty or doesn't exist)"

echo ""
echo "[5] Log files:"
ls -la "$OUT/work_1/"*.log 2>/dev/null || echo "  (no log files found)"

echo ""
echo "Test output location: $OUT"
