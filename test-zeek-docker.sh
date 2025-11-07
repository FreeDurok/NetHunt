#!/bin/bash
# Test script to verify Zeek Docker setup

set -e

echo "==================================="
echo "Zeek Docker Test"
echo "==================================="
echo ""

# Check if PCAP file argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <pcap_file>"
    echo ""
    echo "Example:"
    echo "  $0 capture.pcap"
    exit 1
fi

PCAP_FILE="$1"

# Check if file exists
if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: PCAP file not found: $PCAP_FILE"
    exit 1
fi

# Get absolute paths
PCAP_ABS=$(realpath "$PCAP_FILE")
PCAP_DIR=$(dirname "$PCAP_ABS")
PCAP_NAME=$(basename "$PCAP_ABS")

# Create test output directory
TEST_OUTPUT="./test-zeek-output"
mkdir -p "$TEST_OUTPUT"
TEST_OUTPUT_ABS=$(realpath "$TEST_OUTPUT")

echo "Testing Zeek Docker container..."
echo "PCAP file: $PCAP_ABS"
echo "Output dir: $TEST_OUTPUT_ABS"
echo ""

# Get current user UID:GID
USER_ID=$(id -u)
GROUP_ID=$(id -g)

echo "Running Docker command:"
echo ""
DOCKER_CMD="docker run --rm \
  --user $USER_ID:$GROUP_ID \
  -e LogAscii::use_json=T \
  -e LogAscii::json_timestamps=JSON::TS_ISO8601 \
  -v $PCAP_DIR:/pcaps:ro \
  -v $TEST_OUTPUT_ABS:/logs \
  -w /logs \
  zeek/zeek:latest \
  zeek \
  -C \
  -r /pcaps/$PCAP_NAME \
  policy/tuning/json-logs.zeek \
  frameworks/files/extract-all-files.zeek"

echo "$DOCKER_CMD"
echo ""
echo "Executing..."
echo ""

# Execute the command
eval "$DOCKER_CMD"

# Check results
echo ""
echo "==================================="
echo "Results:"
echo "==================================="

if [ -f "$TEST_OUTPUT/conn.log" ]; then
    echo "✓ conn.log created"
    CONN_LINES=$(wc -l < "$TEST_OUTPUT/conn.log")
    echo "  Lines: $CONN_LINES"
else
    echo "✗ conn.log not found"
fi

if [ -f "$TEST_OUTPUT/http.log" ]; then
    echo "✓ http.log created"
    HTTP_LINES=$(wc -l < "$TEST_OUTPUT/http.log")
    echo "  Lines: $HTTP_LINES"
else
    echo "✗ http.log not found (may be normal if no HTTP traffic)"
fi

if [ -f "$TEST_OUTPUT/dns.log" ]; then
    echo "✓ dns.log created"
    DNS_LINES=$(wc -l < "$TEST_OUTPUT/dns.log")
    echo "  Lines: $DNS_LINES"
else
    echo "✗ dns.log not found (may be normal if no DNS traffic)"
fi

if [ -d "$TEST_OUTPUT/extracted" ]; then
    EXTRACTED_COUNT=$(find "$TEST_OUTPUT/extracted" -type f 2>/dev/null | wc -l)
    echo "✓ extracted/ directory created"
    echo "  Files extracted: $EXTRACTED_COUNT"
else
    echo "✗ extracted/ directory not found"
fi

echo ""
echo "All logs are in: $TEST_OUTPUT"
echo ""

# Check for errors
if [ -f "$TEST_OUTPUT/.stderr" ]; then
    echo "Errors found:"
    cat "$TEST_OUTPUT/.stderr"
fi

echo "Test complete!"
