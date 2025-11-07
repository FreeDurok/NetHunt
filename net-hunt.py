#!/usr/bin/env python3
"""
NetHunt - Advanced PCAP analysis with beaconing detection, file extraction, and comprehensive reporting

This is the CLI entry point that uses the modular nethunt package.
"""

import argparse
from nethunt import analyze


def main():
    ap = argparse.ArgumentParser(
        description="NetHunt: Advanced PCAP analysis with beaconing detection, file extraction, and comprehensive reporting",
        epilog="Zeek runs via Docker for easy deployment on Kali Linux. Ensure Docker is installed: sudo ./install-tools.sh"
    )
    ap.add_argument("pcap", help="Path to PCAP file to analyze")
    ap.add_argument("-o", "--out", default="out", help="Output directory (default: out)")
    ap.add_argument("--chunk", type=int, default=None, help="Split PCAP into chunks of N packets (requires editcap)")
    args = ap.parse_args()

    analyze(args.pcap, args.out, chunk=args.chunk)


if __name__ == "__main__":
    main()
