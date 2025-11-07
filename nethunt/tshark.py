"""
Tshark file extraction module with proper TCP stream reassembly
"""

import pathlib
import subprocess

from .utils import safe_mkdir


def export_objects(pcap_path: str, work_dir: pathlib.Path) -> bool:
    """
    Export objects from PCAP using Tshark with proper TCP reassembly.

    Uses tshark with options to properly reassemble:
    - TCP streams (tcp.desegment_tcp_streams)
    - HTTP body segments (http.desegment_body)
    - Chunked transfer encoding (http.dechunk_body)
    - Two-pass mode (-2) for better reassembly
    """
    success = True

    # Common tshark options for proper reassembly
    reassembly_opts = [
        "-2",  # Two-pass mode: enables better reassembly
        "-o", "tcp.desegment_tcp_streams:TRUE",  # Reassemble TCP streams
        "-o", "http.desegment_body:TRUE",         # Reassemble HTTP body
        "-o", "http.dechunk_body:TRUE",           # Decode chunked transfer encoding
    ]

    for spec, tgt in [("http,export_http", "export_http"),
                      ("ftp-data,export_ftp", "export_ftp"),
                      ("smb,export_smb", "export_smb")]:
        tgt_dir = work_dir / tgt
        safe_mkdir(tgt_dir)
        try:
            cmd = ["tshark"] + reassembly_opts + [
                "-r", pcap_path,
                "--export-objects", spec
            ]
            subprocess.run(cmd, check=True, cwd=work_dir, capture_output=True, timeout=300)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            success = False

    return success
