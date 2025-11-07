"""
Tshark and tcpflow file extraction module with proper TCP stream reassembly
"""

import pathlib
import subprocess

from .utils import safe_mkdir, check_bin


def export_with_tcpflow(pcap_path: str, work_dir: pathlib.Path) -> bool:
    """
    Export files using tcpflow which reconstructs complete TCP streams.
    This handles chunked transfers and fragmented packets better than tshark.
    """
    tcpflow = check_bin("tcpflow")
    if not tcpflow:
        return False

    tgt_dir = work_dir / "export_tcpflow"
    safe_mkdir(tgt_dir)

    try:
        # tcpflow reconstructs complete streams by following TCP conversations
        subprocess.run([
            "tcpflow",
            "-r", pcap_path,
            "-o", str(tgt_dir),
            "-a",  # All packets
            "-e", "http"  # HTTP scanner extracts files
        ], check=True, capture_output=True, timeout=300)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False


def export_objects(pcap_path: str, work_dir: pathlib.Path) -> bool:
    """
    Export objects from PCAP using both tcpflow (best) and tshark (fallback).

    tcpflow is used for HTTP because it properly reconstructs TCP streams,
    tshark is still used for FTP and SMB protocols.
    """
    success = True

    # Try tcpflow first for HTTP (better stream reconstruction)
    if not export_with_tcpflow(pcap_path, work_dir):
        # Fallback to tshark with reassembly options
        reassembly_opts = [
            "-2",  # Two-pass mode: enables better reassembly
            "-o", "tcp.desegment_tcp_streams:TRUE",  # Reassemble TCP streams
            "-o", "http.desegment_body:TRUE",         # Reassemble HTTP body
            "-o", "http.dechunk_body:TRUE",           # Decode chunked transfer encoding
        ]

        tgt_dir = work_dir / "export_http"
        safe_mkdir(tgt_dir)
        try:
            cmd = ["tshark"] + reassembly_opts + [
                "-r", pcap_path,
                "--export-objects", "http,export_http"
            ]
            subprocess.run(cmd, check=True, cwd=work_dir, capture_output=True, timeout=300)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            success = False

    # Use tshark for FTP and SMB (tcpflow doesn't handle these well)
    reassembly_opts = [
        "-2",
        "-o", "tcp.desegment_tcp_streams:TRUE",
    ]

    for spec, tgt in [("ftp-data,export_ftp", "export_ftp"),
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
