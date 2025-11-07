"""
Tshark and tcpflow file extraction module
"""

import pathlib
import subprocess

from .utils import safe_mkdir, check_bin


def export_with_tcpflow(pcap_path: str, work_dir: pathlib.Path) -> bool:
    """
    Export files using tcpflow - reconstructs complete TCP streams
    This is more reliable than tshark --export-objects for fragmented transfers
    """
    tcpflow = check_bin("tcpflow")
    if not tcpflow:
        return False

    tgt_dir = work_dir / "export_tcpflow"
    safe_mkdir(tgt_dir)

    try:
        # tcpflow -r pcap -o outdir
        # -a: print all packets
        # -e: scanner mode (extract files)
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
    """Export objects from PCAP using Tshark and tcpflow"""
    success = True

    # Try tcpflow first (better stream reconstruction)
    if export_with_tcpflow(pcap_path, work_dir):
        # tcpflow succeeded - it already handles HTTP well
        pass
    else:
        # Fallback to tshark for HTTP if tcpflow not available
        tgt_dir = work_dir / "export_http"
        safe_mkdir(tgt_dir)
        try:
            subprocess.run(["tshark", "-r", pcap_path, "--export-objects", "http,export_http"],
                         check=True, cwd=work_dir, capture_output=True)
        except subprocess.CalledProcessError:
            success = False

    # Use tshark for FTP and SMB (tcpflow doesn't handle these as well)
    for spec, tgt in [("ftp-data,export_ftp", "export_ftp"),
                      ("smb,export_smb", "export_smb")]:
        tgt_dir = work_dir / tgt
        safe_mkdir(tgt_dir)
        try:
            subprocess.run(["tshark", "-r", pcap_path, "--export-objects", spec],
                         check=True, cwd=work_dir, capture_output=True)
        except subprocess.CalledProcessError:
            success = False

    return success
