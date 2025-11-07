"""
Tshark file extraction module
"""

import pathlib
import subprocess

from .utils import safe_mkdir


def export_objects(pcap_path: str, work_dir: pathlib.Path) -> bool:
    """Export objects from PCAP using Tshark"""
    success = True

    for spec, tgt in [("http,export_http", "export_http"),
                      ("ftp-data,export_ftp", "export_ftp"),
                      ("smb,export_smb", "export_smb")]:
        tgt_dir = work_dir / tgt
        safe_mkdir(tgt_dir)
        try:
            subprocess.run(["tshark", "-r", pcap_path, "--export-objects", spec],
                         check=True, cwd=work_dir, capture_output=True)
        except subprocess.CalledProcessError:
            success = False

    return success
