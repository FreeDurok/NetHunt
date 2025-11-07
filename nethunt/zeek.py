"""
Zeek execution module (Docker and native support)
"""

import os
import pathlib
import subprocess
from typing import Optional

from .config import ZEEK_DOCKER_IMAGE, ZEEK_PATH
from .utils import check_bin, is_executable


def check_docker() -> bool:
    """Check if Docker is available"""
    return check_bin("docker") is not None


def check_zeek_docker_image() -> bool:
    """Check if Zeek Docker image is available"""
    try:
        result = subprocess.run(
            ["docker", "images", "-q", ZEEK_DOCKER_IMAGE],
            capture_output=True,
            text=True,
            check=False
        )
        return len(result.stdout.strip()) > 0
    except Exception:
        return False


def resolve_zeek_path(user_zeek: Optional[str] = None) -> Optional[str]:
    """Find Zeek binary in system"""
    candidates = []
    if user_zeek:
        candidates.append(user_zeek)
    if ZEEK_PATH:
        candidates.append(ZEEK_PATH)
    if os.getenv("ZEEK_PATH"):
        candidates.append(os.getenv("ZEEK_PATH"))
    if os.getenv("ZEEK"):
        candidates.append(os.getenv("ZEEK"))
    w = check_bin("zeek")
    if w:
        candidates.append(w)
    candidates.extend([
        "/opt/zeek/bin/zeek",
        "/usr/local/zeek/bin/zeek",
        "/usr/local/bin/zeek",
        "/usr/bin/zeek",
    ])
    for c in candidates:
        if not c:
            continue
        p = pathlib.Path(c)
        if is_executable(p):
            return str(p)
    return None


def run_zeek_native(zeek_bin: str, pcap_path: pathlib.Path, work_dir: pathlib.Path) -> bool:
    """Run Zeek natively (without Docker)"""
    env = os.environ.copy()
    env["LogAscii::use_json"] = "T"
    env["LogAscii::json_timestamps"] = "JSON::TS_ISO8601"

    zcmd = [zeek_bin, "-Cr", str(pcap_path),
            "policy/tuning/json-logs.zeek",
            "protocols/ssl/ja3.zeek",
            "frameworks/files/extract-all-files.zeek"]

    try:
        subprocess.run(zcmd, check=True, cwd=work_dir, env=env, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False


def run_zeek_docker(pcap_path: pathlib.Path, work_dir: pathlib.Path) -> bool:
    """Run Zeek via Docker container"""
    if not check_docker():
        return False

    if not check_zeek_docker_image():
        try:
            subprocess.run(["docker", "pull", ZEEK_DOCKER_IMAGE], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            return False

    # Prepare Docker command
    # Mount PCAP as read-only, work directory as read-write
    pcap_abs = pcap_path.resolve()
    work_abs = work_dir.resolve()

    docker_cmd = [
        "docker", "run", "--rm",
        "-v", f"{pcap_abs}:/data/capture.pcap:ro",
        "-v", f"{work_abs}:/logs",
        "-w", "/logs",
        ZEEK_DOCKER_IMAGE,
        "-Cr", "/data/capture.pcap",
        "LogAscii::use_json=T",
        "LogAscii::json_timestamps=JSON::TS_ISO8601",
        "policy/tuning/json-logs.zeek",
        "protocols/ssl/ja3.zeek",
        "frameworks/files/extract-all-files.zeek"
    ]

    try:
        subprocess.run(docker_cmd, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError:
        return False
