import pathlib, os
from .util import run, safe_mkdir

IMAGE = os.environ.get("ZEEK_IMAGE", "zeek/zeek:latest")

def run_zeek_docker(pcap_abs: str, work_dir: pathlib.Path):
    """Esegue Zeek in container. Output log nella dir work_dir (JSON)."""
    safe_mkdir(work_dir)
    # Monta PCAP e out
    cmd = [
        "docker","run","--rm",
        "-u", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{work_dir}:{work_dir}",
        "-v", f"{pcap_abs}:{work_dir}/input.pcap:ro",
        "-w", f"{work_dir}",
        IMAGE,
        "zeek","-Cr", f"{work_dir}/input.pcap",
        "-e", "redef LogAscii::use_json=T; redef LogAscii::json_timestamps=JSON::TS_ISO8601;"
    ]
    run(cmd)
    # conn.log deve essere prodotto in work_dir
    return work_dir / "conn.log"
