import pathlib
from .util import run, safe_mkdir, write_minimal_suricata_yaml, ensure_file_readable

def run_suricata(pcap_abs: str, work_dir: pathlib.Path):
    """Suricata host: eve.json + file carving (filestore v2) in work_dir/suricata"""
    eve_dir = work_dir / "suricata"
    safe_mkdir(eve_dir)
    cfg = work_dir / "minimal-suricata.yaml"
    write_minimal_suricata_yaml(cfg)
    ensure_file_readable(cfg, "Suricata YAML")
    # Test + run
    run(["suricata","-T","-c",str(cfg),"-l",str(eve_dir)])
    run(["suricata","-r",pcap_abs,"-l",str(eve_dir),"-k","none","-c",str(cfg)])
    return eve_dir / "eve.json", eve_dir / "files"
