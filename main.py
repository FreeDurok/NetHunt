#!/usr/bin/env python3
import argparse, json, pathlib
from datetime import datetime, timezone
from libs.util import safe_mkdir, ensure_file_readable, parse_zeek_conn_json, compute_beacons
from libs.zeek_docker import run_zeek_docker
from libs.suricata_host import run_suricata
from libs.tshark_host import export_objects_tshark
from libs.report import collect_files, enrich_with_eve_meta

def analyze(pcap: str, outdir: str, chunk: int|None = None):
    pcap_path = pathlib.Path(pcap).expanduser().resolve()
    ensure_file_readable(pcap_path, "PCAP")
    OUT = pathlib.Path(outdir).expanduser().resolve()
    safe_mkdir(OUT)

    pcaps = [str(pcap_path)]  # (chunking non implementato in questa refactor per semplicità/robustezza)
    all_ts_by_pair = {}
    all_files = []

    for idx, p in enumerate(pcaps, 1):
        print(f"[INFO] Elaboro {p} ({idx}/{len(pcaps)})")
        work = OUT / f"work_{idx}"
        safe_mkdir(work)
        p_abs = str(pathlib.Path(p).resolve())

        # Zeek (Docker, JSON)
        conn_path = run_zeek_docker(p_abs, work)

        # Suricata (host) + TShark export
        eve_path, suri_files_dir = run_suricata(p_abs, work)
        export_objects_tshark(p_abs, work)

        # Parse conn.log per beacon
        ts_by_pair = parse_zeek_conn_json(conn_path)
        for k, v in ts_by_pair.items():
            all_ts_by_pair.setdefault(k, []).extend(v)

        # Files + meta
        files = collect_files(work, suri_files_dir, [])
        files = enrich_with_eve_meta(files, eve_path)
        all_files.extend(files)

    beacons = compute_beacons(all_ts_by_pair)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pcap": str(pcap_path),
        "beaconing": beacons,
        "files": all_files
    }
    (OUT/"report.json").write_text(json.dumps(report, indent=2))
    print(f"[OK] Output in: {OUT}\n - report.json\n - files estratti nei sottodir work_*/")

def main():
    ap = argparse.ArgumentParser(description="Net-Hunt (Docker Zeek): beaconing + file carving")
    ap.add_argument("pcap", help="Percorso PCAP")
    ap.add_argument("-o","--out", default="out", help="Directory output")
    # Nota: chunk non gestito in questa versione (se serve, si aggiunge con editcap + loop)
    args = ap.parse_args()
    analyze(args.pcap, args.out, chunk=None)

if __name__ == "__main__":
    main()
