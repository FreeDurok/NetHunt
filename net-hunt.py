#!/usr/bin/env python3
# net-hunt.py (no-graph) — beaconing + file carving con Suricata YAML, Zeek fuori PATH e check path
import argparse, json, statistics, hashlib, shutil, subprocess, sys, pathlib, os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

# === CONFIG EDITABILE ===
# Imposta qui il percorso di Zeek se fuori PATH (override da CLI --zeek o env ZEEK_PATH / ZEEK).
ZEEK_PATH: Optional[str] = "/opt/zeek/bin/zeek" #  os.getenv("ZEEK_PATH")  # es: "/opt/zeek/bin/zeek"

# ---------- util ----------
def check_bin(name):
    return shutil.which(name)

def is_executable(p: pathlib.Path) -> bool:
    try:
        return p.exists() and p.is_file() and os.access(str(p), os.X_OK)
    except Exception:
        return False

def run(cmd, cwd=None, env=None):
    print("[CMD]", " ".join(cmd))
    subprocess.run(cmd, check=True, cwd=cwd, env=env)

def safe_mkdir(p): pathlib.Path(p).mkdir(parents=True, exist_ok=True)

def ensure_file_readable(p: pathlib.Path, label: str):
    if not p.exists() or not p.is_file():
        sys.exit(f"[ERR] {label} non trovato: {p}")
    if not os.access(str(p), os.R_OK):
        sys.exit(f"[ERR] {label} non leggibile: {p}")

def write_minimal_suricata_yaml(cfg_path: pathlib.Path):
    cfg_path.write_text("""%YAML 1.1
---
default-log-dir: .
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types: [alert, flow, http, tls, dns, ftp, smb, fileinfo]

file-store:
  version: 2
  enabled: yes
  dir: files
  write-fileinfo: yes
  force-magic: yes
  force-hash: [sha256]
""")

def resolve_zeek_path(user_zeek: Optional[str]) -> Optional[str]:
    # Priorità: CLI -> variabile globale ZEEK_PATH -> env ZEEK_PATH -> env ZEEK -> PATH -> location note
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

# ---------- core ----------
def analyze(pcap, outdir, chunk=None, zeek_bin=None):
    pcap_path = pathlib.Path(pcap).expanduser().resolve()
    ensure_file_readable(pcap_path, "PCAP")
    OUT = pathlib.Path(outdir).expanduser().resolve()
    safe_mkdir(OUT)

    # binari
    zeek = resolve_zeek_path(zeek_bin)
    if not zeek:
        print("[WARN] Zeek non trovato (usa --zeek /path/zeek o esporta ZEEK_PATH/ZEEK)")
    else:
        print(f"[INFO] Zeek: {zeek}")
    suricata = check_bin("suricata")
    tshark = check_bin("tshark")

    # chunking opzionale
    pcaps = [str(pcap_path)]
    if chunk:
        print(f"[INFO] Chunking PCAP a {chunk} pacchetti…")
        editcap = check_bin("editcap")
        if not editcap:
            sys.exit("[ERR] editcap mancante per --chunk")
        run([editcap, "-c", str(chunk), str(pcap_path), str(OUT / "chunk_%06d.pcap")])
        pcaps = sorted(map(str, OUT.glob("chunk_*.pcap")))
        if not pcaps:
            sys.exit("[ERR] Nessun chunk generato: verifica input/scrittura")

    # strutture cumulative
    ts_by_pair = defaultdict(list)      # (src,dst,dport)->[ts]
    files_list = []                     # file estratti + hash

    # loop pcaps
    for idx, p in enumerate(pcaps, 1):
        print(f"[INFO] Elaboro {p} ({idx}/{len(pcaps)})")
        work = OUT / f"work_{idx}"
        safe_mkdir(work)
        p_abs = str(pathlib.Path(p).resolve())

        # --- ZEEK (JSON + files) ---
        if zeek:
            env = os.environ.copy()
            env["LogAscii::use_json"] = "T"
            env["LogAscii::json_timestamps"] = "JSON::TS_ISO8601"
            zcmd = [zeek, "-Cr", p_abs,
                    "policy/tuning/json-logs.zeek",
                    "protocols/ssl/ja3.zeek",
                    "frameworks/files/extract-all-files.zeek"]
            try:
                run(zcmd, cwd=work, env=env)
            except subprocess.CalledProcessError as e:
                print(f"[WARN] Zeek fallito: {e}")
        else:
            print("[WARN] Skip Zeek")

        # --- SURICATA (EVE + filestore v2 via YAML) ---
        eve_dir = work / "suricata"; safe_mkdir(eve_dir)
        if suricata:
            cfg = eve_dir.parent / "minimal-suricata.yaml"
            write_minimal_suricata_yaml(cfg)
            ensure_file_readable(cfg, "Suricata YAML")
            # Test config locale per evitare errori a runtime
            run(["suricata", "-T", "-c", str(cfg), "-l", str(eve_dir)])
            run(["suricata", "-r", p_abs, "-l", str(eve_dir), "-k", "none", "-c", str(cfg)])
        else:
            print("[WARN] Skip Suricata (binario non trovato)")

        # --- TSHARK (export oggetti extra) ---
        if tshark:
            for spec, tgt in [("http,export_http", "export_http"),
                              ("ftp-data,export_ftp", "export_ftp"),
                              ("smb,export_smb", "export_smb")]:
                tgt_dir = work / tgt
                safe_mkdir(tgt_dir)
                try:
                    run(["tshark", "-r", p_abs, "--export-objects", spec], cwd=work)
                except subprocess.CalledProcessError as e:
                    print(f"[WARN] tshark export {spec} fallito: {e}")
        else:
            print("[WARN] Skip tshark export (binario non trovato)")

        # --- PARSE ZEEK conn.log (solo per beaconing) ---
        conn = work / "conn.log"
        if conn.exists():
            with conn.open() as f:
                for line in f:
                    try:
                        r = json.loads(line)
                    except Exception:
                        continue
                    if r.get("_path") != "conn":
                        continue
                    src, dst = r.get("id.orig_h"), r.get("id.resp_h")
                    dport, ts = r.get("id.resp_p"), r.get("ts")
                    if not (src and dst and dport):
                        continue
                    if isinstance(ts, (int, float)):
                        ts_by_pair[(src, dst, str(dport))].append(ts)
        else:
            print("[WARN] Zeek conn.log assente (beaconing ridotto)")

        # --- RACCOLTA FILE E HASH ---
        for base, source in [(work / "extracted", "zeek"),
                             (eve_dir / "files", "suricata"),
                             (work / "export_http", "tshark_http"),
                             (work / "export_ftp", "tshark_ftp"),
                             (work / "export_smb", "tshark_smb")]:
            if base.exists():
                for pth in base.rglob("*"):
                    if pth.is_file():
                        try:
                            data = pth.read_bytes()
                            sha256 = hashlib.sha256(data).hexdigest()
                            files_list.append({
                                "source": source,
                                "path": str(pth),
                                "sha256": sha256,
                                "size": len(data)
                            })
                        except Exception:
                            continue

        # --- METADATI FILE DA EVE ---
        eve = eve_dir / "eve.json"
        if eve.exists():
            meta_by_sha = defaultdict(dict)
            with eve.open() as f:
                for line in f:
                    try:
                        ev = json.loads(line)
                    except Exception:
                        continue
                    if ev.get("event_type") == "fileinfo":
                        finfo = ev.get("fileinfo", {})
                        sha = finfo.get("sha256") or finfo.get("sha1")
                        if sha:
                            meta_by_sha[sha] = {
                                "src_ip": ev.get("src_ip"),
                                "dest_ip": ev.get("dest_ip"),
                                "filename": finfo.get("filename"),
                                "magic": finfo.get("magic"),
                                "stored": finfo.get("stored"),
                                "size": finfo.get("size"),
                                "mime_type": finfo.get("mime_type"),
                            }
            for r in files_list:
                if r["sha256"] in meta_by_sha:
                    r.update({k: v for k, v in meta_by_sha[r["sha256"]].items() if v is not None})

    # --- HEURISTIC BEACONING (da Zeek conn.log) ---
    beacons = []
    for k, arr in ts_by_pair.items():
        if len(arr) < 6:
            continue
        arr.sort()
        deltas = [arr[i + 1] - arr[i] for i in range(len(arr) - 1)]
        if len(deltas) < 5:
            continue
        mu = statistics.mean(deltas)
        sigma = statistics.pstdev(deltas) if len(deltas) > 1 else 0.0
        cv = (sigma / mu) if mu > 0 else 9e9
        score = (len(arr)) * (1.0 / (1.0 + cv))
        if score >= 8 and cv <= 0.15 and mu >= 5:
            src, dst, dport = k
            beacons.append({
                "src": src, "dst": dst, "dport": dport,
                "interval_avg_s": round(mu, 2), "cv": round(cv, 3),
                "events": len(arr), "score": round(score, 2)
            })
    beacons.sort(key=lambda x: x["score"], reverse=True)

    # --- REPORT ---
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pcap": str(pcap_path),
        "beaconing": beacons,
        "files": files_list
    }
    (OUT / "report.json").write_text(json.dumps(report, indent=2))
    print(f"[OK] Output in: {OUT}")
    print(" - report.json")
    print(" - files estratti nei sottodir work_*/")

# ---------- cli ----------
def main():
    ap = argparse.ArgumentParser(description="Net-Hunt: beaconing + estrazione file da PCAP (no graph)")
    ap.add_argument("pcap", help="Percorso PCAP")
    ap.add_argument("-o", "--out", default="out", help="Directory output")
    ap.add_argument("--chunk", type=int, default=None, help="Cut in N pacchetti per chunk (editcap)")
    ap.add_argument("--zeek", help="Percorso binario zeek (se non nel PATH)")
    args = ap.parse_args()
    analyze(args.pcap, args.out, chunk=args.chunk, zeek_bin=args.zeek)

if __name__ == "__main__":
    main()
