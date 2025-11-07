import shutil, subprocess, sys, pathlib, os, json, statistics
from collections import defaultdict

def check_bin(name): return shutil.which(name)

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
      types: [alert, flow, http, tls, dns, ftp, smb]

file-store:
  version: 2
  enabled: yes
  dir: files
  write-fileinfo: yes
  force-magic: yes
  force-hash: [sha256]
""")

def parse_zeek_conn_json(conn_path: pathlib.Path):
    ts_by_pair = defaultdict(list)
    if conn_path.exists():
        with conn_path.open() as f:
            for line in f:
                try: r = json.loads(line)
                except Exception: continue
                if r.get("_path") != "conn": continue
                src, dst = r.get("id.orig_h"), r.get("id.resp_h")
                dport, ts = r.get("id.resp_p"), r.get("ts")
                if not (src and dst and dport): continue
                if isinstance(ts,(int,float)):
                    ts_by_pair[(src,dst,str(dport))].append(ts)
    return ts_by_pair

def compute_beacons(ts_by_pair: dict):
    beacons=[]
    for k, arr in ts_by_pair.items():
        if len(arr) < 6: continue
        arr.sort()
        deltas=[arr[i+1]-arr[i] for i in range(len(arr)-1)]
        if len(deltas) < 5: continue
        mu = statistics.mean(deltas)
        sigma = statistics.pstdev(deltas) if len(deltas) > 1 else 0.0
        cv = (sigma/mu) if mu > 0 else 9e9
        score = (len(arr))*(1.0/(1.0+cv))
        if score >= 8 and cv <= 0.15 and mu >= 5:
            src,dst,dport = k
            beacons.append({
                "src":src,"dst":dst,"dport":dport,
                "interval_avg_s":round(mu,2),"cv":round(cv,3),
                "events":len(arr),"score":round(score,2)
            })
    beacons.sort(key=lambda x:x["score"], reverse=True)
    return beacons
