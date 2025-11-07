import pathlib, hashlib, json
from collections import defaultdict

def collect_files(work_dir: pathlib.Path, suricata_files: pathlib.Path, extra_dirs):
    files=[]
    sources = []
    if (work_dir/"extracted").exists(): sources.append(("zeek", work_dir/"extracted"))
    if suricata_files and suricata_files.exists(): sources.append(("suricata", suricata_files))
    for tag, p in [("tshark_http", work_dir/"export_http"),
                   ("tshark_ftp",  work_dir/"export_ftp"),
                   ("tshark_smb",  work_dir/"export_smb")]:
        if p.exists(): sources.append((tag,p))
    # extra_dirs already covered (same paths)
    for source, base in sources:
        for pth in base.rglob("*"):
            if pth.is_file():
                try:
                    data = pth.read_bytes()
                    sha256 = hashlib.sha256(data).hexdigest()
                    files.append({"source":source,"path":str(pth),"sha256":sha256,"size":len(data)})
                except Exception:
                    continue
    return files

def enrich_with_eve_meta(files, eve_path: pathlib.Path):
    if not eve_path.exists(): return files
    meta_by_sha = defaultdict(dict)
    with eve_path.open() as f:
        for line in f:
            try: ev = json.loads(line)
            except Exception: continue
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
    for r in files:
        if r["sha256"] in meta_by_sha:
            r.update({k:v for k,v in meta_by_sha[r["sha256"]].items() if v is not None})
    return files
