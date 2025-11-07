from .util import run, safe_mkdir
import pathlib, os, hashlib

DISPLAY_FILTER = r'http && http.content_type matches "(octet-stream|zip|x-msdownload|pdf|rtf|msi|java-archive|x-dosexec|x-elf|x-sharedlib)"'
PREFS = [
    "-o","tcp.desegment_tcp_streams:true",
    "-o","http.desegment_body:true",
    "-o","http.decompress_body:true",
]

def export_objects_tshark(pcap_abs: str, work_dir: pathlib.Path, min_size=4096, dedup=True):
    outputs=[]
    for spec, tgt in [("http,export_http","export_http"),
                      ("ftp-data,export_ftp","export_ftp"),
                      ("smb,export_smb","export_smb")]:
        tgt_dir = work_dir / tgt
        safe_mkdir(tgt_dir)
        try:
            cmd = ["tshark","-r", pcap_abs] + PREFS + ["-Y", DISPLAY_FILTER, "--export-objects", spec]
            run(cmd, cwd=work_dir)
            outputs.append(tgt_dir)
        except Exception:
            pass
        # cleanup: rimuovi piccoli e duplicati
        seen = set()
        for f in list(tgt_dir.glob("*")):
            try:
                if f.is_file() and f.stat().st_size < min_size:
                    f.unlink()
                    continue
                if dedup and f.is_file():
                    h = hashlib.sha256(f.read_bytes()).hexdigest()
                    if h in seen:
                        f.unlink()
                    else:
                        seen.add(h)
            except Exception:
                continue
    return outputs
