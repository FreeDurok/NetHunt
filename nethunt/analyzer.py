"""
Main analysis orchestration module
"""

import json
import pathlib
import sys
import hashlib
import subprocess
from collections import defaultdict, Counter
from datetime import datetime, timezone
from typing import Optional

from .config import USE_DOCKER_ZEEK
from .utils import check_bin, safe_mkdir, ensure_file_readable, format_bytes
from .zeek import check_docker, check_zeek_docker_image, resolve_zeek_path, run_zeek_native, run_zeek_docker
from .suricata import write_minimal_suricata_yaml, run_suricata
from .tshark import export_objects
from .parsers import parse_http_log, parse_dns_log, parse_ssl_log, deduplicate_files
from .beaconing import detect_beacons, detect_http_beacons
from .domain_filter import filter_legitimate_traffic, classify_url
from .report import generate_html_report


def analyze(pcap, outdir, chunk=None):
    """Main analysis function"""
    pcap_path = pathlib.Path(pcap).expanduser().resolve()
    ensure_file_readable(pcap_path, "PCAP")
    OUT = pathlib.Path(outdir).expanduser().resolve()
    safe_mkdir(OUT)

    # Check tools availability
    print(f"\n{'='*60}")
    print(f"NetHunt - PCAP Analysis")
    print(f"{'='*60}")
    print(f"Input: {pcap_path.name} ({format_bytes(pcap_path.stat().st_size)})")
    print(f"Output: {OUT}")
    print(f"{'='*60}\n")

    # Determine Zeek execution method
    zeek_native_bin = resolve_zeek_path()
    use_zeek_docker = USE_DOCKER_ZEEK and check_docker()
    use_zeek_native = zeek_native_bin and not use_zeek_docker

    if use_zeek_docker:
        if not check_zeek_docker_image():
            try:
                subprocess.run(["docker", "pull", "zeek/zeek:latest"], check=True, capture_output=True)
            except:
                use_zeek_docker = False
                use_zeek_native = zeek_native_bin is not None

    # Print tool status
    print("Tool Status:")
    if use_zeek_docker:
        print(f"  ✓ Zeek (Docker): zeek/zeek:latest")
    elif use_zeek_native:
        print(f"  ✓ Zeek (native): {zeek_native_bin}")
    else:
        print(f"  ✗ Zeek: not available")

    suricata = check_bin("suricata")
    tshark = check_bin("tshark")

    print(f"  {'✓' if suricata else '✗'} Suricata: {'yes' if suricata else 'not found'}")
    print(f"  {'✓' if tshark else '✗'} Tshark: {'yes' if tshark else 'not found'}")
    print("")

    # Chunking
    pcaps = [str(pcap_path)]
    if chunk:
        print(f"Chunking PCAP ({chunk} packets per chunk)...", end=" ", flush=True)
        editcap = check_bin("editcap")
        if not editcap:
            sys.exit("✗ ERROR: editcap not found (required for --chunk)")
        subprocess.run([editcap, "-c", str(chunk), str(pcap_path), str(OUT / "chunk_%06d.pcap")],
                      check=True, capture_output=True)
        pcaps = sorted(map(str, OUT.glob("chunk_*.pcap")))
        if not pcaps:
            sys.exit("✗ ERROR: No chunks generated")
        print(f"✓ ({len(pcaps)} chunks)\n")

    # Data structures
    ts_by_pair = defaultdict(list)
    files_list = []
    all_http_data = {"requests": [], "urls": set(), "methods": Counter(), "status_codes": Counter(),
                     "hosts": Counter(), "user_agents": Counter()}
    all_dns_data = {"queries": [], "query_names": Counter(), "query_types": Counter()}
    all_ssl_data = {"connections": [], "server_names": Counter(), "ja3": Counter(), "versions": Counter()}

    # Process each PCAP
    for idx, p in enumerate(pcaps, 1):
        if len(pcaps) > 1:
            print(f"\n[{idx}/{len(pcaps)}] Processing chunk: {pathlib.Path(p).name}")
        work = OUT / f"work_{idx}"
        safe_mkdir(work)
        p_abs = str(pathlib.Path(p).resolve())

        # Run Zeek
        if use_zeek_docker:
            print("  → Running Zeek (Docker)...", end=" ", flush=True)
            pcap_to_analyze = pathlib.Path(p_abs)
            success, error_msg = run_zeek_docker(pcap_to_analyze, work)
            if success:
                print("✓")
            else:
                print(f"✗ (failed)")
                if error_msg:
                    print(f"     Error: {error_msg}")
                # Try native Zeek as fallback
                if zeek_native_bin:
                    print("     Trying native Zeek as fallback...", end=" ", flush=True)
                    if run_zeek_native(zeek_native_bin, pcap_to_analyze, work):
                        print("✓")
                    else:
                        print("✗ (failed)")
        elif use_zeek_native:
            print("  → Running Zeek (native)...", end=" ", flush=True)
            pcap_to_analyze = pathlib.Path(p_abs)
            if run_zeek_native(zeek_native_bin, pcap_to_analyze, work):
                print("✓")
            else:
                print("✗ (failed)")

        # Run Suricata
        eve_dir = work / "suricata"
        safe_mkdir(eve_dir)
        if suricata:
            print("  → Running Suricata...", end=" ", flush=True)
            cfg = eve_dir.parent / "minimal-suricata.yaml"
            write_minimal_suricata_yaml(cfg)
            if run_suricata(p_abs, eve_dir, cfg):
                print("✓")
            else:
                print("✗ (failed)")

        # Run Tshark
        if tshark:
            print("  → Running Tshark...", end=" ", flush=True)
            if export_objects(p_abs, work):
                print("✓")
            else:
                print("✗ (partial)")

        # Parse Zeek conn.log for beaconing
        conn = work / "conn.log"
        if conn.exists():
            with conn.open() as f:
                for line in f:
                    try:
                        r = json.loads(line)
                    except Exception:
                        continue
                    # Skip if _path exists and is not conn (for compatibility)
                    if "_path" in r and r.get("_path") != "conn":
                        continue
                    src, dst = r.get("id.orig_h"), r.get("id.resp_h")
                    dport, ts = r.get("id.resp_p"), r.get("ts")
                    if not (src and dst and dport):
                        continue
                    if isinstance(ts, (int, float)):
                        ts_by_pair[(src, dst, str(dport))].append(ts)

        # Parse HTTP log
        http_log = work / "http.log"
        if http_log.exists():
            http_data = parse_http_log(http_log)
            all_http_data["requests"].extend(http_data["requests"])
            all_http_data["urls"].update(http_data["urls"])
            for k, v in http_data["methods"].items():
                all_http_data["methods"][k] += v
            for k, v in http_data["status_codes"].items():
                all_http_data["status_codes"][k] += v
            for k, v in http_data["hosts"].items():
                all_http_data["hosts"][k] += v
            for k, v in http_data["user_agents"].items():
                all_http_data["user_agents"][k] += v

        # Parse DNS log
        dns_log = work / "dns.log"
        if dns_log.exists():
            dns_data = parse_dns_log(dns_log)
            all_dns_data["queries"].extend(dns_data["queries"])
            for k, v in dns_data["query_names"].items():
                all_dns_data["query_names"][k] += v
            for k, v in dns_data["query_types"].items():
                all_dns_data["query_types"][k] += v

        # Parse SSL log
        ssl_log = work / "ssl.log"
        if ssl_log.exists():
            ssl_data = parse_ssl_log(ssl_log)
            all_ssl_data["connections"].extend(ssl_data["connections"])
            for k, v in ssl_data["server_names"].items():
                all_ssl_data["server_names"][k] += v
            for k, v in ssl_data["ja3"].items():
                all_ssl_data["ja3"][k] += v
            for k, v in ssl_data["versions"].items():
                all_ssl_data["versions"][k] += v

        # Collect files and hashes
        for base, source in [(work / "extract_files", "zeek"),
                             (work / "extracted", "zeek"),  # Fallback for different Zeek versions
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

        # Parse Suricata EVE for file metadata
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

    # Detect TCP-level beaconing
    beacons = detect_beacons(ts_by_pair)

    # Filter legitimate traffic from HTTP requests
    print("\n  → Filtering legitimate traffic...", end=" ", flush=True)
    original_count = len(all_http_data["requests"])
    filtered_requests = filter_legitimate_traffic(all_http_data["requests"], filter_level="all")
    filtered_count = len(filtered_requests)
    print(f"✓ (removed {original_count - filtered_count} legitimate requests)")

    # Detect HTTP-level beaconing (C2 traffic patterns)
    print("  → Detecting HTTP beaconing...", end=" ", flush=True)
    http_beacons = detect_http_beacons(filtered_requests)
    print(f"✓ (found {len(http_beacons)} patterns)")

    # Deduplicate files
    print("  → Deduplicating files...", end=" ", flush=True)
    files_list = deduplicate_files(files_list)
    # Sort files by size (largest first)
    files_list.sort(key=lambda x: x.get('size', 0), reverse=True)
    print("✓")

    # Prepare report data
    http_report = {
        "urls": sorted(all_http_data["urls"]),
        "requests_count": len(all_http_data["requests"]),
        "methods": dict(all_http_data["methods"].most_common()),
        "status_codes": dict(all_http_data["status_codes"].most_common()),
        "top_hosts": dict(all_http_data["hosts"].most_common(20)),
        "top_user_agents": dict(all_http_data["user_agents"].most_common(10)),
        "requests": all_http_data["requests"][:100]
    }

    dns_report = {
        "queries_count": len(all_dns_data["queries"]),
        "top_queries": dict(all_dns_data["query_names"].most_common(50)),
        "query_types": dict(all_dns_data["query_types"].most_common()),
        "queries": all_dns_data["queries"][:100]
    }

    ssl_report = {
        "connections_count": len(all_ssl_data["connections"]),
        "top_server_names": dict(all_ssl_data["server_names"].most_common(20)),
        "ja3_fingerprints": dict(all_ssl_data["ja3"].most_common(10)),
        "tls_versions": dict(all_ssl_data["versions"].most_common()),
        "connections": all_ssl_data["connections"][:100]
    }

    # Build report
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pcap": str(pcap_path),
        "pcap_size": pcap_path.stat().st_size,
        "beaconing": beacons,
        "http_beaconing": http_beacons,
        "files": files_list,
        "http": http_report,
        "dns": dns_report,
        "ssl": ssl_report,
        "statistics": {
            "total_files": len(files_list),
            "total_beacons": len(beacons),
            "total_http_beacons": len(http_beacons),
            "total_http_requests": len(all_http_data["requests"]),
            "filtered_http_requests": len(filtered_requests),
            "total_dns_queries": len(all_dns_data["queries"]),
            "total_ssl_connections": len(all_ssl_data["connections"]),
            "unique_urls": len(all_http_data["urls"]),
            "unique_domains": len(all_dns_data["query_names"])
        }
    }

    # Save reports
    print("  → Generating reports...", end=" ", flush=True)
    (OUT / "report.json").write_text(json.dumps(report, indent=2))
    html_report = generate_html_report(report)
    (OUT / "report.html").write_text(html_report)
    print("✓")

    # Summary
    print(f"\n{'='*60}")
    print("Analysis Complete!")
    print(f"{'='*60}")
    print(f"Files extracted: {len(files_list)}")
    print(f"HTTP requests: {len(all_http_data['requests'])} ({len(filtered_requests)} after filtering)")
    print(f"DNS queries: {len(all_dns_data['queries'])}")
    print(f"TLS connections: {len(all_ssl_data['connections'])}")
    print(f"TCP beacons detected: {len(beacons)}")
    print(f"HTTP beacons detected: {len(http_beacons)}")
    print(f"\nOutput directory: {OUT}")
    print("  • report.html - Interactive HTML report")
    print("  • report.json - Raw data in JSON format")
    print("  • work_*/ - Extracted files and logs")
    print(f"{'='*60}\n")
