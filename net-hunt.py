#!/usr/bin/env python3
# net-hunt.py — Advanced PCAP analysis with beaconing, file carving, URL extraction, DNS analysis and HTML reporting
# Uses Zeek via Docker for easier deployment on Kali Linux
import argparse, json, statistics, hashlib, shutil, subprocess, sys, pathlib, os, re, base64
from collections import defaultdict, Counter
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse

# === CONFIG EDITABILE ===
# Docker image for Zeek
ZEEK_DOCKER_IMAGE = "zeek/zeek:latest"
USE_DOCKER_ZEEK = True  # Set to False to use local Zeek installation

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

def run_zeek_docker(pcap_path: pathlib.Path, work_dir: pathlib.Path) -> bool:
    """Run Zeek via Docker container"""
    if not check_docker():
        print("[ERROR] Docker not found. Please install Docker first.")
        return False

    if not check_zeek_docker_image():
        print(f"[INFO] Pulling Zeek Docker image: {ZEEK_DOCKER_IMAGE}")
        try:
            subprocess.run(["docker", "pull", ZEEK_DOCKER_IMAGE], check=True)
        except subprocess.CalledProcessError:
            print("[ERROR] Failed to pull Zeek Docker image")
            return False

    # Prepare Docker command
    # Mount PCAP as read-only, work directory as read-write
    pcap_abs = pcap_path.resolve()
    work_abs = work_dir.resolve()

    docker_cmd = [
        "docker", "run", "--rm",
        "-v", f"{pcap_abs}:/data/capture.pcap:ro",
        "-v", f"{work_abs}:/zeek",
        "-w", "/zeek",
        "-e", "LogAscii::use_json=T",
        "-e", "LogAscii::json_timestamps=JSON::TS_ISO8601",
        ZEEK_DOCKER_IMAGE,
        "-Cr", "/data/capture.pcap",
        "LogAscii::use_json=T",
        "LogAscii::json_timestamps=JSON::TS_ISO8601",
        "policy/tuning/json-logs.zeek",
        "protocols/ssl/ja3.zeek",
        "frameworks/files/extract-all-files.zeek"
    ]

    print(f"[CMD] docker run zeek (output in {work_dir})")
    try:
        subprocess.run(docker_cmd, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Zeek Docker execution failed: {e}")
        return False

# ---------- parsers ----------
def parse_http_log(log_path: pathlib.Path) -> Dict[str, Any]:
    """Parse Zeek http.log to extract URLs, methods, status codes"""
    http_requests = []
    urls = set()
    methods = Counter()
    status_codes = Counter()
    hosts = Counter()
    user_agents = Counter()

    if not log_path.exists():
        return {"requests": [], "urls": [], "methods": {}, "status_codes": {}, "hosts": {}, "user_agents": {}}

    with log_path.open() as f:
        for line in f:
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("_path") != "http":
                continue

            method = r.get("method", "")
            host = r.get("host", "")
            uri = r.get("uri", "")
            status = r.get("status_code")
            user_agent = r.get("user_agent", "")

            if host and uri:
                url = f"http://{host}{uri}"
                urls.add(url)
                http_requests.append({
                    "ts": r.get("ts"),
                    "method": method,
                    "url": url,
                    "status_code": status,
                    "user_agent": user_agent[:100] if user_agent else "",
                    "src_ip": r.get("id.orig_h"),
                    "dst_ip": r.get("id.resp_h"),
                    "response_size": r.get("response_body_len", 0)
                })

            if method:
                methods[method] += 1
            if status:
                status_codes[str(status)] += 1
            if host:
                hosts[host] += 1
            if user_agent:
                user_agents[user_agent[:50]] += 1

    return {
        "requests": http_requests,
        "urls": sorted(urls),
        "methods": dict(methods.most_common()),
        "status_codes": dict(status_codes.most_common()),
        "hosts": dict(hosts.most_common(20)),
        "user_agents": dict(user_agents.most_common(10))
    }

def parse_dns_log(log_path: pathlib.Path) -> Dict[str, Any]:
    """Parse Zeek dns.log to extract DNS queries and answers"""
    queries = []
    query_names = Counter()
    query_types = Counter()

    if not log_path.exists():
        return {"queries": [], "query_names": {}, "query_types": {}}

    with log_path.open() as f:
        for line in f:
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("_path") != "dns":
                continue

            query = r.get("query", "")
            qtype_name = r.get("qtype_name", "")
            answers = r.get("answers", [])

            if query:
                query_names[query] += 1
                queries.append({
                    "ts": r.get("ts"),
                    "query": query,
                    "qtype": qtype_name,
                    "answers": answers if isinstance(answers, list) else [answers],
                    "src_ip": r.get("id.orig_h"),
                    "dst_ip": r.get("id.resp_h")
                })

            if qtype_name:
                query_types[qtype_name] += 1

    return {
        "queries": queries,
        "query_names": dict(query_names.most_common(50)),
        "query_types": dict(query_types.most_common())
    }

def parse_ssl_log(log_path: pathlib.Path) -> Dict[str, Any]:
    """Parse Zeek ssl.log to extract TLS certificates and JA3 fingerprints"""
    ssl_conns = []
    server_names = Counter()
    ja3_fingerprints = Counter()
    versions = Counter()

    if not log_path.exists():
        return {"connections": [], "server_names": {}, "ja3": {}, "versions": {}}

    with log_path.open() as f:
        for line in f:
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("_path") != "ssl":
                continue

            server_name = r.get("server_name", "")
            ja3 = r.get("ja3", "")
            version = r.get("version", "")
            subject = r.get("subject", "")

            if server_name:
                server_names[server_name] += 1
            if ja3:
                ja3_fingerprints[ja3] += 1
            if version:
                versions[version] += 1

            ssl_conns.append({
                "ts": r.get("ts"),
                "server_name": server_name,
                "subject": subject,
                "ja3": ja3,
                "version": version,
                "src_ip": r.get("id.orig_h"),
                "dst_ip": r.get("id.resp_h")
            })

    return {
        "connections": ssl_conns,
        "server_names": dict(server_names.most_common(20)),
        "ja3": dict(ja3_fingerprints.most_common(10)),
        "versions": dict(versions.most_common())
    }

def deduplicate_files(files_list: List[Dict]) -> List[Dict]:
    """Remove duplicate files by SHA256 and filter out empty/junk files"""
    seen_hashes = set()
    deduplicated = []

    for f in files_list:
        sha = f.get("sha256")
        size = f.get("size", 0)

        # Skip empty files
        if size == 0:
            continue

        # Skip duplicates
        if sha in seen_hashes:
            continue

        seen_hashes.add(sha)
        deduplicated.append(f)

    return deduplicated

def format_bytes(size: int) -> str:
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"

def generate_html_report(data: Dict[str, Any]) -> str:
    """Generate modern HTML report with all analysis data"""

    stats = data.get("statistics", {})
    beacons = data.get("beaconing", [])
    files = data.get("files", [])
    http = data.get("http", {})
    dns = data.get("dns", {})
    ssl = data.get("ssl", {})

    # Build files table
    files_rows = ""
    for f in files[:100]:  # Limit to 100 files
        size_str = format_bytes(f.get("size", 0))
        sha = f.get("sha256", "")[:16]
        files_rows += f"""
        <tr>
            <td>{f.get('source', 'N/A')}</td>
            <td class="monospace">{f.get('path', 'N/A').split('/')[-1][:50]}</td>
            <td>{size_str}</td>
            <td class="monospace" title="{f.get('sha256', '')}">{sha}...</td>
            <td>{f.get('magic', 'N/A')}</td>
        </tr>
        """

    # Build beaconing table
    beacons_rows = ""
    for b in beacons[:50]:
        beacons_rows += f"""
        <tr>
            <td class="monospace">{b.get('src', 'N/A')}</td>
            <td class="monospace">{b.get('dst', 'N/A')}</td>
            <td>{b.get('dport', 'N/A')}</td>
            <td>{b.get('interval_avg_s', 0):.2f}s</td>
            <td>{b.get('cv', 0):.3f}</td>
            <td>{b.get('events', 0)}</td>
            <td class="score">{b.get('score', 0):.2f}</td>
        </tr>
        """

    # Build HTTP URLs list
    urls_list = ""
    for url in http.get("urls", [])[:100]:
        urls_list += f'<li class="url-item"><a href="{url}" target="_blank">{url}</a></li>\n'

    # Build top hosts
    hosts_rows = ""
    for host, count in list(http.get("top_hosts", {}).items())[:20]:
        hosts_rows += f"<tr><td>{host}</td><td>{count}</td></tr>\n"

    # Build DNS queries
    dns_rows = ""
    for query, count in list(dns.get("top_queries", {}).items())[:50]:
        dns_rows += f"<tr><td class='monospace'>{query}</td><td>{count}</td></tr>\n"

    # Build SSL/TLS server names
    ssl_rows = ""
    for server, count in list(ssl.get("top_server_names", {}).items())[:20]:
        ssl_rows += f"<tr><td class='monospace'>{server}</td><td>{count}</td></tr>\n"

    # Build JA3 fingerprints
    ja3_rows = ""
    for ja3, count in list(ssl.get("ja3_fingerprints", {}).items())[:10]:
        ja3_rows += f"<tr><td class='monospace' title='{ja3}'>{ja3[:32]}...</td><td>{count}</td></tr>\n"

    html = f"""<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetHunt Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}

        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}

        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }}

        header p {{
            opacity: 0.9;
            font-size: 1.1em;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }}

        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
            transition: transform 0.2s;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 12px rgba(0,0,0,0.15);
        }}

        .stat-card h3 {{
            color: #667eea;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }}

        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }}

        .content {{
            padding: 40px;
        }}

        .section {{
            margin-bottom: 50px;
        }}

        .section h2 {{
            color: #667eea;
            font-size: 1.8em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}

        thead {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}

        th {{
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }}

        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }}

        tr:hover {{
            background: #f8f9fa;
        }}

        .monospace {{
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            background: #f1f3f5;
            padding: 2px 6px;
            border-radius: 4px;
        }}

        .score {{
            font-weight: bold;
            color: #e74c3c;
        }}

        .url-item {{
            padding: 8px;
            margin: 5px 0;
            background: #f8f9fa;
            border-left: 3px solid #667eea;
            list-style: none;
            border-radius: 4px;
        }}

        .url-item a {{
            color: #667eea;
            text-decoration: none;
            word-break: break-all;
        }}

        .url-item a:hover {{
            text-decoration: underline;
        }}

        .alert {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }}

        .alert.danger {{
            background: #f8d7da;
            border-left-color: #dc3545;
        }}

        .alert.success {{
            background: #d4edda;
            border-left-color: #28a745;
        }}

        .grid-2 {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
        }}

        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: 1fr;
            }}

            .grid-2 {{
                grid-template-columns: 1fr;
            }}

            header h1 {{
                font-size: 1.8em;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 NetHunt Analysis Report</h1>
            <p>Advanced PCAP Network Traffic Analysis</p>
            <p style="font-size: 0.9em; margin-top: 10px;">Generated: {data.get('generated_at', 'N/A')}</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Files</h3>
                <div class="value">{stats.get('total_files', 0)}</div>
            </div>
            <div class="stat-card">
                <h3>HTTP Requests</h3>
                <div class="value">{stats.get('total_http_requests', 0)}</div>
            </div>
            <div class="stat-card">
                <h3>DNS Queries</h3>
                <div class="value">{stats.get('total_dns_queries', 0)}</div>
            </div>
            <div class="stat-card">
                <h3>TLS Connections</h3>
                <div class="value">{stats.get('total_ssl_connections', 0)}</div>
            </div>
            <div class="stat-card">
                <h3>Unique URLs</h3>
                <div class="value">{stats.get('unique_urls', 0)}</div>
            </div>
            <div class="stat-card">
                <h3>Beacons Detected</h3>
                <div class="value">{stats.get('total_beacons', 0)}</div>
            </div>
        </div>

        <div class="content">
            <!-- Beaconing Section -->
            {f'''
            <div class="section">
                <h2>🚨 Beaconing Detection (Malware C2)</h2>
                <div class="alert danger">
                    <strong>⚠️ Warning:</strong> {len(beacons)} potential beacon(s) detected. This may indicate Command & Control (C2) activity.
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Port</th>
                            <th>Avg Interval</th>
                            <th>CV</th>
                            <th>Events</th>
                            <th>Score</th>
                        </tr>
                    </thead>
                    <tbody>
                        {beacons_rows if beacons_rows else '<tr><td colspan="7" style="text-align:center;">No beaconing detected</td></tr>'}
                    </tbody>
                </table>
            </div>
            ''' if beacons else ''}

            <!-- Extracted Files Section -->
            <div class="section">
                <h2>📁 Extracted Files ({len(files)} unique files)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Source</th>
                            <th>Filename</th>
                            <th>Size</th>
                            <th>SHA256</th>
                            <th>Type</th>
                        </tr>
                    </thead>
                    <tbody>
                        {files_rows if files_rows else '<tr><td colspan="5" style="text-align:center;">No files extracted</td></tr>'}
                    </tbody>
                </table>
            </div>

            <!-- HTTP Analysis Section -->
            <div class="section">
                <h2>🌐 HTTP Traffic Analysis</h2>

                <div class="grid-2">
                    <div>
                        <h3 style="margin: 20px 0 10px 0;">Top Hosts ({len(http.get('top_hosts', {}))} unique)</h3>
                        <table>
                            <thead>
                                <tr><th>Host</th><th>Requests</th></tr>
                            </thead>
                            <tbody>
                                {hosts_rows if hosts_rows else '<tr><td colspan="2">No data</td></tr>'}
                            </tbody>
                        </table>
                    </div>

                    <div>
                        <h3 style="margin: 20px 0 10px 0;">HTTP Methods</h3>
                        <table>
                            <thead>
                                <tr><th>Method</th><th>Count</th></tr>
                            </thead>
                            <tbody>
                                {''.join(f'<tr><td>{m}</td><td>{c}</td></tr>' for m, c in http.get('methods', {}).items()) if http.get('methods') else '<tr><td colspan="2">No data</td></tr>'}
                            </tbody>
                        </table>
                    </div>
                </div>

                <h3 style="margin: 30px 0 10px 0;">URLs Discovered ({len(http.get('urls', []))})</h3>
                <ul style="max-height: 400px; overflow-y: auto;">
                    {urls_list if urls_list else '<li>No URLs found</li>'}
                </ul>
            </div>

            <!-- DNS Analysis Section -->
            <div class="section">
                <h2>🔎 DNS Analysis</h2>
                <h3 style="margin: 20px 0 10px 0;">Top DNS Queries ({dns.get('queries_count', 0)} total)</h3>
                <table>
                    <thead>
                        <tr><th>Query</th><th>Count</th></tr>
                    </thead>
                    <tbody>
                        {dns_rows if dns_rows else '<tr><td colspan="2">No DNS queries</td></tr>'}
                    </tbody>
                </table>
            </div>

            <!-- TLS/SSL Analysis Section -->
            <div class="section">
                <h2>🔒 TLS/SSL Analysis</h2>

                <div class="grid-2">
                    <div>
                        <h3 style="margin: 20px 0 10px 0;">Server Names ({ssl.get('connections_count', 0)} connections)</h3>
                        <table>
                            <thead>
                                <tr><th>Server Name</th><th>Count</th></tr>
                            </thead>
                            <tbody>
                                {ssl_rows if ssl_rows else '<tr><td colspan="2">No TLS connections</td></tr>'}
                            </tbody>
                        </table>
                    </div>

                    <div>
                        <h3 style="margin: 20px 0 10px 0;">JA3 Fingerprints</h3>
                        <table>
                            <thead>
                                <tr><th>JA3 Hash</th><th>Count</th></tr>
                            </thead>
                            <tbody>
                                {ja3_rows if ja3_rows else '<tr><td colspan="2">No JA3 data</td></tr>'}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div class="alert success">
                <strong>✅ Analysis Complete</strong><br>
                PCAP File: {data.get('pcap', 'N/A')}<br>
                Size: {format_bytes(data.get('pcap_size', 0))}<br>
                All extracted files are located in the output directory.
            </div>
        </div>
    </div>
</body>
</html>"""

    return html

# ---------- core ----------
def analyze(pcap, outdir, chunk=None):
    pcap_path = pathlib.Path(pcap).expanduser().resolve()
    ensure_file_readable(pcap_path, "PCAP")
    OUT = pathlib.Path(outdir).expanduser().resolve()
    safe_mkdir(OUT)

    # Check tools availability
    use_zeek = USE_DOCKER_ZEEK
    if use_zeek:
        if not check_docker():
            print("[WARN] Docker not available, Zeek analysis will be skipped")
            print("[INFO] Install Docker: sudo ./install-tools.sh")
            use_zeek = False
        elif not check_zeek_docker_image():
            print(f"[INFO] Zeek Docker image not found, pulling {ZEEK_DOCKER_IMAGE}...")
            use_zeek = check_zeek_docker_image()  # Will attempt to pull
        if use_zeek:
            print(f"[INFO] Using Zeek via Docker: {ZEEK_DOCKER_IMAGE}")

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
    all_http_data = {"requests": [], "urls": set(), "methods": Counter(), "status_codes": Counter(), "hosts": Counter(), "user_agents": Counter()}
    all_dns_data = {"queries": [], "query_names": Counter(), "query_types": Counter()}
    all_ssl_data = {"connections": [], "server_names": Counter(), "ja3": Counter(), "versions": Counter()}

    # loop pcaps
    for idx, p in enumerate(pcaps, 1):
        print(f"[INFO] Elaboro {p} ({idx}/{len(pcaps)})")
        work = OUT / f"work_{idx}"
        safe_mkdir(work)
        p_abs = str(pathlib.Path(p).resolve())

        # --- ZEEK (JSON + files via Docker) ---
        if use_zeek:
            pcap_to_analyze = pathlib.Path(p_abs)
            if not run_zeek_docker(pcap_to_analyze, work):
                print(f"[WARN] Zeek Docker execution failed")
        else:
            print("[WARN] Skip Zeek (Docker not available)")

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

        # --- PARSE HTTP log ---
        http_log = work / "http.log"
        if http_log.exists():
            print("[INFO] Parsing HTTP traffic...")
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

        # --- PARSE DNS log ---
        dns_log = work / "dns.log"
        if dns_log.exists():
            print("[INFO] Parsing DNS queries...")
            dns_data = parse_dns_log(dns_log)
            all_dns_data["queries"].extend(dns_data["queries"])
            for k, v in dns_data["query_names"].items():
                all_dns_data["query_names"][k] += v
            for k, v in dns_data["query_types"].items():
                all_dns_data["query_types"][k] += v

        # --- PARSE SSL log ---
        ssl_log = work / "ssl.log"
        if ssl_log.exists():
            print("[INFO] Parsing TLS/SSL connections...")
            ssl_data = parse_ssl_log(ssl_log)
            all_ssl_data["connections"].extend(ssl_data["connections"])
            for k, v in ssl_data["server_names"].items():
                all_ssl_data["server_names"][k] += v
            for k, v in ssl_data["ja3"].items():
                all_ssl_data["ja3"][k] += v
            for k, v in ssl_data["versions"].items():
                all_ssl_data["versions"][k] += v

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

    # --- DEDUPLICATE FILES ---
    print("[INFO] Deduplicating files...")
    files_list = deduplicate_files(files_list)

    # --- PREPARE REPORT DATA ---
    http_report = {
        "urls": sorted(all_http_data["urls"]),
        "requests_count": len(all_http_data["requests"]),
        "methods": dict(all_http_data["methods"].most_common()),
        "status_codes": dict(all_http_data["status_codes"].most_common()),
        "top_hosts": dict(all_http_data["hosts"].most_common(20)),
        "top_user_agents": dict(all_http_data["user_agents"].most_common(10)),
        "requests": all_http_data["requests"][:100]  # Limit to first 100 for JSON
    }

    dns_report = {
        "queries_count": len(all_dns_data["queries"]),
        "top_queries": dict(all_dns_data["query_names"].most_common(50)),
        "query_types": dict(all_dns_data["query_types"].most_common()),
        "queries": all_dns_data["queries"][:100]  # Limit to first 100
    }

    ssl_report = {
        "connections_count": len(all_ssl_data["connections"]),
        "top_server_names": dict(all_ssl_data["server_names"].most_common(20)),
        "ja3_fingerprints": dict(all_ssl_data["ja3"].most_common(10)),
        "tls_versions": dict(all_ssl_data["versions"].most_common()),
        "connections": all_ssl_data["connections"][:100]  # Limit to first 100
    }

    # --- REPORT ---
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pcap": str(pcap_path),
        "pcap_size": pcap_path.stat().st_size,
        "beaconing": beacons,
        "files": files_list,
        "http": http_report,
        "dns": dns_report,
        "ssl": ssl_report,
        "statistics": {
            "total_files": len(files_list),
            "total_beacons": len(beacons),
            "total_http_requests": len(all_http_data["requests"]),
            "total_dns_queries": len(all_dns_data["queries"]),
            "total_ssl_connections": len(all_ssl_data["connections"]),
            "unique_urls": len(all_http_data["urls"]),
            "unique_domains": len(all_dns_data["query_names"])
        }
    }

    # Save JSON report
    (OUT / "report.json").write_text(json.dumps(report, indent=2))

    # Generate HTML report
    print("[INFO] Generating HTML report...")
    html_report = generate_html_report(report)
    (OUT / "report.html").write_text(html_report)

    print(f"[OK] Output in: {OUT}")
    print(" - report.json")
    print(" - report.html")
    print(" - files estratti nei sottodir work_*/")

# ---------- cli ----------
def main():
    ap = argparse.ArgumentParser(
        description="NetHunt: Advanced PCAP analysis with beaconing detection, file extraction, and comprehensive reporting",
        epilog="Zeek runs via Docker for easy deployment on Kali Linux. Ensure Docker is installed: sudo ./install-tools.sh"
    )
    ap.add_argument("pcap", help="Path to PCAP file to analyze")
    ap.add_argument("-o", "--out", default="out", help="Output directory (default: out)")
    ap.add_argument("--chunk", type=int, default=None, help="Split PCAP into chunks of N packets (requires editcap)")
    args = ap.parse_args()
    analyze(args.pcap, args.out, chunk=args.chunk)

if __name__ == "__main__":
    main()
