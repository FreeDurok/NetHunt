"""
Report generation module (HTML and JSON)
"""

from typing import Dict, Any
from .utils import format_bytes


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
