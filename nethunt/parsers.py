"""
Log parsing functions for Zeek logs
"""

import json
import pathlib
from collections import Counter
from typing import Dict, Any, List


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
            # Skip if _path exists and is not http (for compatibility)
            if "_path" in r and r.get("_path") != "http":
                continue

            method = r.get("method", "")
            host = r.get("host", "")
            uri = r.get("uri", "")
            status = r.get("status_code")
            user_agent = r.get("user_agent", "")

            # Determine protocol based on port
            port = r.get("id.resp_p", 80)
            protocol = "https" if port == 443 else "http"

            # Build URL - handle hosts that already include port
            if host and uri:
                # Remove port from host if it's already there (format: host:port)
                if ":" in host:
                    host_clean = host.split(":")[0]
                    # Use the port from the host field if present
                    if len(host.split(":")) > 1:
                        try:
                            port = int(host.split(":")[1])
                            protocol = "https" if port == 443 else "http"
                        except:
                            pass
                    host = host_clean

                # Build URL with proper protocol
                if port in [80, 443]:
                    # Standard ports - don't include in URL
                    url = f"{protocol}://{host}{uri}"
                else:
                    # Non-standard port - include it
                    url = f"{protocol}://{host}:{port}{uri}"

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
            # Skip if _path exists and is not dns (for compatibility)
            if "_path" in r and r.get("_path") != "dns":
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
            # Skip if _path exists and is not ssl (for compatibility)
            if "_path" in r and r.get("_path") != "ssl":
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
