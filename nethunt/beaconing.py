"""
Beaconing detection module
"""

import statistics
from typing import Dict, List, Tuple
from collections import defaultdict
from urllib.parse import urlparse

from .config import BEACONING_MIN_EVENTS, BEACONING_MIN_SCORE, BEACONING_MAX_CV, BEACONING_MIN_INTERVAL


def detect_http_beacons(http_requests: List[Dict]) -> List[Dict]:
    """
    Detect HTTP-level beaconing activity (C2 communication patterns)

    Args:
        http_requests: List of HTTP request dictionaries with 'url', 'ts', 'method' fields

    Returns:
        List of detected HTTP beacons with scoring information
    """
    # Group requests by host (domain)
    requests_by_host = defaultdict(list)

    for req in http_requests:
        url = req.get("url", "")
        ts = req.get("ts")
        method = req.get("method", "")

        if not url or not ts:
            continue

        try:
            parsed = urlparse(url)
            host = parsed.netloc
            if host:
                requests_by_host[host].append({
                    "ts": float(ts) if isinstance(ts, str) else ts,
                    "url": url,
                    "method": method,
                    "path": parsed.path
                })
        except:
            continue

    beacons = []

    for host, reqs in requests_by_host.items():
        if len(reqs) < BEACONING_MIN_EVENTS:
            continue

        # Sort by timestamp
        reqs.sort(key=lambda x: x["ts"])
        timestamps = [r["ts"] for r in reqs]

        # Calculate intervals
        deltas = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

        if len(deltas) < 5:
            continue

        # Statistical analysis
        mu = statistics.mean(deltas)
        sigma = statistics.pstdev(deltas) if len(deltas) > 1 else 0.0
        cv = (sigma / mu) if mu > 0 else 9e9
        score = len(reqs) * (1.0 / (1.0 + cv))

        # Check if it looks like beaconing (regular intervals)
        if score >= BEACONING_MIN_SCORE and cv <= BEACONING_MAX_CV and mu >= BEACONING_MIN_INTERVAL:
            # Analyze request patterns
            methods = [r["method"] for r in reqs]
            paths = [r["path"] for r in reqs]
            unique_paths = len(set(paths))

            # Check for suspicious indicators
            post_count = methods.count("POST")

            beacons.append({
                "host": host,
                "interval_avg_s": round(mu, 2),
                "cv": round(cv, 3),
                "events": len(reqs),
                "score": round(score, 2),
                "post_requests": post_count,
                "unique_paths": unique_paths,
                "sample_urls": [r["url"] for r in reqs[:3]],  # First 3 URLs as examples
                "methods": list(set(methods))
            })

    beacons.sort(key=lambda x: x["score"], reverse=True)
    return beacons


def detect_beacons(ts_by_pair: Dict[Tuple[str, str, str], List[float]]) -> List[Dict]:
    """
    Detect beaconing activity from connection timestamps

    Args:
        ts_by_pair: Dictionary mapping (src_ip, dst_ip, dst_port) to list of timestamps

    Returns:
        List of detected beacons with scoring information
    """
    beacons = []

    for k, arr in ts_by_pair.items():
        if len(arr) < BEACONING_MIN_EVENTS:
            continue

        arr.sort()
        deltas = [arr[i + 1] - arr[i] for i in range(len(arr) - 1)]

        if len(deltas) < 5:
            continue

        mu = statistics.mean(deltas)
        sigma = statistics.pstdev(deltas) if len(deltas) > 1 else 0.0
        cv = (sigma / mu) if mu > 0 else 9e9
        score = (len(arr)) * (1.0 / (1.0 + cv))

        if score >= BEACONING_MIN_SCORE and cv <= BEACONING_MAX_CV and mu >= BEACONING_MIN_INTERVAL:
            src, dst, dport = k
            beacons.append({
                "src": src,
                "dst": dst,
                "dport": dport,
                "interval_avg_s": round(mu, 2),
                "cv": round(cv, 3),
                "events": len(arr),
                "score": round(score, 2)
            })

    beacons.sort(key=lambda x: x["score"], reverse=True)
    return beacons
