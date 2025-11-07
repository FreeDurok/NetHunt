"""
Beaconing detection module
"""

import statistics
from typing import Dict, List, Tuple
from collections import defaultdict

from .config import BEACONING_MIN_EVENTS, BEACONING_MIN_SCORE, BEACONING_MAX_CV, BEACONING_MIN_INTERVAL


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
