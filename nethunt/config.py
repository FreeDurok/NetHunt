"""
Configuration constants for NetHunt
"""

from typing import Optional

# Docker image for Zeek
ZEEK_DOCKER_IMAGE = "zeek/zeek:latest"

# Set to False to force local Zeek installation
USE_DOCKER_ZEEK = True

# Path to native Zeek installation (if available)
ZEEK_PATH: Optional[str] = "/opt/zeek/bin/zeek"

# Beaconing detection thresholds
BEACONING_MIN_EVENTS = 6
BEACONING_MIN_SCORE = 8
BEACONING_MAX_CV = 0.15
BEACONING_MIN_INTERVAL = 5.0
