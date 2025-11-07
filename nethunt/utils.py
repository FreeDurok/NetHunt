"""
Utility functions for NetHunt
"""

import pathlib
import shutil
import os
import sys


def check_bin(name: str) -> str:
    """Check if a binary is available in PATH"""
    return shutil.which(name)


def is_executable(p: pathlib.Path) -> bool:
    """Check if a path is an executable file"""
    try:
        return p.exists() and p.is_file() and os.access(str(p), os.X_OK)
    except Exception:
        return False


def safe_mkdir(p):
    """Create directory if it doesn't exist"""
    pathlib.Path(p).mkdir(parents=True, exist_ok=True)


def ensure_file_readable(p: pathlib.Path, label: str):
    """Ensure a file exists and is readable"""
    if not p.exists() or not p.is_file():
        sys.exit(f"ERROR: {label} not found: {p}")
    if not os.access(str(p), os.R_OK):
        sys.exit(f"ERROR: {label} not readable: {p}")


def format_bytes(size: int) -> str:
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"
