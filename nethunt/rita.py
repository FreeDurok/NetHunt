"""
RITA (Real Intelligence Threat Analytics) integration module
"""

import pathlib
import subprocess
from .utils import check_bin


def run_rita_import(zeek_logs_dir: pathlib.Path, dataset_name: str) -> bool:
    """
    Import Zeek logs into RITA for threat analysis.

    RITA analyzes Zeek logs to detect:
    - Command & Control (C2) beaconing
    - DNS tunneling
    - Long connections
    - Threat intelligence matches

    Args:
        zeek_logs_dir: Directory containing Zeek log files
        dataset_name: Name for the RITA dataset

    Returns:
        True if import successful, False otherwise
    """
    rita_bin = check_bin("rita")
    if not rita_bin:
        return False

    if not zeek_logs_dir.exists():
        return False

    try:
        # Import Zeek logs into RITA database
        subprocess.run([
            "rita", "import",
            f"--database={dataset_name}",
            f"--logs={str(zeek_logs_dir)}"
        ], check=True, capture_output=True, timeout=600)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False


def run_rita_analysis(dataset_name: str, output_dir: pathlib.Path) -> bool:
    """
    Run RITA analysis and export results to CSV.

    Args:
        dataset_name: Name of the RITA dataset to analyze
        output_dir: Directory to save RITA analysis results

    Returns:
        True if analysis successful, False otherwise
    """
    rita_bin = check_bin("rita")
    if not rita_bin:
        return False

    try:
        # Export RITA results to stdout and save to file
        result = subprocess.run([
            "rita", "view",
            "--stdout",
            dataset_name
        ], check=True, capture_output=True, timeout=300, text=True)

        # Save results to file
        output_file = output_dir / f"rita_analysis_{dataset_name}.csv"
        output_file.write_text(result.stdout)

        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False
