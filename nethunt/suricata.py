"""
Suricata configuration and execution module
"""

import pathlib
import subprocess


def write_minimal_suricata_yaml(cfg_path: pathlib.Path):
    """Write minimal Suricata configuration for EVE logging"""
    cfg_path.write_text("""%YAML 1.1
---
default-log-dir: .
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            enabled: yes
        - http:
            enabled: yes
            extended: yes
        - dns:
            enabled: yes
        - tls:
            enabled: yes
        - files:
            enabled: yes
            force-magic: yes
            force-hash: [sha256]
        - smtp:
            enabled: yes
        - ssh:
            enabled: yes
        - flow:
            enabled: yes

file-store:
  enabled: yes
  log-dir: files
  force-filestore: yes
  force-hash: [sha256]
""")


def run_suricata(pcap_path: str, output_dir: pathlib.Path, config_path: pathlib.Path) -> bool:
    """Run Suricata on PCAP file"""
    try:
        # Test config
        subprocess.run(["suricata", "-T", "-c", str(config_path), "-l", str(output_dir)],
                     check=True, capture_output=True, text=True)
        # Run analysis
        subprocess.run(["suricata", "-r", pcap_path, "-l", str(output_dir), "-k", "none", "-c", str(config_path)],
                     check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError:
        return False
