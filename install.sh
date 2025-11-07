#!/usr/bin/env bash
# install_kali_net-hunt.sh — Kali: Docker + Suricata/TShark (no Graphviz), Zeek via container
set -euo pipefail

echo "[*] APT base"
sudo apt update
sudo apt install -y docker.io suricata wireshark-common tshark jq curl ca-certificates

echo "[*] Docker enable"
sudo systemctl enable --now docker || true
sudo usermod -aG docker "$USER" || true

echo "[*] Pull immagine Zeek"
sudo docker pull zeek/zeek:latest

echo "[*] Test binari"
(docker --version || true)
(suricata -V || true)
(tshark -v | head -n1 || true)

echo "[DONE] Riavvia la sessione per usare 'docker' senza sudo."
echo "Esegui: python3 main.py <pcap> -o out"
