#!/usr/bin/env bash
# cleanup_zeek_build.sh — rimuove toolchain usata per build Zeek e residui
set -euo pipefail

echo "[*] Purge toolchain e lib dev"
sudo apt purge -y build-essential cmake ninja-build pkg-config autoconf automake libtool \
  flex bison zlib1g-dev libpcap0.8-dev libssl-dev python3-dev libmaxminddb-dev \
  libkrb5-dev libjemalloc-dev libgoogle-perftools-dev libcurl4-openssl-dev git || true
sudo apt autoremove -y
sudo apt clean

echo "[*] Rimuovo Zeek locale se presente"
sudo rm -rf /opt/zeek || true
sed -i '/export ZEEK_PATH=.*\/zeek/d' "$HOME/.bashrc" || true

echo "[DONE]"
