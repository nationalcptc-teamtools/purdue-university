#!/usr/bin/env bash
set -euo pipefail
source /etc/os-release
[[ "$ID" == kali ]] || { echo 'Run this on Kali Linux.' >&2; exit 1; }
sudo apt-get update
sudo apt-get install -y docker.io docker-compose
sudo systemctl enable --now docker
