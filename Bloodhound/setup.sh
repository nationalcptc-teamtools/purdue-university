#!/usr/bin/env bash
set -euo pipefail
bin=$HOME/.local/bin
mkdir -p "$bin"
archive=$(mktemp)
trap 'rm -f "$archive"' EXIT
curl -fL --retry 3 https://github.com/SpecterOps/bloodhound-cli/releases/download/v0.2.1/bloodhound-cli-linux-amd64.tar.gz -o "$archive"
tar -xzf "$archive" -C "$bin" bloodhound-cli
sudo systemctl enable --now docker
sudo usermod -aG docker "$(id -un)"
action=install
[[ ! -f "${XDG_CONFIG_HOME:-$HOME/.config}/bloodhound/docker-compose.yml" ]] || action=up
printf -v command '%q %s' "$bin/bloodhound-cli" "$action"
sg docker -c "$command"
