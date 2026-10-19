#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export TEAMTOOLS_HOME
TEAMTOOLS_HOME=$(realpath -m "${TEAMTOOLS_HOME:-$HOME/.local/share/teamtools}")
python3 "$root/scripts/copyparty.py"
exec sudo env TEAMTOOLS_HOME="$TEAMTOOLS_HOME" docker compose -f "$root/CopyParty/docker-compose.yaml" up -d
