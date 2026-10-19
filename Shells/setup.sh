#!/usr/bin/env bash
set -euo pipefail
directory=${TEAMTOOLS_HOME:-$HOME/.local/share/teamtools}/src/reverse-shell-generator
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
directory=$(realpath -m "$directory")
case "$directory/" in "$root/"*) echo 'TEAMTOOLS_HOME must be outside the repo.' >&2; exit 1;; esac
mkdir -p "$(dirname -- "$directory")"
[[ -d "$directory/.git" ]] || git clone --depth 1 https://github.com/0dayCTF/reverse-shell-generator.git "$directory"
sudo docker build -t reverse_shell_generator "$directory"
sudo docker container inspect reverse-shell-generator >/dev/null 2>&1 || sudo docker create --name reverse-shell-generator -p 3003:80 reverse_shell_generator
sudo docker start reverse-shell-generator
