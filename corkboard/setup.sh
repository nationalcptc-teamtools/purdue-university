#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ $# -le 1 ]] || { echo "Usage: $0 [engagement-name]" >&2; exit 2; }
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || { echo 'This installer requires Linux amd64.' >&2; exit 1; }
if [[ "$EUID" -ne 0 ]]; then
    exec sudo -- "$root/setup.sh" "$@"
fi
systemctl show-environment >/dev/null
[[ -f "$root/dist/cork_linux_amd64" ]] || { echo 'Missing dist/cork_linux_amd64.' >&2; exit 1; }
(cd "$root/dist" && sha256sum --check --ignore-missing SHA256SUMS)
unit=$root/deploy/cork.service
[[ -f "$unit" ]] || unit=$root/docs/cork.service

getent group cork >/dev/null || groupadd --system cork
id -u cork >/dev/null 2>&1 || useradd --system --gid cork --home-dir /var/lib/cork --no-create-home --shell /usr/sbin/nologin cork
install -m 755 "$root/dist/cork_linux_amd64" /usr/local/bin/cork
install -d -m 700 -o cork -g cork /var/lib/cork
chown -R cork:cork /var/lib/cork
if [[ ! -f /var/lib/cork/server.yaml ]]; then
    runuser -u cork -- /usr/local/bin/cork init --data /var/lib/cork --engagement "${1:-New engagement}"
fi
sed -i 's/^listen: .*/listen: 0.0.0.0:8000/' /var/lib/cork/server.yaml
install -m 644 "$unit" /etc/systemd/system/cork.service
systemctl daemon-reload
systemctl enable cork
systemctl restart cork
systemctl is-active --quiet cork
printf '\nCorkboard: https://<host-ip>:8000\nService: cork.service\nData: /var/lib/cork\n'
