#!/usr/bin/env bash
set -euo pipefail

services=false
case "${1:-}" in
    '') ;;
    --services) services=true ;;
    *) echo "Usage: $0 [--services]" >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || { echo "Usage: $0 [--services]" >&2; exit 2; }

source /etc/os-release
[[ "$ID" == kali && "$(uname -m)" == x86_64 ]] || { echo 'Run this on Kali Linux amd64.' >&2; exit 1; }
[[ "$EUID" -ne 0 ]] || { echo 'Run as your normal user; package installation uses sudo.' >&2; exit 1; }

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
data=${TEAMTOOLS_HOME:-$HOME/.local/share/teamtools}
data=$(realpath -m "$data")
bin=$HOME/.local/bin
export TEAMTOOLS_HOME="$data"
export PATH="$bin:$PATH"
export GOBIN="$bin"
case "$data/" in "$root/"*) echo 'TEAMTOOLS_HOME must be outside the repo.' >&2; exit 1;; esac
mkdir -p "$data/src" "$data/tools" "$bin"

sudo apt-get update
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates curl git python3-venv python3-dev pipx build-essential \
    libssl-dev libffi-dev pkg-config golang-go tmux perl gawk file unzip \
    util-linux util-linux-extra jq nmap smbclient ldap-utils dnsutils snmp onesixtyone \
    nfs-common default-mysql-client postgresql-client freerdp3-x11 \
    krb5-user proxychains4 socat netcat-openbsd hashcat john wordlists \
    seclists enum4linux-ng responder ruby ruby-dev libkrb5-dev libreadline-dev \
    chromium gowitness nuclei ffuf feroxbuster whatweb oathtool sqlmap rustscan \
    mitm6 penelope mono-devel docker.io docker-compose

clone() {
    [[ -d "$data/src/$2/.git" ]] || git clone --depth 1 "https://github.com/$1.git" "$data/src/$2"
}

python_tool() {
    local repo=$1 name=$2 script=$3
    clone "$repo" "$name"
    local src="$data/src/$name"
    [[ -x "$src/.venv/bin/python" ]] || python3 -m venv "$src/.venv"
    [[ ! -f "$src/requirements.txt" ]] || "$src/.venv/bin/python" -m pip install -r "$src/requirements.txt"
    shift 3
    [[ $# -eq 0 ]] || "$src/.venv/bin/python" -m pip install "$@"
    printf '#!/usr/bin/env bash\nset -e\ncd %q\nexec %q %q "$@"\n' "$src" "$src/.venv/bin/python" "$src/$script" > "$bin/$name"
    chmod +x "$bin/$name"
}

pip_tool() {
    command -v "$1" >/dev/null 2>&1 || pipx install "$2"
}

fetch() {
    local temporary
    temporary=$(mktemp "$data/tools/.download.XXXXXX")
    if curl -fL --retry 3 "$1" -o "$temporary"; then
        mv "$temporary" "$2"
    else
        rm -f "$temporary"
        return 1
    fi
}

clone gpakosz/.tmux oh-my-tmux
if [[ -e "$HOME/.tmux.conf" || -L "$HOME/.tmux.conf" ]]; then
    config=$HOME
    main=$config/.tmux.conf
    local_config=$config/.tmux.conf.local
else
    config=${XDG_CONFIG_HOME:-$HOME/.config}/tmux
    main=$config/tmux.conf
    local_config=$config/tmux.conf.local
fi
mkdir -p "$config"
if [[ "$(readlink -f "$main" 2>/dev/null || true)" != "$data/src/oh-my-tmux/.tmux.conf" ]]; then
    [[ ! -e "$main" && ! -L "$main" ]] || mv "$main" "$main.$(date -u +%Y%m%dT%H%M%S%N).bak"
    ln -s "$data/src/oh-my-tmux/.tmux.conf" "$main"
fi
[[ -e "$local_config" || -L "$local_config" ]] || cp "$root/Tmux/tmux.conf.local" "$local_config"

pip_tool nxc git+https://github.com/Pennyw0rth/NetExec.git
pip_tool secretsdump.py impacket
pip_tool certipy certipy-ad
pip_tool bloodyAD bloodyAD
pip_tool bloodhound-ce-python bloodhound-ce
pip_tool git-dumper git-dumper
pip_tool dirsearch dirsearch
pip_tool manspider man-spider
sharphound_url=$(curl -fsSL --retry 3 https://api.github.com/repos/SpecterOps/SharpHound/releases/tags/v2.17.1 | jq -er '[.assets[] | select(.name == "SharpHound_v2.17.1_windows_x86.zip") | .browser_download_url] | if length == 1 then .[0] else error("SharpHound asset not found") end')
fetch "$sharphound_url" "$data/tools/sharphound.zip"
unzip -o "$data/tools/sharphound.zip" -d "$data/tools/sharphound"
rm "$data/tools/sharphound.zip"
if ! command -v evil-winrm >/dev/null 2>&1; then
    gem install evil-winrm --no-document --install-dir "$data/gems" --bindir "$data/gems/bin"
    printf '#!/usr/bin/env bash\nexport GEM_HOME=%q\nexport GEM_PATH=%q\nexec %q "$@"\n' "$data/gems" "$data/gems" "$data/gems/bin/evil-winrm" > "$bin/evil-winrm"
    chmod +x "$bin/evil-winrm"
fi
command -v kerbrute >/dev/null 2>&1 || go install github.com/ropnop/kerbrute@v1.0.3
(cd "$root/corkboard/dist" && sha256sum --check --ignore-missing --quiet SHA256SUMS)
install -m 755 "$root/corkboard/dist/cork_linux_amd64" "$bin/cork"

python_tool ShutdownRepo/targetedKerberoast targetedKerberoast targetedKerberoast.py
python_tool vladko312/SSTImap sstimap sstimap.py
python_tool garrettfoster13/sccmhunter sccmhunter sccmhunter.py
python_tool dirkjanm/krbrelayx krbrelayx krbrelayx.py impacket dnspython ldap3 pycryptodome
python_tool dirkjanm/PKINITtools gettgtpkinit gettgtpkinit.py impacket minikerberos
for script in getnthash gets4uticket; do
    printf '#!/usr/bin/env bash\nexec %q %q "$@"\n' "$data/src/gettgtpkinit/.venv/bin/python" "$data/src/gettgtpkinit/$script.py" > "$bin/$script"
    chmod +x "$bin/$script"
done
for script in printerbug dnstool addspn; do
    printf '#!/usr/bin/env bash\nexec %q %q "$@"\n' "$data/src/krbrelayx/.venv/bin/python" "$data/src/krbrelayx/$script.py" > "$bin/$script"
    chmod +x "$bin/$script"
done

fetch https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 "$data/tools/pspy64"
fetch https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64s "$data/tools/pspy64s"
fetch https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh "$data/tools/linpeas.sh"
fetch https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe "$data/tools/winPEASx64.exe"
chmod +x "$data/tools/pspy64" "$data/tools/pspy64s" "$data/tools/linpeas.sh"
ln -sfn "$data/tools/pspy64" "$bin/pspy"

fetch https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_windows_amd64.zip "$data/tools/ligolo-windows.zip"
unzip -p "$data/tools/ligolo-windows.zip" agent.exe > "$data/tools/ligolo-agent.exe"
rm "$data/tools/ligolo-windows.zip"
cp "$root/tools/l-agent" "$data/tools/ligolo-agent_linux_amd64"
cp "$root/tools/proxy" "$data/tools/ligolo-proxy"
chmod +x "$data/tools/ligolo-agent_linux_amd64" "$data/tools/ligolo-proxy"
ln -sfn "$data/tools/ligolo-proxy" "$bin/ligolo-proxy"
roslyn=$data/tools/roslyn-4.14.0
if [[ ! -f "$roslyn/.complete" ]]; then
    fetch https://api.nuget.org/v3-flatcontainer/microsoft.net.compilers.toolset/4.14.0/microsoft.net.compilers.toolset.4.14.0.nupkg "$data/tools/roslyn.nupkg"
    mkdir -p "$roslyn"
    unzip -oq "$data/tools/roslyn.nupkg" -d "$roslyn"
    rm "$data/tools/roslyn.nupkg"
    touch "$roslyn/.complete"
fi
for name in Seatbelt SharpUp; do
    clone "GhostPack/$name" "$name"
    xbuild "$data/src/$name/$name.sln" /t:Rebuild /p:Configuration=Release /p:TargetFrameworkVersion=v4.5 \
        /p:CscToolPath="$roslyn/tasks/net472" /p:CscToolExe=csc.exe
    install -m 644 "$data/src/$name/$name/bin/Release/$name.exe" "$data/tools/$name.exe"
done

nuclei -update-templates
python3 "$root/scripts/copyparty.py"

if "$services"; then
    sudo systemctl enable --now docker
    sudo env TEAMTOOLS_HOME="$data" docker compose -f "$root/CopyParty/docker-compose.yaml" up -d
    sudo docker compose -f "$root/CyberChef/compose.yaml" up -d
    "$root/Shells/setup.sh"
    "$root/Bloodhound/setup.sh"
fi
printf '\nTools: %s/tools\nPATH: export PATH="%s:$PATH"\n' "$data" "$bin"
