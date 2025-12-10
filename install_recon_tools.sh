#!/usr/bin/env bash
set -euo pipefail

# ---- SUDO təyin et ----
if [[ "$EUID" -ne 0 ]]; then
    SUDO="sudo"
else
    SUDO=""
fi

echo "[*] Paketlər yenilənir..."
$SUDO apt update -y

echo "[*] Lazımi paketlər quraşdırılır..."
$SUDO apt install -y golang-go python3 python3-pip git curl jq gospider

# ---- GO konfiqurasiya ----
export GO111MODULE=on
if [[ -z "${GOPATH:-}" ]]; then
    export GOPATH="$HOME/go"
fi
mkdir -p "$GOPATH/bin"
export PATH="$PATH:$GOPATH/bin"

echo "[*] Go alətləri quraşdırılır (subfinder, httpx, katana, waybackurls, ffuf, nuclei)..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "[*] Python alətləri quraşdırılır (LinkFinder, Shodan, Censys)..."
python3 -m pip install --upgrade pip
python3 -m pip install linkfinder shodan censys

# ---- SecretFinder ----
if [[ ! -d "$HOME/SecretFinder" ]]; then
    echo "[*] SecretFinder klonlanır..."
    git clone https://github.com/m4ll0k/SecretFinder.git "$HOME/SecretFinder"
    python3 -m pip install -r "$HOME/SecretFinder/requirements.txt"
else
    echo "[*] SecretFinder artıq mövcuddur, skip."
fi

# ---- ParamSpider ----
if [[ ! -d "$HOME/ParamSpider" ]]; then
    echo "[*] ParamSpider klonlanır..."
    git clone https://github.com/devanshbatham/ParamSpider.git "$HOME/ParamSpider"
    python3 -m pip install -r "$HOME/ParamSpider/requirements.txt"
    # paramspider komandasını PATH-ə link edək
    $SUDO ln -sf "$HOME/ParamSpider/paramspider.py" /usr/local/bin/paramspider
    $SUDO chmod +x /usr/local/bin/paramspider
else
    echo "[*] ParamSpider artıq mövcuddur, skip."
fi

echo "[*] Nuclei templatelər yenilənir..."
nuclei -update-templates || true

echo
echo "===================================="
echo "  Bütün recon alətləri quraşdırıldı!"
echo "===================================="
echo
echo "Əlavə olaraq PATH-a bunu əlavə elə (əgər yoxdursa):"
echo "  export GOPATH=\$HOME/go"
echo "  export PATH=\$PATH:\$GOPATH/bin"
echo
echo "Sonra terminalı bağla-aç və belə test et:"
echo "  subfinder -h"
echo "  httpx -h"
echo "  katana -h"
echo "  waybackurls -h"
echo "  ffuf -h"
echo "  nuclei -h"
