#!/usr/bin/env bash
# setup.sh - deps + optional capability untuk netcut-linux
set -euo pipefail

cd "$(dirname "$0")"

say() { printf '\n\033[1;36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$1"; }

say "Cek dependency Python"
if python3 -c "import scapy" 2>/dev/null; then
    echo "    scapy: OK ($(python3 -c 'import scapy;print(scapy.__version__)'))"
else
    warn "scapy belum ada. Install dengan: sudo dnf install python3-scapy"
    exit 1
fi

if [ -r /usr/share/hwdata/oui.txt ]; then
    echo "    oui.txt: OK"
else
    warn "oui.txt tidak ada, lookup vendor akan mengembalikan 'unknown'"
fi

if ! command -v nft >/dev/null; then
    warn "nftables tidak ditemukan. Install dengan: sudo dnf install nftables"
fi

say "Build launcher (opsional, biar tidak perlu password sudo tiap run)"
if command -v gcc >/dev/null; then
    gcc -O2 -Wall -o netcut-launcher launcher.c
    echo "    binary: netcut-launcher"
    if command -v setcap >/dev/null; then
        echo "    untuk aktifkan capability, jalankan:"
        echo "      sudo setcap cap_net_raw+ep ./netcut-launcher"
    fi
else
    warn "gcc tidak ada, launcher dilewati (pakai sudo langsung)"
fi

say "Jalankan test"
python3 test_parser.py

cat <<'EOF'

Selesai. Cara pakai:

  sudo ./netcut.py                  monitor real-time
  sudo ./netcut.py --once           snapshot sekali
  sudo ./netcut.py --json           output JSON
  sudo ./netcut.py --scan           ARP scan
  sudo ./netcut.py --block <ip>     blokir host
  sudo ./netcut.py --limit <ip> <kbps>  batasi bandwidth

Detail lengkap: ./README.md
EOF
