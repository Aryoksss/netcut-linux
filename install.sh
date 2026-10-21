#!/usr/bin/env bash
# install.sh - pasang netcut-linux sebagai aplikasi Linux native (user level)
#
# Yang dipasang:
#   ~/.local/bin/netcut              launcher (bisa dipanggil dari mana saja)
#   ~/.local/share/applications/netcut.desktop   entry app menu
#   ~/.local/share/icons/hicolor/scalable/apps/netcut.svg   icon
#   ~/.config/autostart/netcut.desktop           autostart (opsional)
#
# Tidak butuh root (kecuali pakai --with-deps untuk memasang dependency).
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
AUTO_DIR="$HOME/.config/autostart"
BASE="http://127.0.0.1:${NETCUT_PORT:-8080}"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$1"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$1"; }
err()  { printf '\033[1;31m[x]\033[0m %s\n' "$1"; }

# ---------------------------------------------------------------- dependency
# Tanpa scapy + nftables netcut tidak bisa jalan sama sekali, jadi dicek
# dulu sebelum memasang launcher.
MISSING=()
check_deps() {
    say "Cek dependency"
    if python3 -c "import scapy" 2>/dev/null; then
        ok "scapy: OK"
    else
        MISSING+=("scapy")
        warn "scapy belum ada - wajib (capture paket & ARP scan)"
    fi
    if command -v nft >/dev/null; then
        ok "nftables: OK"
    else
        MISSING+=("nftables")
        warn "nftables belum ada - wajib (blokir & limit)"
    fi
    if [ -r /usr/share/hwdata/oui.txt ]; then
        ok "database OUI: OK"
    else
        warn "database OUI belum ada - hanya vendor yang tidak terbaca"
    fi
}

# perintah pasang dependency per distro
pkg_cmd() {
    if command -v dnf >/dev/null; then
        echo "sudo dnf install -y python3-scapy nftables hwdata"
    elif command -v apt-get >/dev/null; then
        echo "sudo apt-get install -y python3-scapy nftables hwdata"
    elif command -v pacman >/dev/null; then
        echo "sudo pacman -S --needed python-scapy nftables hwdata"
    else
        echo "install python3-scapy, nftables, dan hwdata sesuai distromu"
    fi
}

if [[ "${1:-}" == "--with-deps" ]]; then
    check_deps
    if [ ${#MISSING[@]} -gt 0 ]; then
        say "Memasang dependency"
        # shellcheck disable=SC2046
        $(pkg_cmd) || true
        check_deps
    fi
    shift
fi

if [[ "${1:-}" != "--skip-deps" ]]; then
    check_deps
    if [ ${#MISSING[@]} -gt 0 ]; then
        err "dependency belum lengkap. Yang perlu dijalankan:"
        echo "    $(pkg_cmd)"
        echo
        echo "Atau pasang semuanya sekaligus:  sudo $0 --with-deps"
        echo
        echo "Lanjut pasang tanpa dependency? (netcut --doctor bisa cek nanti)"
        printf "[y/N] "
        read -r ans || true
        if [[ "${ans,,}" != "y" ]]; then
            err "dibatalkan"
            exit 1
        fi
    fi
fi

say "Membuat direktori"
mkdir -p "$BIN_DIR" "$APP_DIR" "$ICON_DIR" "$AUTO_DIR"

# ---------------------------------------------------------------- launcher
say "Memasang launcher ke $BIN_DIR/netcut"
cat > "$BIN_DIR/netcut" <<EOF
#!/usr/bin/env bash
# netcut - launcher aplikasi
exec python3 "$SRC/netcut_app.py" "\$@"
EOF
chmod +x "$BIN_DIR/netcut"
ok "launcher terpasang"

# ---------------------------------------------------------------- icon
say "Memasang icon"
cp "$SRC/netcut.svg" "$ICON_DIR/netcut.svg"
ok "icon terpasang ($ICON_DIR/netcut.svg)"

# ---------------------------------------------------------------- desktop entry
say "Memasang entry app menu"
cat > "$APP_DIR/netcut.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=NetCut
GenericName=Network Bandwidth Monitor
Comment=Pantau & batasi bandwidth perangkat di jaringan lokal
Exec=$BIN_DIR/netcut
Icon=netcut
Terminal=false
Categories=Network;Monitor;
Keywords=network;bandwidth;monitor;block;limit;wifi;
StartupNotify=true
StartupWMClass=netcut
EOF
chmod +x "$APP_DIR/netcut.desktop"
ok "entry app menu terpasang"

# entry tambahan: tray only (tanpa membuka browser)
cat > "$APP_DIR/netcut-tray.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=NetCut (System Tray)
GenericName=Network Monitor Tray
Comment=Jalankan NetCut di system tray saja
Exec=$BIN_DIR/netcut --tray
Icon=netcut
Terminal=false
Categories=Network;Monitor;
NoDisplay=false
StartupNotify=true
EOF
chmod +x "$APP_DIR/netcut-tray.desktop"
ok "entry tray-only terpasang"

# ---------------------------------------------------------------- autostart
if [[ "${1:-}" == "--autostart" ]]; then
    say "Memasang autostart"
    cat > "$AUTO_DIR/netcut.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=NetCut
Exec=$BIN_DIR/netcut --tray
Icon=netcut
Terminal=false
X-GNOME-Autostart-enabled=true
NoDisplay=false
EOF
    ok "autostart terpasang"
else
    say "Autostart dilewati (jalankan ulang dengan --autostart untuk mengaktifkan)"
fi

# ---------------------------------------------------------------- desktop database
if command -v update-desktop-database >/dev/null; then
    update-desktop-database "$APP_DIR" 2>/dev/null || true
    ok "database app menu diperbarui"
fi

# ---------------------------------------------------------------- icon cache
if command -v gtk-update-icon-cache >/dev/null; then
    gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
fi

say "Selesai!"

# ---------------------------------------------------------------- PATH
# Tanpa ini user harus mengetik path penuh setiap kali mau jalan.
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    warn "$BIN_DIR belum ada di PATH"
    RC="$HOME/.bashrc"
    if [[ -f "$RC" ]] && grep -qF "$BIN_DIR" "$RC"; then
        ok "sudah tercatat di $RC"
    else
        printf "Tambahkan ke %s sekarang? [Y/n] " "$RC"
        read -r ans || true
        if [[ "${ans,,}" != "n" ]]; then
            {
                printf '\n# netcut-linux launcher\n'
                printf 'export PATH="$HOME/.local/bin:$PATH"\n'
            } >> "$RC"
            ok "PATH ditambahkan ke $RC"
            echo "    (terminal baru / source $RC agar berlaku sekarang)"
        else
            warn "tambahkan manual: export PATH=\"\$HOME/.local/bin:\$PATH\""
        fi
    fi
fi

cat <<EOF

  Launcher      : $BIN_DIR/netcut
  App menu      : cari "NetCut" di menu aplikasi
  Icon          : $ICON_DIR/netcut.svg

  Langkah berikutnya:
    netcut --doctor     cek environment (dependency, hak akses, mode)
    netcut              buka dashboard web + system tray
    netcut --status     cek server
    netcut --stop       hentikan server

  Dashboard     : $BASE
EOF

