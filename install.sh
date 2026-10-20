#!/usr/bin/env bash
# install.sh - pasang netcut-linux sebagai aplikasi Linux native (user level)
#
# Yang dipasang:
#   ~/.local/bin/netcut              launcher (bisa dipanggil dari mana saja)
#   ~/.local/share/applications/netcut.desktop   entry app menu
#   ~/.local/share/icons/hicolor/scalable/apps/netcut.svg   icon
#   ~/.config/autostart/netcut.desktop           autostart (opsional)
#
# Tidak butuh root.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
AUTO_DIR="$HOME/.config/autostart"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$1"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$1"; }

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
cat <<EOF

  Launcher      : $BIN_DIR/netcut
  App menu      : cari "NetCut" di menu aplikasi
  Icon          : $ICON_DIR/netcut.svg

  Pemakaian:
    netcut              buka web GUI + system tray
    netcut --status     cek server jalan/tidak
    netcut --stop       hentikan server

  GTK launcher  : gtk-launch netcut
EOF

# cek PATH
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    warn "$BIN_DIR belum ada di PATH. Tambahkan ke ~/.bashrc:"
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
fi
