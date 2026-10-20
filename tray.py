"""System tray icon untuk netcut-linux (GTK3 + AppIndicator3).

AppIndicator3 dipakai karena tray di Wayland (niri) hanya bisa lewat
protokol AppIndicator, bukan XEmbed. GTK3 dipakai karena binding
AppIndicator3 tidak tersedia untuk GTK4.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("AppIndicator3", "0.1")
from gi.repository import AppIndicator3, GLib, Gtk  # noqa: E402

PORT = int(os.environ.get("NETCUT_PORT", "8080"))
BASE = f"http://127.0.0.1:{PORT}"
ICON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netcut.svg")


def api(path: str, body: dict | None = None) -> dict:
    try:
        if body is None:
            req = urllib.request.Request(f"{BASE}{path}")
        else:
            req = urllib.request.Request(
                f"{BASE}{path}",
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}


def notify(title: str, body: str) -> None:
    try:
        subprocess.run(["notify-send", "-a", "netcut", title, body],
                       capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass


class TrayIcon:
    def __init__(self, server, open_dashboard):
        self.server = server
        self.open_dashboard = open_dashboard
        self.indicator = None
        self._last_net = None
        self._last_blocked = set()

    # -- menu actions --------------------------------------------------
    def act_scan(self, *_a):
        api("/api/scan", {})
        notify("netcut", "Scan ARP dimulai…")

    def act_rules(self, *_a):
        r = api("/api/rules")
        rules = r.get("rules", "")
        if not rules.strip():
            rules = "(tidak ada aturan aktif)"
        _show_text("Aturan nftables", rules)

    def act_unblock_all(self, *_a):
        snap = api("/api/hosts")
        for ip in snap.get("blocked", []):
            api("/api/unblock", {"ip": ip})
        for ip in snap.get("limited", {}):
            api("/api/unlimit", {"ip": ip})
        notify("netcut", "Semua blokir/limit dilepas")

    def act_quit(self, *_a):
        notify("netcut", "netcut dihentikan")
        try:
            self.server.stop()
        except Exception:
            pass
        Gtk.main_quit()

    # -- monitoring ----------------------------------------------------
    def _watch(self):
        while True:
            try:
                snap = api("/api/hosts")
                if snap and "net" in snap:
                    net = snap["net"]
                    sig = (net.get("ssid", ""), net.get("gateway", ""))
                    if self._last_net and sig != self._last_net:
                        notify("netcut",
                               f"Jaringan berubah: {net.get('ssid') or net.get('gateway')}")
                    self._last_net = sig

                    blocked = set(snap.get("blocked", []))
                    for ip in blocked - self._last_blocked:
                        notify("netcut", f"{ip} diblokir")
                    self._last_blocked = blocked
            except Exception:
                pass
            time.sleep(3)

    def run(self) -> int:
        self.indicator = AppIndicator3.Indicator.new(
            "netcut-tray", ICON,
            AppIndicator3.IndicatorCategory.APPLICATION_STATUS)
        self.indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self.indicator.set_title("netcut")

        menu = Gtk.Menu()

        item_dash = Gtk.MenuItem.new_with_label("Buka Dashboard")
        item_dash.connect("activate", lambda *_: self.open_dashboard())
        menu.append(item_dash)

        item_scan = Gtk.MenuItem.new_with_label("Scan ARP")
        item_scan.connect("activate", self.act_scan)
        menu.append(item_scan)

        item_rules = Gtk.MenuItem.new_with_label("Aturan nftables")
        item_rules.connect("activate", self.act_rules)
        menu.append(item_rules)

        menu.append(Gtk.SeparatorMenuItem())

        item_unblock = Gtk.MenuItem.new_with_label("Lepas Semua Blokir")
        item_unblock.connect("activate", self.act_unblock_all)
        menu.append(item_unblock)

        menu.append(Gtk.SeparatorMenuItem())

        item_quit = Gtk.MenuItem.new_with_label("Keluar")
        item_quit.connect("activate", self.act_quit)
        menu.append(item_quit)

        menu.show_all()
        self.indicator.set_menu(menu)

        # Catatan: AppIndicator3 TIDAK punya signal "activate" (memakai
        # protokol StatusNotifier, klik selalu membuka menu). Karena itu
        # dashboard dibuka lewat item menu paling atas, bukan lewat signal.
        # Signal 'scroll-event' tetap dipakai untuk_'middle click' pada
        # beberapa desktop yang menyediakannya.
        try:
            self.indicator.connect("scroll-event", self._on_scroll)
        except Exception:
            pass

        threading.Thread(target=self._watch, daemon=True).start()

        signal.signal(signal.SIGINT, lambda *_: Gtk.main_quit())
        signal.signal(signal.SIGTERM, lambda *_: Gtk.main_quit())

        GLib.timeout_add_seconds(1, self._update_title)
        Gtk.main()
        return 0

    def _on_scroll(self, *_a):
        """Klik tengah pada icon = buka dashboard."""
        try:
            self.open_dashboard()
        except Exception:
            pass
        return False

    def _update_title(self):
        """Tampilkan ringkasan di tooltip icon."""
        try:
            snap = api("/api/hosts")
            if snap and "hosts" in snap:
                n = len(snap["hosts"])
                blocked = len(snap.get("blocked", []))
                net = snap.get("net", {})
                label = f"netcut - {net.get('ssid') or net.get('iface')}: {n} host"
                if blocked:
                    label += f", {blocked} diblokir"
                self.indicator.set_title(label)
        except Exception:
            pass
        return True


def _show_text(title: str, body: str) -> None:
    """Tampilkan teks panjang di terminal (karena notify-send potong)."""
    try:
        subprocess.run(["zenity", "--info", f"--title={title}", "--text", body[:1500]],
                       capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        pass
