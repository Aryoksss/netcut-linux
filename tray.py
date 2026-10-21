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


def notify(title: str, body: str, icon: str = "network-wireless") -> None:
    try:
        subprocess.run(["notify-send", "-a", "netcut", "-i", icon, title, body],
                       capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass


def fmt_rate(bps: float) -> str:
    bps = bps or 0
    for unit, div in (("GB/s", 1e9), ("MB/s", 1e6), ("KB/s", 1e3)):
        if bps >= div:
            return f"{bps / div:.1f} {unit}"
    return f"{bps:.0f} B/s"


def zenity_available() -> bool:
    try:
        r = subprocess.run(["which", "zenity"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class TrayIcon:
    def __init__(self, server, open_dashboard):
        self.server = server
        self.open_dashboard = open_dashboard
        self.indicator = None
        self._last_net = None
        self._last_blocked = set()
        self._last_limited = set()
        self._online = True
        self._snap: dict = {}
        self._items: dict = {}

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
        snap = self._snap or api("/api/hosts")
        n = 0
        for ip in snap.get("blocked", []):
            if api("/api/unblock", {"ip": ip}).get("ok"):
                n += 1
        for ip in snap.get("limited", {}):
            if api("/api/unlimit", {"ip": ip}).get("ok"):
                n += 1
        notify("netcut", f"{n} aturan blokir/limit dilepas")

    def act_quit(self, *_a):
        notify("netcut", "netcut dihentikan")
        try:
            self.server.stop()
        except Exception:
            pass
        Gtk.main_quit()

    # -- blokir cepat (multi-select) -----------------------------------
    def _quick_pick(self, title: str, hint: str, rows: list[tuple[str, str]],
                    preselect: bool = False) -> list[str]:
        """Buka dialog checklist zenity, kembalikan daftar IP terpilih."""
        if not zenity_available():
            notify("netcut", "Butuh zenity untuk dialog pilih perangkat",
                   "dialog-error")
            return []
        if not rows:
            notify("netcut", "Tidak ada perangkat yang bisa dipilih")
            return []
        args = ["zenity", "--list", "--checklist",
                f"--title={title}", f"--text={hint}",
                "--column=Pilih", "--column=IP", "--column=Perangkat",
                "--separator=|", "--width=460", "--height=420",
                "--hide-column-header=1"]
        for ip, dev in rows:
            args.append(f"{'TRUE' if preselect else 'FALSE'}|{ip}|{dev}")
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=300)
        except (OSError, subprocess.SubprocessError) as exc:
            notify("netcut", f"Gagal membuka dialog: {exc}", "dialog-error")
            return []
        if proc.returncode != 0:
            return []  # pengguna menekan cancel
        picked = []
        for line in proc.stdout.splitlines():
            parts = line.split("|")
            if len(parts) >= 2 and parts[1].strip():
                picked.append(parts[1].strip())
        return picked

    def act_quick_block(self, *_a):
        snap = self._snap or api("/api/hosts")
        blocked = set(snap.get("blocked", []))
        rows = [(h["ip"], (h.get("vendor") or "unknown")[:28])
                for h in snap.get("hosts", []) if h["ip"] not in blocked]
        picked = self._quick_pick("Blokir perangkat",
                                  "Pilih perangkat yang mau diblokir", rows)
        if not picked:
            return
        ok = 0
        for ip in picked:
            if api("/api/block", {"ip": ip}).get("ok"):
                ok += 1
        notify("netcut", f"{ok}/{len(picked)} perangkat diblokir")

    def act_quick_unblock(self, *_a):
        snap = self._snap or api("/api/hosts")
        rows = [(ip, "diblokir") for ip in snap.get("blocked", [])]
        rows += [(ip, f"limit {kbps} kbps")
                 for ip, kbps in snap.get("limited", {}).items()
                 if ip not in snap.get("blocked", [])]
        picked = self._quick_pick("Buka blokir / limit",
                                  "Pilih perangkat yang mau dilepas", rows)
        if not picked:
            return
        ok = 0
        for ip in picked:
            r = api("/api/unblock", {"ip": ip})
            r2 = api("/api/unlimit", {"ip": ip})
            if r.get("ok") or r2.get("ok"):
                ok += 1
        notify("netcut", f"{ok}/{len(picked)} perangkat dibuka")

    # -- monitoring ----------------------------------------------------
    def _watch(self):
        """Satu poller untuk tooltip, notifikasi, dan status server."""
        while True:
            try:
                snap = api("/api/hosts")
                if snap and "hosts" in snap:
                    if not self._online:
                        self._online = True
                        notify("netcut", "Server kembali merespons")
                    self._snap = snap
                    net = snap.get("net", {})
                    sig = (net.get("ssid", ""), net.get("gateway", ""))
                    if self._last_net and sig != self._last_net:
                        notify("netcut",
                               f"Jaringan berubah: {net.get('ssid') or net.get('gateway')}")
                    self._last_net = sig

                    blocked = set(snap.get("blocked", []))
                    for ip in blocked - self._last_blocked:
                        notify("netcut", f"{ip} diblokir")
                    self._last_blocked = blocked

                    limited = set(snap.get("limited", {}))
                    for ip in limited - self._last_limited:
                        notify("netcut", f"{ip} dibatasi "
                                         f"{snap['limited'][ip]} kbps")
                    self._last_limited = limited
                elif self._online:
                    self._online = False
                    notify("netcut", "Server netcut tidak merespons",
                           "dialog-error")
            except Exception:
                pass
            self._refresh_ui()
            time.sleep(2)

    def _refresh_ui(self) -> None:
        """Perbarui tooltip dan ikon dari snapshot terakhir."""
        if self.indicator is None:
            return
        snap = self._snap
        if not snap:
            self.indicator.set_title("netcut - server tidak merespons")
            return
        n = len(snap.get("hosts", []))
        blocked = len(snap.get("blocked", []))
        limited = len(snap.get("limited", {}))
        net = snap.get("net", {})
        label = f"netcut - {net.get('ssid') or net.get('iface') or '?'}: {n} host"
        if blocked:
            label += f", {blocked} diblokir"
        if limited:
            label += f", {limited} limited"
        self.indicator.set_title(label)

        # ikon attention ketika ada perangkat yang diblokir
        try:
            if blocked:
                self.indicator.set_attention_icon(
                    AppIndicator3.Indicator.new_full(ICON, "netcut"))
            else:
                self.indicator.set_attention_icon(
                    AppIndicator3.Indicator.new_full("", ""))
        except Exception:
            pass

        # baris info di menu
        rate = fmt_rate((snap.get("rx_rate") or 0) + (snap.get("tx_rate") or 0))
        self._set_info("iNet", net.get("ssid") or net.get("iface") or "tidak ada")
        self._set_info("iStat", f"{n} host · {rate}"
                                + (f" · {blocked} diblokir" if blocked else ""))

    def _set_info(self, key: str, text: str) -> None:
        item = self._items.get(key)
        if item is None:
            return
        label = item.get_child()
        if label is not None:
            label.set_text(text)

    def run(self) -> int:
        self.indicator = AppIndicator3.Indicator.new(
            "netcut-tray", ICON,
            AppIndicator3.IndicatorCategory.APPLICATION_STATUS)
        self.indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self.indicator.set_title("netcut")

        menu = Gtk.Menu()

        # baris informasi (tidak bisa diklik)
        self._items["iNet"] = self._info_item(menu, "memuat")
        self._items["iStat"] = self._info_item(menu, "memuat")
        menu.append(Gtk.SeparatorMenuItem())

        item_dash = Gtk.MenuItem.new_with_label("Buka Dashboard")
        item_dash.connect("activate", lambda *_: self.open_dashboard())
        menu.append(item_dash)

        item_scan = Gtk.MenuItem.new_with_label("Scan ARP")
        item_scan.connect("activate", self.act_scan)
        menu.append(item_scan)

        item_qb = Gtk.MenuItem.new_with_label("Blokir cepat…")
        item_qb.connect("activate", self.act_quick_block)
        menu.append(item_qb)

        item_qu = Gtk.MenuItem.new_with_label("Buka blokir / limit…")
        item_qu.connect("activate", self.act_quick_unblock)
        menu.append(item_qu)

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

        Gtk.main()
        return 0

    @staticmethod
    def _info_item(menu: Gtk.Menu, text: str) -> Gtk.MenuItem:
        """Baris menu non-interaktif sebagai penanda status."""
        item = Gtk.MenuItem.new_with_label(text)
        item.set_sensitive(False)
        menu.append(item)
        return item

    def _on_scroll(self, *_a):
        """Klik tengah pada icon = buka dashboard."""
        try:
            self.open_dashboard()
        except Exception:
            pass
        return False


def _show_text(title: str, body: str) -> None:
    """Tampilkan teks panjang di terminal (karena notify-send potong)."""
    try:
        subprocess.run(["zenity", "--info", f"--title={title}", "--text", body[:1500]],
                       capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        pass
