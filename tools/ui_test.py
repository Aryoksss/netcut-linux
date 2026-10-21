#!/usr/bin/env python3
"""Uji UI dashboard netcut-linux dengan Playwright.

Menjalankan skenario interaksi utama terhadap server web yang sedang hidup
(default http://127.0.0.1:8080) memakai data demo, lalu memeriksa hasilnya.

    python3 tools/ui_test.py            # pakai server yang sedang jalan
    python3 tools/ui_test.py --serve    # jalankan server sendiri (mode
                                        # fallback, tanpa blokir sungguhan)

Butuh: playwright + chromium.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEMO = {
    "iface": "wlp0s20f3",
    "mode": "capture",
    "stale": False,
    "uptime": 4242,
    "packets": 12345,
    "dropped": 7,
    "rx_rate": 67400,
    "tx_rate": 8800,
    "peer_rate": 1200,
    "total_rate": 76200,
    "net": {"ssid": "Uji-WiFi", "gateway": "192.168.1.1", "ip": "192.168.1.17",
            "net": "192.168.1.0/24"},
    "scanning": False,
    "scan_result": {"found": 4},
    "blocked": ["192.168.1.139"],
    "limited": {"192.168.1.42": 512},
    "spoofing": [{"ip": "192.168.1.139"}],
    "notes": {"192.168.1.42": "Router menolak ARP spoof: limit hanya upload."},
    "interfaces": ["wlp0s20f3", "eth0", "lo"],
    "hosts": [
        {"ip": "192.168.1.17", "mac": "aa:bb:cc:dd:ee:01", "vendor": "unknown",
         "rx": 100, "tx": 50, "total": 150, "rx_rate": 67400, "tx_rate": 8200,
         "seen_ago": 0.2, "source": "capture"},
        {"ip": "192.168.1.25", "mac": "aa:bb:cc:dd:ee:02",
         "vendor": "Realme Chongqing MobileTelecom", "rx": 10, "tx": 5,
         "total": 15, "rx_rate": 12400, "tx_rate": 3100, "seen_ago": 1.0,
         "source": "capture"},
        {"ip": "192.168.1.42", "mac": "aa:bb:cc:dd:ee:03", "vendor": "unknown",
         "rx": 1, "tx": 1, "total": 2, "rx_rate": 0, "tx_rate": 0,
         "seen_ago": 60.0, "source": "capture"},
        {"ip": "192.168.1.139", "mac": "aa:bb:cc:dd:ee:04", "vendor": "unknown",
         "rx": 1, "tx": 1, "total": 2, "rx_rate": 0, "tx_rate": 0,
         "seen_ago": 2.0, "source": "capture"},
    ],
}

PASS, FAIL = [], []


def check(name: str, cond: bool, extra: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    mark = "  ok  " if cond else " FAIL "
    print(f"[{mark}] {name}" + (f"  -> {extra}" if extra and not cond else ""))


def serve_demo(port: int) -> ThreadingHTTPServer:
    """Server statis yang meniru API netcut dengan data demo."""
    from http.server import BaseHTTPRequestHandler

    calls: list[tuple[str, dict]] = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                from webgui import PAGE
                init = json.dumps(DEMO).replace("</", "<\\/")
                body = PAGE.replace("__INIT_DATA__", init).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif path == "/api/hosts":
                self._json(DEMO)
            elif path == "/api/rules":
                self._json({"rules": "table inet netcut {\n  chain forward {\n"
                                     "    ip saddr 192.168.1.139 drop\n  }\n}"})
            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n) or b"{}")
            calls.append((self.path.split("?")[0], data))
            if self.path.endswith("/api/bulk"):
                ips = data.get("ips", [])
                action = data.get("action")
                self._json({"ok": True, "action": action,
                            "results": {ip: {"ok": True} for ip in ips}})
            elif self.path.endswith("/api/block"):
                self._json({"ok": True, "ip": data.get("ip")})
            elif self.path.endswith("/api/unblock"):
                self._json({"ok": True, "ip": data.get("ip")})
            elif self.path.endswith("/api/limit"):
                self._json({"ok": True, "ip": data.get("ip"),
                            "kbps": data.get("kbps")})
            elif self.path.endswith("/api/unlimit"):
                self._json({"ok": True, "ip": data.get("ip")})
            elif self.path.endswith("/api/scan"):
                self._json({"ok": True, "started": True})
            elif self.path.endswith("/api/iface"):
                self._json({"ok": True, "iface": data.get("iface")})
            else:
                self._json({"error": "not found"}, 404)

    httpd = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    httpd.calls = calls  # type: ignore[attr-defined]
    return httpd


def run(page, base: str) -> None:
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)

    page.goto(base, wait_until="networkidle")
    page.wait_for_selector("tbody tr[data-ip]")

    # --- render dasar ------------------------------------------------
    rows = page.locator("tbody tr[data-ip]")
    check("tabel berisi 4 host", rows.count() == 4, f"got {rows.count()}")
    check("kartu host menampilkan 4", "4" in page.locator("#cHosts").inner_text())
    check("badge mode = capture",
          page.locator("#modeBadge").inner_text().strip().lower() == "capture")
    check("badge Jeda tersembunyi", not page.locator("#pauseBadge").is_visible())
    check("SSID tampil di header",
          page.locator("#netName").inner_text().strip() == "Uji-WiFi")
    check("tag 'laptop ini' ada",
          page.locator(".tag.self").count() == 1)
    check("tag diblokir ada", page.locator(".tag.blk").count() == 1)
    check("tag limit ada", page.locator(".tag.lim").count() == 1)
    check("baris idle diredupkan",
          page.locator("tbody tr.idle").count() == 1)

    # --- pencarian ----------------------------------------------------
    page.fill("#q", "Realme")
    page.wait_for_timeout(120)
    check("pencarian menyaring baris",
          page.locator("tbody tr[data-ip]").count() == 1)
    page.fill("#q", "192.168.1.42")
    page.wait_for_timeout(120)
    check("pencarian cocok IP",
          page.locator("tbody tr[data-ip]").count() == 1)
    page.fill("#q", "zzz-tidak-ada")
    page.wait_for_timeout(120)
    check("empty state saat tidak ada hasil",
          page.locator(".empty").count() == 1)
    page.click("#clearFilter")
    page.wait_for_timeout(120)
    check("tombol bersihkan filter memulihkan baris",
          page.locator("tbody tr[data-ip]").count() == 4)

    # --- filter chip -------------------------------------------------
    page.click(".chip[data-f='blocked']")
    page.wait_for_timeout(120)
    check("filter Diblokir menyisakan 1 baris",
          page.locator("tbody tr[data-ip]").count() == 1)
    page.click(".chip[data-f='limited']")
    page.wait_for_timeout(120)
    check("filter Limited menyisakan 1 baris",
          page.locator("tbody tr[data-ip]").count() == 1)
    page.click(".chip[data-f='all']")
    page.wait_for_timeout(120)
    check("filter Semua memulihkan 4 baris",
          page.locator("tbody tr[data-ip]").count() == 4)

    # --- sortir lokal (tanpa request server) --------------------------
    n_before = len(getattr(page, "_ncalls", []))
    page.click("th[data-k='ip']")
    page.wait_for_timeout(150)
    ips = page.locator("tbody tr[data-ip]").evaluate_all(
        "els => els.map(e => e.dataset.ip)")
    check("sortir IP menaik", ips == sorted(ips), str(ips))
    check("sortir tidak memicu request server",
          len(getattr(page, "_ncalls", [])) == n_before)
    page.click("th[data-k='rx_rate']")
    page.wait_for_timeout(150)
    check("aria-sort terisi pada kolom aktif",
          page.locator("th[aria-sort]").count() == 1)
    rates = page.locator("tbody tr[data-ip]").evaluate_all(
        "els => els.map(e => parseFloat(e.children[4].textContent))")
    check("sortir rate menurun", rates == sorted(rates, reverse=True), str(rates))

    # --- multi-select -------------------------------------------------
    check("bulk bar tersembunyi sebelum pilih",
          not page.locator("#bulkbar").is_visible())
    page.click("tbody tr[data-ip='192.168.1.17'] td.c-ip")
    page.wait_for_timeout(100)
    page.click("tbody tr[data-ip='192.168.1.25'] td.c-ip")
    page.wait_for_timeout(100)
    check("2 baris ter-select", page.locator("tbody tr.sel").count() == 2)
    check("bulk bar tampil", page.locator("#bulkbar").is_visible())
    check("counter bulk = 2",
          page.locator("#selCount").inner_text().strip() == "2")

    # select all
    page.click("#selAll")
    page.wait_for_timeout(120)
    check("select-all memilih 4", page.locator("tbody tr.sel").count() == 4)
    page.click("#bulkClear")
    page.wait_for_timeout(120)
    check("batal mengembalikan 0",
          page.locator("#selCount").inner_text().strip() == "0")

    # --- bulk block: dialog konfirmasi --------------------------------
    page.click("tbody tr[data-ip='192.168.1.17'] td.c-ip")
    page.click("tbody tr[data-ip='192.168.1.25'] td.c-ip")
    page.click("#bulkBlock")
    page.wait_for_timeout(150)
    check("dialog konfirmasi bulk terbuka",
          page.locator("#modal.on").count() == 1)
    check("judul dialog menyebut jumlah",
          "2" in page.locator("#modalTitle").inner_text())
    page.click("#modal [data-ok]")
    page.wait_for_timeout(300)
    check("dialog tertutup setelah konfirmasi",
          page.locator("#modal.on").count() == 0)
    check("toast sukses muncul",
          page.locator(".toast.ok").count() >= 1)

    # --- modal limit ---------------------------------------------------
    page.click("tbody tr[data-ip='192.168.1.17'] button[data-act='limit']")
    page.wait_for_timeout(150)
    check("modal limit terbuka", page.locator("#modal.on").count() == 1)
    check("modal limit punya preset", page.locator("[data-preset]").count() == 5)
    page.click("[data-preset='1024']")
    check("preset mengisi input",
          page.locator("#kbps").input_value() == "1024")
    page.click("#modal [data-ok]")
    page.wait_for_timeout(250)
    check("modal limit tertutup", page.locator("#modal.on").count() == 0)

    # --- modal rules ---------------------------------------------------
    page.click("#rulesBtn")
    page.wait_for_timeout(250)
    check("modal rules terbuka", page.locator("#modal.on").count() == 1)
    check("isi rules ditampilkan",
          "netcut" in page.locator("#modalBody").inner_text())
    page.click("#modal [data-x]")
    page.wait_for_timeout(120)
    check("modal rules ditutup", page.locator("#modal.on").count() == 0)

    # --- tema ----------------------------------------------------------
    page.click("#themeBtn")
    page.wait_for_timeout(120)
    check("tema beralih ke light",
          page.get_attribute("html", "data-theme") == "light")
    page.click("#themeBtn")
    page.wait_for_timeout(120)
    check("tema kembali ke dark",
          page.get_attribute("html", "data-theme") == "dark")

    # --- jeda polling --------------------------------------------------
    page.click("#pauseBtn")
    page.wait_for_timeout(120)
    check("badge Jeda muncul saat dijeda",
          page.locator("#pauseBadge").is_visible())
    page.click("#pauseBtn")
    page.wait_for_timeout(120)
    check("badge Jeda hilang setelah dilanjutkan",
          not page.locator("#pauseBadge").is_visible())

    # --- keyboard -------------------------------------------------------
    page.keyboard.press("Escape")
    page.fill("#q", "Realme")
    page.wait_for_timeout(100)
    page.keyboard.press("Escape")
    page.wait_for_timeout(100)
    check("Esc membersihkan pencarian",
          page.locator("#q").input_value() == "")
    page.click("body")
    page.keyboard.press("/")
    page.wait_for_timeout(100)
    check("tombol / memfokuskan pencarian",
          page.evaluate("document.activeElement.id") == "q")
    page.keyboard.press("Escape")

    # --- tidak ada error JS --------------------------------------------
    real = [e for e in errors if "favicon" not in e.lower()]
    check("tidak ada error JavaScript", not real, "; ".join(real[:3]))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", action="store_true",
                    help="jalankan server demo sendiri")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--url", default=None, help="URL server yang diuji")
    args = ap.parse_args()

    from playwright.sync_api import sync_playwright

    httpd = None
    if args.url:
        base = args.url
    elif args.serve:
        httpd = serve_demo(args.port)
        base = f"http://127.0.0.1:{args.port}"
    else:
        base = "http://127.0.0.1:8080"

    print(f"menguji {base}\n")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1400, "height": 900})
        page = ctx.new_page()
        try:
            run(page, base)
        finally:
            ctx.close()
            browser.close()
    if httpd:
        httpd.shutdown()

    print(f"\n{len(PASS)} lulus, {len(FAIL)} gagal")
    if FAIL:
        for f in FAIL:
            print(f"  - {f}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
