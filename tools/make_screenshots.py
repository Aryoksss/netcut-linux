#!/usr/bin/env python3
"""Render screenshot dashboard netcut-linux dari HTML asli webgui.py.

Dipakai untuk dokumentasi (assets/*.png). Data yang dipakai adalah data demo
sintetis — bukan tangkapan jaringan nyata — supaya screenshot tidak memuat
SSID atau MAC perangkat siapa pun.

Butuh: firefox (headless) + python3.

    python3 tools/make_screenshots.py
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets"

# Data demo. Angka & nama dibuat-buat, MAC memakai prefix vendor asli supaya
# kolom "perangkat" terlihat wajar.
DEMO_HOSTS = [
    {"ip": "192.168.1.17", "mac": "d6:ae:9a:16:53:9e", "vendor": "unknown",
     "rx_rate": 67400, "tx_rate": 8200, "total": 10_600_000},
    {"ip": "192.168.1.25", "mac": "44:46:87:8f:cf:47",
     "vendor": "Realme Chongqing MobileTelecom", "rx_rate": 12400,
     "tx_rate": 3100, "total": 3_400_000},
    {"ip": "192.168.1.1", "mac": "6c:b7:e2:aa:7c:c6",
     "vendor": "HUAWEI TECHNOLOGIES CO.,LTD", "rx_rate": 0,
     "tx_rate": 620, "total": 30_800},
    {"ip": "192.168.1.18", "mac": "b2:8f:9a:e3:7e:a5", "vendor": "unknown",
     "rx_rate": 0, "tx_rate": 0, "total": 630},
    {"ip": "192.168.1.31", "mac": "f4:70:18:80:e7:b0",
     "vendor": "Hangzhou Ezviz Software Co.,Lt", "rx_rate": 0,
     "tx_rate": 0, "total": 0},
    {"ip": "192.168.1.42", "mac": "ae:d9:b2:54:51:4b", "vendor": "unknown",
     "rx_rate": 0, "tx_rate": 0, "total": 755},
    {"ip": "192.168.1.139", "mac": "9e:48:5a:33:a5:47", "vendor": "unknown",
     "rx_rate": 0, "tx_rate": 0, "total": 4200},
]


def snapshot(blocked_139: bool) -> dict:
    hosts = [dict(h) for h in DEMO_HOSTS]
    return {
        "iface": "wlp0s20f3",
        "mode": "capture",
        "stale": False,
        "uptime": 140,
        "packets": 27300,
        "rx_rate": 67400,
        "tx_rate": 8800,
        "total_rate": 76200,
        "hosts": hosts,
        "interfaces": ["wlp0s20f3", "eth0", "lo"],
        "net": {"ssid": "Rumah-WiFi", "gateway": "192.168.1.1"},
        "scanning": False,
        "scan_result": {"found": 7},
        "blocked": ["192.168.1.139"] if blocked_139 else [],
        "limited": {},
        "spoofing": [{"ip": "192.168.1.139"}] if blocked_139 else [],
        "notes": {},
    }


def build_html(data: dict, dest: Path) -> None:
    sys.path.insert(0, str(ROOT))
    from webgui import PAGE  # noqa: PLC0415  (import setelah sys.path diatur)

    html = PAGE.replace("__INIT_DATA__", json.dumps(data))
    # Tanpa server, poll() gagal dan header berubah jadi "server tidak
    # merespons". Stub fetch harus dipasang SEBELUM script dashboard jalan,
    # jadi disisipkan tepat sebelum tag <script> milik halaman.
    stub = (
        "<script>\n"
        f"const DEMO = {json.dumps(data)};\n"
        "window.fetch = () => Promise.resolve({\n"
        "  ok: true, status: 200,\n"
        "  text: () => Promise.resolve(JSON.stringify(DEMO)),\n"
        "});\n"
        "</script>\n"
    )
    html = html.replace("<script>", stub + "<script>", 1)
    dest.write_text(html, encoding="utf-8")


def shoot(html: Path, png: Path, size: str) -> None:
    profile = Path(tempfile.mkdtemp(prefix="ffprof-"))
    try:
        subprocess.run(
            ["firefox", "--headless", "--profile", str(profile),
             "--screenshot", str(png), "--window-size", size,
             f"file://{html}"],
            check=True, capture_output=True, timeout=180,
        )
    finally:
        shutil.rmtree(profile, ignore_errors=True)


def trim_bottom(png: Path, bg=(17, 19, 26), pad: int = 18) -> None:
    """Pangkas ruang kosong di bawah screenshot.

    Dashboard tidak selalu memakai seluruh tinggi viewport, jadi bagian bawah
    dibuang sampai baris terakhir yang berisi konten. PIL opsional: kalau tidak
    terpasang, screenshot dibiarkan apa adanya.
    """
    try:
        from PIL import Image  # noqa: PLC0415
    except ImportError:
        return

    with Image.open(png) as im:
        im = im.convert("RGB")
        w, h = im.size
        px = im.load()
        last = 0
        for y in range(h - 1, -1, -1):
            row_has_content = any(
                abs(px[x, y][0] - bg[0]) > 6
                or abs(px[x, y][1] - bg[1]) > 6
                or abs(px[x, y][2] - bg[2]) > 6
                for x in range(0, w, 4)
            )
            if row_has_content:
                last = y
                break
        new_h = min(h, last + pad)
        if new_h < h:
            im.crop((0, 0, w, new_h)).save(png)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="netcut-shot-"))
    try:
        jobs = [
            ("dashboard", snapshot(blocked_139=False), "1400,700"),
            ("blocked", snapshot(blocked_139=True), "1400,700"),
        ]
        for name, data, size in jobs:
            html = tmp / f"{name}.html"
            png = OUT / f"{name}.png"
            build_html(data, html)
            shoot(html, png, size)
            trim_bottom(png)
            print(f"  {png.relative_to(ROOT)}  {png.stat().st_size // 1024} KB")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
