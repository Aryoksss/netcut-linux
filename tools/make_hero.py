#!/usr/bin/env python3
"""Render assets/hero.png dari assets/hero.html.

Hero banner di README bukan screenshot dan bukan gambar hasil generator: itu
HTML/CSS biasa yang dirender lewat Chromium (Playwright). Alasannya supaya
tajam di semua ukuran, warnanya ikut palet dashboard, dan bisa diubah tanpa
tool desain.

Dipakai:
    python3 tools/make_hero.py

Butuh: playwright + chromium (``python3 -m playwright install chromium``).
"""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "assets" / "hero.html"
OUT = ROOT / "assets" / "hero.png"

# Ukuran logis banner; device_scale_factor 2 membuat hasilnya 2x lipat
# sehingga tetap tajam di layar HiDPI.
WIDTH, HEIGHT = 1280, 520
SCALE = 2


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("butuh playwright: pip install playwright && python3 -m playwright install chromium",
              file=sys.stderr)
        return 1

    if not SRC.exists():
        print(f"tidak ada {SRC}", file=sys.stderr)
        return 1

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": WIDTH, "height": HEIGHT},
                                device_scale_factor=SCALE)
        page.goto(SRC.resolve().as_uri())
        page.wait_for_timeout(400)  # biarkan font & gradient settle
        page.screenshot(path=str(OUT))
        browser.close()

    print(f"{OUT.relative_to(ROOT)}  ({WIDTH * SCALE}x{HEIGHT * SCALE})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
