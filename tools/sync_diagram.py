#!/usr/bin/env python3
"""Sinkronkan diagram Mermaid ke README.

GitHub merender blok ```mermaid langsung di README, tapi diagramnya harus
disalin manual ke dua file README (Indonesia & Inggris). Supaya tidak
berhimpit, sumbernya disimpan di assets/*.mmd dan blok di README diganti
otomatis oleh tool ini.

    python3 tools/sync_diagram.py           # tulis ke README
    python3 tools/sync_diagram.py --check   # hanya cek, exit != 0 kalau beda
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# key -> (file sumber .mmd, file README, penanda)
TARGETS = {
    "id": ("assets/architecture.mmd", "README.id.md", "architecture"),
    "en": ("assets/architecture.en.mmd", "README.md", "architecture"),
}


def build_block(src: str, marker: str) -> str:
    return (f"<!-- diagram:{marker} -->\n"
            f"```mermaid\n{src.strip()}\n```\n"
            f"<!-- /diagram:{marker} -->")


def sync(key: str, check: bool) -> bool:
    src_rel, readme_rel, marker = TARGETS[key]
    src_path = ROOT / src_rel
    readme_path = ROOT / readme_rel
    if not src_path.exists():
        print(f"  {src_rel} tidak ada")
        return False

    text = readme_path.read_text(encoding="utf-8")
    start = f"<!-- diagram:{marker} -->"
    end = f"<!-- /diagram:{marker} -->"
    if start not in text or end not in text:
        print(f"  {readme_rel}: penanda diagram tidak ditemukan "
              f"({start} ... {end})")
        return False

    new_block = build_block(src_path.read_text(encoding="utf-8"), marker)
    head, _, rest = text.partition(start)
    _, _, tail = rest.partition(end)
    updated = head + new_block + tail

    if updated == text:
        print(f"  {readme_rel}: sudah sinkron")
        return True
    if check:
        print(f"  {readme_rel}: BELUM sinkron — jalankan "
              f"`python3 tools/sync_diagram.py`")
        return False
    readme_path.write_text(updated, encoding="utf-8")
    print(f"  {readme_rel}: diperbarui")
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="hanya cek sinkronisasi, jangan menulis")
    args = ap.parse_args()

    ok = True
    for key in TARGETS:
        ok = sync(key, args.check) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
