#!/usr/bin/env python3
"""Ubah oui.csv IEEE menjadi format oui.txt ala hwdata.

Paket hwdata di Debian tidak menyertakan database OUI (di Fedora ada di
/usr/share/hwdata/oui.txt). File ini mengonversi oui.csv resmi IEEE ke
format yang diharapkan VendorDB di netcut.py:

    28-6F-B9   (hex)<TAB><TAB>Nokia Shanghai Bell Co., Ltd.

Pemakaian:
    python3 tools/oui_csv_to_hwdata.py <oui.csv> <keluaran>
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

# Hanya MA-L (6 digit hex) yang dipakai untuk prefix MAC. MA-S (3 digit)
# dan IAB/MA-M (12 digit) tidak cocok dengan parser yang mengambil 6
# digit pertama, jadi dilewati supaya tidak salah vendor.
MA_L_LEN = 6


def convert(src: Path, dst: Path) -> int:
    dst.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    seen: set[str] = set()
    with src.open(newline="", encoding="utf-8", errors="replace") as fh, \
            dst.open("w", encoding="utf-8") as out:
        reader = csv.reader(fh)
        next(reader, None)  # header
        for row in reader:
            if len(row) < 3:
                continue
            assignment = row[1].strip().upper().replace("-", "")
            vendor = row[2].strip().strip('"').strip()
            if len(assignment) != MA_L_LEN or not vendor:
                continue
            if assignment in seen:
                continue
            seen.add(assignment)
            prefix = (assignment[:2] + "-" + assignment[2:4] + "-"
                      + assignment[4:6])
            out.write(f"{prefix}   (hex)\t\t{vendor}\n")
            written += 1
    return written


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    if not src.exists():
        print(f"error: {src} tidak ada")
        return 1
    n = convert(src, dst)
    size = dst.stat().st_size // 1024
    print(f"{dst}: {n} prefix ({size} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
