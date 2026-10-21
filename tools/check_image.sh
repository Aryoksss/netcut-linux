#!/usr/bin/env sh
# Cek isi image Docker netcut-linux.
#
# Dipakai CI (dan bisa dijalankan manual):
#   docker build -t netcut-linux . && docker run --rm --entrypoint sh netcut-linux -c "$(cat tools/check_image.sh)"
set -eu

fail() { echo "GAGAL: $1"; exit 1; }

command -v nft >/dev/null || fail "nft tidak ada"
command -v ip  >/dev/null || fail "ip tidak ada"
python3 -c "import scapy" 2>/dev/null || fail "scapy tidak ada"
test -s /usr/share/hwdata/oui.txt || fail "database OUI tidak ada"

python3 - <<'PY'
import sys
sys.path.insert(0, "/app")
from netcut import VendorDB

db = VendorDB()
db.load()
if not db._db:
    print("GAGAL: database OUI kosong")
    sys.exit(1)
vendor = db.lookup("00:00:0c:11:22:33")
if vendor == "unknown":
    print("GAGAL: lookup vendor tidak jalan")
    sys.exit(1)
print(f"image OK - {len(db._db)} prefix OUI, contoh: {vendor}")
PY
