# Kontribusi

Terima kasih sudah mau membantu.

## Development

```bash
git clone https://github.com/Aryoksss/netcut-linux
cd netcut-linux

# dependency
sudo dnf install python3-scapy nftables      # Fedora
sudo apt-get install python3-scapy nftables   # Debian/Ubuntu

# test
python3 test_parser.py       # unit test, tanpa root
sudo python3 test_suite.py   # end-to-end, butuh root + CAP_NET_ADMIN
python3 tools/ui_test.py --serve   # test UI dashboard, butuh playwright
```

## Struktur UI

Dashboard web hidup di satu file: `webgui.py` berisi `PAGE` (HTML + CSS + JS)
yang di-*inject* ke browser sebagai satu string. Data awal disisipkan lewat
placeholder `__INIT_DATA__` supaya halaman tidak flash kosong.

Konvensi yang perlu dijaga:

- Tema lewat atribut `data-theme` di `<html>` (`dark` | `light`), token warna
  ada di blok CSS `:root` — jangan pakai warna literal di luar token itu
- Tabel dirender ulang **in-place** (baris di-*reuse* lewat `S.rows`), bukan
  di-*rebuild* tiap detik, supaya scroll position tidak loncat
- Pencarian, filter, dan sortir berjalan **di sisi client** — jangan kirim
  request server untuk itu
- Ada `tools/ui_test.py` yang menguji interaksi utama; jalankan sebelum push
- Diagram arsitektur adalah **Mermaid**, bukan gambar. Sumbernya ada di
  `assets/architecture.mmd` (Indonesia) dan `assets/architecture.en.mmd`
  (Inggris); blok di kedua README di-*sync* dengan
  `python3 tools/sync_diagram.py`. Jangan menyalin diagram manual ke README.

## Image Docker

`Dockerfile` membangun image mandiri: Python, scapy, nftables, dan database
OUI sudah di dalam image, jadi tidak ada mount filesystem host yang
dibutuhkan. Yang dibagi dengan host hanya network namespace-nya
(`--network=host`) — ARP spoofing dan relay harus jalan di interface host.

Kalau menambah dependency sistem, remember dua hal:

- Paket `hwdata` di Debian **tidak** menyertakan `oui.txt`. Database OUI
  diambil dari `assets/oui.txt` (build context), dengan fallback unduh dari
  IEEE. Kalau menambah file besar ke `assets/`, cek dulu `.dockerignore`.
- `tools/oui_csv_to_hwdata.py` mengubah `oui.csv` IEEE jadi format
  `hwdata` yang dipakai `netcut.py`. Jalankan ulang kalau ingin menyegarkan
  `assets/oui.txt`.


## Gaya kode

- Type hints di fungsi publik
- Docstring singkat yang menjelaskan *kenapa*, bukan *apa*
- Komentar berbahasa Indonesia, konsisten dengan sisa kode
- Garis maksimal 88 karakter

## Commit message

Format: `tipe(scope): ringkasan singkat`

Tipe yang dipakai: `feat`, `fix`, `test`, `docs`, `chore`, `refactor`.

Contoh:

```
feat(spoof): relay dua arah agar rate limit bekerja
fix(block): pertahankan state saat gateway berkedip
```

Tambahkan body jika perubahannya perlu penjelasan:

```
fix(traffic): konversi kbps ke kbytes untuk nft limit rate

nft 'limit rate' hanya menerima bytes/kbytes/mbytes per detik.
```

## Hal penting

Proyek ini mengerjakan ARP spoofing — teknik yang bisa mengarah ke penyalahgunaan
pada jaringan yang bukan milikmu. Karena itu:

- Hanya untuk perangkat milik sendiri di jaringan sendiri
- Jangan dipakai untuk memutus akses perangkat orang lain
- Untuk Presentation/bug report, sertakan mode yang dipakai
  (`capture` atau `fallback-no-root`) supaya mudah ditelusuri

## Menjalankan di lingkungan terbatas

`test_suite.py` memakai `veth` + network namespace sehingga tidak menyentuh
jaringan host. Ia tetap butuh `CAP_NET_ADMIN` untuk membuat namespace.
