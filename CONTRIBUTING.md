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
```

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
