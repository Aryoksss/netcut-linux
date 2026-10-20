# netcut-linux

Port Linux dari **NetCut** (arcai.com) — monitor bandwidth per-host & kontrol trafik
di jaringan lokal.

Dibangun dengan reverse engineering binary Windows NetCut memakai skill REA
(`reverse-engineer-anything`) terhadap Ghidra 12.1.4.

## Asal mula: apa yang ditemukan dari RE

`netcut.exe` ternyata **bukan aplikasinya** — itu installer Inno Setup 6.3.0
(32-bit Delphi stub, tanpa import Winsock sama sekali). Payload asli ada di
blob LZMA di dalam installer. `innoextract 1.9` belum mendukung format 6.3.0,
jadi payload diekstrak lewat Wine, lalu binary-nya dianalisis:

```
C:\Program Files (x86)\arcai.com\
├── netcut_windows.exe   5.85 MB  PE32 console, C++ (MSVC)
├── aips.exe             1.89 MB  "Arp Intelligent Protection Service"
├── macdata             737 KB    database vendor MAC
└── WinPcap_4_1_3.exe           WinPcap 4.1.3
```

Arsitektur NetCut yang terpetakan dari RTTI class + string evidence:

| Class NetCut (MSVC RTTI) | Fungsi | Padanan di tool ini |
|---|---|---|
| `VCNetCutSniffer2` | capture libpcap, promiscuous mode, `\Device\NPF_` | raw `AF_PACKET` + `IFF_PROMISC` |
| `CNetCutDiscover` | discovery host di jaringan | ARP scan (scapy) + `ip neigh` |
| `CNetCutSpoofer` | ARP spoofing (MITM) | **tidak diimplementasi** → nftables |
| `CNetCutSpeedLimiter` | batasi bandwidth host | nftables `limit rate` |
| `CNetCutNetLock` | "cut" / blokir koneksi host | nftables `drop` |
| `CNetCutRouterOS` | integrasi MikroTik RouterOS | — |
| `CNetCutWebServer` | web server bawaan | — |
| `CNetCutAuthManager` | lisensi / auth ke arcai.com | — |
| `CIPCMessage` | IPC antar modul | — |
| `NetCutNat` | NAT & port pool | — |
| file `macdata` | MAC prefix → vendor | `/usr/share/hwdata/oui.txt` |

Bukti kunci yang dipakai untuk menentukan implementasi:

- `pcap_compile`, `pcap_open_live`, `pcap_sendpacket`, `pcap_geterr`,
  `pcap_freecode` → WinPcap linked statis, filter BPF `"ip or ip6 or arp or rarp"`
- `\Device\NPF_` → enumerasi device via NPF
- `FwpmFilterAdd0` / `FwpmFilterDeleteById0` / `FwpmEngineOpen0` →
  Windows Filtering Platform untuk speed limit
- `iphlpapi.dll`, `GetAdaptersAddresses` → enumerasi adapter & MAC lookup
- `CNetCutSpoofer` + `aips.exe` → ARP spoofing untuk mode MITM

## Web GUI

```
sudo ./netcut.py --web                  # http://127.0.0.1:8080
sudo ./netcut.py --web --web-port 9000
```

![web GUI](out/netcut-web2.png)

Meniru `CNetCutWebServer` pada NetCut Windows. Fitur:

- Tabel live per-host: IP, MAC, vendor, download, upload, total
- Sortir per kolom (klik header)
- Tombol **Blokir** / **Buka** dan **Limit** / **Buka limit** per baris
- Kartu ringkasan: total download, upload, host aktif, paket, trafik total
- **Scan ARP** (jalan di background, tidak membekukan UI)
- **Aturan nft** untuk melihat rule yang aktif
- Ganti interface langsung dari header
- Data awal di-inject server-side, jadi tidak ada flash halaman kosong

API JSON (berguna untuk scripting):

| Endpoint | Method | Body | Fungsi |
|---|---|---|---|
| `/api/hosts` | GET | — | snapshot host + rate |
| `/api/rules` | GET | — | daftar aturan nftables aktif |
| `/api/block` | POST | `{"ip":"..."}` | blokir host |
| `/api/unblock` | POST | `{"ip":"..."}` | lepas blokir |
| `/api/limit` | POST | `{"ip":"...","kbps":512}` | batasi bandwidth |
| `/api/unlimit` | POST | `{"ip":"..."}` | lepas limit |
| `/api/scan` | POST | `{"net":"..."}` | ARP scan (background) |
| `/api/iface` | POST | `{"iface":"..."}` | ganti interface |

Default bind ke `127.0.0.1` (hanya lokal). Kalau mau diakses dari perangkat lain
di LAN, pakai `--web-host 0.0.0.0` — tapi тогда siapa pun di LAN bisa
memblokir host di mesinmu, jadi pakai hanya di jaringan yang kamu percaya.

## Arsitektur: ARP spoofing (seperti NetCut asli)

Ini bagian paling penting, dan Bedanya dari pendekatan "nftables biasa".

**Kenapa nftables biasa tidak cukup.** Aturan di chain `input`/`output` hanya
berlaku untuk trafik yang *dimiliki* mesin itu sendiri. Trafik internet milik
HP lain di LAN **tidak pernah melewati laptop** — WiFi bekerja sebagai switch
dan router yang melakukan forwarding. Resultnya: rule `drop` terpasang dengan
benar, tapi counter-nya tetap 0 dan HP tetap online.

**Solusinya: ARP spoofing** (class `CNetCutSpoofer` + `aips.exe` di NetCut).

```
     sebelum                          sesudah
  HP ──(gateway MAC)──> router    HP ──(MAC laptop)──> laptop ──> router
```

1. **Spoof sisi korban** — korban diberi tahu gateway ada di MAC laptop kita,
   jadi trafiknya dialihkan ke laptop.
2. **Spoof sisi router** — router diberi tahu IP korban ada di MAC laptop
   kita, jadi balasan internetnya juga lewat laptop. Tanpa ini, korban tidak
   pernah menerima balasan.
3. **Relay dua arah** — laptop meneruskan trafik korban ke gateway asli
   (TTL dikurangi, checksum IP dihitung ulang). Ini yang membuat mode *limit*
   bekerja: koneksi tetap hidup, hanya bandwidth-nya yang dibatasi.
4. **Blokir** — trafik yang sudah dialihkan ke laptop di-drop di chain
   `prerouting`/`forward`, persis seperti NetCut.

### Batasan WiFi & router yang ditemukan saat pengujian

Pengujian dilakukan pada router **Raisecom** (192.168.1.1) di jaringan WiFi.
Tiga batasan nyata ditemukan:

**1. Access point WiFi membuang frame dengan source MAC asing.**

- ARP reply dari MAC gateway (untuk restore cache ARP) tidak pernah sampai ke
  korban. Restore dilakukan dengan menghentikan re-assert spoof; cache ARP
  korban expired sendiri lalu korban broadcast request yang dijawab router
  asli.
- Frame relay harus memakai **MAC laptop sendiri** di field ethernet source.
  Kalau memakai MAC gateway, frame dibuang AP sebelum sampai router.
- `sendto()` pada AF_PACKET tidak menerima MAC sebagai string
  (`No such device`); address tuple harus 5-elemen:
  `(ifname, proto, pkttype, hatype, addr)`.

**2. Router kebal ARP spoofing (Raisecom).**

Router menolak semua variasi ARP spoof ke sisi router (ARP reply, ARP
request, gratuitous ARP, HAP). Akibatnya entri ARP router untuk IP korban
tetap menunjuk MAC asli, sehingga **balasan download dari internet dikirim
langsung ke korban** tanpa melewati laptop.

Konsekuensi:
- **Blokir tetap bekerja penuh** — trafik korban (upload maupun request)
  sudah dialihkan ke laptop dan di-drop sebelum sampai router.
- **Limit hanya berlaku untuk arah upload** pada router seperti ini, karena
  balasan download tidak melewati laptop. Tool mendeteksi ini otomatis
  (`ArpSpoofer.router_spoofable()`) dan menampilkan badge `!` beserta
  penjelasan di UI.

Di router yang menerima ARP spoof (misalnya OpenWrt dengan `arp_ignore=0`,
atau MikroTik tanpa `arp=reply-only` yang sesuai), **kedua arah bisa
dibatasi** — relay dua arah di `spoof.py` sudah mendukungnya.

**3. Checksum IP hanya menutupi header.** Menghitung checksum atas seluruh
paket (header + payload) membuat router membuang frame, karena isinya tidak
sesuai RFC 1071. `spoof.py` memakai `ihl` untuk membatasi perhitungan ke header.

### Mode operasi

| Mode | Perilaku | Status di router Raisecom |
|---|---|---|
| `block` | Trafik korban dialihkan ke laptop lalu di-drop → HP kehilangan internet | ✅ bekerja penuh |
| `relay` + `limit` | Trafik diteruskan, bandwidth dibatasi | ⚠️ hanya arah upload |

### Mode operasi

| Mode | Perilaku |
|---|---|
| `block` | Trafik korban dialihkan ke laptop lalu di-drop → HP kehilangan internet |
| `relay` | Trafik dialihkan & diteruskan → HP tetap online, bandwidth dibatasi |

Untuk keamanan, tool ini hanya dipakai pada **perangkat milik sendiri di
jaringan sendiri**. ARP spoofing adalah MITM: seluruh trafik korban melewati
mesin kita dan bisa dibaca. Jangan dipakai pada jaringan bersama yang
bukan milikmu.

### Perbedaan lain dari NetCut Windows

- NetCut Windows memakai Windows Filtering Platform (`FwpmFilterAdd0`) untuk
  speed limit. Di Linux, padanannya `nft limit rate` di chain `forward`.
- `nft limit rate` hanya menerima satuan `bytes`/`kbytes`/`mbytes` per detik,
  jadi kbps dikonversi ke kbytes (`/8`).
- Token bucket `nft limit` memungkinkan burst di awal, sehingga rata-rata
  aktual lebih rendah dari nominal; dipakai faktor kompensasi 1.6.
- Aturan `limit` dipasang untuk **kedua arah** (`saddr` dan `daddr`),
  kalau hanya satu arah separuh trafik tidak ikut dibatasi.

## Kebutuhan

- Fedora 44 (atau distro lain dengan `nftables` + `python3-scapy`)
- `python3-scapy` — sudah terpasang di Fedora
- `hwdata` (untuk `/usr/share/hwdata/oui.txt`) — sudah terpasang di Fedora
- Akses root: `sudo` atau `setcap`

## Pemasangan

```bash
cd ~/netcut-linux

# 1. dependency check
python3 -c "import scapy" || sudo dnf install python3-scapy

# 2. opsional: biar capture jalan tanpa password sudo
gcc -O2 -o netcut-launcher launcher.c
sudo setcap cap_net_raw+ep netcut-launcher
```

Tanpa `setcap`, jalankan dengan `sudo`.

## Penggunaan

```bash
# web GUI (browser) - dengan tombol Blokir/Limit yang bekerja seperti NetCut
sudo ./netcut.py --web

# cut koneksi device lain (mode NetCut: ARP spoof + drop)
sudo ./netcut.py --cut 192.168.1.7

# blokir device lain
sudo ./netcut.py --block 192.168.1.7

# batasi bandwidth device lain (ARP spoof + relay + rate limit)
sudo ./netcut.py --limit 192.168.1.7 512

# monitor real-time (TUI di terminal)
sudo ./netcut.py

# snapshot sekali
sudo ./netcut.py --once --seconds 10

# output JSON untuk dipipeline
sudo ./netcut.py --json --seconds 10

# ARP scan subnet
sudo ./netcut.py --scan --net 192.168.1.0/24

# blokir / lepas blokir
sudo ./netcut.py --block 192.168.1.50
sudo ./netcut.py --unblock 192.168.1.50

# batasi bandwidth (kbps) / lepas
sudo ./netcut.py --limit 192.168.1.50 1024
sudo ./netcut.py --unlimit 192.168.1.50

# lihat aturan yang aktif
sudo ./netcut.py --list-rules

# lihat perintah nft tanpa eksekusi
sudo ./netcut.py --block 192.168.1.50 --dry-run
```

### Tanpa root

Tanpa root, tool otomatis jatuh ke **mode fallback**: menampilkan total
trafik interface dari `/proc/net/dev` plus daftar host dari `ip neigh`, tanpa
data per-host. Berguna untuk melihat apakah link sedang dipakai, tapi untuk
monitoring per-host memang butuh root.

## Contoh output

```
IP              MAC                        RX         TX      TOTAL  VENDOR
----------------------------------------------------------------------------------------------------
192.168.1.18    3a:cf:c8:f2:b9:4c  477.9 KB/s  11.8 KB/s     3.8 MB  unknown
192.168.1.1     78:91:e9:bd:77:14           0     71 B/s      576 B  Raisecom Technology CO., LTD
192.168.1.7     32:e6:36:7f:7c:fe           0     13 B/s      105 B  unknown
(internet via gateway)                      93.9 KB     3.7 MB     3.8 MB
```

Baris `(internet via gateway)` adalah trafik menuju/dari internet — dipisahkan
dari host LAN agar tabel tetap jelas.

## Ganti WiFi otomatis

Tool memantau perpindahan jaringan (gateway / IP / SSID) setiap 3 detik.
Begitu kamu pindah WiFi atau ganti hotspot, tool otomatis:

1. mengembalikan ARP cache korban & menghentikan spoofing lama
2. menghapus rule nftables lama (IP-nya sudah tidak relevan)
3. membuang daftar host dari subnet sebelumnya
4. mem-flush cache ARP kernel
5. **scan ARP subnet baru** dan menampilkan host-host yang baru

Tidak perlu klik tombol "Scan ARP" lagi.

Status jaringan (SSID, gateway, IP, subnet) tampil di header web GUI, dan
badge `scanning…` muncul selama scan berjalan.

Deteksi berdasarkan `(gateway, IP, SSID)` — jadi tetap jalan walau kamu ganti
ke hotspot yang punya subnet sama, karena SSID-nya berbeda.

### Test perpindahan jaringan

```bash
sudo python3 test_suite.py     # grup [7] PERPINDAHAN JARINGAN
```

Mensimulasikan perpindahan dengan mengubah default route & address interface,
lalu memverifikasi: host lama dibersihkan, daftar blocked/limited dibersihkan,
signature diperbarui, net_info ter-update, scan otomatis jalan, dan scan
memakai subnet baru.

## Aplikasi Linux native

Tool ini bisa dipasang sebagai aplikasi desktop biasa — dipanggil dari app
menu, lewat keybind, atau dari terminal.

```bash
./install.sh              # pasang (user level, tanpa root)
./install.sh --autostart  # + jalankan otomatis saat login
```

Yang dipasang:

| Lokasi | Isi |
|---|---|
| `~/.local/bin/netcut` | launcher (ada di PATH) |
| `~/.local/share/applications/netcut.desktop` | entry app menu |
| `~/.local/share/applications/netcut-tray.desktop` | entry tray-only |
| `~/.local/share/icons/hicolor/scalable/apps/netcut.svg` | ikon |
| `~/.config/autostart/netcut.desktop` | autostart (opsional) |

Perintah:

```bash
netcut              # buka web GUI + system tray
netcut --tray       # hanya system tray (tanpa buka browser)
netcut --status     # cek server jalan/tidak
netcut --stop       # hentikan server
gtk-launch netcut   # sama seperti dari app menu
```

### System tray

Ikon di system tray menampilkan tooltip live: `netcut - <SSID>: <jumlah> host`.
Menu klik-kanan:

- **Buka Dashboard** — buka web GUI di browser
- **Scan ARP** — scan subnet aktif
- **Aturan nftables** — tampilkan rule aktif
- **Lepas Semua Blokir** — cabut blokir & limit
- **Keluar** — hentikan

Tray memakai `AppIndicator3` (protokol StatusNotifier), karena di Wayland
(`niri`) tray hanya bisa lewat protokol itu — GTK4 tidak punya binding-nya.
Notifikasi desktop muncul saat jaringan berubah atau ada host diblokir.

### Keybind niri

Sudah ditambahkan ke `~/.config/niri/config.kdl`:

```
Mod+Shift+N  →  NetCut
```

Untuk menambah keybind lain, tambahkan blok `binds` di config niri:

```
Mod+Shift+N hotkey-overlay-title="NetCut" {
    spawn "/home/aryoks/.local/bin/netcut";
}
```

### Privilege tanpa sudo

Capture per-host butuh `CAP_NET_RAW`, dan pemblokiran butuh
`CAP_NET_ADMIN`. Supaya tidak perlu `sudo` setiap kali menjalankan,
`netcut_app.py` otomatis mendeteksi:

1. **Punya CAP_NET_RAW** → jalankan server langsung (user root / setcap)
2. **Bisa pakai docker** (user ada di grup `docker`) → jalankan server di
   container dengan `--cap-add=NET_RAW --cap-add=NET_ADMIN` dan
   `--network=host`. Karena berbagi network namespace dengan host, aturan
   nftables langsung berlaku di host.
3. **Else** → mode fallback (hanya monitoring total interface, tanpa
   kontrol blokir/limit)

Status mode ini terlihat di header dashboard: `capture` (penuh) atau
`fallback-no-root` (terbatas).

## Test

```bash
# unit test parser (tanpa root)
python3 test_parser.py

# test suite lengkap (butuh root + CAP_NET_ADMIN + CAP_NET_RAW)
sudo python3 test_suite.py
```

`test_parser.py` — 9 unit test: parsing IPv4, pemetaan MAC, ARP, klasifikasi
remote-vs-LAN, trafik peer-to-peer, tidak ada double-count antar bucket,
perhitungan rate, penolakan frame pendek, helper formatting.

`test_suite.py` — 24 test end-to-end di jaringan virtual (veth + netns),
terisolasi total dari jaringan nyata:

| Grup | Yang diuji |
|---|---|
| Parser | IPv4, ARP, MAC, vendor, remote-vs-LAN, peer traffic |
| VNet | konektivitas korban, setup namespace |
| Spoof+Relay | traffic diteruskan, korban tetap online |
| Block | traffic = 0, korban kehilangan koneksi |
| Limit | bandwidth turun dari 2 MB ke 8 KB |
| Cleanup | traffic kembali normal, semua rule terhapus |
| Perpindahan jaringan | deteksi ganti WiFi, reset state, scan subnet baru |

Dijalankan di container:

```bash
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
  -v /usr:/usr:ro -v /lib:/lib:ro -v /lib64:/lib64:ro \
  -v ~/.local:/root/.local:ro -v "$PWD:/app" -w /app \
  -e PYTHONPATH=/root/.local/lib/python3.14/site-packages \
  fedora:44 /usr/bin/python3.14 /app/test_suite.py
```

Test fungsional blokir di jaringan nyata (bukan cuma rule terpasang):

```
baseline  : ping 192.168.1.1 -> 0% loss
diblokir  : ping 192.168.1.1 -> 100% loss
dilepas   : ping 192.168.1.1 -> 0% loss
```

## Catatan

- `--limit` memakai satuan **kbps** di antarmuka, dikonversi ke
  `kbytes/second` untuk nftables (nft hanya menerima bytes/kbytes/mbytes).
- Loopback-only. Untuk mengatur trafik perangkat lain, pasang aturan di router.
- `CNetCutRouterOS` (dukungan MikroTik RouterOS) tidak diimplementasi — pakai
  RouterOS native `/ip firewall filter` untuk kontrol di level router.
- Modul lisensi (`CNetCutAuthManager`) tidak diimplementasi; tool ini bebas
  dipakai tanpa aktivasi.
