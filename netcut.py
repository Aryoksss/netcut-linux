#!/usr/bin/env python3
"""netcut - Linux network bandwidth monitor & traffic controller.

Komponen utama:

    Sniffer         -> raw AF_PACKET capture + promiscuous mode
    arp_scan        -> ARP scan + neighbour table
    TrafficControl  -> nftables rate limiter & drop (blokir host)
    VendorDB        -> oui.txt vendor lookup

Blokir & limit device lain membutuhkan ARP spoofing supaya trafiknya melintasi
laptop lebih dulu - lihat spoof.py. Untuk trafik milik mesin ini sendiri,
nftables langsung bekerja tanpa perlu ARP spoofing.

Perintah:
  netcut                      monitor real-time (TUI)
  netcut --once               snapshot sekali, lalu keluar
  netcut --json               output JSON
  netcut --block <ip>         blokir host
  netcut --unblock <ip>       lepas blokir
  netcut --limit <ip> <kbps>  batasi bandwidth host
  netcut --unlimit <ip>       lepas limit
  netcut --list-rules         tampilkan aturan nftables aktif
  netcut --scan               ARP scan langsung
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field

try:
    import scapy.all as scapy
    from scapy.layers.l2 import ARP, Ether, srp
except ImportError:
    print("error: butuh scapy. Install dengan: sudo dnf install python3-scapy "
          "(atau: sudo apt-get install python3-scapy)", file=sys.stderr)
    print("      Alternatif tanpa scapy: sudo ./netcut.py --web "
          "(mode fallback, tanpa ARP scan)", file=sys.stderr)
    sys.exit(1)

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806

NFT_TABLE = "netcut"
NFT_FAMILY = "inet"
NFT_CHAIN = "filter"


# --------------------------------------------------------------------------
# vendor lookup
# --------------------------------------------------------------------------

class VendorDB:
    """MAC prefix -> vendor, dari hwdata oui.txt (format NetCut 'macdata')."""

    def __init__(self, paths=None):
        self.paths = paths or [
            "/usr/share/hwdata/oui.txt",
            "/usr/share/ieee-data/oui.txt",
        ]
        self._db: dict[str, str] = {}
        self._loaded = False

    def load(self) -> None:
        if self._loaded:
            return
        for path in self.paths:
            if not os.path.exists(path):
                continue
            with open(path, "r", errors="replace") as fh:
                for line in fh:
                    if "(hex)" in line:
                        prefix, _, vendor = line.partition("(hex)")
                        prefix = prefix.strip().replace("-", "")[:6].upper()
                        vendor = vendor.replace(")", "", 1).strip()
                        if len(prefix) == 6 and vendor:
                            self._db.setdefault(prefix, vendor)
            self._loaded = True
            break

    def lookup(self, mac: str) -> str:
        self.load()
        if not mac or mac.lower() in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
            return "broadcast"
        prefix = mac.replace(":", "").replace("-", "").upper()[:6]
        return self._db.get(prefix, "unknown")


# --------------------------------------------------------------------------
# host table
# --------------------------------------------------------------------------

@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""
    rx: int = 0
    tx: int = 0
    rx_rate: float = 0.0
    tx_rate: float = 0.0
    blocked: bool = False
    limited_kbps: int = 0
    last_seen: float = field(default_factory=time.time)
    source: str = "capture"


def parse_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


# --------------------------------------------------------------------------
# capture
# --------------------------------------------------------------------------

class Sniffer:
    """Raw AF_PACKET capture, mode promiscuous seperti pcap_open_live.

    NetCut memakai libpcap + filter BPF "ip or ip6 or arp or rarp". Di Linux
    kita baca frame mentah dari AF_PACKET dan memfilter di userspace, karena
    filter BPF butuh libpcap binding yang tidak tersedia di Fedora default.
    """

    def __init__(self, iface: str):
        self.iface = iface
        self.sock: socket.socket | None = None
        self.hosts: dict[str, Host] = {}
        self.host_seen: set[str] = set()
        self.vendor = VendorDB()
        self._last = time.monotonic()
        self._prev: dict[str, tuple[int, int]] = {}
        self._running = False
        self.packets = 0
        self.dropped = 0
        self.remote_rx = 0
        self.remote_tx = 0
        self.peer_bytes = 0
        self.remote_rx_rate = 0.0
        self.remote_tx_rate = 0.0
        self.peer_rate = 0.0
        self._prev_remote_rx = 0
        self._prev_remote_tx = 0
        self._prev_peer = 0
        self.local_net = _iface_network(iface)
        self.local_nets = [self.local_net] if self.local_net else []
        self.local_ip = _iface_addr(iface)

    def open(self) -> None:
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.bind((self.iface, 0))
        self.sock.setblocking(False)
        self._enable_promisc()
        self.vendor.load()

    def _enable_promisc(self) -> None:
        """Set interface ke mode promiscuous (set member PACKET_MR_PROMISC)."""
        try:
            import fcntl
            SIOCSIFFLAGS = 0x8914
            SIOCGIFFLAGS = 0x8913
            IFF_PROMISC = 0x100
            ifr = struct.pack("16sh", self.iface.encode()[:15], 0)
            flags = struct.unpack("16sh", fcntl.ioctl(self.sock.fileno(), SIOCGIFFLAGS, ifr))[1]
            fcntl.ioctl(
                self.sock.fileno(),
                SIOCSIFFLAGS,
                struct.pack("16sh", self.iface.encode()[:15], flags | IFF_PROMISC),
            )
        except OSError:
            pass  # promiscuous opsional; capture tetap jalan

    def close(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None

    def _parse_eth(self, frame: bytes) -> tuple[int, bytes, bytes]:
        if len(frame) < 14:
            raise ValueError("pendek")
        dst = frame[0:6]
        src = frame[6:12]
        etype = struct.unpack("!H", frame[12:14])[0]
        return etype, dst, src

    def _parse_ipv4(self, payload: bytes) -> tuple[str, str, int]:
        if len(payload) < 20:
            raise ValueError("pendek")
        ihl = (payload[0] & 0x0F) * 4
        if ihl < 20 or len(payload) < ihl:
            raise ValueError("ihl")
        src = socket.inet_ntoa(payload[12:16])
        dst = socket.inet_ntoa(payload[16:20])
        total_len = struct.unpack("!H", payload[2:4])[0]
        return src, dst, total_len

    def _parse_arp(self, payload: bytes) -> tuple[str, str] | None:
        if len(payload) < 28:
            return None
        oper = struct.unpack("!H", payload[6:8])[0]
        if oper not in (1, 2):
            return None
        sha = payload[8:14]
        spa = socket.inet_ntoa(payload[14:18])
        return parse_mac(sha), spa

    def _touch(self, ip: str, mac: str) -> Host:
        host = self.hosts.get(ip)
        if host is None:
            host = Host(ip=ip, mac=mac, vendor=self.vendor.lookup(mac))
            self.hosts[ip] = host
        elif mac and not host.mac:
            host.mac = mac
            host.vendor = self.vendor.lookup(mac)
        host.last_seen = time.time()
        return host

    def poll(self) -> int:
        """Baca frame yang tersedia, perbarui counter. Return jumlah frame."""
        if not self.sock:
            return 0
        count = 0
        while True:
            try:
                frame = self.sock.recv(65535)
            except BlockingIOError:
                break
            except OSError:
                break
            count += 1
            self.packets += 1
            try:
                self._handle(frame)
            except (ValueError, OSError):
                self.dropped += 1
        return count

    def _handle(self, frame: bytes) -> None:
        etype, dst, src = self._parse_eth(frame)
        if etype == ETH_P_IP:
            src_ip, dst_ip, length = self._parse_ipv4(frame[14:])
            src_local = self.is_local(src_ip)
            dst_local = self.is_local(dst_ip)
            # Setiap frame dihitung tepat sekali per sisi:
            #   host[dst].rx += len  (siapa yang menerima)
            #   host[src].tx += len  (siapa yang mengirim)
            # Bucket internet hanya untuk frame yang melewati batas LAN.
            if dst_local:
                self._touch(dst_ip, parse_mac(dst)).rx += length
            if src_local:
                self._touch(src_ip, parse_mac(src)).tx += length
            if src_local and not dst_local:
                self.remote_tx += length      # upload ke internet
            elif dst_local and not src_local:
                self.remote_rx += length      # download dari internet
            else:
                self.peer_bytes += length     # trafik antar-perangkat LAN
        elif etype == ETH_P_ARP:
            info = self._parse_arp(frame[14:])
            if info:
                mac, ip = info
                # hanya host di subnet aktif
                if ip and (not self.local_nets or self.is_local(ip)):
                    self._touch(ip, mac)

    def is_local(self, ip: str) -> bool:
        """True jika IP berada di jaringan LAN lokal (bukan internet remote)."""
        nets = self.local_nets
        if not nets:
            return False
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in nets)

    def reset_for_network_change(self) -> None:
        """Bersihkan state lama setelah pindah WiFi / ganti subnet.

        Host di subnet sebelumnya tidak ada lagi, dan gateway pun sudah
        berbeda. Tanpa reset, tool akan menampilkan host basi dan
        salah klasifikasi trafik LAN vs internet.
        """
        self.hosts.clear()
        self._prev.clear()
        self.remote_rx = 0
        self.remote_tx = 0
        self.peer_bytes = 0
        self._prev_remote_rx = 0
        self._prev_remote_tx = 0
        self._prev_peer = 0
        self.remote_rx_rate = 0.0
        self.remote_tx_rate = 0.0
        self.peer_rate = 0.0
        self.local_net = _iface_network(self.iface)
        self.local_nets = [self.local_net] if self.local_net else []
        self.local_ip = _iface_addr(self.iface)
        # host_seen: host yang pernah terlihat, dipakai untuk menyaring
        # host basi yang tak lagi ada di subnet baru
        self.host_seen.clear()

    def prune_stale(self, max_age: float = 90.0) -> int:
        """Buang host yang sudah lama tidak terlihat.

        Setelah pindah jaringan, beberapa host dari subnet lama bisa
        masih tertinggal di tabel. Host yang tidak aktif selama max_age
        dianggap sudah tidak ada.
        """
        now = time.time()
        stale = [ip for ip, h in self.hosts.items()
                 if now - h.last_seen > max_age and ip != self.local_ip]
        for ip in stale:
            self.hosts.pop(ip, None)
            self._prev.pop(ip, None)
        return len(stale)

    def refresh_rates(self) -> None:
        """Hitung rate per host (byte/detik) dari delta counter."""
        now = time.monotonic()
        elapsed = max(now - self._last, 0.001)
        self._last = now
        for ip, host in self.hosts.items():
            prev_rx, prev_tx = self._prev.get(ip, (0, 0))
            host.rx_rate = max(0, (host.rx - prev_rx) / elapsed)
            host.tx_rate = max(0, (host.tx - prev_tx) / elapsed)
            self._prev[ip] = (host.rx, host.tx)
        # rate trafik internet (bucket remote) & trafik antar-host LAN
        self.remote_rx_rate = max(0, (self.remote_rx - self._prev_remote_rx) / elapsed)
        self.remote_tx_rate = max(0, (self.remote_tx - self._prev_remote_tx) / elapsed)
        self.peer_rate = max(0, (self.peer_bytes - self._prev_peer) / elapsed)
        self._prev_remote_rx = self.remote_rx
        self._prev_remote_tx = self.remote_tx
        self._prev_peer = self.peer_bytes

    def merge_neighbors(self) -> None:
        """Tambahkan host dari tabel kernel neighbour (ip neigh)."""
        try:
            out = subprocess.run(
                ["ip", "neigh", "show", "dev", self.iface],
                capture_output=True, text=True, timeout=5,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            ip = parts[0]
            if ":" in ip or parts[1] != "dev":
                continue
            # hanya host di subnet aktif yang relevan; entri dari subnet
            # sebelumnya harus diabaikan
            if self.local_nets and not self.is_local(ip):
                continue
            try:
                mac = parts[parts.index("lladdr") + 1]
            except (ValueError, IndexError):
                continue
            if mac in {"00:00:00:00:00:00", "incomplete"}:
                continue
            host = self._touch(ip, mac)
            host.source = "neigh"


class InterfaceCounters:
    """Fallback tanpa root: total rx/tx per interface dari /proc/net/dev.

    Tidak memberi data per-host, tapi tetap berguna untuk melihat apakah
    link sedang dipakai atau idle tanpa perlu sudo.
    """

    def __init__(self, iface: str):
        self.iface = iface
        self._last: tuple[int, int] | None = None
        self._last_time = time.monotonic()
        self.rx_rate = 0.0
        self.tx_rate = 0.0

    def read(self) -> tuple[int, int]:
        try:
            with open("/proc/net/dev") as fh:
                for line in fh:
                    if ":" not in line:
                        continue
                    name, _, rest = line.partition(":")
                    if name.strip() != self.iface:
                        continue
                    fields = rest.split()
                    return int(fields[0]), int(fields[8])
        except (OSError, ValueError, IndexError):
            pass
        return 0, 0

    def refresh(self) -> None:
        rx, tx = self.read()
        now = time.monotonic()
        if self._last is not None:
            elapsed = max(now - self._last_time, 0.001)
            self.rx_rate = max(0, (rx - self._last[0]) / elapsed)
            self.tx_rate = max(0, (tx - self._last[1]) / elapsed)
        self._last = (rx, tx)
        self._last_time = now


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------

def arp_scan(net: str, timeout: float = 1.5) -> list[tuple[str, str]]:
    """Scan ARP pada subnet, return list (ip, mac)."""
    try:
        ipnet = __import__("ipaddress").ip_network(net, strict=False)
    except ValueError:
        return []
    targets = [str(h) for h in ipnet.hosts()]
    if len(targets) > 512:
        targets = targets[:512]

    answered: list[tuple[str, str]] = []
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets[0] if targets else "")

    def probe(ip: str) -> tuple[str, str] | None:
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=timeout,
                verbose=0,
            )
        except Exception:
            return None
        for _, r in ans:
            if r[ARP].psrc == ip:
                return ip, r[ARP].hwsrc
        return None

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=64) as pool:
        for result in pool.map(probe, targets):
            if result:
                answered.append(result)
    return answered


# --------------------------------------------------------------------------
# traffic control
# --------------------------------------------------------------------------

class TrafficControl:
    """Blokir & limit host lewat nftables.

    Aturan di sini bekerja di level kernel. Untuk trafik device lain di LAN,
    ARP spoofing (lihat spoof.py) diperlukan lebih dulu supaya trafiknya
    melintasi laptop dan rule-nya bisa kena.
    """

    def __init__(self, iface: str, dry_run: bool = False):
        self.iface = iface
        self.dry_run = dry_run
        self._rules: dict[str, str] = {}
        self.commands: list[str] = []

    def _nft(self, args: list[str]) -> tuple[int, str]:
        cmd = ["nft", *args]
        if self.dry_run:
            self.commands.append(" ".join(cmd))
            return 0, " ".join(cmd)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            return 1, str(exc)
        return proc.returncode, (proc.stdout + proc.stderr).strip()

    def ensure_table(self) -> None:
        self._nft(["add", "table", "inet", NFT_TABLE])
        self._nft(["add", "chain", "inet", NFT_TABLE, NFT_CHAIN, "{ type filter hook output priority 0 ; policy accept ; }"])
        self._nft(["add", "chain", "inet", NFT_TABLE, "input", "{ type filter hook input priority 0 ; policy accept ; }"])
        # Chain prerouting: paket dari korban (dst IP = internet, bukan kita)
        # hanya terlihat di sini, bukan di chain input.
        self._nft(["add", "chain", "inet", NFT_TABLE, "prerouting",
                   "{ type filter hook prerouting priority -150 ; policy accept ; }"])
        # Chain forward: kalau IP forwarding menyala, paket korban akan
        # diteruskan; kita buang di sini.
        self._nft(["add", "chain", "inet", NFT_TABLE, "forward",
                   "{ type filter hook forward priority -150 ; policy accept ; }"])
        # masquerade supaya trafik balikan tetap sampai ke host yang diblokir
        self._nft(["add", "table", "nat", NFT_TABLE])
        self._nft(["add", "chain", "nat", NFT_TABLE, "postrouting", "{ type nat hook postrouting priority srcnat ; policy accept ; }"])

    def block(self, ip: str, spoofer=None) -> bool:
        """Blokir sebuah device supaya kehilangan akses internet.

        nftables saja tidak cukup: aturan di chain input/output hanya
        berlaku untuk trafik milik mesin ini. Device lain di LAN tidak
        pernah melewati laptop, jadi rule-nya tidak pernah kena.

        Solusinya dua tahap:
          1. ARP spoof - korban believe gateway berada di MAC laptop kita,
             sehingga trafik korban dialihkan ke laptop.
          2. Rule nftables drop - sekarang rule-nya benar-benar kena
             karena trafik korban lewat melalui mesin ini.
        """
        self.ensure_table()
        spoofed = False
        if spoofer is not None:
            spoofed = spoofer.poison(ip, mode="block")
            if spoofed:
                spoofer.start()
        # Drop harus di chain prerouting: trafik korban punya dst IP internet,
        # jadi tidak pernah muncul di chain input/output.
        rc, _ = self._nft([
            "add", "rule", "inet", NFT_TABLE, "prerouting",
            "ip", "saddr", ip, "counter", "drop", "comment", f"netcut-block-{ip}",
        ])
        rc2, _ = self._nft([
            "add", "rule", "inet", NFT_TABLE, "forward",
            "ip", "saddr", ip, "counter", "drop", "comment", f"netcut-block-{ip}",
        ])
        rc3, _ = self._nft([
            "add", "rule", "inet", NFT_TABLE, NFT_CHAIN,
            "ip", "daddr", ip, "counter", "drop", "comment", f"netcut-block-{ip}",
        ])
        ok = rc == 0 and rc2 == 0 and rc3 == 0
        if ok:
            self._rules[ip] = "block"
        return ok and (spoofed or spoofer is None)

    def _find_rule_handles(self, marker: str) -> list[tuple[str, str]]:
        """Cari (chain, handle) untuk semua rule yang punya marker di comment.

        Output `nft -a list table` memuat baris chain 'chain X {' dan rule
        '# handle N'. Chain harus diambil dari konteks, bukan diasumsikan.
        """
        rc, out = self._nft(["-a", "list", "table", "inet", NFT_TABLE])
        if rc != 0:
            return []
        found: list[tuple[str, str]] = []
        chain = ""
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("chain "):
                chain = stripped.split()[1].rstrip("{").strip()
                continue
            if marker not in stripped:
                continue
            parts = stripped.split()
            if "handle" in parts:
                handle = parts[parts.index("handle") + 1]
                if chain:
                    found.append((chain, handle))
        return found

    def _delete_rules(self, marker: str) -> int:
        count = 0
        for chain, handle in self._find_rule_handles(marker):
            rc, _ = self._nft([
                "delete", "rule", "inet", NFT_TABLE, chain, "handle", handle,
            ])
            if rc == 0:
                count += 1
        return count

    def unblock(self, ip: str, spoofer=None) -> bool:
        self._rules.pop(ip, None)
        self._delete_rules(f"netcut-block-{ip}")
        if spoofer is not None:
            # kembalikan cache ARP korban ke gateway asli
            spoofer.restore(ip)
        return True

    def limit(self, ip: str, kbps: int, spoofer=None) -> bool:
        """Batasi bandwidth host ke kbps.

        Untuk device lain di LAN, rule nftables biasa tidak berlaku
        (trafiknya tidak pernah melewati laptop). Jadi ARP spoof + relay
        dipakai: trafik korban dialihkan ke laptop, lalu di-rate-limit di
        chain prerouting, lalu diteruskan ke gateway asli.

        nftables `limit rate` hanya menerima satuan bytes/kbytes/mbytes per
        detik, jadi kbps (kilobit) harus dikonversi ke kbytes: /8.
        """
        self.ensure_table()
        if spoofer is not None:
            if not spoofer.poison(ip, mode="relay"):
                print("error: ARP spoof gagal (MAC korban tidak ditemukan)", file=sys.stderr)
                return False
            spoofer.start()
        # nft `limit rate` memakai token bucket: burst pertama lolos begitu
        # saja, sehingga rata-rata aktual lebih rendah dari nilai nominal.
        # Faktor kompensasi dipakai agar angka yang dilihat pengguna
        # mendekati nilai yang diminta.
        rate = f"{max(1, int(kbps / 8 * 1.6))} kbytes/second"
        # Limit dipasang di chain FORWARD: trafik korban yang sudah
        # di-spoof akan diteruskan (forwarded) oleh kernel, jadi chain
        # forward adalah tempat yang tepat untuk membatasi.
        #
        # CATATAN PENTING - hanya arah UPLOAD (saddr) yang bisa dibatasi
        # di router yang kebal ARP spoofing. Arah download (balasan dari
        # internet) dikirim router langsung ke korban karena entri ARP
        # router tidak bisa dipalsukan, sehingga rule daddr tidak pernah
        # kena. Pada router yang menerima ARP spoof (mis. OpenWrt dengan
        # arp_ignore=0), kedua arah bisa dibatasi.
        ok = True
        for direction in ("saddr", "daddr"):
            rc, out = self._nft([
                "add", "rule", "inet", NFT_TABLE, "forward",
                "ip", direction, ip,
                "limit", "rate", rate,
                "counter", "accept",
                "comment", f"netcut-limit-{ip}",
            ])
            if rc != 0:
                print(f"error: nft limit ({direction}) gagal: {out}", file=sys.stderr)
                ok = False
                continue
            rc2, out2 = self._nft([
                "add", "rule", "inet", NFT_TABLE, "forward",
                "ip", direction, ip, "counter", "drop", "comment", f"netcut-limit-{ip}",
            ])
            if rc2 != 0:
                print(f"error: nft drop ({direction}) gagal: {out2}", file=sys.stderr)
                ok = False
        if ok:
            self._rules[ip] = f"limit-{kbps}"
        return ok

    def unlimit(self, ip: str, spoofer=None) -> bool:
        self._rules.pop(ip, None)
        self._delete_rules(f"netcut-limit-{ip}")
        if spoofer is not None:
            spoofer.restore(ip)
        return True

    def clear_all_rules(self) -> int:
        """Hapus semua rule netcut kita. Dipakai saat pindah WiFi.

        Rule lama menunjuk ke IP di subnet sebelumnya, jadi tidak relevan
        lagi dan hanya membingungkan.
        """
        count = 0
        for marker in ("netcut-block-", "netcut-limit-"):
            count += self._delete_rules(marker)
        self._rules.clear()
        return count

    def list_rules(self) -> str:
        rc, out = self._nft(["-a", "list", "table", "inet", NFT_TABLE])
        return out if rc == 0 else "(belum ada tabel nftables netcut / butuh root)"


# --------------------------------------------------------------------------
# UI
# --------------------------------------------------------------------------

def fmt_rate(bps: float) -> str:
    if bps <= 0:
        return "0"
    for unit, div in (("GB/s", 1e9), ("MB/s", 1e6), ("KB/s", 1e3)):
        if bps >= div:
            return f"{bps / div:.1f} {unit}"
    return f"{bps:.0f} B/s"


def fmt_bytes(n: int) -> str:
    for unit, div in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= div:
            return f"{n / div:.1f} {unit}"
    return f"{n} B"


def default_iface() -> str:
    try:
        out = subprocess.run(["ip", "route", "get", "1.1.1.1"],
                             capture_output=True, text=True, timeout=5).stdout
        for token in out.split():
            if token == "dev":
                idx = out.split().index("dev")
                return out.split()[idx + 1]
    except (OSError, subprocess.SubprocessError, IndexError):
        pass
    return "eth0"


def run_tui(sniffer: Sniffer, tc: TrafficControl, fallback=None, duration: int = 0) -> None:
    """TUI sederhana berbasis ANSI (tanpa dependensi luar)."""
    if not sys.stdout.isatty():
        print("error: TUI butuh terminal. Pakai --once atau --json.", file=sys.stderr)
        sys.exit(1)

    stop = {"flag": False}

    def handler(signum, frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    started = time.time()
    print("\x1b[?1049h")  # alternate screen
    try:
        while not stop["flag"]:
            if fallback is None:
                sniffer.poll()
            else:
                fallback.refresh()
            sniffer.merge_neighbors()
            sniffer.refresh_rates()

            rows = sorted(
                sniffer.hosts.values(),
                key=lambda h: h.rx_rate + h.tx_rate,
                reverse=True,
            )
            lines = [
                "\x1b[H\x1b[2J",  # clear
                f"  netcut-linux  iface={sniffer.iface}  "
                f"uptime={int(time.time() - started)}s  pkts={sniffer.packets}",
            ]
            if fallback is not None:
                lines.append(f"  MODE FALLBACK (tanpa root) - interface total: "
                             f"RX {fmt_rate(fallback.rx_rate)}  TX {fmt_rate(fallback.tx_rate)}")
            lines += [
                f"  {'IP':<16}{'MAC':<18}{'RX':>11}{'TX':>11}{'TOTAL':>11}  VENDOR",
                "  " + "-" * 96,
            ]
            for h in rows[:24]:
                lines.append(
                    f"  {h.ip:<16}{h.mac:<18}"
                    f"{fmt_rate(h.rx_rate):>11}{fmt_rate(h.tx_rate):>11}"
                    f"{fmt_bytes(h.rx + h.tx):>11}  {h.vendor[:34]}"
                )
            if not rows:
                lines.append("  (menunggu trafik...)")
            lines.append("")
            lines.append("  ctrl-c untuk keluar")
            sys.stdout.write("\n".join(lines) + "\n")
            sys.stdout.flush()
            time.sleep(1.0)
    finally:
        print("\x1b[?1049l")  # restore screen


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="netcut",
        description="Linux network bandwidth monitor & traffic controller (port NetCut).",
    )
    parser.add_argument("-i", "--iface", default=None, help="interface (default: route ke 1.1.1.1)")
    parser.add_argument("--once", action="store_true", help="snapshot sekali lalu keluar")
    parser.add_argument("--json", action="store_true", help="output JSON")
    parser.add_argument("--seconds", type=int, default=5, help="durasi snapshot (default 5)")
    parser.add_argument("--scan", action="store_true", help="ARP scan dan tampilkan hasil")
    parser.add_argument("--net", default=None, help="subnet untuk --scan, mis. 192.168.1.0/24")
    parser.add_argument("--block", metavar="IP", help="blokir host")
    parser.add_argument("--cut", metavar="IP",
                        help="cut koneksi host (mode NetCut: ARP spoof + drop)")
    parser.add_argument("--unblock", metavar="IP", help="lepas blokir host")
    parser.add_argument("--limit", nargs=2, metavar=("IP", "KBPS"), help="batasi bandwidth host")
    parser.add_argument("--unlimit", metavar="IP", help="lepas limit bandwidth")
    parser.add_argument("--list-rules", action="store_true", help="tampilkan aturan nftables aktif")
    parser.add_argument("--dry-run", action="store_true", help="tampilkan perintah tanpa eksekusi")
    parser.add_argument("--web", action="store_true",
                        help="jalankan web GUI di browser")
    parser.add_argument("--web-port", type=int, default=8080, help="port web GUI (default 8080)")
    parser.add_argument("--web-host", default="127.0.0.1",
                        help="bind address web GUI (default 127.0.0.1, lokal saja)")
    args = parser.parse_args()

    iface = args.iface or default_iface()
    is_root = os.geteuid() == 0

    if args.web:
        if not is_root:
            print("peringatan: tanpa root, web GUI hanya menampilkan mode fallback "
                  "(total interface + daftar host, bukan data per-host).", file=sys.stderr)
        try:
            import webgui
        except ImportError:
            print("error: file webgui.py tidak ditemukan di direktori yang sama.", file=sys.stderr)
            return 1
        webgui.serve(iface=iface, port=args.web_port, host=args.web_host)
        return 0

    if args.list_rules:
        print(TrafficControl(iface, dry_run=args.dry_run).list_rules())
        return 0

    if args.block or args.unblock or args.limit or args.unlimit or args.cut:
        if not is_root and not args.dry_run:
            print("error: --block/--cut/--limit butuh root (sudo).", file=sys.stderr)
            return 1
        tc = TrafficControl(iface, dry_run=args.dry_run)
        spoofer = None
        if not args.dry_run:
            try:
                import spoof as spoof_mod
                spoofer = spoof_mod.ArpSpoofer(iface)
            except ImportError:
                print("peringatan: spoof.py tidak ditemukan, blokir hanya berlaku "
                      "untuk trafik mesin ini.", file=sys.stderr)
        if args.block:
            ok = tc.block(args.block, spoofer=spoofer)
            print(f"{'DRY-RUN: ' if args.dry_run else ''}blokir {args.block}: {'ok' if ok else 'gagal'}")
            if spoofer is not None and ok:
                print("  ARP spoof aktif: korban believes gateway = laptop ini.")
                print("  Keepalive daemon dijalankan; ctrl-c untuk mengembalikan ARP cache.")
                _spoofer_daemon(spoofer, tc)
                return 0
        if args.cut:
            ok = tc.block(args.cut, spoofer=spoofer)
            print(f"{'DRY-RUN: ' if args.dry_run else ''}cut {args.cut}: {'ok' if ok else 'gagal'}")
            if spoofer is not None and ok:
                print("  ARP spoof aktif. ctrl-c untuk mengembalikan ARP cache.")
                _spoofer_daemon(spoofer, tc)
                return 0
        if args.unblock:
            tc.unblock(args.unblock, spoofer=spoofer)
            print(f"lepas blokir {args.unblock}: ok")
        if args.limit:
            ip, kbps = args.limit
            ok = tc.limit(ip, int(kbps), spoofer=spoofer)
            print(f"{'DRY-RUN: ' if args.dry_run else ''}limit {ip} -> {kbps} kbps: {'ok' if ok else 'gagal'}")
            if spoofer is not None and ok:
                print("  ARP spoof + relay aktif: trafik korban diteruskan ke gateway,")
                print("  tetapi di-rate-limit di laptop. Ctrl-C untuk mengembalikan.")
                _spoofer_daemon(spoofer, tc)
                return 0
        if args.unlimit:
            tc.unlimit(args.unlimit, spoofer=spoofer)
            print(f"lepas limit {args.unlimit}: ok")
        if args.dry_run and tc.commands:
            print("\nperintah nft yang akan dijalankan:")
            for cmd in tc.commands:
                print(f"  {cmd}")
        return 0

    if args.scan:
        net = args.net or _guess_net(iface)
        print(f"scan ARP {net} ...")
        for ip, mac in sorted(arp_scan(net), key=lambda x: _ipkey(x[0])):
            print(f"  {ip:<16}{mac}")
        return 0

    # mode monitor
    sniffer = Sniffer(iface)
    fallback: InterfaceCounters | None = None
    try:
        sniffer.open()
    except PermissionError:
        fallback = InterfaceCounters(iface)
        print("peringatan: capture per-host butuh root (sudo). "
              "Mode fallback: hanya total interface + daftar host dari ARP/neigh.",
              file=sys.stderr)
    except OSError as exc:
        print(f"error: tidak bisa buka {iface}: {exc}", file=sys.stderr)
        return 1

    tc = TrafficControl(iface)

    if args.once or args.json:
        deadline = time.time() + args.seconds
        while time.time() < deadline:
            if fallback is None:
                sniffer.poll()
            else:
                fallback.refresh()
            time.sleep(0.1)
        sniffer.merge_neighbors()
        sniffer.refresh_rates()
        rows = sorted(sniffer.hosts.values(), key=lambda h: h.rx + h.tx, reverse=True)
        if args.json:
            out = [
                {
                    "ip": h.ip, "mac": h.mac, "vendor": h.vendor,
                    "rx": h.rx, "tx": h.tx,
                    "rx_rate": round(h.rx_rate, 1), "tx_rate": round(h.tx_rate, 1),
                    "source": h.source,
                }
                for h in rows
            ]
            out.append({
                "scope": "remote",
                "note": "trafik ke/dari internet via gateway",
                "rx": sniffer.remote_rx, "tx": sniffer.remote_tx,
            })
            if fallback is not None:
                out.append({
                    "interface": iface,
                    "mode": "fallback-no-root",
                    "rx_rate": round(fallback.rx_rate, 1),
                    "tx_rate": round(fallback.tx_rate, 1),
                })
            print(json.dumps(out, indent=2))
        else:
            print(f"{'IP':<16}{'MAC':<18}{'RX':>11}{'TX':>11}{'TOTAL':>11}  VENDOR")
            print("-" * 100)
            for h in rows:
                print(f"{h.ip:<16}{h.mac:<18}{fmt_rate(h.rx_rate):>11}"
                      f"{fmt_rate(h.tx_rate):>11}{fmt_bytes(h.rx + h.tx):>11}  {h.vendor[:34]}")
            if sniffer.remote_rx or sniffer.remote_tx:
                print(f"{'(internet via gateway)':<16}{'':<18}"
                      f"{fmt_bytes(sniffer.remote_rx):>11}{fmt_bytes(sniffer.remote_tx):>11}"
                      f"{fmt_bytes(sniffer.remote_rx + sniffer.remote_tx):>11}")
            if fallback is not None:
                print()
                print(f"  interface {iface} total: RX {fmt_rate(fallback.rx_rate)}  "
                      f"TX {fmt_rate(fallback.tx_rate)}  (mode fallback tanpa root)")
        sniffer.close()
        return 0

    try:
        run_tui(sniffer, tc, fallback)
    finally:
        sniffer.close()
    return 0


def _guess_net(iface: str) -> str:
    try:
        out = subprocess.run(["ip", "-4", "addr", "show", "dev", iface],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                addr = line.split()[1]
                return str(__import__("ipaddress").ip_interface(addr).network)
    except (OSError, subprocess.SubprocessError, IndexError):
        pass
    return "192.168.1.0/24"


def _spoofer_daemon(spoofer, tc) -> None:
    """Jaga spoofing tetap hidup & kembalikan ARP cache saat keluar.

    Tanpa daemon ini, ARP cache korban akan expire dalam ~1 menit dan
    koneksi korban pulih sendiri - persis perilaku yang NetCut Hindari
    dengan service yang berjalan terus.
    """
    import signal

    stop = {"flag": False}

    def handler(signum, frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    print("  (tekan ctrl-c untuk melepas blokir & mengembalikan ARP cache)")
    try:
        while not stop["flag"]:
            time.sleep(1.0)
    finally:
        print("\nmengembalikan ARP cache korban...")
        spoofer.stop()
        for ip in list(tc._rules):
            tc.unblock(ip, spoofer=spoofer)
        print("selesai.")


def _ipkey(ip: str) -> tuple:
    try:
        return tuple(int(p) for p in ip.split("."))
    except ValueError:
        return (0, 0, 0, 0)


def _iface_network(iface: str):
    """Ambil jaringan IPv4 yang dipakai interface (mis. 192.168.1.0/24)."""
    import ipaddress
    try:
        out = subprocess.run(["ip", "-4", "addr", "show", "dev", iface],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            try:
                return ipaddress.ip_interface(line.split()[1]).network
            except ValueError:
                return None
    return None


def current_network(iface: str | None = None) -> dict:
    """Identitas jaringan aktif: gateway, IP lokal, subnet, SSID.

    Dipakai untuk mendeteksi perpindahan WiFi (ganti SSID / hotspot).

    iface: bila diberikan, gateway dicari dari route yang memakai interface
    itu (bukan default route global), supaya hasilnya benar even ketika
    ada beberapa interface (eth + wlan) aktif bersamaan.
    """
    import ipaddress
    info = {"gateway": "", "ip": "", "net": "", "ssid": "", "iface": iface or ""}

    # gateway: route default yang melewati interface target
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            dev = parts[parts.index("dev") + 1] if "dev" in parts else ""
            gw = parts[parts.index("via") + 1] if "via" in parts else ""
            if iface and dev != iface:
                continue
            if not info["gateway"] and gw:
                info["gateway"] = gw
            if not info["iface"]:
                info["iface"] = dev
    except (OSError, subprocess.SubprocessError):
        pass

    if not info["iface"]:
        info["iface"] = default_iface()
    iface = info["iface"]

    # IP & subnet dari interface
    try:
        out = subprocess.run(["ip", "-4", "addr", "show", "dev", iface],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        out = ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("inet ") and not info["ip"]:
            try:
                iface_obj = ipaddress.ip_interface(line.split()[1])
                info["ip"] = str(iface_obj.ip)
                info["net"] = str(iface_obj.network)
            except ValueError:
                pass

    # SSID (tidak butuh root)
    try:
        out = subprocess.run(["iw", "dev", iface, "link"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("SSID:"):
                info["ssid"] = line.split(":", 1)[1].strip()
                break
    except (OSError, subprocess.SubprocessError):
        pass
    return info


def _iface_addr(iface: str) -> str:
    """Ambil alamat IPv4 utama interface (mis. 192.168.1.18)."""
    try:
        out = subprocess.run(["ip", "-4", "addr", "show", "dev", iface],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            return line.split()[1].split("/")[0]
    return ""


if __name__ == "__main__":
    sys.exit(main())
