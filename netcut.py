#!/usr/bin/env python3
"""netcut - Linux network bandwidth monitor & traffic controller.

Arsitektur mengikuti analisis REA terhadap NetCut (arcai.com) Windows build:

    VCNetCutSniffer2   -> raw AF_PACKET capture + promiscuous mode
    CNetCutDiscover    -> ARP scan + neighbour table
    CNetCutSpoofer     -> (tidak diimplementasi; digantikan nftables)
    CNetCutSpeedLimiter-> nftables rate limiter
    CNetCutNetLock     -> nftables drop (blokir host)
    macdata            -> oui.txt vendor lookup

Perbedaan penting dari NetCut Windows:
  - NetCut memakai ARP spoofing (MITM) untuk memblokir host lain. Itu butuh
    root, merusak jaringan, dan membocorkan trafik ke laptop kita. Di sini
    pemblokiran & limit dilakukan lewat nftables, jadi tidak ada ARP reply
    palsu yang dikirim ke jaringan.
  - Pemetaan MAC -> vendor memakai /usr/share/hwdata/oui.txt (paket hwdata)
    alih-alih file 'macdata' bawaan NetCut.

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
    print("error: butuh scapy. Install dengan: sudo dnf install python3-scapy", file=sys.stderr)
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
# capture  (padanan VCNetCutSniffer2)
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
        description="Linux network bandwidth monitor (port NetCut).",
    )
    parser.add_argument("-i", "--iface", default=None,
                        help="interface (default: route ke 1.1.1.1)")
    parser.add_argument("--once", action="store_true", help="snapshot sekali lalu keluar")
    parser.add_argument("--json", action="store_true", help="output JSON")
    parser.add_argument("--seconds", type=int, default=5, help="durasi snapshot")
    args = parser.parse_args()

    iface = args.iface or default_iface()
    sniffer = Sniffer(iface)
    try:
        sniffer.open()
    except PermissionError:
        print("error: butuh root untuk AF_PACKET capture (sudo).", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: tidak bisa buka {iface}: {exc}", file=sys.stderr)
        return 1

    deadline = time.time() + args.seconds
    while time.time() < deadline:
        sniffer.poll()
        time.sleep(0.1)
    sniffer.refresh_rates()
    rows = sorted(sniffer.hosts.values(), key=lambda h: h.rx + h.tx, reverse=True)
    if args.json:
        print(json.dumps([
            {"ip": h.ip, "mac": h.mac, "rx": h.rx, "tx": h.tx,
             "rx_rate": round(h.rx_rate, 1), "tx_rate": round(h.tx_rate, 1)}
            for h in rows
        ], indent=2))
    else:
        print(f"{'IP':<16}{'MAC':<18}{'RX':>11}{'TX':>11}{'TOTAL':>11}")
        print("-" * 78)
        for h in rows:
            print(f"{h.ip:<16}{h.mac:<18}{fmt_rate(h.rx_rate):>11}"
                  f"{fmt_rate(h.tx_rate):>11}{fmt_bytes(h.rx + h.tx):>11}")
    sniffer.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
