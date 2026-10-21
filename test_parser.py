#!/usr/bin/env python3
"""Unit test untuk parser frame di netcut.py (tanpa perlu root).

Membangun frame Ethernet/IPv4/ARP sintetis dengan scapy lalu memastikan
Sniffer._handle menghitung byte dan memetakan MAC -> vendor dengan benar.
"""
import socket
import struct
import sys
import types

sys.path.insert(0, "/home/aryoks/netcut-linux")

import netcut as nc
from scapy.all import ARP, Ether, IP, TCP


def make_snip(net="10.0.0.0/24") -> nc.Sniffer:
    # network test mencakup 10.0.0.0/24 dan 192.168.1.0/24 supaya ARP
    # test (192.168.1.50) tetap dianggap host lokal.
    ipaddress = __import__("ipaddress")
    s = nc.Sniffer("lo")
    s.hosts = {}
    s.local_net = ipaddress.ip_network("10.0.0.0/24")
    s.local_nets = [s.local_net, ipaddress.ip_network("192.168.1.0/24")]
    # vendor db minimal untuk assertion
    s.vendor = nc.VendorDB()
    s.vendor._db = {"286FB9": "Nokia Shanghai Bell Co., Ltd."}
    s.vendor._loaded = True
    return s
    s = nc.Sniffer("lo")
    s.hosts = {}
    s.local_net = __import__("ipaddress").ip_network(net)
    s.local_nets = [s.local_net]
    # vendor db minimal untuk assertion
    s.vendor = nc.VendorDB()
    s.vendor._db = {"286FB9": "Nokia Shanghai Bell Co., Ltd."}
    s.vendor._loaded = True
    return s


def test_ipv4_counting():
    s = make_snip()
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()
    frame = bytes(pkt)
    s._handle(frame)
    assert "10.0.0.2" in s.hosts, "dst host tidak terdaftar"
    assert "10.0.0.1" in s.hosts, "src host tidak terdaftar"
    src_h = s.hosts["10.0.0.1"]
    dst_h = s.hosts["10.0.0.2"]
    # panjang IP total harus sama untuk src (tx) dan dst (rx)
    assert src_h.tx == dst_h.rx, f"tx {src_h.tx} != rx {dst_h.rx}"
    assert src_h.tx == len(pkt) - 14, f"panjang {src_h.tx} != {len(pkt) - 14}"
    assert src_h.mac == "00:11:22:33:44:55", src_h.mac
    assert dst_h.mac == "66:77:88:99:aa:bb", dst_h.mac
    print("  ok  ipv4 counting & mac mapping")


def test_arp_parsing():
    s = make_snip()
    pkt = Ether(src="28:6f:b9:aa:bb:cc", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc="28:6f:b9:aa:bb:cc", psrc="192.168.1.50")
    s._handle(bytes(pkt))
    assert "192.168.1.50" in s.hosts, "host ARP tidak terdaftar"
    h = s.hosts["192.168.1.50"]
    assert h.mac == "28:6f:b9:aa:bb:cc", h.mac
    assert h.vendor == "Nokia Shanghai Bell Co., Ltd.", h.vendor
    print("  ok  arp parse & vendor lookup")


def test_broadcast_ignored():
    """Broadcast (255.255.255.255) bukan host LAN -> masuk bucket remote."""
    s = make_snip()
    s._handle(bytes(Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:ff") / IP(src="10.0.0.9", dst="255.255.255.255")))
    assert "255.255.255.255" not in s.hosts, "broadcast tidak boleh jadi host"
    assert s.remote_tx > 0, "broadcast harus dihitung sebagai trafik keluar"
    assert s.hosts["10.0.0.9"].tx > 0, "src LAN harus tercatat"
    print("  ok  broadcast treated as remote")


def test_rate_calc():
    s = make_snip()
    s._handle(bytes(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()))
    before = s.hosts["10.0.0.1"].tx
    s._handle(bytes(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()))
    s.refresh_rates()
    assert s.hosts["10.0.0.1"].tx > before, "counter tidak bertambah"
    assert s.hosts["10.0.0.1"].tx_rate > 0, "rate harus > 0"
    print("  ok  rate calculation")


def test_short_frame_rejected():
    s = make_snip()
    for bad in (b"", b"\x00" * 10):
        try:
            s._handle(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"frame pendek {len(bad)}B seharusnya ditolak")
    print("  ok  short frame rejected")


def test_remote_split():
    """IP di luar LAN harus masuk bucket remote, bukan jadi host LAN."""
    s = make_snip(net="10.0.0.0/24")
    s._handle(bytes(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                     / IP(src="10.0.0.1", dst="93.184.216.34") / TCP()))
    assert "10.0.0.1" in s.hosts, "src LAN harus jadi host"
    assert "93.184.216.34" not in s.hosts, "IP remote tidak boleh jadi host LAN"
    assert s.remote_tx > 0, "remote_tx (upload ke internet) harus bertambah"
    assert s.remote_rx == 0, "remote_rx harus 0 untuk trafik keluar"
    assert s.peer_bytes == 0, "peer_bytes harus 0 untuk trafik ke internet"
    assert s.hosts["10.0.0.1"].tx > 0, "tx host LAN harus bertambah"

    # paket dari internet ke host LAN -> remote_rx (download)
    s2 = make_snip(net="10.0.0.0/24")
    s2._handle(bytes(Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
                      / IP(src="93.184.216.34", dst="10.0.0.1") / TCP()))
    assert s2.remote_rx > 0, "remote_rx (download dari internet) harus bertambah"
    assert s2.remote_tx == 0, "remote_tx harus 0 untuk trafik masuk"
    assert s2.peer_bytes == 0, "peer_bytes harus 0 untuk trafik dari internet"
    assert s2.hosts["10.0.0.1"].rx > 0, "rx host LAN harus bertambah"
    print("  ok  remote vs local traffic split")


def test_peer_traffic():
    """Trafik antar dua host LAN harus masuk bucket peer, bukan internet."""
    s = make_snip(net="10.0.0.0/24")
    s._handle(bytes(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                     / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()))
    assert s.peer_bytes > 0, "peer_bytes harus bertambah"
    assert s.remote_rx == 0 and s.remote_tx == 0, "trafik LAN tidak boleh masuk bucket internet"
    assert s.hosts["10.0.0.1"].tx > 0 and s.hosts["10.0.0.2"].rx > 0, "arah tx/rx salah"
    print("  ok  peer-to-peer LAN traffic separated")


def test_no_double_count():
    """Total yang dihitung tidak boleh dobel untuk satu frame.

    Frame internet->LAN: total rx host + remote_rx boleh dua sisi berbeda,
    tapi bucket peer harus 0 dan host remote tidak boleh ada.
    """
    s = make_snip(net="10.0.0.0/24")
    frame = bytes(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                  / IP(src="93.184.216.34", dst="10.0.0.1") / TCP())
    s._handle(frame)
    ip_len = len(frame) - 14
    # total byte yang tercatat = rx host (1x) + peer (0) ; remote_rx adalah
    # view yang sama, bukan tambahan
    assert s.hosts["10.0.0.1"].rx == ip_len, "rx host harus sama dengan panjang IP"
    assert s.peer_bytes == 0, "trafik internet bukan peer"
    print("  ok  no double counting across buckets")


def test_fmt_helpers():
    assert nc.fmt_rate(0) == "0"
    assert "MB/s" in nc.fmt_rate(5_000_000)
    assert nc.fmt_bytes(0) == "0 B"
    assert "KB" in nc.fmt_bytes(2048)
    print("  ok  formatting helpers")


def test_neigh_parser() -> None:
    """parse_neigh harus menerima kedua bentuk output `ip neigh show`.

    Regresi: dulu parser mewajibkan token `dev`, padahal pemanggilan dengan
    `dev <iface>` tidak menyertakan token itu — akibatnya tabel neighbour
    tidak pernah masuk dan perangkat idle hilang dari dashboard.
    """
    tanpa_filter = (
        "192.168.1.7 dev wlp0s20f3 lladdr 32:e6:36:7f:7c:fe STALE\n"
        "192.168.1.1 dev wlp0s20f3 lladdr 78:91:e9:bd:77:14 REACHABLE\n"
        "fe80::30e6:36ff:fe7f:7cfe dev wlp0s20f3 lladdr 32:e6:36:7f:7c:fe STALE\n"
    )
    dengan_filter = (
        "192.168.1.7 lladdr 32:e6:36:7f:7c:fe STALE\n"
        "192.168.1.1 lladdr 78:91:e9:bd:77:14 REACHABLE\n"
        "192.168.1.9 dev wlp0s20f3 FAILED\n"
        "fe80::30e6:36ff:fe7f:7cfe lladdr 32:e6:36:7f:7c:fe STALE\n"
    )
    harap = [("192.168.1.7", "32:e6:36:7f:7c:fe"),
             ("192.168.1.1", "78:91:e9:bd:77:14")]
    assert nc.parse_neigh(tanpa_filter) == harap, nc.parse_neigh(tanpa_filter)
    assert nc.parse_neigh(dengan_filter) == harap, nc.parse_neigh(dengan_filter)
    assert nc.parse_neigh("") == []
    print("  ok  parser ip neigh (dengan & tanpa filter dev)")


def test_hostname_cleanup() -> None:
    """clean_hostname: buang domain, tolak placeholder, batasi panjang."""
    assert nc.clean_hostname("hp-andi.lan.", "192.168.0.7") == "hp-andi"
    assert nc.clean_hostname("Galaxy-A54.local") == "Galaxy-A54"
    assert nc.clean_hostname("router") == "router"
    # placeholder / tidak berguna
    assert nc.clean_hostname("") == ""
    assert nc.clean_hostname("   ") == ""
    assert nc.clean_hostname("localhost") == ""
    assert nc.clean_hostname("unknown.") == ""
    assert nc.clean_hostname("192.168.0.7", "192.168.0.7") == ""
    assert nc.clean_hostname("bad\x00name") == ""
    # dipotong, bukan dibuang
    assert len(nc.clean_hostname("x" * 80)) == 32
    print("  ok  pembersih nama host (PTR)")


def test_name_protocols() -> None:
    """Parser mDNS (PTR) dan NetBIOS (NBSTAT) membaca nama dari paket jawaban."""
    # mDNS: satu record PTR
    ans = nc._dns_encode_name("hp-andi.lan")
    pkt = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    pkt += ans + struct.pack("!HHIH", 12, 1, 120, len(ans)) + ans
    assert nc._dns_parse_ptr(pkt) == "hp-andi.lan"

    # nama panjang: encoding label-length harus benar
    assert nc._dns_encode_name("a.bc") == b"\x01a\x02bc\x00"

    # NetBIOS: dua entri, yang pertama group name (harus dilewati)
    group = b"WORKGROUP".ljust(15) + struct.pack("!H", 0x8400)
    unik = b"HP-ANDI".ljust(15) + struct.pack("!H", 0x0400)
    rdata = bytes([2]) + group + unik
    question = nc._nbns_encode_name("*") + struct.pack("!HH", 0x21, 1)
    pkt2 = struct.pack("!HHHHHH", 0x4E43, 0x8400, 1, 1, 0, 0)
    pkt2 += question + b"\xc0\x0c"
    pkt2 += struct.pack("!HHIH", 0x21, 1, 0, len(rdata)) + rdata
    assert nc._nbns_parse_name(pkt2) == "HP-ANDI"

    # paket rusak tidak boleh melempar exception
    assert nc._dns_parse_ptr(b"") == ""
    assert nc._nbns_parse_name(b"\x00") == ""
    assert nc._nbns_parse_name(pkt2[:20]) == ""
    print("  ok  parser nama mDNS + NetBIOS")


def test_dhcp_name() -> None:
    """parse_dhcp membaca hostname (opsi 12) dan vendor class (opsi 60)."""
    def opt(code: int, val: bytes) -> bytes:
        return bytes([code, len(val)]) + val

    bootp = bytearray(236)
    bootp[0] = 1                                    # BOOTREQUEST
    bootp[28:34] = bytes.fromhex("aabbcc001122")    # chaddr
    pkt = bytes(bootp) + b"\x63\x82\x53\x63"
    pkt += opt(53, b"\x01") + opt(12, b"Galaxy-A54")
    pkt += opt(60, b"android-dhcp-14") + b"\xff"

    mac, host, vendor = nc.parse_dhcp(pkt)
    assert mac == "aa:bb:cc:00:11:22"
    assert host == "Galaxy-A54"
    assert vendor == "android-dhcp-14"

    # paket tanpa magic cookie / terlalu pendek harus ditolak, bukan crash
    assert nc.parse_dhcp(b"") is None
    assert nc.parse_dhcp(b"\x00" * 300) is None
    print("  ok  parser DHCP (nama perangkat dari opsi 12/60)")


if __name__ == "__main__":
    print("netcut parser unit tests:")
    for fn in (
        test_ipv4_counting,
        test_arp_parsing,
        test_broadcast_ignored,
        test_rate_calc,
        test_short_frame_rejected,
        test_remote_split,
        test_peer_traffic,
        test_no_double_count,
        test_fmt_helpers,
        test_neigh_parser,
        test_hostname_cleanup,
        test_name_protocols,
        test_dhcp_name,
    ):
        fn()
    print("semua test lulus")
