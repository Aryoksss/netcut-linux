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
    ):
        fn()
    print("semua test lulus")
