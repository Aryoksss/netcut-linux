#!/usr/bin/env python3
"""Test suite lengkap netcut-linux.

Dijalankan di container dengan:
  docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
    -v ...:/app fedora:44 /usr/bin/python3.14 /app/test_suite.py

menguji:
  1. parser frame (IPv4, ARP, remote-vs-LAN, peer traffic, no double count)
  2. ARP spoof: trafik korban dialihkan ke laptop
  3. Relay: trafik dua arah lewat laptop, korban tetap online
  4. Block: korban kehilangan internet sepenuhnya
  5. Limit: bandwidth korban dibatasi
  6. Cleanup: rule & ARP dikembalikan
"""
import os
import socket
import struct
import subprocess
import sys
import time
from unittest import mock

sys.path.insert(0, "/app")

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print(f"  PASS  {name} {detail}", flush=True)
    else:
        FAIL.append(name)
        print(f"  FAIL  {name} {detail}", flush=True)


def sh(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


# ---------------------------------------------------------------- parser
def test_parser():
    print("\n[1] PARSER", flush=True)
    import netcut
    import ipaddress

    s = netcut.Sniffer("lo")
    s.hosts = {}
    s.local_net = ipaddress.ip_network("10.0.0.0/24")
    s.local_nets = [s.local_net, ipaddress.ip_network("192.168.1.0/24")]
    s.vendor = netcut.VendorDB()
    s.vendor._db = {"286FB9": "Nokia"}
    s.vendor._loaded = True

    from scapy.all import ARP, Ether, IP, TCP
    f = bytes(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
              / IP(src="10.0.0.1", dst="10.0.0.2") / TCP())
    s._handle(f)
    check("ipv4 counting", s.hosts["10.0.0.1"].tx == len(f) - 14)
    check("mac mapping", s.hosts["10.0.0.1"].mac == "00:11:22:33:44:55")

    s2 = netcut.Sniffer("lo")
    s2.hosts = {}
    s2.local_net = ipaddress.ip_network("192.168.1.0/24")
    s2.local_nets = [s2.local_net]
    s2.vendor = netcut.VendorDB()
    s2.vendor._db = {"286FB9": "Nokia"}
    s2.vendor._loaded = True
    s2._handle(bytes(Ether(src="28:6f:b9:aa:bb:cc", dst="ff:ff:ff:ff:ff:ff")
                     / ARP(op=1, hwsrc="28:6f:b9:aa:bb:cc", psrc="192.168.1.50")))
    check("arp parse", s2.hosts.get("192.168.1.50") is not None)
    check("vendor lookup", s2.hosts["192.168.1.50"].vendor == "Nokia",
          s2.hosts["192.168.1.50"].vendor)

    s3 = netcut.Sniffer("lo")
    s3.hosts = {}
    s3.local_net = ipaddress.ip_network("10.0.0.0/24")
    s3.local_nets = [s3.local_net]
    s3.vendor = netcut.VendorDB()
    s3.vendor._loaded = True
    s3._handle(bytes(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                     / IP(src="10.0.0.1", dst="93.184.216.34") / TCP()))
    check("remote not a host", "93.184.216.34" not in s3.hosts)
    check("remote bucket", s3.remote_tx > 0 and s3.peer_bytes == 0)


# ---------------------------------------------------------------- vnet
NS_V, NS_R = "nc_victim", "nc_router"
V_IP, V_GW, R_IP, R_GW = "10.10.0.2", "10.10.0.1", "10.20.0.2", "10.20.0.1"
V_MAC, R_MAC = "02:00:00:00:00:02", "02:00:00:00:00:01"


def setup_vnet():
    sh(f"ip netns del {NS_V} 2>/dev/null; ip netns del {NS_R} 2>/dev/null")
    for i in ("vh1", "vh2", "vh1v", "vh2r"):
        sh(f"ip link del {i} 2>/dev/null")
    sh(f"ip netns add {NS_V}; ip netns add {NS_R}")
    sh(f"ip link add vh1 type veth peer name vh1v")
    sh(f"ip link add vh2 type veth peer name vh2r")
    sh(f"ip link set vh1v netns {NS_V}; ip link set vh2r netns {NS_R}")
    sh(f"ip addr add {V_GW}/24 dev vh1; ip link set vh1 up")
    sh(f"ip addr add {R_GW}/24 dev vh2; ip link set vh2 up")
    sh("sysctl -w net.ipv4.ip_forward=1 >/dev/null")
    sh(f"ip netns exec {NS_V} ip link set lo up")
    sh(f"ip netns exec {NS_V} ip addr add {V_IP}/24 dev vh1v")
    sh(f"ip netns exec {NS_V} ip link set vh1v address {V_MAC}")
    sh(f"ip netns exec {NS_V} ip link set vh1v up")
    sh(f"ip netns exec {NS_V} ip route add default via {V_GW} dev vh1v")
    sh(f"ip netns exec {NS_R} ip link set lo up")
    sh(f"ip netns exec {NS_R} ip addr add {R_IP}/24 dev vh2r")
    sh(f"ip netns exec {NS_R} ip link set vh2r address {R_MAC}")
    sh(f"ip netns exec {NS_R} ip link set vh2r up")
    sh(f"ip netns exec {NS_R} ip route add default via {R_GW} dev vh2r")
    with open("/tmp/nc_srv.py", "w") as fh:
        fh.write("import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
                 "s.bind(('0.0.0.0',9999))\nb=b'x'*4096\n"
                 "while True:\n d,a=s.recvfrom(2048)\n"
                 " for _ in range(500): s.sendto(b,a)\n")
    subprocess.Popen(["setsid", "ip", "netns", "exec", NS_R, "/usr/bin/python3.14", "/tmp/nc_srv.py"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)


def victim_dl(dur=5):
    with open("/tmp/nc_cli.py", "w") as fh:
        fh.write("import socket,sys,time\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
                 "s.settimeout(1.0)\nh,d=sys.argv[1],float(sys.argv[2])\n"
                 "s.sendto(b'g',(h,9999))\nt=0\nend=time.time()+d\n"
                 "while time.time()<end:\n"
                 " try: x,_=s.recvfrom(8192); t+=len(x)\n"
                 " except socket.timeout: break\nprint(t)\n")
    rc, out = sh(f"ip netns exec {NS_V} timeout {dur+5} "
                 f"/usr/bin/python3.14 /tmp/nc_cli.py {R_IP} {dur}")
    for line in out.splitlines():
        if line.strip().isdigit():
            return int(line.strip())
    return 0


def victim_ping():
    """Return (reachable, deskripsi).

    Waspada: "0% packet loss" juga merupakan substring dari
    "100% packet loss", jadi harus dicek persis.
    """
    rc, out = sh(f"ip netns exec {NS_V} ping -c 3 -W 1 {R_IP}")
    for line in out.splitlines():
        if "packet loss" in line:
            pct = line.split("%")[0].strip().split()[-1]
            return (pct == "0"), line.strip()
    return False, out.strip()


def test_vnet():
    print("\n[2] JARINGAN VIRTUAL", flush=True)
    setup_vnet()
    ok, detail = victim_ping()
    check("baseline konektivitas korban", ok, detail)

    import netcut
    import spoof as spoof_mod
    tc = netcut.TrafficControl("vh1")
    sp = spoof_mod.ArpSpoofer("vh1")
    sp.gateway_ip = V_GW
    sp.gateway_mac = sh("cat /sys/class/net/vh1/address")[1].strip()
    sp.our_mac = sp.gateway_mac

    print("\n[3] ARP SPOOF + RELAY", flush=True)
    base = victim_dl(5)
    check("baseline traffic", base > 0, f"{base} byte")
    ok = sp.poison(V_IP, victim_mac=V_MAC, mode="relay")
    check("poison victim", ok)
    sp.start()
    time.sleep(2)
    relayed = victim_dl(5)
    check("relay meneruskan traffic", relayed > 0, f"{relayed} byte")
    ok, detail = victim_ping()
    check("korban tetap online lewat relay", ok, detail)

    print("\n[4] BLOCK", flush=True)
    tc.block(V_IP, spoofer=sp)
    time.sleep(2)
    blocked = victim_dl(5)
    check("block menghentikan traffic", blocked == 0, f"{blocked} byte")
    ok, detail = victim_ping()
    check("korban kehilangan koneksi", not ok, detail)

    print("\n[5] LIMIT", flush=True)
    tc.unblock(V_IP, spoofer=sp)
    sp.stop()
    time.sleep(2)
    ok = tc.limit(V_IP, 64, spoofer=sp)
    check("limit terpasang", ok)
    time.sleep(2)
    limited = victim_dl(6)
    check("limit membatasi bandwidth", limited < base / 2,
          f"{limited} byte vs baseline {base} byte")

    print("\n[6] CLEANUP", flush=True)
    tc.unlimit(V_IP, spoofer=sp)
    sp.stop()
    time.sleep(3)
    after = victim_dl(5)
    check("traffic kembali normal", after > limited * 3, f"{after} byte")
    rc, out = tc._nft(["-a", "list", "table", "inet", "netcut"])
    live = [l for l in out.splitlines() if "netcut-limit" in l or "netcut-block" in l]
    check("semua rule dibersihkan", not live, f"{len(live)} rule tersisa")

    sh(f"ip netns del {NS_V} 2>/dev/null; ip netns del {NS_R} 2>/dev/null")


def test_netchange():
    """Deteksi perpindahan WiFi + reset otomatis."""
    print("\n[7] PERPINDAHAN JARINGAN", flush=True)
    import webgui
    from netcut import current_network

    IFACE = os.environ.get("NC_TEST_IFACE", "wlp0s20f3")
    FAKE_GW = "192.168.50.1"

    st = webgui.WebState(IFACE)
    sh(f"ip route replace default via 192.168.1.1 dev {IFACE}")
    time.sleep(0.5)
    st.net_info = current_network(IFACE)
    st._net_sig = (st.net_info.get("gateway", ""), st.net_info.get("ip", ""),
                   st.net_info.get("ssid", ""))
    if not st.net_info.get("gateway"):
        print("  SKIP  tidak ada default route di interface uji", flush=True)
        return

    # seed state basi
    st.sniffer.hosts["10.0.0.99"] = webgui.Host(ip="10.0.0.99", mac="aa:bb:cc:dd:ee:ff")
    st.blocked_hosts.add("10.0.0.99")
    st.limited_hosts["10.0.0.99"] = 100

    # simulasi ganti WiFi
    sh(f"ip addr flush dev {IFACE}")
    sh(f"ip addr add 192.168.50.18/24 dev {IFACE}")
    sh(f"ip route replace default via {FAKE_GW} dev {IFACE}")
    time.sleep(1.0)
    # perlu 2 konfirmasi berturut-turut sebelum dianggap berubah
    st.check_network_change()
    time.sleep(0.5)
    st._last_net_check = 0.0
    st.check_network_change()

    check("host lama dibersihkan", "10.0.0.99" not in st.sniffer.hosts)
    check("daftar blocked dibersihkan", not st.blocked_hosts)
    check("daftar limited dibersihkan", not st.limited_hosts)
    check("signature jaringan diperbarui", st._net_sig[0] == FAKE_GW)
    check("net_info ter-update", st.net_info.get("gateway") == FAKE_GW)
    check("scan otomatis dijalankan", st.scanning or st.scan_result is not None)
    # scan harus memakai subnet BARU, bukan subnet lama
    for _ in range(40):
        if st.scan_result:
            break
        time.sleep(0.2)
    got = st.scan_result.get("net") if st.scan_result else None
    check("scan memakai subnet baru", got == "192.168.50.0/24", f"scan net = {got}")

    # kembalikan
    sh(f"ip addr flush dev {IFACE}")
    sh(f"ip addr add 192.168.1.18/24 dev {IFACE}")
    sh(f"ip route replace default via 192.168.1.1 dev {IFACE}")
    time.sleep(1.0)


def test_flapping():
    """Gateway berkedip (DHCP reassociation) BUKAN ganti jaringan.

    Kasus ini pernah menghapus spoof + daftar blocked sehingga blokir
    yang baru dibuat langsung hilang dari UI.
    """
    print("\n[8] GATEWAY BERKEDIP (flapping)", flush=True)
    import webgui
    from netcut import current_network

    IFACE = os.environ.get("NC_TEST_IFACE", "wlp0s20f3")
    st = webgui.WebState(IFACE)
    sh(f"ip route replace default via 192.168.1.1 dev {IFACE}")
    time.sleep(0.5)
    st.net_info = current_network(IFACE)
    st._net_sig = (st.net_info.get("gateway", ""), st.net_info.get("ip", ""),
                   st.net_info.get("ssid", ""))
    st._last_net_check = 0.0

    # seed: ada target spoof & host yang diblokir
    st.blocked_hosts.add("192.168.1.50")
    st.limited_hosts["192.168.1.50"] = 100
    st.sniffer.hosts["192.168.1.50"] = webgui.Host(ip="192.168.1.50", mac="aa:bb:cc:dd:ee:ff")

    # simulasi gateway kosong sesaat (link down saat DHCP reassoc)
    st.net_info = {**st.net_info, "gateway": ""}
    st._last_net_check = 0.0
    with mock.patch("webgui.current_network",
                    return_value={**st.net_info, "gateway": ""}):
        st.check_network_change()
    check("spoof & blocked tetap ada saat gateway kosong",
          "192.168.1.50" in st.blocked_hosts and "192.168.1.50" in st.limited_hosts)
    check("host tidak dibersihkan saat gateway kosong",
          "192.168.1.50" in st.sniffer.hosts)

    # gateway kembali, signature sama -> harus dianggap stabil, tidak reset
    st._last_net_check = 0.0
    back = {**st.net_info, "gateway": "192.168.1.1"}
    with mock.patch("webgui.current_network", return_value=back):
        st.check_network_change()
    check("gateway kembali = jaringan sama, state tak direset",
          "192.168.1.50" in st.blocked_hosts)

    # ganti subnet sungguhan -> harus reset (setelah 2 konfirmasi)
    st._last_net_check = 0.0
    newnet = {"gateway": "192.168.50.1", "ip": "192.168.50.18",
              "net": "192.168.50.0/24", "ssid": "WiFiBaru", "iface": IFACE}
    with mock.patch("webgui.current_network", return_value=newnet):
        st.check_network_change()   # konfirmasi 1
        st._last_net_check = 0.0
        st.check_network_change()   # konfirmasi 2 -> reset
    check("ganti subnet sungguhan -> state direset",
          "192.168.1.50" not in st.blocked_hosts
          and "192.168.1.50" not in st.limited_hosts)

    sh(f"ip route replace default via 192.168.1.1 dev {IFACE}")
    time.sleep(0.5)


def main():
    print("=" * 60, flush=True)
    print("netcut-linux TEST SUITE", flush=True)
    print("=" * 60, flush=True)
    test_parser()
    test_vnet()
    test_netchange()
    test_flapping()
    print("\n" + "=" * 60, flush=True)
    print(f"HASIL: {len(PASS)} lulus, {len(FAIL)} gagal", flush=True)
    for f in FAIL:
        print(f"  GAGAL: {f}", flush=True)
    print("=" * 60, flush=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
