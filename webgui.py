"""Web GUI untuk netcut-linux.

Padanan CNetCutWebServer pada NetCut Windows: antarmuka web untuk melihat
trafik per-host dan mengatur blokir/limit.

Dipakai lewat:  netcut.py --web [--web-port 8080]
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from netcut import (
    Host,
    Sniffer,
    TrafficControl,
    arp_scan,
    current_network,
    default_iface,
    fmt_bytes,
    fmt_rate,
)

PAGE = r"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>netcut-linux</title>
<style>
  :root{
    --bg:#11131a; --panel:#181b24; --panel2:#1e222d; --line:#2a2f3d;
    --fg:#e4e7ee; --dim:#8b93a7; --accent:#5aa9ff; --ok:#4ec98a;
    --warn:#f0b429; --bad:#ef5f6b; --rx:#5aa9ff; --tx:#c98bff;
    --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);
       font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
  header{display:flex;align-items:center;gap:16px;padding:10px 18px;
         background:var(--panel);border-bottom:1px solid var(--line);
         position:sticky;top:0;z-index:10;flex-wrap:wrap}
  .brand{font-weight:650;letter-spacing:-.2px;font-size:15px}
  .brand b{color:var(--accent)}
  .meta{color:var(--dim);font-family:var(--mono);font-size:12px}
  .grow{flex:1}
  .dot{width:7px;height:7px;border-radius:50%;background:var(--ok);
       display:inline-block;margin-right:6px;vertical-align:middle}
  .dot.stale{background:var(--warn)}
  button{font:inherit;font-size:13px;padding:5px 11px;border-radius:6px;
         border:1px solid var(--line);background:var(--panel2);color:var(--fg);
         cursor:pointer}
  button:hover{background:#262b38;border-color:#39405480}
  button.pri{background:#1d4ed8;border-color:#2563eb;color:#fff}
  button.pri:hover{background:#2563eb}
  button.danger{border-color:#ef5f6b55;color:var(--bad)}
  button.danger:hover{background:#ef5f6b1a}
  input,select{font:inherit;font-size:13px;padding:5px 8px;border-radius:6px;
        border:1px solid var(--line);background:#0e1016;color:var(--fg);
        font-family:var(--mono)}
  main{padding:16px 18px 40px;max-width:1400px;margin:0 auto}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
         gap:10px;margin-bottom:16px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:9px;
        padding:11px 13px}
  .card .k{color:var(--dim);font-size:11px;text-transform:uppercase;
           letter-spacing:.5px;margin-bottom:5px}
  .card .v{font-family:var(--mono);font-size:19px;font-weight:600}
  .card .v small{font-size:12px;color:var(--dim);font-weight:400}
  table{width:100%;border-collapse:collapse;background:var(--panel);
        border:1px solid var(--line);border-radius:9px;overflow:hidden}
  th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.5px;
     color:var(--dim);font-weight:600;padding:9px 12px;background:var(--panel2);
     cursor:pointer;white-space:nowrap;user-select:none}
  th:hover{color:var(--fg)}
  td{padding:7px 12px;border-top:1px solid var(--line);font-family:var(--mono);
     font-size:13px;vertical-align:middle}
  tbody tr:hover{background:#1b1f2a}
  tr.blocked{background:#ef5f6b12}
  tr.blocked td:first-child{box-shadow:inset 3px 0 0 var(--bad)}
  .vendor{color:var(--dim);font-family:system-ui,sans-serif;font-size:12px;
          max-width:210px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .num{text-align:right}
  .bar{display:inline-block;height:4px;border-radius:2px;vertical-align:middle;
       margin-left:7px;background:var(--accent)}
  .tag{display:inline-block;padding:1px 7px;border-radius:20px;font-size:11px;
       font-family:system-ui,sans-serif}
  .tag.blk{background:#ef5f6b22;color:var(--bad)}
  .tag.lim{background:#f0b42922;color:var(--warn)}
  .tag.arp{background:#c98bff22;color:var(--tx)}
  .tag.warn{background:#f0b42922;color:var(--warn);cursor:help}
  .row-act{display:flex;gap:5px;justify-content:flex-end}
  .row-act button{padding:3px 8px;font-size:12px}
  .empty{padding:36px;text-align:center;color:var(--dim)}
  #toast{position:fixed;right:16px;bottom:16px;background:var(--panel2);
         border:1px solid var(--line);border-left:3px solid var(--accent);
         padding:9px 14px;border-radius:7px;font-size:13px;opacity:0;
         transform:translateY(8px);transition:.2s;pointer-events:none;z-index:99;
         max-width:340px}
  #toast.on{opacity:1;transform:none}
  #toast.err{border-left-color:var(--bad)}
  .foot{color:var(--dim);font-size:12px;margin-top:14px;line-height:1.6}
  code{font-family:var(--mono);background:#0e1016;padding:1px 5px;border-radius:4px;
       border:1px solid var(--line)}
  .note{background:#f0b42912;border-left:3px solid var(--warn);
        padding:8px 12px;border-radius:5px;margin:10px 0;font-size:13px;
        color:var(--fg)}
  .note b{color:var(--warn)}
</style>
</head>
<body>
<header>
  <span class="brand">netcut<b>-linux</b></span>
  <span class="meta" id="meta">memuat…</span>
  <span class="grow"></span>
  <select id="ifaceSel" title="interface"></select>
  <button id="scanBtn">Scan ARP</button>
  <button id="rulesBtn">Aturan nft</button>
</header>

<main>
  <div class="cards">
    <div class="card"><div class="k">Download</div>
      <div class="v" id="cRx">0</div></div>
    <div class="card"><div class="k">Upload</div>
      <div class="v" id="cTx">0</div></div>
    <div class="card"><div class="k">Host aktif</div>
      <div class="v" id="cHosts">0</div></div>
    <div class="card"><div class="k">Paket</div>
      <div class="v" id="cPkts">0</div></div>
    <div class="card"><div class="k">Total trafik</div>
      <div class="v" id="cTotal">0</div></div>
  </div>

  <table>
    <thead><tr>
      <th data-k="ip">IP</th>
      <th data-k="mac">MAC</th>
      <th data-k="vendor">Perangkat</th>
      <th data-k="rx_rate" class="num">Download</th>
      <th data-k="tx_rate" class="num">Upload</th>
      <th data-k="total" class="num">Total</th>
      <th class="num">Status</th>
      <th class="num">Aksi</th>
    </tr></thead>
    <tbody id="rows"><tr><td colspan="8" class="empty">memuat…</td></tr></tbody>
  </table>

  <p class="foot">
    <b>Blokir</b> memakai ARP spoofing (persis seperti NetCut): victim's gateway
    diarahkan ke laptop ini, lalu rule nftables&nbsp;<code>drop</code> membuang
    trafiknya. Badge <span class="tag arp">ARP spoof</span> menandai target aktif.
    Hanya untuk perangkat milik sendiri di jaringan sendiri.
    <br><b>Limit</b> membatasi bandwidth lewat rate limiter nftables di
    chain&nbsp;<code>forward</code>. Badge <span class="tag warn">!</span>&nbsp;muncul
    bila router menolak ARP spoof - dalam hal ini limit hanya berlaku untuk
    arah upload, dan <b>Blokir</b> adalah cara yang pasti membatasi total.
  </p>
  <div id="notes"></div>
</main>

<div id="toast"></div>

<script>
const $ = s => document.querySelector(s);
let sortKey = "rx_rate", sortDir = -1, blocked = new Set(), limited = new Map();
let maxRate = 1;
let spoofing = new Set();
let notes = {};
let curNet = {};
// Data awal di-inject server-side, jadi halaman tidak flash kosong.
window.__INIT__ = __INIT_DATA__;

function toast(msg, err) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "on" + (err ? " err" : "");
  clearTimeout(t._h);
  t._h = setTimeout(() => t.className = "", 2600);
}

async function api(path, body) {
  const opt = body
    ? {method: "POST", headers: {"Content-Type": "application/json"},
       body: JSON.stringify(body)}
    : {};
  const r = await fetch(path, opt);
  const txt = await r.text();
  try { return JSON.parse(txt); }
  catch { throw new Error(txt.slice(0, 200) || "HTTP " + r.status); }
}

function num(v) { return (v || 0).toLocaleString("id-ID"); }

function render(d) {
  const h = d.hosts || [];
  // Status blokir & spoofing datang dari server supaya tidak hilang saat refresh
  blocked = new Set(d.blocked || []);
  limited = new Map(Object.entries(d.limited || {}));
  spoofing = new Set((d.spoofing || []).map(s => s.ip));
  notes = d.notes || {};
  const scanTxt = d.scanning ? " &middot; <b>scanning…</b>"
                 : (d.scan_result ? " &middot; scan: " + d.scan_result.found + " host" : "");
  const net = d.net || {};
  curNet = net;
  const ssid = net.ssid ? '<b>' + net.ssid + '</b> @ ' + net.gateway : d.iface;
  $("#meta").innerHTML =
    '<span class="dot' + (d.stale ? " stale" : "") + '"></span>' +
    ssid + " &middot; " + h.length + " host &middot; " +
    (d.uptime | 0) + "s &middot; " + d.mode + scanTxt;

  $("#cRx").innerHTML = fmt(d.rx_rate);
  $("#cTx").innerHTML = fmt(d.tx_rate);
  $("#cHosts").textContent = h.length;
  $("#cPkts").textContent = num(d.packets);
  $("#cTotal").innerHTML = fmt(d.total_rate);

  // catatan per host (mis. router menolak ARP spoof)
  const noteKeys = Object.keys(notes);
  $("#notes").innerHTML = noteKeys.length
    ? noteKeys.map(k => '<div class="note"><b>' + k + '</b>: ' + (notes[k]||"") + '</div>').join("")
    : "";

  const sel = $("#ifaceSel");
  if (sel.dataset.done !== "1" && d.interfaces) {
    sel.innerHTML = d.interfaces.map(i =>
      `<option value="${i}"${i === d.iface ? " selected" : ""}>${i}</option>`).join("");
    sel.dataset.done = "1";
  }

  h.sort((a, b) => {
    const x = a[sortKey], y = b[sortKey];
    if (typeof x === "string") return sortDir * x.localeCompare(y);
    return sortDir * ((x || 0) - (y || 0));
  });

  const top = Math.max(...h.map(x => (x.rx_rate || 0) + (x.tx_rate || 0)), 1);
  maxRate = top;

  if (!h.length) {
    $("#rows").innerHTML = '<tr><td colspan="8" class="empty">belum ada host terdeteksi</td></tr>';
    return;
  }

  $("#rows").innerHTML = h.map(x => {
    const bl = blocked.has(x.ip), lim = limited.get(x.ip);
    const sp = spoofing.has(x.ip);
    const total = (x.rx_rate || 0) + (x.tx_rate || 0);
    const w = Math.min(60, (total / top) * 60);
    let st = "";
    if (bl) st += '<span class="tag blk">diblokir</span> ';
    if (sp) st += '<span class="tag arp">ARP spoof</span> ';
    if (lim) st += '<span class="tag lim">limit '+lim+'k</span>';
    if (notes[x.ip]) st += ' <span class="tag warn" title="' +
      (notes[x.ip]||"").replace(/"/g,'&quot;') + '">!</span>';
    return `<tr class="${bl ? "blocked" : ""}">
      <td>${x.ip}</td>
      <td>${x.mac || "-"}</td>
      <td class="vendor" title="${x.vendor || ""}">${x.vendor || "unknown"}</td>
      <td class="num">${fmt(x.rx_rate)}${x.rx_rate ?
        `<span class="bar" style="width:${Math.min(60,(x.rx_rate/top)*60)}px;background:var(--rx)"></span>` : ""}</td>
      <td class="num">${fmt(x.tx_rate)}${x.tx_rate ?
        `<span class="bar" style="width:${Math.min(60,(x.tx_rate/top)*60)}px;background:var(--tx)"></span>` : ""}</td>
      <td class="num">${fmtBytes(x.total)}</td>
      <td class="num">${st}</td>
      <td><div class="row-act">
        ${bl
          ? `<button class="danger" data-act="unblock" data-ip="${x.ip}">Buka</button>`
          : `<button class="danger" data-act="block" data-ip="${x.ip}">Blokir</button>`}
        <button data-act="limit" data-ip="${x.ip}">Limit</button>
        ${lim ? `<button data-act="unlimit" data-ip="${x.ip}">Buka limit</button>` : ""}
      </div></td>
    </tr>`;
  }).join("");
}

function fmt(bps) {
  bps = bps || 0;
  if (bps >= 1e9) return (bps/1e9).toFixed(1) + " <small>GB/s</small>";
  if (bps >= 1e6) return (bps/1e6).toFixed(1) + " <small>MB/s</small>";
  if (bps >= 1e3) return (bps/1e3).toFixed(1) + " <small>KB/s</small>";
  return bps.toFixed(0) + " <small>B/s</small>";
}
function fmtBytes(n) {
  n = n || 0;
  if (n >= 1<<30) return (n/(1<<30)).toFixed(1) + " GB";
  if (n >= 1<<20) return (n/(1<<20)).toFixed(1) + " MB";
  if (n >= 1<<10) return (n/(1<<10)).toFixed(1) + " KB";
  return n + " B";
}

async function poll() {
  try {
    const d = await api("/api/hosts");
    render(d);
  } catch (e) {
    $("#meta").innerHTML = '<span class="dot stale"></span>server tidak merespons';
  }
}

document.querySelectorAll("th[data-k]").forEach(th => {
  th.onclick = () => {
    const k = th.dataset.k;
    if (sortKey === k) sortDir *= -1; else { sortKey = k; sortDir = -1; }
    poll();
  };
});

$("#rows").addEventListener("click", async ev => {
  const b = ev.target.closest("button[data-act]");
  if (!b) return;
  const ip = b.dataset.ip, act = b.dataset.act;
  b.disabled = true;
  try {
    if (act === "block") {
      const r = await api("/api/block", {ip});
      if (r.ok) { blocked.add(ip); toast(ip + " diblokir"); }
      else toast("Gagal blokir " + ip + ": " + (r.error || "tidak diketahui"), true);
    } else if (act === "unblock") {
      const r = await api("/api/unblock", {ip});
      if (r.ok) { blocked.delete(ip); toast(ip + " dibuka"); }
      else toast("Gagal: " + (r.error || "?"), true);
    } else if (act === "limit") {
      const v = prompt("Batas bandwidth untuk " + ip + " (kbps):", "512");
      if (v === null) return;
      const kbps = parseInt(v, 10);
      if (!kbps || kbps <= 0) { toast("Nilai kbps tidak valid", true); return; }
      const r = await api("/api/limit", {ip, kbps});
      if (r.ok) { limited.set(ip, kbps); toast(ip + " dibatasi " + kbps + " kbps"); }
      else toast("Gagal limit " + ip + ": " + (r.error || "tidak diketahui"), true);
    } else if (act === "unlimit") {
      const r = await api("/api/unlimit", {ip});
      if (r.ok) { limited.delete(ip); toast("Limit " + ip + " dibuka"); }
      else toast("Gagal: " + (r.error || "?"), true);
    }
  } catch (e) { toast("Error: " + e.message, true); }
  finally { b.disabled = false; poll(); }
});

$("#scanBtn").onclick = async () => {
  try {
    const body = (curNet && curNet.net) ? { net: curNet.net } : {};
    const r = await api("/api/scan", body);
    if (r.started) { toast("Scanning ARP… (background)"); poll(); }
    else toast("Scan gagal: " + (r.error || "?"), true);
  } catch (e) { toast("Scan gagal: " + e.message, true); }
};

$("#rulesBtn").onclick = async () => {
  try {
    const r = await api("/api/rules");
    alert(r.rules || "(tidak ada aturan)");
  } catch (e) { toast("Gagal: " + e.message, true); }
};

$("#ifaceSel").onchange = async () => {
  const i = $("#ifaceSel").value;
  try {
    const r = await api("/api/iface", {iface: i});
    if (r.ok) { toast("Interface diganti ke " + i); poll(); }
    else toast("Gagal: " + (r.error || "?"), true);
  } catch (e) { toast("Error: " + e.message, true); }
};

if (window.__INIT__) { try { render(window.__INIT__); } catch (e) {} }
poll();
setInterval(poll, 1000);
</script>
</body>
</html>
"""


class WebState:
    """State bersama antara thread capture dan thread HTTP."""

    def __init__(self, iface: str):
        self.lock = threading.Lock()
        self.iface = iface
        self.sniffer = Sniffer(iface)
        self.tc = TrafficControl(iface)
        self.spoofer = None
        try:
            import spoof as spoof_mod
            self.spoofer = spoof_mod.ArpSpoofer(iface)
        except ImportError:
            pass
        self.started = time.time()
        self.stale = False
        self.stop = threading.Event()
        self.hosts_extra: dict[str, str] = {}  # ip -> vendor
        self.scanning = False
        self.scan_result: dict | None = None
        self.blocked_hosts: set[str] = set()
        self.limited_hosts: dict[str, int] = {}
        self.notes: dict[str, str] = {}
        self._net_sig: tuple = ()
        self._pending_sig: tuple | None = None
        self._pending_count = 0
        self._last_net_check = 0.0
        self._last_prune = 0.0
        self.net_info: dict = {}

    # -- capture loop -------------------------------------------------
    def run_capture(self) -> None:
        try:
            self.sniffer.open()
        except (PermissionError, OSError) as exc:
            self.stale = True
            print(f"[web] capture gagal: {exc}", flush=True)
            while not self.stop.is_set():
                self.check_network_change()
                time.sleep(1.0)
            return

        while not self.stop.is_set():
            # deteksi perubahan jaringan DULUAN, sebelum data host lama
            # ditambahkan ke tabel - supaya tidak ada host basi yang
            # lolos ke tampilan.
            self.check_network_change()
            self.sniffer.poll()
            self.sniffer.merge_neighbors()
            self.sniffer.refresh_rates()
            # buang host yang sudah lama tidak terlihat (mis. sisa dari
            # subnet sebelumnya)
            now = time.monotonic()
            if now - self._last_prune > 15:
                self._last_prune = now
                self.sniffer.prune_stale()
            time.sleep(0.25)

    def check_network_change(self) -> None:
        """Deteksi perpindahan WiFi dan lakukan reset + scan otomatis.

        Ganti WiFi (SSID berbeda / hotspot) berarti gateway dan subnet
        berubah. Tanpa handling ini:
          - host list masih berisi IP dari subnet lama
          - ARP spoof masih menunjuk ke gateway yang salah
          - klasifikasi trafik LAN vs internet jadi keliru
        """
        now = time.monotonic()
        if now - self._last_net_check < 3.0:
            return
        self._last_net_check = now

        net = current_network(self.iface)
        sig = (net.get("gateway", ""), net.get("ip", ""), net.get("ssid", ""))
        if not self._net_sig:
            self._net_sig = sig
            self.net_info = net
            return
        if sig == self._net_sig:
            # jaringan stabil - reset counter konfirmasi
            self._pending_sig = None
            self._pending_count = 0
            return

        #.transien (gateway kosong sesaat saat DHCP reassociation) BUKAN
        # perpindahan jaringan. Tanpa pengecekan ini, spoof & daftar
        # blocked ikut terhapus setiap kali WiFi berkedip.
        if not net.get("gateway"):
            # link sedang down / berkedip - tunggu, jangan reset state
            self._pending_sig = None
            self._pending_count = 0
            return

        # Require 2 pemeriksaan berturut-turut dengan signature sama
        # sebelum benar-benar menganggap jaringan berubah.
        if self._pending_sig == sig:
            self._pending_count += 1
        else:
            self._pending_sig = sig
            self._pending_count = 1
        if self._pending_count < 2:
            return

        old = self.net_info or {}
        self._net_sig = sig
        self.net_info = net
        self._pending_sig = None
        self._pending_count = 0
        print(f"[web] jaringan berubah: {old.get('ssid') or old.get('gateway')} "
              f"-> {net.get('ssid') or net.get('gateway')} "
              f"(gw {old.get('gateway')} -> {net.get('gateway')})", flush=True)

        # 1. flush cache ARP kernel DULUAN, supaya entri subnet lama tidak
        #    terambil lagi oleh merge_neighbors() setelah reset
        try:
            subprocess.run(["ip", "neigh", "flush", "dev", self.iface],
                           capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass
        # 2. kembalikan ARP cache korban & hentikan spoofing lama
        if self.spoofer is not None:
            try:
                self.spoofer.reset_for_network_change()
            except Exception:
                pass
        # 3. bersihkan rule nftables lama (IP-nya sudah tidak relevan)
        try:
            self.tc.clear_all_rules()
        except Exception:
            pass
        self.blocked_hosts.clear()
        self.limited_hosts.clear()
        self.notes.clear()
        # 4. reset cache host & deteksi subnet baru
        self.sniffer.reset_for_network_change()
        self.sniffer.host_seen.clear()
        # IP lokal bisa ikut berubah (DHCP memberi IP baru) - perbarui
        # juga label host lokal supaya tidak dianggap host lain.
        self.sniffer.local_ip = net.get("ip", "")
        # 5. scan subnet baru secara otomatis
        self.start_scan()

    def start_scan(self) -> None:
        """Jalankan ARP scan di background (tidak memblokir UI)."""
        if self.scanning:
            return
        self.scanning = True
        self.scan_result = None
        # subnet dibaca langsung dari interface saat ini, bukan dari
        # net_info yang bisa masih berisi data subnet lama
        net = _guess_net(self.iface)

        def _run() -> None:
            try:
                found = arp_scan(net)
                for ip, mac in found:
                    host = self.sniffer.hosts.get(ip)
                    if host:
                        host.mac = mac
                        host.vendor = self.sniffer.vendor.lookup(mac)
                    else:
                        host = self.sniffer._touch(ip, mac)
                        host.vendor = self.sniffer.vendor.lookup(mac)
                self.scan_result = {"found": len(found), "net": net}
            except Exception as exc:
                self.scan_result = {"found": 0, "net": net, "error": str(exc)}
            finally:
                self.scanning = False

        threading.Thread(target=_run, daemon=True).start()

    def swap_iface(self, iface: str) -> tuple[bool, str]:
        with self.lock:
            self.sniffer.close()
            self.iface = iface
            self.sniffer = Sniffer(iface)
            self.tc = TrafficControl(iface)
            try:
                import spoof as spoof_mod
                self.spoofer = spoof_mod.ArpSpoofer(iface)
            except ImportError:
                self.spoofer = None
        try:
            self.sniffer.open()
        except (PermissionError, OSError) as exc:
            self.stale = True
            return False, str(exc)
        self.stale = False
        return True, ""

    def block(self, ip: str) -> tuple[bool, str]:
        """Blokir host lain di LAN (ARP spoof + drop), seperti NetCut.

        ARP resolve bisa memakan waktu beberapa detik, jadi dilakukan di
        background thread supaya request HTTP tidak timeout.
        """
        if self.spoofer is None:
            ok = self.tc.block(ip, spoofer=None)
            if ok:
                self.blocked_hosts.add(ip)
            return ok, "" if ok else "gagal menambah rule nftables"

        if ip in self.blocked_hosts:
            return True, ""

        def _run() -> None:
            try:
                # MAC korban diambil dari tabel host bila ada: kalau device
                # sedang diblokir, dia tidak akan menjawab ARP request.
                host = self.sniffer.hosts.get(ip)
                vmac = host.mac if host else ""
                if not self.spoofer.poison(ip, victim_mac=vmac, mode="block"):
                    print(f"[web] blokir {ip}: ARP spoof gagal "
                          f"(MAC korban tidak ditemukan)", flush=True)
                    self.blocked_hosts.discard(ip)
                    return
                self.spoofer.start()
                ok = self.tc.block(ip, spoofer=None)
                if not ok:
                    print(f"[web] blokir {ip}: gagal menambah rule nftables", flush=True)
                    self.blocked_hosts.discard(ip)
                    return
                self.blocked_hosts.add(ip)
                print(f"[web] blokir {ip}: aktif", flush=True)
            except Exception as exc:
                print(f"[web] blokir {ip} error: {exc!r}", flush=True)
                self.blocked_hosts.discard(ip)

        threading.Thread(target=_run, daemon=True).start()
        # tunggu supaya UI bisa menampilkan status sebelum respons dikirim
        for _ in range(60):
            if ip in self.blocked_hosts:
                return True, ""
            time.sleep(0.1)
        # gagal: jelaskan ke user, jangan laporkan sukses palsu
        return False, "ARP spoof gagal: MAC device tidak ditemukan di jaringan ini"

    def unblock(self, ip: str) -> tuple[bool, str]:
        if self.spoofer is not None:
            self.spoofer.restore(ip)
        self.tc.unblock(ip, spoofer=None)
        self.blocked_hosts.discard(ip)
        return True, ""

    def limit(self, ip: str, kbps: int) -> tuple[bool, str]:
        """Batasi bandwidth device lain (ARP spoof + relay + rate limit)."""
        if self.spoofer is None:
            ok = self.tc.limit(ip, kbps, spoofer=None)
            if ok:
                self.limited_hosts[ip] = kbps
            return ok, "" if ok else "gagal memasang rule limit"

        if ip in self.limited_hosts:
            return True, ""

        note = ""
        # MAC korban dari tabel host: kalau device sedang diblokir dia
        # tidak akan menjawab ARP request.
        host = self.sniffer.hosts.get(ip)
        vmac = host.mac if host else ""

        def _run() -> None:
            nonlocal note
            try:
                # Spoof harus aktif lebih dulu: relay bergantung pada
                # victim's ARP cache yang sudah diarahkan ke laptop, baru
                # rule limit di chain forward bisa mengenali trafiknya.
                if not self.spoofer.poison(ip, victim_mac=vmac, mode="relay"):
                    print(f"[web] limit {ip}: ARP spoof gagal", flush=True)
                    self.limited_hosts.pop(ip, None)
                    return
                self.spoofer.start()
                ok = self.tc.limit(ip, kbps, spoofer=None)
                if ok:
                    self.limited_hosts[ip] = kbps
                    # cek apakah router menerima ARP spoof kita. Kalau tidak,
                    # balasan download bypass laptop sehingga limit hanya
                    # berlaku untuk arah upload.
                    if vmac and not self.spoofer.router_spoofable(ip, vmac):
                        note = ("Router menolak ARP spoof: limit hanya berlaku "
                                "untuk upload. Gunakan Blokir untuk membatasi total.")
                        self.notes[ip] = note
                else:
                    self.limited_hosts.pop(ip, None)
            except Exception as exc:
                print(f"[web] limit {ip} gagal: {exc!r}", flush=True)
                self.limited_hosts.pop(ip, None)

        threading.Thread(target=_run, daemon=True).start()
        for _ in range(80):
            if ip in self.limited_hosts:
                break
            time.sleep(0.1)
        ok = ip in self.limited_hosts
        return ok, (note if ok else "ARP spoof gagal: MAC device tidak ditemukan")

    def unlimit(self, ip: str) -> tuple[bool, str]:
        self.tc.unlimit(ip, spoofer=self.spoofer)
        self.limited_hosts.pop(ip, None)
        self.notes.pop(ip, None)
        return True, ""

    def snapshot(self) -> dict:
        s = self.sniffer
        hosts = []
        for h in s.hosts.values():
            hosts.append({
                "ip": h.ip,
                "mac": h.mac,
                "vendor": h.vendor,
                "rx": h.rx,
                "tx": h.tx,
                "total": h.rx + h.tx,
                "rx_rate": h.rx_rate,
                "tx_rate": h.tx_rate,
                "source": h.source,
            })
        # Total trafik tidak boleh dobel hitung. Setiap frame sudah masuk ke
        # host[src].tx dan host[dst].rx, sehingga menjumlahkan semua host
        # akan menghitung dua kali. Sumber kebenaran:
        #   - trafik internet  : remote_rx_rate + remote_tx_rate
        #   - trafik LAN antar host (bukan ke/dari internet): peer_rate
        rx_total = s.remote_rx_rate
        tx_total = s.remote_tx_rate
        return {
            "iface": self.iface,
            "uptime": time.time() - self.started,
            "mode": "capture" if not self.stale else "fallback-no-root",
            "stale": self.stale,
            "packets": s.packets,
            "dropped": s.dropped,
            "rx_rate": rx_total,
            "tx_rate": tx_total,
            "peer_rate": s.peer_rate,
            "total_rate": rx_total + tx_total + s.peer_rate,
            "hosts": hosts,
            "scanning": self.scanning,
            "scan_result": self.scan_result,
            "net": self.net_info,
            "blocked": sorted(self.blocked_hosts),
            "limited": dict(self.limited_hosts),
            "notes": dict(self.notes),
            "spoofing": self.spoofer.status() if self.spoofer else [],
            "interfaces": _list_ifaces(),
        }


def _list_ifaces() -> list[str]:
    import subprocess
    try:
        out = subprocess.run(["ip", "-o", "link", "show"], capture_output=True,
                             text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    names = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) > 2:
            names.append(parts[1].strip())
    return names


class Handler(BaseHTTPRequestHandler):
    state: WebState = None  # type: ignore
    server_version = "netcut-linux"

    def log_message(self, fmt, *args):
        pass  # quieter

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode())

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            # Inject data awal supaya halaman langsung terisi (no flash kosong)
            init = json.dumps(self.state.snapshot())
            body = PAGE.replace("__INIT_DATA__", init).encode()
            self._send(200, body, "text/html; charset=utf-8")
        elif path == "/api/hosts":
            self._json(self.state.snapshot())
        elif path == "/api/rules":
            self._json({"rules": self.state.tc.list_rules()})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        try:
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, OSError):
            data = {}

        tc = self.state.tc
        try:
            if path == "/api/block":
                ip = data.get("ip", "")
                if not ip:
                    self._json({"ok": False, "error": "ip wajib diisi"}, 400)
                    return
                ok, err = self.state.block(ip)
                self._json({"ok": bool(ok), "ip": ip, "error": err})
            elif path == "/api/unblock":
                ip = data.get("ip", "")
                ok, err = self.state.unblock(ip)
                self._json({"ok": bool(ok), "ip": ip, "error": err})
            elif path == "/api/limit":
                ip = data.get("ip", "")
                kbps = int(data.get("kbps", 0) or 0)
                if not ip or kbps <= 0:
                    self._json({"ok": False, "error": "ip dan kbps wajib diisi"}, 400)
                    return
                ok, err = self.state.limit(ip, kbps)
                self._json({"ok": bool(ok), "ip": ip, "kbps": kbps, "error": err})
            elif path == "/api/unlimit":
                ip = data.get("ip", "")
                ok, err = self.state.unlimit(ip)
                self._json({"ok": bool(ok), "ip": ip, "error": err})
            elif path == "/api/scan":
                net = data.get("net") or _guess_net(self.state.iface)
                # scan bisa memakan waktu lama, jadi jalankan di background
                # supaya UI tidak blocking.
                if self.state.scanning:
                    self._json({"ok": False, "error": "scan sedang berjalan"}, 409)
                    return
                self.state.scanning = True

                def _run() -> None:
                    try:
                        found = arp_scan(net)
                        for ip, mac in found:
                            host = self.state.sniffer.hosts.get(ip)
                            if host:
                                host.mac = mac
                                host.vendor = self.state.sniffer.vendor.lookup(mac)
                            else:
                                host = self.state.sniffer._touch(ip, mac)
                                host.vendor = self.state.sniffer.vendor.lookup(mac)
                        self.state.scan_result = {"found": len(found), "net": net}
                    except Exception as exc:
                        self.state.scan_result = {"found": 0, "net": net, "error": str(exc)}
                    finally:
                        self.state.scanning = False

                threading.Thread(target=_run, daemon=True).start()
                self._json({"ok": True, "started": True, "net": net})
            elif path == "/api/iface":
                iface = data.get("iface", "")
                if not iface:
                    self._json({"ok": False, "error": "iface wajib diisi"}, 400)
                    return
                ok, err = self.state.swap_iface(iface)
                self._json({"ok": ok, "error": err, "iface": iface})
            else:
                self._json({"error": "not found"}, 404)
        except Exception as exc:  # jangan biarkan server mati
            self._json({"ok": False, "error": str(exc)}, 500)


def _guess_net(iface: str) -> str:
    import ipaddress
    import subprocess
    try:
        out = subprocess.run(["ip", "-4", "addr", "show", "dev", iface],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return str(ipaddress.ip_interface(line.split()[1]).network)
    except (OSError, subprocess.SubprocessError, IndexError):
        pass
    return "192.168.1.0/24"


def serve(iface: str | None = None, port: int = 8080, host: str = "127.0.0.1") -> None:
    """Jalankan web GUI. Blocking call."""
    iface = iface or default_iface()
    state = WebState(iface)
    Handler.state = state

    # deteksi jaringan awal + scan otomatis saat start
    state.net_info = current_network(iface)
    state._net_sig = (state.net_info.get("gateway", ""),
                      state.net_info.get("ip", ""),
                      state.net_info.get("ssid", ""))
    print(f"[web] jaringan: {state.net_info.get('ssid') or '?'} "
          f"gw={state.net_info.get('gateway')} ip={state.net_info.get('ip')} "
          f"net={state.net_info.get('net')}", flush=True)

    t = threading.Thread(target=state.run_capture, daemon=True)
    t.start()

    # Bersihkan rule nftables yang tertinggal dari sesi sebelumnya.
    # Tanpa ini, device yang masih diblokir tidak akan menjawab ARP
    # request sehingga tidak ditemukan di scan berikutnya.
    try:
        removed = state.tc.clear_all_rules()
        if removed:
            print(f"[web] {removed} rule lama dibersihkan", flush=True)
    except Exception:
        pass

    # scan subnet awal di background
    threading.Thread(target=state.start_scan, daemon=True).start()

    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"netcut web GUI: http://{host}:{port}  (iface {iface})", flush=True)
    print("  Ctrl-C untuk berhenti", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping…", flush=True)
    finally:
        state.stop.set()
        state.sniffer.close()
        httpd.server_close()
