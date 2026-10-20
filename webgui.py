"""Dashboard web sederhana untuk netcut-linux."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from netcut import Sniffer, arp_scan, default_iface, fmt_bytes, fmt_rate

PAGE = """<!DOCTYPE html>
<html lang="id"><head><meta charset="utf-8">
<title>netcut-linux</title>
<style>
 body{margin:0;background:#11131a;color:#e4e7ee;font:14px system-ui,sans-serif}
 header{padding:10px 18px;background:#181b24;border-bottom:1px solid #2a2f3d}
 main{padding:16px 18px}
 table{width:100%;border-collapse:collapse;background:#181b24;border-radius:8px;overflow:hidden}
 th{text-align:left;font-size:11px;text-transform:uppercase;color:#8b93a7;padding:9px 12px;background:#1e222d}
 td{padding:7px 12px;border-top:1px solid #2a2f3d;font-family:ui-monospace,monospace;font-size:13px}
 .num{text-align:right}
</style></head><body>
<header><b>netcut-linux</b> <span id="meta"></span></header>
<main><table>
<thead><tr><th>IP</th><th>MAC</th><th>Perangkat</th>
<th class="num">Download</th><th class="num">Upload</th><th class="num">Total</th></tr></thead>
<tbody id="rows"></tbody></table></main>
<script>
async function poll(){
 const r=await fetch("/api/hosts"); const d=await r.json();
 document.getElementById("meta").textContent=" "+d.iface+" - "+d.hosts.length+" host";
 document.getElementById("rows").innerHTML=d.hosts.map(h=>
  `<tr><td>${h.ip}</td><td>${h.mac}</td><td>${h.vendor}</td>`+
  `<td class="num">${h.rx_rate}</td><td class="num">${h.tx_rate}</td>`+
  `<td class="num">${h.total}</td></tr>`).join("");
}
poll(); setInterval(poll,1000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    sniffer = None

    def log_message(self, *a):
        pass

    def _send(self, body, ctype="application/json"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            self._send(PAGE.encode(), "text/html; charset=utf-8")
        elif path == "/api/hosts":
            s = self.sniffer
            hosts = [{"ip": h.ip, "mac": h.mac, "vendor": h.vendor,
                      "rx": h.rx, "tx": h.tx, "total": h.rx + h.tx,
                      "rx_rate": round(h.rx_rate, 1),
                      "tx_rate": round(h.tx_rate, 1)} for h in s.hosts.values()]
            self._send(json.dumps({"iface": s.iface, "hosts": hosts}).encode())
        else:
            self._send(b'{"error":"not found"}', )


def serve(iface=None, port=8080, host="127.0.0.1"):
    iface = iface or default_iface()
    sniffer = Sniffer(iface)
    try:
        sniffer.open()
    except (PermissionError, OSError) as exc:
        print(f"error: {exc}", flush=True)
        return 1
    Handler.sniffer = sniffer

    def loop():
        while True:
            sniffer.poll()
            sniffer.merge_neighbors()
            sniffer.refresh_rates()
            time.sleep(0.25)

    threading.Thread(target=loop, daemon=True).start()
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"netcut web GUI: http://{host}:{port}", flush=True)
    httpd.serve_forever()
    return 0
