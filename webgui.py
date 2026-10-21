"""Web GUI untuk netcut-linux.

Antarmuka web untuk melihat trafik per-host dan mengatur blokir/limit.

Dipakai lewat:  netcut.py --web [--web-port 8080]
"""

from __future__ import annotations

import json
import os
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
<html lang="id" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>netcut-linux</title>
<script>
/* Bootstrap tema: jalan sebelum paint supaya tidak ada flash putih. */
(function () {
  var t = null;
  try { t = localStorage.getItem("netcut-theme"); } catch (e) {}
  if (t !== "light" && t !== "dark") t = "dark";  /* dark-first */
  document.documentElement.setAttribute("data-theme", t);
})();
</script>
<style>
/* ============================================================ tokens */
html[data-theme="dark"]{
  --bg:#0e1016; --panel:#161923; --panel2:#1b1f2a; --panel3:#222736;
  --line:#272d3b; --line2:#343c4d;
  --fg:#e7eaf1; --fg2:#b5bcca; --dim:#7e8698;
  --accent:#5aa9ff; --accent-soft:#5aa9ff1f; --accent-line:#5aa9ff55;
  --on-accent:#08111f;
  --ok:#4ec98a; --ok-soft:#4ec98a1f;
  --warn:#f0b429; --warn-soft:#f0b4291f;
  --bad:#ef5f6b; --bad-soft:#ef5f6b1f;
  --rx:#5aa9ff; --tx:#c98bff;
  --shadow:0 12px 32px #0007;
  --sel:#5aa9ff24; --hover:#ffffff08;
}
html[data-theme="light"]{
  --bg:#f2f4f8; --panel:#ffffff; --panel2:#f4f6fa; --panel3:#eaeef4;
  --line:#e0e5ec; --line2:#ccd4e0;
  --fg:#141821; --fg2:#3b4353; --dim:#697283;
  --accent:#2563eb; --accent-soft:#2563eb12; --accent-line:#2563eb44;
  --on-accent:#ffffff;
  --ok:#0f8a54; --ok-soft:#0f8a5414;
  --warn:#9a6300; --warn-soft:#9a630014;
  --bad:#d32b3a; --bad-soft:#d32b3a14;
  --rx:#2563eb; --tx:#9333ea;
  --shadow:0 10px 28px #0f172a1c;
  --sel:#2563eb14; --hover:#0f172a06;
}
:root{
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,Inter,sans-serif;
  --hh:54px; --r:10px;
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0;background:var(--bg);color:var(--fg);
  font:14px/1.45 var(--sans);
  -webkit-font-smoothing:antialiased;
}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;
  overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}
.ic{width:16px;height:16px;flex:none;fill:none;stroke:currentColor;
  stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}
.ic.sm{width:13px;height:13px}

/* ============================================================ topbar */
.topbar{
  position:sticky;top:0;z-index:30;min-height:var(--hh);
  display:flex;align-items:center;gap:10px;flex-wrap:wrap;
  padding:8px 16px;background:var(--panel);
  border-bottom:1px solid var(--line);
}
.brand{display:flex;align-items:center;gap:8px;font-weight:650;
  letter-spacing:-.2px;font-size:15px;white-space:nowrap}
.brand .logo{width:22px;height:22px;color:var(--accent)}
.brand b{color:var(--accent);font-weight:650}
.brand .ver{color:var(--dim);font-weight:400;font-size:12px}

.netchip{display:flex;align-items:center;gap:7px;min-width:0;
  background:var(--panel2);border:1px solid var(--line);
  border-radius:20px;padding:4px 11px 4px 9px;font-size:13px}
.netchip .ic{color:var(--accent)}
.netchip .ssid{font-weight:600;white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis;max-width:22ch}
.netchip .gw{color:var(--dim);font-family:var(--mono);font-size:11.5px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--ok);flex:none;
  box-shadow:0 0 0 3px var(--ok-soft)}
.dot.stale{background:var(--warn);box-shadow:0 0 0 3px var(--warn-soft)}
.dot.off{background:var(--bad);box-shadow:0 0 0 3px var(--bad-soft)}

.badge{display:inline-flex;align-items:center;gap:5px;font-size:11px;
  font-weight:600;letter-spacing:.3px;text-transform:uppercase;
  padding:3px 8px;border-radius:6px;background:var(--panel3);color:var(--dim);
  white-space:nowrap}
.badge.ok{background:var(--ok-soft);color:var(--ok)}
.badge.warn{background:var(--warn-soft);color:var(--warn)}
.badge.bad{background:var(--bad-soft);color:var(--bad)}
.badge.acc{background:var(--accent-soft);color:var(--accent)}
.badge.paused{background:var(--warn-soft);color:var(--warn)}
.badge[hidden]{display:none}

.grow{flex:1 1 auto}
.ctrls{display:flex;align-items:center;gap:6px;flex-wrap:wrap}

/* ============================================================ controls */
.btn{
  font:inherit;font-size:13px;font-weight:500;line-height:1;
  display:inline-flex;align-items:center;gap:6px;
  padding:7px 11px;border-radius:8px;
  border:1px solid var(--line2);background:var(--panel2);color:var(--fg);
  cursor:pointer;transition:background .13s,border-color .13s,color .13s;
  white-space:nowrap;
}
.btn:hover:not(:disabled){background:var(--panel3);border-color:var(--accent-line)}
.btn:active:not(:disabled){transform:translateY(.5px)}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn.pri{background:var(--accent);border-color:var(--accent);color:var(--on-accent);
  font-weight:600}
.btn.pri:hover:not(:disabled){filter:brightness(1.08)}
.btn.danger{color:var(--bad);border-color:var(--bad-soft);background:var(--bad-soft)}
.btn.danger:hover:not(:disabled){background:var(--bad);color:#fff;
  border-color:var(--bad)}
.btn.ghost{background:transparent}
.btn.icon{padding:7px;width:32px;justify-content:center}
.btn.sm{padding:5px 9px;font-size:12px}
.btn.on{background:var(--accent-soft);border-color:var(--accent-line);
  color:var(--accent)}
select,input[type=text],input[type=number],input[type=search]{
  font:inherit;font-size:13px;padding:7px 9px;border-radius:8px;
  border:1px solid var(--line2);background:var(--panel2);color:var(--fg);
  font-family:var(--mono);max-width:100%;
}
select:focus,input:focus{outline:2px solid var(--accent);outline-offset:1px}
label.field{display:inline-flex;align-items:center;gap:6px}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:6px}

/* ============================================================ layout */
main{padding:16px;max-width:1560px;margin:0 auto;padding-bottom:96px}
.cards{display:grid;gap:10px;margin-bottom:14px;
  grid-template-columns:repeat(auto-fit,minmax(158px,1fr))}
.card{background:var(--panel);border:1px solid var(--line);
  border-radius:var(--r);padding:11px 13px;display:flex;gap:11px;
  align-items:flex-start}
.card .ic{width:18px;height:18px;margin-top:2px;color:var(--dim)}
.card .k{color:var(--dim);font-size:10.5px;text-transform:uppercase;
  letter-spacing:.6px;font-weight:600;display:flex;align-items:center;gap:5px}
.card .v{font-family:var(--mono);font-size:20px;font-weight:650;
  line-height:1.2;margin-top:3px;letter-spacing:-.5px}
.card .v small{font-size:11.5px;color:var(--dim);font-weight:500;
  letter-spacing:0}
.card .s{color:var(--dim);font-size:11.5px;margin-top:2px;font-family:var(--mono)}
.card.rx .ic{color:var(--rx)} .card.tx .ic{color:var(--tx)}
.card.hosts .ic{color:var(--accent)}
.card.blk .ic{color:var(--bad)}
.card.blk.hot .ic,.card.blk.hot .v{color:var(--bad)}
.card.pkt .ic{color:var(--dim)}

/* ============================================================ toolbar */
.toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;
  margin-bottom:10px}
.search{position:relative;flex:1 1 240px;max-width:380px;min-width:180px}
.search .ic{position:absolute;left:9px;top:50%;transform:translateY(-50%);
  color:var(--dim);pointer-events:none}
.search input{width:100%;padding-left:31px;font-family:var(--sans)}
.search kbd{position:absolute;right:8px;top:50%;transform:translateY(-50%);
  color:var(--dim);font-size:10px;font-family:var(--mono);
  border:1px solid var(--line2);border-radius:4px;padding:0 4px;
  pointer-events:none}
.search input:not(:placeholder-shown)~kbd{display:none}
.chips{display:flex;gap:5px;background:var(--panel2);padding:3px;
  border-radius:9px;border:1px solid var(--line)}
.chip{font:inherit;font-size:12.5px;font-weight:500;padding:5px 10px;
  border-radius:6px;border:0;background:transparent;color:var(--dim);
  cursor:pointer;display:inline-flex;align-items:center;gap:5px}
.chip:hover{color:var(--fg)}
.chip[aria-pressed="true"]{background:var(--panel);color:var(--fg);
  box-shadow:0 1px 3px #0003}
.chip .ct{font-family:var(--mono);font-size:11px;color:var(--dim)}
.chip[aria-pressed="true"] .ct{color:var(--accent)}
.chip.danger[aria-pressed="true"]{color:var(--bad)}

/* ============================================================ table */
.tablewrap{background:var(--panel);border:1px solid var(--line);
  border-radius:var(--r);overflow:auto;max-height:calc(100vh - 300px)}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px}
thead th{
  position:sticky;top:0;z-index:5;text-align:left;
  font-size:10.5px;text-transform:uppercase;letter-spacing:.6px;
  color:var(--dim);font-weight:650;padding:0 12px;height:36px;
  background:var(--panel2);white-space:nowrap;
  border-bottom:1px solid var(--line);
}
thead th.sortable{cursor:pointer;user-select:none}
thead th.sortable:hover{color:var(--fg)}
thead th .sortmark{display:inline-block;width:10px;margin-left:4px;
  opacity:0;transition:opacity .12s}
thead th[aria-sort] .sortmark{opacity:1;color:var(--accent)}
thead th[aria-sort="ascending"] .sortmark{transform:rotate(180deg)}
thead th.num,td.num{text-align:right}
tbody td{padding:0 12px;height:38px;border-bottom:1px solid var(--line);
  font-family:var(--mono);font-size:12.5px;vertical-align:middle;
  white-space:nowrap}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:var(--hover)}
tbody tr.sel{background:var(--sel)}
tbody tr.blocked{background:var(--bad-soft)}
tbody tr.blocked:hover{background:var(--bad-soft);filter:brightness(1.15)}
tbody tr.blocked td:first-child{box-shadow:inset 3px 0 0 var(--bad)}
tbody tr.idle{opacity:.5}
td.c-sel{width:34px;padding-right:0}
td.c-ip{width:132px}
td.c-mac{width:140px;color:var(--fg2)}
td.c-dev{min-width:150px;max-width:260px}
td.c-num{width:112px}
td.c-tot{width:92px;color:var(--fg2)}
td.c-st{min-width:110px}
td.c-act{width:158px}
td.c-dev{cursor:pointer}
td.c-dev:hover .hostname{color:var(--accent);text-decoration:underline dotted}
.devbox{display:flex;flex-direction:column;min-width:0;line-height:1.3}
.hostname{font-family:var(--sans);font-size:12.5px;font-weight:650;color:var(--fg);
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hostname:empty{display:none}
.vendor{font-family:var(--sans);font-size:12.5px;color:var(--fg2);
  overflow:hidden;text-overflow:ellipsis}
.vendor.sub{font-size:11px;color:var(--dim)}
.iptext{font-family:var(--mono);font-size:12.5px}
.copybtn{font:inherit;background:none;border:0;color:var(--dim);cursor:pointer;
  padding:1px 2px;border-radius:4px;display:inline-flex;vertical-align:middle;
  opacity:0;transition:opacity .12s}
tr:hover .copybtn,.copybtn:focus-visible{opacity:1}
.copybtn:hover{color:var(--accent);background:var(--panel3)}
.micro{font-family:var(--sans);font-size:10.5px;color:var(--dim);
  border:1px solid var(--line2);border-radius:4px;padding:0 4px;
  margin-left:5px}
.bar{display:inline-block;height:4px;border-radius:2px;vertical-align:middle;
  margin-left:7px;background:var(--rx);min-width:1px}
.bar.tx{background:var(--tx)}
.rowact{display:flex;gap:5px;justify-content:flex-end;align-items:center}
.tag{display:inline-flex;align-items:center;gap:4px;padding:1px 7px;
  border-radius:20px;font-size:11px;font-family:var(--sans);
  font-weight:600;margin-right:4px}
.tag.blk{background:var(--bad-soft);color:var(--bad)}
.tag.lim{background:var(--warn-soft);color:var(--warn)}
.tag.arp{background:#c98bff22;color:var(--tx)}
.tag.self{background:var(--accent-soft);color:var(--accent)}
.tag.warn{background:var(--warn-soft);color:var(--warn);cursor:help}
tfoot td{position:sticky;bottom:0;background:var(--panel2);
  border-top:1px solid var(--line2);height:34px;font-family:var(--mono);
  font-size:12px;font-weight:600;color:var(--fg2);z-index:4}
.fallback{display:flex;gap:10px;align-items:flex-start;
  background:var(--warn-soft);border:1px solid var(--warn);
  border-radius:var(--r);padding:11px 14px;margin-bottom:10px;
  font-size:13px;line-height:1.55;color:var(--fg)}
.fallback[hidden]{display:none}
.fallback .ic{color:var(--warn);flex:none;margin-top:2px}
.fallback b{color:var(--warn)}
.fallback code{font-family:var(--mono);background:var(--panel2);
  padding:1px 5px;border-radius:4px;border:1px solid var(--line)}
.empty{padding:44px 20px;text-align:center;color:var(--dim)}
.empty .ic{width:30px;height:30px;margin-bottom:10px;color:var(--line2);
  stroke-width:1.4}
.empty h3{color:var(--fg2);font-size:14px;margin:0 0 5px;font-weight:600}
.empty p{margin:0 0 14px;font-size:13px}

/* ============================================================ bulk bar */
.bulkbar{position:fixed;left:50%;bottom:18px;transform:translate(-50%,18px);
  z-index:40;display:flex;align-items:center;gap:9px;
  background:var(--panel);border:1px solid var(--line2);border-radius:12px;
  padding:8px 10px 8px 14px;box-shadow:var(--shadow);
  opacity:0;visibility:hidden;pointer-events:none;
  transition:opacity .18s,transform .18s,visibility .18s}
.bulkbar.on{opacity:1;visibility:visible;transform:translate(-50%,0);
  pointer-events:auto}
.bulkbar .cnt{font-size:13px;font-weight:600;white-space:nowrap}
.bulkbar .cnt b{color:var(--accent);font-family:var(--mono)}
.bulkbar .sep{width:1px;height:20px;background:var(--line)}
input[type=checkbox]{accent-color:var(--accent);width:15px;height:15px;
  cursor:pointer;margin:0;vertical-align:middle}

/* ============================================================ modal */
.backdrop{position:fixed;inset:0;background:#000a;backdrop-filter:blur(3px);
  z-index:50;display:flex;align-items:center;justify-content:center;
  padding:20px;opacity:0;pointer-events:none;transition:opacity .16s}
.backdrop.on{opacity:1;pointer-events:auto}
.modal{background:var(--panel);border:1px solid var(--line2);
  border-radius:14px;box-shadow:var(--shadow);width:min(520px,100%);
  max-height:86vh;display:flex;flex-direction:column;
  transform:translateY(8px) scale(.99);transition:transform .16s}
.backdrop.on .modal{transform:none}
.modal.wide{width:min(760px,100%)}
.modal header{display:flex;align-items:center;gap:9px;padding:14px 16px;
  border-bottom:1px solid var(--line)}
.modal header h2{font-size:14.5px;margin:0;font-weight:650;flex:1}
.modal .body{padding:16px;overflow:auto}
.modal footer{display:flex;gap:8px;justify-content:flex-end;padding:12px 16px;
  border-top:1px solid var(--line);background:var(--panel2);
  border-radius:0 0 14px 14px}
.xbtn{background:none;border:0;color:var(--dim);cursor:pointer;padding:4px;
  border-radius:6px;display:inline-flex}
.xbtn:hover{color:var(--fg);background:var(--panel3)}
.fieldlbl{display:block;font-size:11px;text-transform:uppercase;
  letter-spacing:.6px;color:var(--dim);font-weight:650;margin-bottom:6px}
.presets{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0 14px}
.presets .btn{flex:1 1 84px;justify-content:center}
.hostslist{display:flex;flex-direction:column;gap:5px;max-height:220px;
  overflow:auto;margin:10px 0 0;padding:0;list-style:none}
.hostslist li{display:flex;align-items:center;gap:8px;font-family:var(--mono);
  font-size:12px;background:var(--panel2);border:1px solid var(--line);
  border-radius:7px;padding:6px 10px}
.hostslist li .vd{font-family:var(--sans);color:var(--dim);margin-left:auto;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:45%}
.hint{font-size:12px;color:var(--dim);margin-top:8px;line-height:1.55}
.note{background:var(--warn-soft);border-left:3px solid var(--warn);
  padding:9px 12px;border-radius:6px;margin:10px 0;font-size:12.5px;
  line-height:1.5}
.note b{color:var(--warn)}
pre.code{font-family:var(--mono);font-size:12px;background:var(--panel2);
  border:1px solid var(--line);border-radius:8px;padding:12px;margin:0;
  overflow:auto;max-height:52vh;white-space:pre;line-height:1.5}

/* ============================================================ toasts */
.toasts{position:fixed;top:calc(var(--hh) + 10px);right:14px;z-index:60;
  display:flex;flex-direction:column;gap:8px;max-width:min(370px,calc(100vw - 28px))}
.toast{display:flex;align-items:flex-start;gap:9px;background:var(--panel);
  border:1px solid var(--line2);border-left:3px solid var(--accent);
  border-radius:9px;padding:9px 12px;box-shadow:var(--shadow);font-size:13px;
  animation:tin .18s ease-out}
.toast.err{border-left-color:var(--bad)}
.toast.ok{border-left-color:var(--ok)}
.toast.warn{border-left-color:var(--warn)}
.toast .ic{margin-top:1px;color:var(--accent)}
.toast.err .ic{color:var(--bad)}
.toast.ok .ic{color:var(--ok)}
.toast.warn .ic{color:var(--warn)}
.toast .msg{flex:1;line-height:1.4;word-break:break-word}
.toast .msg b{font-weight:650}
.toast.out{animation:tout .16s ease-in forwards}
@keyframes tin{from{opacity:0;transform:translateX(14px)}to{opacity:1;transform:none}}
@keyframes tout{to{opacity:0;transform:translateX(14px)}}

/* ============================================================ footer */
.foot{margin-top:14px;color:var(--dim);font-size:12px;line-height:1.65;
  border-top:1px solid var(--line);padding-top:12px}
.foot summary{cursor:pointer;color:var(--fg2);font-weight:600;
  list-style:none;display:flex;align-items:center;gap:7px;
  width:fit-content;padding:4px 0}
.foot summary::-webkit-details-marker{display:none}
.foot summary:hover{color:var(--fg)}
.foot .inner{padding:6px 0 2px;max-width:80ch}
.foot code{font-family:var(--mono);background:var(--panel2);padding:1px 5px;
  border-radius:4px;border:1px solid var(--line)}
kbd{font-family:var(--mono);font-size:11px;background:var(--panel2);
  border:1px solid var(--line2);border-bottom-width:2px;border-radius:5px;
  padding:1px 5px;color:var(--fg2)}
.keys{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
  gap:6px 18px;margin-top:10px}
.keys div{display:flex;align-items:center;gap:8px;font-size:12px}
.keys div span{color:var(--dim)}

/* ============================================================ responsive */
@media (max-width:900px){
  .netchip .gw{display:none}
  .tablewrap{max-height:none}
  thead th, tbody td, tfoot td{height:auto}
}
@media (max-width:760px){
  main{padding:11px}
  .topbar{padding:7px 11px;gap:7px}
  .brand .ver{display:none}
  .cards{grid-template-columns:repeat(auto-fit,minmax(128px,1fr))}
  .card .v{font-size:17px}
  /* tabel -> kartu */
  .tablewrap{background:transparent;border:0;border-radius:0;overflow:visible}
  table,tbody,tr,td{display:block;width:100%}
  thead{display:none}
  tbody tr{background:var(--panel);border:1px solid var(--line);
    border-radius:var(--r);margin-bottom:8px;padding:8px 4px;position:relative}
  tbody tr.blocked{border-color:var(--bad)}
  tbody td{height:auto;padding:3px 10px;border:0;display:flex;
    align-items:center;gap:8px;white-space:nowrap}
  tbody td.c-dev{white-space:normal}
  tbody td.c-dev .vendor{white-space:normal}
  tbody td .rowact{flex:1}
  tbody td::before{content:attr(data-label);color:var(--dim);font-family:var(--sans);
    font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;
    width:74px;flex:none;font-weight:650}
  tbody td.c-sel{position:absolute;top:9px;right:9px;width:auto;padding:0}
  tbody td.c-sel::before{display:none}
  tbody td.c-ip{width:auto}
  tbody td.c-ip::before{display:none}
  tbody td.c-ip .iptext{font-size:14px;font-weight:600}
  tbody td.c-ip .copybtn{opacity:1}
  tbody td.c-act{width:auto;padding-top:8px}
  tbody td.c-act::before{display:none}
  tfoot{display:none}
  .bulkbar{left:10px;right:10px;transform:none;bottom:10px;flex-wrap:wrap;
    justify-content:center}
  .bulkbar.on{transform:none}
  .toasts{right:10px;left:10px;max-width:none}
}
@media (prefers-reduced-motion:reduce){
  *{animation-duration:.01ms!important;transition-duration:.01ms!important}
}
</style>
</head>
<body>

<svg style="display:none" aria-hidden="true"><defs>
<symbol id="i-wifi" viewBox="0 0 24 24"><path d="M2 8.8a16 16 0 0 1 20 0"/><path d="M5 12.5a11 11 0 0 1 14 0"/><path d="M8.5 16a6 6 0 0 1 7 0"/><path d="M12 19.5h.01"/></symbol>
<symbol id="i-down" viewBox="0 0 24 24"><path d="M12 4v14"/><path d="m6 13 6 6 6-6"/></symbol>
<symbol id="i-up" viewBox="0 0 24 24"><path d="M12 20V6"/><path d="m6 11 6-6 6 6"/></symbol>
<symbol id="i-host" viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.2"/><path d="M2.6 20a6.4 6.4 0 0 1 12.8 0"/><path d="M16.5 5.3a3.2 3.2 0 0 1 0 5.6"/><path d="M17.5 14.2A6.4 6.4 0 0 1 21.4 20"/></symbol>
<symbol id="i-ban" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/></symbol>
<symbol id="i-pkg" viewBox="0 0 24 24"><path d="M21 8v8a2 2 0 0 1-1 1.7l-7 4a2 2 0 0 1-2 0l-7-4A2 2 0 0 1 3 16V8a2 2 0 0 1 1-1.7l7-4a2 2 0 0 1 2 0l7 4A2 2 0 0 1 21 8z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/></symbol>
<symbol id="i-gauge" viewBox="0 0 24 24"><path d="M3.5 18a9 9 0 1 1 17 0"/><path d="m12 14 4-4"/><path d="M12 18h.01"/></symbol>
<symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20.5 20.5-4.2-4.2"/></symbol>
<symbol id="i-pause" viewBox="0 0 24 24"><rect x="6" y="5" width="4" height="14" rx="1.2"/><rect x="14" y="5" width="4" height="14" rx="1.2"/></symbol>
<symbol id="i-play" viewBox="0 0 24 24"><path d="M8 5.5v13l10-6.5z"/></symbol>
<symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M19.1 4.9l-1.8 1.8M6.7 17.3l-1.8 1.8"/></symbol>
<symbol id="i-moon" viewBox="0 0 24 24"><path d="M20.5 14.5A8.6 8.6 0 0 1 9.5 3.5a8.6 8.6 0 1 0 11 11z"/></symbol>
<symbol id="i-copy" viewBox="0 0 24 24"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></symbol>
<symbol id="i-check" viewBox="0 0 24 24"><path d="m5 13 4.5 4.5L19 7"/></symbol>
<symbol id="i-x" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></symbol>
<symbol id="i-list" viewBox="0 0 24 24"><path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01"/></symbol>
<symbol id="i-scan" viewBox="0 0 24 24"><circle cx="12" cy="12" r="2"/><path d="M12 20a8 8 0 1 1 8-8"/><path d="M12 16a4 4 0 1 1 4-4"/></symbol>
<symbol id="i-alert" viewBox="0 0 24 24"><path d="M12 9v4.5M12 17h.01"/><path d="M10.3 4 1.9 18.2A2 2 0 0 0 3.6 21h16.8a2 2 0 0 0 1.7-2.8L13.7 4a2 2 0 0 0-3.4 0z"/></symbol>
<symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></symbol>
<symbol id="i-lock" viewBox="0 0 24 24"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></symbol>
<symbol id="i-netcut" viewBox="0 0 24 24"><path d="M12 2 4 6.5v6c0 5 3.4 8.9 8 9.9 4.6-1 8-4.9 8-9.9v-6z"/><path d="M9 12h6"/><path d="m11.5 9-2.5 3 2.5 3M12.5 9l2.5 3-2.5 3"/></symbol>
</defs></svg>

<header class="topbar">
  <span class="brand">
    <svg class="logo"><use href="#i-netcut"/></svg>
    netcut<b>-linux</b>
  </span>

  <span class="netchip" id="netChip" title="Jaringan aktif">
    <span class="dot" id="statusDot"></span>
    <svg class="ic"><use href="#i-wifi"/></svg>
    <span class="ssid" id="netName">memuat…</span>
    <span class="gw" id="netGw"></span>
  </span>

  <span class="badge" id="modeBadge">—</span>
  <span class="badge" id="scanBadge" hidden></span>
  <span class="badge" id="pauseBadge" hidden>Jeda</span>

  <span class="grow"></span>

  <div class="ctrls">
    <label class="field">
      <span class="sr-only">Interface jaringan</span>
      <select id="ifaceSel" title="Interface jaringan"></select>
    </label>
    <button class="btn" id="scanBtn" title="Scan ARP (S)">
      <svg class="ic"><use href="#i-scan"/></svg>Scan
    </button>
    <button class="btn ghost" id="rulesBtn" title="Aturan nftables aktif (R)">
      <svg class="ic"><use href="#i-list"/></svg>Rules
    </button>
    <button class="btn ghost icon" id="pauseBtn" title="Jeda / lanjut polling (P)"
            aria-label="Jeda polling"><svg class="ic"><use href="#i-pause"/></svg></button>
    <button class="btn ghost icon" id="themeBtn" title="Ganti tema (T)"
            aria-label="Ganti tema"><svg class="ic"><use href="#i-sun"/></svg></button>
    <button class="btn ghost icon" id="helpBtn" title="Bantuan (?)"
            aria-label="Bantuan"><svg class="ic"><use href="#i-info"/></svg></button>
  </div>
</header>

<main>
  <div class="cards">
    <div class="card rx">
      <svg class="ic"><use href="#i-down"/></svg>
      <div><div class="k">Download</div><div class="v" id="cRx">0</div>
        <div class="s" id="cRxSub">—</div></div>
    </div>
    <div class="card tx">
      <svg class="ic"><use href="#i-up"/></svg>
      <div><div class="k">Upload</div><div class="v" id="cTx">0</div>
        <div class="s" id="cTxSub">—</div></div>
    </div>
    <div class="card hosts">
      <svg class="ic"><use href="#i-host"/></svg>
      <div><div class="k">Host</div><div class="v" id="cHosts">0</div>
        <div class="s" id="cHostsSub">—</div></div>
    </div>
    <div class="card blk" id="cardBlk">
      <svg class="ic"><use href="#i-ban"/></svg>
      <div><div class="k">Diblokir</div><div class="v" id="cBlk">0</div>
        <div class="s" id="cBlkSub">—</div></div>
    </div>
    <div class="card pkt">
      <svg class="ic"><use href="#i-pkg"/></svg>
      <div><div class="k">Paket</div><div class="v" id="cPkts">0</div>
        <div class="s" id="cPktsSub">—</div></div>
    </div>
  </div>

  <div class="toolbar">
    <div class="search">
      <svg class="ic"><use href="#i-search"/></svg>
      <input type="search" id="q" placeholder="Cari IP, MAC, atau perangkat…"
             autocomplete="off" spellcheck="false" aria-label="Cari host">
      <kbd>/</kbd>
    </div>
    <div class="chips" role="group" aria-label="Filter host">
      <button class="chip" data-f="all" aria-pressed="true">Semua
        <span class="ct" id="ctAll">0</span></button>
      <button class="chip" data-f="active" aria-pressed="false">Aktif
        <span class="ct" id="ctActive">0</span></button>
      <button class="chip" data-f="blocked" aria-pressed="false">Diblokir
        <span class="ct" id="ctBlocked">0</span></button>
      <button class="chip danger" data-f="limited" aria-pressed="false">Limited
        <span class="ct" id="ctLimited">0</span></button>
    </div>
    <span class="grow"></span>
    <span class="badge" id="uptimeBadge" title="Waktu aktif">0s</span>
  </div>

  <div id="fwWarn" class="fallback" hidden>
    <svg class="ic"><use href="#i-alert"/></svg>
    <div>
      <b>Firewall host membuang trafik forward &mdash; Limit tidak berlaku.</b>
      <span id="fwWarnText"></span> Verdict <code>accept</code> di rantai
      netcut tidak menghentikan hook, jadi aturan firewall host tetap
      membuang paketnya. Yang bisa dilakukan: pakai <b>Blokir</b>, atau
      longgarkan firewall host (mis. izinkan trafik dari perangkat target).
    </div>
  </div>

  <div id="fallback" class="fallback" hidden>
    <svg class="ic"><use href="#i-alert"/></svg>
    <div>
      <b>Mode fallback — hanya monitoring, tanpa kontrol.</b>
      Server tidak punya <code>CAP_NET_RAW</code>/<code>CAP_NET_ADMIN</code>,
      jadi blokir &amp; limit dinonaktifkan. Jalankan <code>netcut --doctor</code>
      untuk cek, atau jalankan lewat docker / <code>sudo</code> agar semua fitur aktif.
    </div>
  </div>

  <div class="tablewrap">
    <table>
      <thead><tr>
        <th class="c-sel"><input type="checkbox" id="selAll"
               aria-label="Pilih semua host yang tampil"></th>
        <th class="sortable c-ip" data-k="ip">IP<span class="sortmark">▾</span></th>
        <th class="sortable c-mac" data-k="mac">MAC<span class="sortmark">▾</span></th>
        <th class="sortable c-dev" data-k="vendor">Perangkat<span class="sortmark">▾</span></th>
        <th class="sortable num c-num" data-k="rx_rate">↓ Download<span class="sortmark">▾</span></th>
        <th class="sortable num c-num" data-k="tx_rate">↑ Upload<span class="sortmark">▾</span></th>
        <th class="sortable num c-tot" data-k="total">Total<span class="sortmark">▾</span></th>
        <th class="c-st">Status</th>
        <th class="num c-act">Aksi</th>
      </tr></thead>
      <tbody id="rows"></tbody>
      <tfoot id="foot"><tr>
        <td class="c-sel"></td>
        <td class="c-ip" id="footCount">0 host</td>
        <td class="c-mac"></td>
        <td class="c-dev" id="footLabel"></td>
        <td class="num" id="footRx">0 B/s</td>
        <td class="num" id="footTx">0 B/s</td>
        <td class="num" id="footSum">0 B</td>
        <td class="c-st"></td>
        <td class="num c-act"></td>
      </tr></tfoot>
    </table>
  </div>

  <div id="notes"></div>

  <details class="foot">
    <summary><svg class="ic sm"><use href="#i-info"/></svg>Cara kerja &amp; penjelasan</summary>
    <div class="inner">
      <p><b>Blokir</b> memakai ARP spoofing (persis seperti NetCut): gateway
      korban diarahkan ke laptop ini, lalu rule nftables <code>drop</code>
      membuang trafiknya. Badge <span class="tag arp">ARP spoof</span> menandai
      target aktif. Hanya untuk perangkat milik sendiri di jaringan sendiri.</p>
      <p><b>Limit</b> membatasi bandwidth lewat rate limiter nftables di chain
      <code>forward</code>. Badge <span class="tag warn">!</span> muncul bila
      router menolak ARP spoof — dalam hal ini limit hanya berlaku untuk arah
      upload, dan <b>Blokir</b> adalah cara yang pasti membatasi total.</p>
      <div class="keys">
        <div><kbd>/</kbd><span>Cari host</span></div>
        <div><kbd>Ctrl</kbd>+<kbd>A</kbd><span>Pilih semua yang tampil</span></div>
        <div><kbd>Esc</kbd><span>Tutup dialog / bersihkan pencarian</span></div>
        <div><kbd>S</kbd><span>Scan ARP</span></div>
        <div><kbd>R</kbd><span>Lihat aturan nftables</span></div>
        <div><kbd>P</kbd><span>Jeda / lanjut polling</span></div>
        <div><kbd>T</kbd><span>Ganti tema</span></div>
        <div><kbd>?</kbd><span>Bantuan ini</span></div>
      </div>
    </div>
  </details>
</main>

<div class="bulkbar" id="bulkbar" role="region" aria-label="Aksi massal">
  <span class="cnt"><b id="selCount">0</b> dipilih</span>
  <span class="sep"></span>
  <button class="btn danger sm" id="bulkBlock">
    <svg class="ic sm"><use href="#i-ban"/></svg>Blokir</button>
  <button class="btn sm" id="bulkUnblock">Buka blokir</button>
  <button class="btn sm" id="bulkLimit">Limit…</button>
  <button class="btn sm" id="bulkUnlimit">Buka limit</button>
  <span class="sep"></span>
  <button class="btn ghost sm" id="bulkClear">Batal</button>
</div>

<div class="backdrop" id="modal" role="dialog" aria-modal="true"
     aria-labelledby="modalTitle">
  <div class="modal" id="modalBox">
    <header>
      <h2 id="modalTitle">Judul</h2>
      <button class="xbtn" id="modalX" aria-label="Tutup">
        <svg class="ic"><use href="#i-x"/></svg></button>
    </header>
    <div class="body" id="modalBody"></div>
    <footer id="modalFoot"></footer>
  </div>
</div>

<div class="toasts" id="toasts" role="status" aria-live="polite"></div>

<!--FETCH_STUB-->
<script>
"use strict";
const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));

const S = {
  hosts: [], blocked: new Set(), limited: new Map(), spoofing: new Set(),
  notes: {}, net: {}, iface: "", mode: "", uptime: 0, stale: false,
  forwardBlocked: "",
  packets: 0, dropped: 0, rxRate: 0, txRate: 0, peerRate: 0,
  sortKey: "rx_rate", sortDir: -1, query: "", filter: "all",
  selected: new Set(), paused: false, online: true, scanning: false,
  scanResult: null, interfaces: [], rows: new Map(), lastOrder: "",
  lastAnchor: null, busy: false,
};
window.__INIT__ = __INIT_DATA__;

/* ---------------------------------------------------------- format */
const num = v => (v || 0).toLocaleString("id-ID");
function fmtRate(bps) {
  bps = bps || 0;
  if (bps >= 1e9) return (bps / 1e9).toFixed(1) + " <small>GB/s</small>";
  if (bps >= 1e6) return (bps / 1e6).toFixed(1) + " <small>MB/s</small>";
  if (bps >= 1e3) return (bps / 1e3).toFixed(1) + " <small>KB/s</small>";
  return bps.toFixed(0) + " <small>B/s</small>";
}
function fmtBytes(n) {
  n = n || 0;
  if (n >= 1 << 30) return (n / (1 << 30)).toFixed(1) + " GB";
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + " MB";
  if (n >= 1 << 10) return (n / (1 << 10)).toFixed(1) + " KB";
  return n + " B";
}
function fmtBytesPlain(n) { return fmtBytes(n).replace(/(\.\d)? /, " "); }
function fmtUptime(s) {
  s = Math.max(0, s | 0);
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600),
        m = Math.floor(s % 3600 / 60), sec = s % 60;
  if (d) return d + "h " + h + "j";
  if (h) return h + "j " + m + "m";
  if (m) return m + "m " + sec + "d";
  return sec + "d";
}
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function setHTML(el, html) { if (el._h !== html) { el.innerHTML = html; el._h = html; } }
function setText(el, txt) { if (el._t !== txt) { el.textContent = txt; el._t = txt; } }

/* ---------------------------------------------------------- toast */
function toast(msg, kind, action) {
  const box = $("#toasts");
  const el = document.createElement("div");
  el.className = "toast" + (kind ? " " + kind : "");
  const ic = kind === "err" ? "alert" : kind === "ok" ? "check"
           : kind === "warn" ? "alert" : "info";
  el.innerHTML = `<svg class="ic"><use href="#i-${ic}"/></svg>
    <span class="msg">${msg}</span>`;
  if (action) {
    const b = document.createElement("button");
    b.className = "btn sm";
    b.textContent = action.label;
    b.onclick = () => { action.fn(); dismiss(); };
    el.appendChild(b);
  }
  box.appendChild(el);
  while (box.children.length > 4) box.firstChild.remove();
  const ttl = kind === "err" ? 8000 : kind === "warn" ? 6000 : 3600;
  const timer = setTimeout(dismiss, ttl);
  function dismiss() {
    clearTimeout(timer);
    el.classList.add("out");
    setTimeout(() => el.remove(), 180);
  }
  el.addEventListener("mouseenter", () => clearTimeout(timer));
  el.addEventListener("mouseleave", () => { timer = setTimeout(dismiss, 2000); });
  return el;
}

/* ---------------------------------------------------------- api */
async function api(path, body) {
  const opt = body
    ? { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body) }
    : {};
  const r = await fetch(path, opt);
  const txt = await r.text();
  try { return JSON.parse(txt); }
  catch { throw new Error(txt.slice(0, 200) || ("HTTP " + r.status)); }
}

/* ---------------------------------------------------------- snapshot */
function applySnapshot(d) {
  S.hosts = d.hosts || [];
  S.blocked = new Set(d.blocked || []);
  S.limited = new Map(Object.entries(d.limited || {}));
  S.spoofing = new Set((d.spoofing || []).map(s => s.ip));
  S.notes = d.notes || {};
  S.forwardBlocked = d.forward_blocked || "";
  S.net = d.net || {};
  S.iface = d.iface || "";
  S.mode = d.mode || "";
  S.stale = !!d.stale;
  S.uptime = d.uptime || 0;
  S.packets = d.packets || 0;
  S.dropped = d.dropped || 0;
  S.rxRate = d.rx_rate || 0;
  S.txRate = d.tx_rate || 0;
  S.peerRate = d.peer_rate || 0;
  S.scanning = !!d.scanning;
  S.scanResult = d.scan_result || null;
  if (d.interfaces) S.interfaces = d.interfaces;
  // buang host yang hilang dari server
  const alive = new Set(S.hosts.map(h => h.ip));
  Array.from(S.selected).forEach(ip => { if (!alive.has(ip)) S.selected.delete(ip); });
  S.online = true;
}

/* ---------------------------------------------------------- selection */
function visibleHosts() {
  let out = S.hosts.slice();
  if (S.filter === "blocked") out = out.filter(h => S.blocked.has(h.ip));
  else if (S.filter === "limited") out = out.filter(h => S.limited.has(h.ip));
  else if (S.filter === "active")
    out = out.filter(h => (h.rx_rate || 0) + (h.tx_rate || 0) > 0);

  const q = S.query.trim().toLowerCase();
  if (q) {
    out = out.filter(h =>
      h.ip.toLowerCase().includes(q) ||
      (h.mac || "").toLowerCase().includes(q) ||
      (h.vendor || "").toLowerCase().includes(q));
  }
  const k = S.sortKey, dir = S.sortDir;
  out.sort((a, b) => {
    // kolom Perangkat: urutkan menurut nama host, fallback ke vendor
    const x = k === "vendor" ? (a.name || a.vendor) : a[k];
    const y = k === "vendor" ? (b.name || b.vendor) : b[k];
    if (typeof x === "string" || typeof y === "string") {
      return dir * String(x || "").localeCompare(String(y || ""), "id");
    }
    return dir * ((x || 0) - (y || 0));
  });
  return out;
}

/* ---------------------------------------------------------- rows */
function makeRow(h) {
  const tr = document.createElement("tr");
  tr.dataset.ip = h.ip;
  tr.innerHTML =
    `<td class="c-sel" data-label=""><input type="checkbox" class="rowsel"
       aria-label="Pilih ${esc(h.ip)}"></td>` +
    `<td class="c-ip" data-label="IP"><span class="iptext"></span>
       <button class="copybtn" title="Salin IP" aria-label="Salin IP">
         <svg class="ic sm"><use href="#i-copy"/></svg></button></td>` +
    `<td class="c-mac" data-label="MAC"></td>` +
    `<td class="c-dev" data-label="Perangkat">` +
      `<div class="devbox"><span class="hostname"></span>` +
      `<span class="vendor"></span></div></td>` +
    `<td class="num c-num c-rx" data-label="Download"></td>` +
    `<td class="num c-num c-tx" data-label="Upload"></td>` +
    `<td class="num c-tot" data-label="Total"></td>` +
    `<td class="c-st" data-label="Status"></td>` +
    `<td class="c-act" data-label=""><div class="rowact"></div></td>`;
  tr._c = {
    sel: tr.querySelector(".rowsel"),
    ip: tr.querySelector(".iptext"),
    mac: tr.querySelector(".c-mac"),
    dev: tr.querySelector(".vendor"),
    host: tr.querySelector(".hostname"),
    rx: tr.querySelector(".c-rx"),
    tx: tr.querySelector(".c-tx"),
    tot: tr.querySelector(".c-tot"),
    st: tr.querySelector(".c-st"),
    act: tr.querySelector(".rowact"),
  };
  tr._c.sel.addEventListener("click", ev => {
    ev.stopPropagation();
    toggleSelect(h.ip, ev.shiftKey);
  });
  tr.querySelector(".copybtn").addEventListener("click", ev => {
    ev.stopPropagation();
    copyText(h.ip);
  });
  tr.querySelector(".c-dev").addEventListener("click", ev => {
    ev.stopPropagation();
    renameModal(tr.dataset.ip, (tr._c.host.textContent || "").trim());
  });
  tr.addEventListener("click", ev => {
    if (ev.target.closest("button,input,a")) return;
    toggleSelect(h.ip, ev.shiftKey);
  });
  return tr;
}

function statusHTML(h) {
  let st = "";
  if (S.blocked.has(h.ip)) st += '<span class="tag blk">diblokir</span>';
  if (S.spoofing.has(h.ip)) st += '<span class="tag arp">ARP spoof</span>';
  const lim = S.limited.get(h.ip);
  if (lim) st += `<span class="tag lim">${lim} kbps</span>`;
  if (S.notes[h.ip])
    st += `<span class="tag warn" title="${esc(S.notes[h.ip])}">!</span>`;
  if (S.net && S.net.ip && h.ip === S.net.ip)
    st += '<span class="tag self" title="Perangkat ini (laptop Anda)">laptop ini</span>';
  return st || '<span style="color:var(--dim)">—</span>';
}

function actHTML(h) {
  const bl = S.blocked.has(h.ip), lim = S.limited.has(h.ip);
  // Di mode fallback server tidak punya hak nftables/ARP spoof, jadi tombol
  // kontrol dimatikan dari awal. Lebih baik mati dengan penjelasan daripada
  // gagal setelah diklik.
  const dis = S.mode === "capture" ? "" : " disabled";
  let s = bl
    ? `<button class="btn sm" data-act="unblock" data-ip="${esc(h.ip)}"${dis}>Buka</button>`
    : `<button class="btn sm danger" data-act="block" data-ip="${esc(h.ip)}"${dis}>Blokir</button>`;
  s += `<button class="btn sm" data-act="limit" data-ip="${esc(h.ip)}"${dis}>Limit</button>`;
  if (lim)
    s += `<button class="btn sm ghost" data-act="unlimit" data-ip="${esc(h.ip)}"${dis}>×</button>`;
  return s;
}

function updateRow(tr, h, top) {
  const c = tr._c;
  const total = (h.rx_rate || 0) + (h.tx_rate || 0);
  const wRx = Math.min(56, (h.rx_rate || 0) / top * 56);
  const wTx = Math.min(56, (h.tx_rate || 0) / top * 56);

  setText(c.ip, h.ip);
  setText(c.mac, h.mac || "—");
  const label = h.label || h.name || "";
  setText(c.host, label);
  c.host.title = label ? "Klik untuk mengganti nama" : "Klik untuk memberi nama";
  setText(c.dev, h.vendor || (label ? "" : "unknown"));
  c.dev.classList.toggle("sub", !!label);
  c.dev.title = [
    h.label ? "nama: " + h.label : "",
    h.name ? "terdeteksi: " + h.name + " (" + (h.name_src || "?") + ")" : "",
    h.vendor ? "vendor: " + h.vendor : "",
  ].filter(Boolean).join(" · ");
  setHTML(c.rx, fmtRate(h.rx_rate) +
    (h.rx_rate ? `<span class="bar" style="width:${wRx.toFixed(1)}px"></span>` : ""));
  setHTML(c.tx, fmtRate(h.tx_rate) +
    (h.tx_rate ? `<span class="bar tx" style="width:${wTx.toFixed(1)}px"></span>` : ""));
  setText(c.tot, fmtBytes(h.total));
  setHTML(c.st, statusHTML(h));
  setHTML(c.act, actHTML(h));

  tr.classList.toggle("blocked", S.blocked.has(h.ip));
  tr.classList.toggle("idle", (h.seen_ago || 0) > 45);
  const want = S.selected.has(h.ip);
  if (c.sel.checked !== want) c.sel.checked = want;
  tr.classList.toggle("sel", want);
}

/* ---------------------------------------------------------- render */
function render() {
  const list = visibleHosts();
  const tbody = $("#rows");

  // header meta
  const net = S.net || {};
  setText($("#netName"), net.ssid || S.iface || "—");
  setText($("#netGw"), net.gateway || "");
  $("#statusDot").className = "dot" + (!S.online ? " off" : S.stale ? " stale" : "");
  const badge = $("#modeBadge");
  badge.className = "badge " + (S.mode === "capture" ? "ok" : "warn");
  setText(badge, S.mode === "capture" ? "capture" : "fallback");
  badge.title = S.mode === "capture"
    ? "Capture penuh: blokir, limit, dan ARP spoof aktif"
    : "Mode fallback: hanya total interface, tanpa kontrol blokir/limit";
  $("#pauseBadge").hidden = !S.paused;

  // status scan: sedang jalan, hasil, atau error (mis. kurang hak akses)
  const scanBadge = $("#scanBadge");
  if (S.scanning) {
    scanBadge.hidden = false;
    scanBadge.className = "badge acc";
    setText(scanBadge, "scanning…");
    scanBadge.title = "ARP scan sedang berjalan";
  } else if (S.scanResult) {
    scanBadge.hidden = false;
    if (S.scanResult.error) {
      scanBadge.className = "badge bad";
      setText(scanBadge, "scan gagal");
      scanBadge.title = String(S.scanResult.error);
    } else {
      scanBadge.className = "badge";
      setText(scanBadge, "scan: " + (S.scanResult.found || 0) + " host");
      scanBadge.title = "Hasil ARP scan terakhir";
    }
  } else {
    scanBadge.hidden = true;
  }

  const fwWarn = $("#fwWarn");
  if (S.forwardBlocked) {
    fwWarn.hidden = false;
    setText($("#fwWarnText"), S.forwardBlocked + ".");
  } else {
    fwWarn.hidden = true;
  }

  const fallback = S.mode !== "capture";
  $("#fallback").hidden = !fallback;
  // tanpa hak nftables/ARP spoof tombol kontrol dimatikan, bukan gagal saat diklik
  $("#bulkBlock").disabled = fallback;
  $("#bulkLimit").disabled = fallback;
  setText($("#uptimeBadge"), fmtUptime(S.uptime));
  $("#uptimeBadge").title = "Uptime " + Math.round(S.uptime) + " detik";

  // kartu ringkasan
  let sumRx = 0, sumTx = 0;
  for (const h of S.hosts) { sumRx += h.rx || 0; sumTx += h.tx || 0; }
  setHTML($("#cRx"), fmtRate(S.rxRate));
  setHTML($("#cTx"), fmtRate(S.txRate));
  setText($("#cRxSub"), sumRx ? fmtBytesPlain(sumRx) + " total" : "—");
  setText($("#cTxSub"), sumTx ? fmtBytesPlain(sumTx) + " total" : "—");
  setText($("#cHosts"), S.hosts.length);
  setText($("#cHostsSub"), S.peerRate
    ? "LAN " + fmtBytesPlain(S.peerRate) + "/s" : "—");
  const nBlk = S.blocked.size, nLim = S.limited.size;
  setText($("#cBlk"), nBlk);
  setText($("#cBlkSub"), nLim ? nLim + " limited" : "—");
  $("#cardBlk").classList.toggle("hot", nBlk > 0);
  setText($("#cPkts"), num(S.packets));
  setText($("#cPktsSub"), S.dropped ? num(S.dropped) + " drop" : "0 drop");

  // counter filter
  const active = S.hosts.filter(h => (h.rx_rate || 0) + (h.tx_rate || 0) > 0).length;
  setText($("#ctAll"), S.hosts.length);
  setText($("#ctActive"), active);
  setText($("#ctBlocked"), nBlk);
  setText($("#ctLimited"), nLim);

  // select interface
  const sel = $("#ifaceSel");
  if (sel.dataset.done !== "1" && S.interfaces.length) {
    sel.innerHTML = S.interfaces.map(i =>
      `<option value="${esc(i)}"${i === S.iface ? " selected" : ""}>${esc(i)}</option>`).join("");
    sel.dataset.done = "1";
  } else if (sel.value !== S.iface && S.iface) {
    sel.value = S.iface;
  }

  // tabel
  if (!list.length) {
    const emptyMsg = S.hosts.length
      ? `<h3>Tidak ada host yang cocok</h3><p>Coba ubah kata kunci atau filter.</p>
         <button class="btn" id="clearFilter">Bersihkan filter</button>`
      : `<h3>Belum ada host terdeteksi</h3>
         <p>Jalankan scan ARP untuk menemukan perangkat di jaringan ini.</p>
         <button class="btn pri" id="emptyScan">Scan ARP</button>`;
    if (tbody._empty !== emptyMsg) {
      tbody.innerHTML = `<tr><td colspan="9" class="empty">
        <svg class="ic"><use href="#i-host"/></svg>${emptyMsg}</td></tr>`;
      tbody._empty = emptyMsg;
      const es = $("#emptyScan");
      if (es) es.onclick = () => doScan();
      const cf = $("#clearFilter");
      if (cf) cf.onclick = () => {
        S.query = ""; $("#q").value = "";
        setFilter("all"); render();
      };
    }
    S.lastOrder = "";
    updateFoot([], 0);
  } else {
    tbody._empty = null;
    if (tbody.firstChild && tbody.firstChild.tagName === "TR" &&
        tbody.firstChild.querySelector(".empty")) tbody.innerHTML = "";

    const top = Math.max(1, ...list.map(x => (x.rx_rate || 0) + (x.tx_rate || 0)));
    const ips = list.map(h => h.ip);
    const order = ips.join(",");
    const reorder = order !== S.lastOrder;

    for (const h of list) {
      let tr = S.rows.get(h.ip);
      if (!tr) {
        tr = makeRow(h);
        S.rows.set(h.ip, tr);
      }
      updateRow(tr, h, top);
      if (reorder || !tr.isConnected) tbody.appendChild(tr);
    }
    // buang baris yang tidak ada di list
    for (const [ip, tr] of S.rows) {
      if (!ips.includes(ip)) { tr.remove(); S.rows.delete(ip); }
    }
    S.lastOrder = order;
    updateFoot(list, top);
  }

  // catatan global
  const noteKeys = Object.keys(S.notes);
  setHTML($("#notes"), noteKeys.length
    ? noteKeys.map(k => `<div class="note"><b>${esc(k)}</b>: ${esc(S.notes[k])}</div>`).join("")
    : "");

  updateSelUI(list);
}

function updateFoot(list, top) {
  let rx = 0, tx = 0, sum = 0;
  for (const h of list) { rx += h.rx_rate || 0; tx += h.tx_rate || 0; sum += h.total || 0; }
  setText($("#footCount"), list.length + " host terlihat");
  setText($("#footRx"), fmtBytesPlain(rx) + "/s");
  setText($("#footTx"), fmtBytesPlain(tx) + "/s");
  setText($("#footSum"), fmtBytesPlain(sum));
}

/* ---------------------------------------------------------- selection UI */
function toggleSelect(ip, range) {
  if (range && S.lastAnchor && S.lastAnchor !== ip) {
    const list = visibleHosts().map(h => h.ip);
    const a = list.indexOf(S.lastAnchor), b = list.indexOf(ip);
    if (a > -1 && b > -1) {
      const [lo, hi] = a < b ? [a, b] : [b, a];
      const on = !S.selected.has(ip);
      for (let i = lo; i <= hi; i++) {
        if (on) S.selected.add(list[i]); else S.selected.delete(list[i]);
      }
      updateSelUI(visibleHosts());
      return;
    }
  }
  if (S.selected.has(ip)) S.selected.delete(ip); else S.selected.add(ip);
  S.lastAnchor = ip;
  updateSelUI(visibleHosts());
}

function updateSelUI(list) {
  list = list || visibleHosts();
  const n = S.selected.size;
  setText($("#selCount"), n);
  $("#bulkbar").classList.toggle("on", n > 0);
  const ids = list.map(h => h.ip);
  const selInView = ids.filter(ip => S.selected.has(ip)).length;
  const all = $("#selAll");
  all.checked = ids.length > 0 && selInView === ids.length;
  all.indeterminate = selInView > 0 && selInView < ids.length;
  all.disabled = ids.length === 0;
  for (const [ip, tr] of S.rows) {
    const want = S.selected.has(ip);
    if (tr._c.sel.checked !== want) tr._c.sel.checked = want;
    tr.classList.toggle("sel", want);
  }
}

/* ---------------------------------------------------------- modal */
let modalCloser = null;
function openModal(title, bodyHTML, footHTML, onMount) {
  setText($("#modalTitle"), title);
  $("#modalBody").innerHTML = bodyHTML;
  $("#modalFoot").innerHTML = footHTML || "";
  $("#modal").classList.add("on");
  $("#modalBox").classList.toggle("wide", !!footHTML);
  modalCloser = onMount || null;
  const f = $("#modalFoot button");
  if (f) f.focus();
  if (onMount) onMount();
}
function closeModal() {
  $("#modal").classList.remove("on");
  if (modalCloser) { modalCloser(); modalCloser = null; }
}
$("#modalX").onclick = closeModal;
$("#modal").addEventListener("mousedown", ev => { if (ev.target === $("#modal")) closeModal(); });

function confirmModal(title, message, confirmLabel, onConfirm) {
  openModal(title, `<p style="margin:0;line-height:1.55">${message}</p>`,
    `<button class="btn" data-x>Cancel</button>
     <button class="btn pri" data-ok>${esc(confirmLabel)}</button>`);
  $('[data-x]').onclick = closeModal;
  $('[data-ok]').onclick = () => { closeModal(); onConfirm(); };
}

function renameModal(ip, current) {
  openModal("Nama perangkat",
    `<p style="margin:0 0 12px;color:var(--fg2);font-size:12.5px;line-height:1.5">
       Nama ini dipakai dashboard untuk <b>${esc(ip)}</b> dan disimpan lokal.
       Kosongkan untuk menghapus.</p>
     <input type="text" id="nameInput" maxlength="32" placeholder="mis. HP Andi"
       value="${esc(current)}" style="width:100%">`,
    `<button class="btn" data-x>Batal</button>
     <button class="btn pri" data-ok>Simpan</button>`,
    () => {
      const el = $("#nameInput");
      el.focus(); el.select();
      el.addEventListener("keydown", e => {
        if (e.key === "Enter") $("[data-ok]").click();
      });
    });
  $("[data-x]").onclick = closeModal;
  $("[data-ok]").onclick = async () => {
    const val = $("#nameInput").value.trim();
    closeModal();
    try {
      const r = await api("/api/name", { ip, name: val });
      if (!r.ok) throw new Error(r.error || "gagal");
      toast(val ? "Nama disimpan" : "Nama dihapus", "ok");
      poll();
    } catch (err) {
      toast("Gagal menyimpan nama: " + err.message, "err");
    }
  };
}

/* ---------------------------------------------------------- limit modal */
function limitModal(ips, current) {
  const title = ips.length === 1
    ? "Batasi bandwidth " + ips[0]
    : "Batasi bandwidth " + ips.length + " perangkat";
  const presets = [128, 256, 512, 1024, 2048];
  const body =
    (ips.length > 1 ? `<div class="note">Perubahan ini berlaku untuk
       <b>${ips.length} perangkat</b> terpilih.</div>` : "") +
    `<label class="fieldlbl" for="kbps">Batas (kbps)</label>
     <input type="number" id="kbps" min="1" step="1" value="${current || 512}"
            style="width:140px">
     <div class="presets">${presets.map(p =>
        `<button class="btn" data-preset="${p}">${p}</button>`).join("")}</div>
     <p class="hint">Token bucket: ada burst kecil di awal, nilai rata-rata
        aktual sedikit di bawah nominal. Aturan berlaku untuk trafik yang lewat
        laptop ini.</p>`;
  openModal(title, body,
    `<button class="btn" data-x>Batal</button>
     <button class="btn pri" data-ok>Terapkan</button>`);
  const inp = $("#kbps");
  inp.focus(); inp.select();
  $$("[data-preset]").forEach(b => b.onclick = () => {
    inp.value = b.dataset.preset; inp.focus();
  });
  $('[data-x]').onclick = closeModal;
  $('[data-ok]').onclick = async () => {
    const kbps = parseInt(inp.value, 10);
    if (!kbps || kbps <= 0) { toast("Nilai kbps tidak valid", "err"); inp.focus(); return; }
    closeModal();
    await applyLimit(ips, kbps);
  };
  inp.onkeydown = ev => {
    if (ev.key === "Enter") $('[data-ok]').click();
  };
}

async function applyLimit(ips, kbps) {
  if (ips.length === 1) {
    const ip = ips[0];
    try {
      const r = await api("/api/limit", { ip, kbps });
      if (r.ok) {
        toast(`<b>${esc(ip)}</b> dibatasi ${kbps} kbps`, "ok");
        if (r.error) toast(esc(r.error), "warn");
      } else toast("Gagal limit " + ip + ": " + esc(r.error || "tidak diketahui"), "err");
    } catch (e) { toast("Error: " + esc(e.message), "err"); }
    poll(); return;
  }
  const t = toast("Memproses " + ips.length + " perangkat…");
  try {
    const r = await api("/api/bulk", { ips, action: "limit", kbps });
    const res = (r && r.results) || {};
    const ok = ips.filter(ip => res[ip] && res[ip].ok);
    const bad = ips.filter(ip => !(res[ip] && res[ip].ok));
    t.remove();
    if (ok.length) toast(`<b>${ok.length}</b> perangkat dibatasi ${kbps} kbps`, "ok");
    bad.forEach(ip => toast(esc(ip) + ": " + esc((res[ip] && res[ip].error) || "gagal"), "err"));
  } catch (e) {
    t.remove();
    toast("Error: " + esc(e.message), "err");
  }
  poll();
}

/* ---------------------------------------------------------- rules modal */
async function showRules() {
  let body = "<p class='hint'>Memuat…</p>";
  openModal("Aturan nftables aktif", body, "");
  try {
    const r = await api("/api/rules");
    const rules = (r && r.rules || "").trim();
    const pre = rules
      ? `<pre class="code">${esc(rules)}</pre>`
      : `<p style="margin:0;color:var(--dim)">Tidak ada aturan nftables aktif.</p>`;
    $("#modalBody").innerHTML =
      pre + `<p class="hint">Aturan ini dibuat oleh netcut untuk membatasi
        perangkat lain. Menghapus manual lewat nft akan membuat status di
        dashboard tidak sinkron.</p>`;
    const f = $("#modalFoot");
    f.innerHTML = rules
      ? `<button class="btn" data-copy>Salin</button><button class="btn pri" data-x>Tutup</button>`
      : `<button class="btn pri" data-x>Tutup</button>`;
    $('[data-x]').onclick = closeModal;
    const cp = $('[data-copy]');
    if (cp) cp.onclick = () => copyText(rules);
  } catch (e) {
    $("#modalBody").innerHTML = `<p style="color:var(--bad)">Gagal: ${esc(e.message)}</p>`;
  }
}

/* ---------------------------------------------------------- clipboard */
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Disalin: " + esc(text), "ok");
  } catch (e) {
    const ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); toast("Disalin: " + esc(text), "ok"); }
    catch (e2) { toast("Gagal menyalin", "err"); }
    ta.remove();
  }
}

/* ---------------------------------------------------------- actions */
async function doBlock(ip) {
  try {
    const r = await api("/api/block", { ip });
    if (r.ok) {
      toast(`<b>${esc(ip)}</b> diblokir`, "ok", {
        label: "Buka", fn: () => doUnblock(ip),
      });
    } else {
      toast("Gagal blokir " + esc(ip) + ": " + esc(r.error || "tidak diketahui"), "err");
    }
  } catch (e) { toast("Error: " + esc(e.message), "err"); }
  poll();
}
async function doUnblock(ip) {
  try {
    const r = await api("/api/unblock", { ip });
    if (r.ok) toast(`<b>${esc(ip)}</b> dibuka`, "ok");
    else toast("Gagal: " + esc(r.error || "?"), "err");
  } catch (e) { toast("Error: " + esc(e.message), "err"); }
  poll();
}
async function doUnlimit(ip) {
  try {
    const r = await api("/api/unlimit", { ip });
    if (r.ok) toast(`Limit <b>${esc(ip)}</b> dibuka`, "ok");
    else toast("Gagal: " + esc(r.error || "?"), "err");
  } catch (e) { toast("Error: " + esc(e.message), "err"); }
  poll();
}
async function doScan() {
  const btn = $("#scanBtn");
  btn.disabled = true;
  try {
    const body = (S.net && S.net.net) ? { net: S.net.net } : {};
    const r = await api("/api/scan", body);
    if (r.started) {
      toast("Scan ARP dimulai…", "ok");
      S.scanning = true; render();
      setTimeout(poll, 400);
    } else toast("Scan gagal: " + esc(r.error || "?"), "err");
  } catch (e) { toast("Scan gagal: " + esc(e.message), "err"); }
  finally { setTimeout(() => { btn.disabled = false; }, 800); }
}

/* ---------------------------------------------------------- bulk */
async function bulkAction(action, ips, kbps) {
  if (!ips.length) return;
  const t = toast("Memproses " + ips.length + " perangkat…");
  try {
    const r = await api("/api/bulk", { ips, action, kbps: kbps || 0 });
    const res = (r && r.results) || {};
    const ok = ips.filter(ip => res[ip] && res[ip].ok);
    const bad = ips.filter(ip => !(res[ip] && res[ip].ok));
    t.remove();
    if (action === "block") {
      if (ok.length) toast(`<b>${ok.length}</b> perangkat diblokir`, "ok", {
        label: "Buka semua", fn: () => bulkAction("unblock", ok),
      });
    } else if (action === "unblock") {
      if (ok.length) toast(`<b>${ok.length}</b> perangkat dibuka`, "ok");
    } else if (action === "unlimit") {
      if (ok.length) toast(`Limit <b>${ok.length}</b> perangkat dibuka`, "ok");
    }
    bad.forEach(ip => toast(esc(ip) + ": " + esc((res[ip] && res[ip].error) || "gagal"), "err"));
    if (!ok.length && !bad.length) toast("Tidak ada perubahan", "warn");
  } catch (e) {
    t.remove();
    toast("Error: " + esc(e.message), "err");
  }
  poll();
}

function selectedIps() {
  return Array.from(S.selected);
}

/* ---------------------------------------------------------- polling */
let pollTimer = null;
async function poll() {
  if (S.paused) return;
  try {
    const d = await api("/api/hosts");
    applySnapshot(d);
    render();
  } catch (e) {
    if (S.online) {
      S.online = false;
      render();
      toast("Server tidak merespons — mencoba lagi…", "err");
    }
  }
}
function setPolling(on) {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  if (on) pollTimer = setInterval(poll, 1000);
}

/* ---------------------------------------------------------- filter */
function setFilter(f) {
  S.filter = f;
  $$(".chip").forEach(c =>
    c.setAttribute("aria-pressed", c.dataset.f === f ? "true" : "false"));
  render();
}

/* ---------------------------------------------------------- events */
$("#q").addEventListener("input", ev => {
  S.query = ev.target.value;
  render();
});
$$(".chip").forEach(c => c.onclick = () => setFilter(c.dataset.f));

$("#selAll").addEventListener("change", ev => {
  const list = visibleHosts();
  if (ev.target.checked) list.forEach(h => S.selected.add(h.ip));
  else list.forEach(h => S.selected.delete(h.ip));
  updateSelUI(list);
});

$("#rows").addEventListener("click", async ev => {
  const b = ev.target.closest("button[data-act]");
  if (!b) return;
  const ip = b.dataset.ip, act = b.dataset.act;
  b.disabled = true;
  try {
    if (act === "block") await doBlock(ip);
    else if (act === "unblock") await doUnblock(ip);
    else if (act === "limit") limitModal([ip], S.limited.get(ip));
    else if (act === "unlimit") await doUnlimit(ip);
  } finally { b.disabled = false; }
});

$("#bulkBlock").onclick = () => {
  const ips = selectedIps();
  confirmModal("Blokir " + ips.length + " perangkat?",
    "ARP spoofing akan diarahkan ke <b>" + ips.length +
    "</b> perangkat terpilih dan trafik internetnya dibuang.<br><br>" +
    "<span class='mono' style='font-size:11.5px'>" +
    ips.map(esc).join(", ") + "</span>",
    "Blokir", () => bulkAction("block", ips));
};
$("#bulkUnblock").onclick = () => bulkAction("unblock", selectedIps());
$("#bulkUnlimit").onclick = () => bulkAction("unlimit", selectedIps());
$("#bulkLimit").onclick = () => {
  const ips = selectedIps();
  const cur = ips.length === 1 ? S.limited.get(ips[0]) : 0;
  limitModal(ips, cur);
};
$("#bulkClear").onclick = () => { S.selected.clear(); updateSelUI(); };

$("#scanBtn").onclick = doScan;
$("#rulesBtn").onclick = showRules;

$("#ifaceSel").onchange = async ev => {
  const i = ev.target.value;
  try {
    const r = await api("/api/iface", { iface: i });
    if (r.ok) { toast("Interface diganti ke " + esc(i), "ok"); poll(); }
    else { toast("Gagal: " + esc(r.error || "?"), "err"); ev.target.value = S.iface; }
  } catch (e) { toast("Error: " + esc(e.message), "err"); }
};

$("#pauseBtn").onclick = () => {
  S.paused = !S.paused;
  $("#pauseBtn").classList.toggle("on", S.paused);
  $("#pauseBtn").innerHTML = S.paused
    ? '<svg class="ic"><use href="#i-play"/></svg>'
    : '<svg class="ic"><use href="#i-pause"/></svg>';
  $("#pauseBtn").setAttribute("aria-label", S.paused ? "Lanjutkan polling" : "Jeda polling");
  if (S.paused) { setPolling(false); toast("Polling dijeda", "warn"); }
  else { setPolling(true); poll(); toast("Polling dilanjutkan", "ok"); }
  render();
};

function applyTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  try { localStorage.setItem("netcut-theme", t); } catch (e) {}
  $("#themeBtn").innerHTML = t === "dark"
    ? '<svg class="ic"><use href="#i-sun"/></svg>'
    : '<svg class="ic"><use href="#i-moon"/></svg>';
}
$("#themeBtn").onclick = () => {
  const cur = document.documentElement.getAttribute("data-theme");
  applyTheme(cur === "dark" ? "light" : "dark");
};

$("#helpBtn").onclick = () => {
  openModal("Bantuan netcut-linux",
    `<p class="hint" style="margin-top:0">Pantau trafik per perangkat di
      jaringan lokal, lalu blokir atau batasi bandwidth-nya. Semua kontrol
      bekerja lewat nftables + ARP spoofing, jadi butuh hak akses jaringan.</p>
     <div class="keys" style="margin-top:12px">
      <div><kbd>/</kbd><span>Cari host</span></div>
      <div><kbd>Ctrl</kbd>+<kbd>A</kbd><span>Pilih semua yang tampil</span></div>
      <div><kbd>Esc</kbd><span>Tutup dialog / bersihkan pencarian</span></div>
      <div><kbd>S</kbd><span>Scan ARP</span></div>
      <div><kbd>R</kbd><span>Lihat aturan nftables</span></div>
      <div><kbd>P</kbd><span>Jeda / lanjut polling</span></div>
      <div><kbd>T</kbd><span>Ganti tema</span></div>
      <div><kbd>?</kbd><span>Bantuan ini</span></div>
     </div>
     <p class="hint">Klik baris untuk menyelect perangkat, lalu pakai bilah
       aksi massal di bawah untuk memblokir banyak perangkat sekaligus.</p>`,
    `<button class="btn pri" data-x>Tutup</button>`);
  $('[data-x]').onclick = closeModal;
};

/* header kolom: sort lokal, tanpa request ke server */
$$("th.sortable").forEach(th => {
  th.onclick = () => {
    const k = th.dataset.k;
    if (S.sortKey === k) S.sortDir *= -1;
    else { S.sortKey = k; S.sortDir = (k === "ip" || k === "mac" || k === "vendor") ? 1 : -1; }
    $$("th.sortable").forEach(o => o.removeAttribute("aria-sort"));
    th.setAttribute("aria-sort", S.sortDir === 1 ? "ascending" : "descending");
    S.lastOrder = "";
    render();
  };
});

document.addEventListener("keydown", ev => {
  const tag = (ev.target.tagName || "").toLowerCase();
  const typing = tag === "input" || tag === "textarea" || tag === "select";
  if (ev.key === "Escape") {
    if ($("#modal").classList.contains("on")) { closeModal(); return; }
    if (typing && ev.target.id === "q") { ev.target.value = ""; S.query = ""; render(); }
    return;
  }
  if (typing) return;
  if (ev.key === "/" ) { ev.preventDefault(); $("#q").focus(); $("#q").select(); return; }
  if (ev.key === "?") { ev.preventDefault(); $("#helpBtn").click(); return; }
  if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "a") {
    ev.preventDefault();
    visibleHosts().forEach(h => S.selected.add(h.ip));
    updateSelUI();
    return;
  }
  const k = ev.key.toLowerCase();
  if (k === "s") { ev.preventDefault(); doScan(); }
  else if (k === "r") { ev.preventDefault(); showRules(); }
  else if (k === "p") { ev.preventDefault(); $("#pauseBtn").click(); }
  else if (k === "t") { ev.preventDefault(); $("#themeBtn").click(); }
});

document.addEventListener("visibilitychange", () => {
  if (document.hidden) setPolling(false);
  else if (!S.paused) { setPolling(true); poll(); }
});

/* ---------------------------------------------------------- start */
applyTheme(document.documentElement.getAttribute("data-theme") || "dark");
if (window.__INIT__) { try { applySnapshot(window.__INIT__); render(); } catch (e) {} }
render();
poll();
setPolling(true);
</script>
</body>
</html>
"""


LABELS_FILE = os.path.join(
    os.environ.get("NETCUT_STATE_DIR", os.path.expanduser("~/.cache/netcut")),
    "labels.json")


def load_labels() -> dict[str, str]:
    """Nama perangkat yang diberikan pengguna (ip -> nama), dari disk."""
    try:
        with open(LABELS_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str) and v}


def save_labels(labels: dict[str, str]) -> None:
    try:
        os.makedirs(os.path.dirname(LABELS_FILE), exist_ok=True)
        tmp = LABELS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(labels, f, ensure_ascii=False, indent=1, sort_keys=True)
        os.replace(tmp, LABELS_FILE)
    except OSError as exc:
        print(f"[web] gagal menyimpan nama perangkat: {exc}", flush=True)


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
        self.labels: dict[str, str] = load_labels()
        self._net_sig: tuple = ()
        self._pending_sig: tuple | None = None
        self._pending_count = 0
        self._last_net_check = 0.0
        self._last_prune = 0.0
        self.net_info: dict = {}
        self.forward_block = ""
        self._tc_lock = threading.Lock()

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
            self.sniffer.refresh_names()
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

    def start_scan(self, net: str | None = None) -> bool:
        """Jalankan ARP scan di background (tidak memblokir UI).

        Mengembalikan False kalau scan sebelumnya belum selesai.
        """
        if self.scanning:
            return False
        self.scanning = True
        self.scan_result = None
        # subnet dibaca langsung dari interface saat ini, bukan dari
        # net_info yang bisa masih berisi data subnet lama
        net = net or _guess_net(self.iface)

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
                # probe nama diulang untuk semua host: perangkat yang tadi
                # mati bisa sudah hidup lagi sejak scan terakhir
                self.sniffer.names.forget()
                self.scan_result = {"found": len(found), "net": net}
            except Exception as exc:
                self.scan_result = {"found": 0, "net": net, "error": str(exc)}
            finally:
                self.scanning = False

        threading.Thread(target=_run, daemon=True).start()
        return True

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

    # -- blokir / limit ----------------------------------------------
    def _start_block(self, ip: str, res: dict) -> None:
        """Blokir satu host di background. Hasil akhir ditulis ke `res`."""
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
                    res[ip] = {"ok": False,
                               "error": "ARP spoof gagal: MAC device tidak "
                                        "ditemukan di jaringan ini"}
                    return
                self.spoofer.start()
                with self._tc_lock:
                    ok = self.tc.block(ip, spoofer=None)
                if not ok:
                    print(f"[web] blokir {ip}: gagal menambah rule nftables", flush=True)
                    self.blocked_hosts.discard(ip)
                    res[ip] = {"ok": False, "error": "gagal menambah rule nftables"}
                    return
                self.blocked_hosts.add(ip)
                res[ip] = {"ok": True}
                print(f"[web] blokir {ip}: aktif", flush=True)
            except Exception as exc:
                print(f"[web] blokir {ip} error: {exc!r}", flush=True)
                self.blocked_hosts.discard(ip)
                res[ip] = {"ok": False, "error": str(exc)}

        threading.Thread(target=_run, daemon=True).start()

    def block(self, ip: str) -> tuple[bool, str]:
        """Blokir host lain di LAN (ARP spoof + drop), seperti NetCut.

        ARP resolve bisa memakan waktu beberapa detik, jadi dilakukan di
        background thread supaya request HTTP tidak timeout.
        """
        if self.spoofer is None:
            with self._tc_lock:
                ok = self.tc.block(ip, spoofer=None)
            if ok:
                self.blocked_hosts.add(ip)
            return ok, "" if ok else "gagal menambah rule nftables"

        if ip in self.blocked_hosts:
            return True, ""

        res: dict = {}
        self._start_block(ip, res)
        for _ in range(60):
            if ip in res:
                return bool(res[ip].get("ok")), res[ip].get("error", "")
            time.sleep(0.1)
        # gagal: jelaskan ke user, jangan laporkan sukses palsu
        return False, "ARP spoof gagal: MAC device tidak ditemukan di jaringan ini"

    def unblock(self, ip: str) -> tuple[bool, str]:
        if self.spoofer is not None:
            self.spoofer.restore(ip)
        with self._tc_lock:
            self.tc.unblock(ip, spoofer=None)
        self.blocked_hosts.discard(ip)
        return True, ""

    def _start_limit(self, ip: str, kbps: int, res: dict) -> None:
        """Pasang limit bandwidth di background. Hasil akhir ditulis ke `res`."""
        def _run() -> None:
            try:
                # Spoof harus aktif lebih dulu: relay bergantung pada
                # victim's ARP cache yang sudah diarahkan ke laptop, baru
                # rule limit di chain forward bisa mengenali trafiknya.
                host = self.sniffer.hosts.get(ip)
                vmac = host.mac if host else ""
                if not self.spoofer.poison(ip, victim_mac=vmac, mode="relay"):
                    print(f"[web] limit {ip}: ARP spoof gagal", flush=True)
                    self.limited_hosts.pop(ip, None)
                    res[ip] = {"ok": False,
                               "error": "ARP spoof gagal: MAC device tidak "
                                        "ditemukan di jaringan ini"}
                    return
                self.spoofer.start()
                with self._tc_lock:
                    ok = self.tc.limit(ip, kbps, spoofer=None)
                if not ok:
                    self.limited_hosts.pop(ip, None)
                    res[ip] = {"ok": False, "error": "gagal memasang rule limit"}
                    return
                self.limited_hosts[ip] = kbps
                res[ip] = {"ok": True}
                # Kalau firewall host membuang trafik forward, limit tidak
                # akan berlaku although rule-nya terpasang.
                block = self.tc.forward_policy_blocks()
                if block:
                    self.forward_block = block
                    res[ip]["warning"] = (
                        f"{block}. Verdict accept tidak menghentikan hook, "
                        "jadi trafik korban tetap dibuang dan Limit tidak "
                        "berlaku. Pakai Blokir, atau longgarkan firewall host.")
                # cek apakah router menerima ARP spoof kita. Kalau tidak,
                # balasan download bypass laptop sehingga limit hanya
                # berlaku untuk arah upload.
                if vmac and not self.spoofer.router_spoofable(ip, vmac):
                    note = ("Router menolak ARP spoof: limit hanya berlaku "
                            "untuk upload. Gunakan Blokir untuk membatasi total.")
                    self.notes[ip] = note
                    res[ip]["note"] = note
            except Exception as exc:
                print(f"[web] limit {ip} gagal: {exc!r}", flush=True)
                self.limited_hosts.pop(ip, None)
                res[ip] = {"ok": False, "error": str(exc)}

        threading.Thread(target=_run, daemon=True).start()

    def limit(self, ip: str, kbps: int) -> tuple[bool, str]:
        """Batasi bandwidth device lain (ARP spoof + relay + rate limit)."""
        if self.spoofer is None:
            with self._tc_lock:
                ok = self.tc.limit(ip, kbps, spoofer=None)
            if ok:
                self.limited_hosts[ip] = kbps
            return ok, "" if ok else "gagal memasang rule limit"

        if ip in self.limited_hosts:
            return True, ""

        res: dict = {}
        self._start_limit(ip, kbps, res)
        for _ in range(80):
            if ip in res:
                return bool(res[ip].get("ok")), res[ip].get("error", "")
            time.sleep(0.1)
        ok = ip in self.limited_hosts
        return ok, ("ARP spoof gagal: MAC device tidak ditemukan"
                    if not ok else "")

    def unlimit(self, ip: str) -> tuple[bool, str]:
        with self._tc_lock:
            self.tc.unlimit(ip, spoofer=self.spoofer)
        self.limited_hosts.pop(ip, None)
        self.notes.pop(ip, None)
        return True, ""

    # -- aksi massal --------------------------------------------------
    def bulk(self, ips: list[str], action: str, kbps: int = 0) -> dict:
        """Jalankan aksi untuk banyak IP sekaligus.

        Semua IP diproses paralel supaya blkiran 10 perangkat tidak
        menunggu 10x waktu ARP resolve. Hasil per IP dikembalikan dalam
        bentuk {"ip": {"ok": bool, "error": str, "note": str}}.
        """
        ips = [ip for ip in dict.fromkeys(ips or []) if ip]
        results: dict = {}
        if not ips:
            return results

        if action == "block":
            pending = []
            for ip in ips:
                if ip in self.blocked_hosts:
                    results[ip] = {"ok": True}
                else:
                    pending.append(ip)
            for ip in pending:
                self._start_block(ip, results)
            self._await(results, pending, timeout=25.0)

        elif action == "unblock":
            for ip in ips:
                self.unblock(ip)
                results[ip] = {"ok": True}

        elif action == "limit":
            pending = []
            for ip in ips:
                if ip in self.limited_hosts:
                    results[ip] = {"ok": True}
                else:
                    pending.append(ip)
            for ip in pending:
                self._start_limit(ip, kbps, results)
            self._await(results, pending, timeout=30.0)

        elif action == "unlimit":
            for ip in ips:
                self.unlimit(ip)
                results[ip] = {"ok": True}

        else:
            raise ValueError(f"aksi tidak dikenal: {action}")

        for ip in ips:
            results.setdefault(ip, {"ok": False, "error": "timeout"})
        return results

    @staticmethod
    def _await(results: dict, pending: list[str], timeout: float) -> None:
        end = time.time() + timeout
        while time.time() < end:
            if all(ip in results for ip in pending):
                return
            time.sleep(0.1)

    # -- snapshot -----------------------------------------------------
    def snapshot(self) -> dict:
        s = self.sniffer
        now = time.time()
        hosts = []
        for h in s.hosts.values():
            hosts.append({
                "ip": h.ip,
                "mac": h.mac,
                "vendor": h.vendor,
                "name": h.name,
                "name_src": h.name_src,
                "label": self.labels.get(h.ip, ""),
                "rx": h.rx,
                "tx": h.tx,
                "total": h.rx + h.tx,
                "rx_rate": h.rx_rate,
                "tx_rate": h.tx_rate,
                "seen_ago": round(now - h.last_seen, 1),
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
            "forward_blocked": self.forward_block,
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
            init = json.dumps(self.state.snapshot()).replace("</", "<\\/")
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
            elif path == "/api/bulk":
                ips = data.get("ips") or []
                action = data.get("action", "")
                kbps = int(data.get("kbps", 0) or 0)
                if not isinstance(ips, list) or not ips:
                    self._json({"ok": False, "error": "ips wajib diisi"}, 400)
                    return
                if action not in ("block", "unblock", "limit", "unlimit"):
                    self._json({"ok": False, "error": "action tidak dikenal"}, 400)
                    return
                if action == "limit" and kbps <= 0:
                    self._json({"ok": False, "error": "kbps wajib diisi"}, 400)
                    return
                results = self.state.bulk([str(i) for i in ips], action, kbps)
                self._json({"ok": True, "action": action, "results": results})
            elif path == "/api/name":
                ip = str(data.get("ip", "")).strip()
                if not ip:
                    self._json({"ok": False, "error": "ip wajib diisi"}, 400)
                    return
                name = str(data.get("name", "")).strip()[:32]
                if name:
                    self.state.labels[ip] = name
                else:
                    self.state.labels.pop(ip, None)
                save_labels(self.state.labels)
                self._json({"ok": True, "ip": ip, "name": name})
            elif path == "/api/scan":
                net = data.get("net") or _guess_net(self.state.iface)
                # scan memakan waktu (254 probe), jadi dijalankan di background
                if not self.state.start_scan(net):
                    self._json({"ok": False, "error": "scan sedang berjalan"}, 409)
                    return
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
