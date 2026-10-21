# netcut-linux

Per-host bandwidth monitoring & traffic control for your local network on Linux.

Inspired by **NetCut** for Windows — the interface and behaviour are similar,
but it is reimplemented with native Linux tooling.

**English** · [Bahasa Indonesia](README.id.md)

![netcut-linux dashboard](assets/dashboard.png)

## Features

- **Real-time monitoring** per host: IP, MAC, vendor, download, upload, total
- **Block a device** — cut a device's internet access on the network
- **Bandwidth limiting** per device (kbps)
- **Bulk actions** — select many devices at once, then block, unblock or limit
  them all in one go
- **Search & filter** — by IP/MAC/vendor, plus Active/Blocked/Limited filters
- **Vendor lookup** from the local OUI database
- **Host discovery** via ARP scan + kernel ARP cache
- **Web dashboard** with a JSON REST API
- **Dark & light themes** (dark-first, with a toggle that remembers your pick)
- **Native Linux app**: launcher, app menu entry, system tray
- **Automatic WiFi change detection** — rescan when the network changes

## Installation

```bash
git clone https://github.com/Aryoksss/netcut-linux
cd netcut-linux
./install.sh
```

The launcher is installed to `~/.local/bin/netcut` and the app appears in your
application menu.

Without installing:

```bash
./netcut.py --web      # dashboard at http://127.0.0.1:8080
```

### Dependencies

| Package | Debian/Ubuntu | Fedora |
|---|---|---|
| Scapy | `python3-scapy` | `python3-scapy` |
| nftables | `nftables` | `nftables` |
| OUI database | `hwdata` | `hwdata` |

### Privileges

Blocking and limiting other devices requires `CAP_NET_RAW` (capture) and
`CAP_NET_ADMIN` (nftables). The launcher picks a privilege path automatically:

1. **Has `CAP_NET_RAW`** → runs directly
2. **Docker available** (user is in the `docker` group) → server runs in a
   container with `--cap-add=NET_RAW --cap-add=NET_ADMIN --network=host`
3. **Otherwise** → fallback mode: whole-interface monitoring only, no control

The active mode is shown in the dashboard header: `capture` (full) or
`fallback-no-root` (limited).

## Usage

### CLI

```bash
netcut                          # open web GUI + system tray
netcut --tray                   # system tray only
netcut --status                 # server status (URL, mode, host count)
netcut --stop                   # stop the server
netcut --port 8090              # use a different port
netcut --no-tray                # run the server without a tray icon
netcut --help                   # help

sudo ./netcut.py --once         # single snapshot
sudo ./netcut.py --json         # JSON output
sudo ./netcut.py --scan         # ARP scan
sudo ./netcut.py --block 192.168.1.50      # block a device
sudo ./netcut.py --cut 192.168.1.50        # cut a device's connection
sudo ./netcut.py --limit 192.168.1.50 512  # limit to 512 kbps
sudo ./netcut.py --unblock 192.168.1.50    # remove block
sudo ./netcut.py --list-rules               # active nftables rules
```

### Web dashboard

```bash
sudo ./netcut.py --web --web-port 8080
```

- Live per-host table: IP, MAC, vendor, download, upload, total
- Sort by column (click a header) — entirely client side, no server round-trip
- **Search** by IP/MAC/vendor, plus **filters** for All / Active / Blocked / Limited
- **Multi-select**: tick a checkbox or click a row to select several devices,
  then use the bulk action bar to block, unblock or limit them all at once
- **Block** / **Unblock** and **Limit** / **Remove limit** buttons per row
- Limit dialog with presets (128/256/512/1024/2048 kbps) instead of `prompt()`
- Summary cards: total download, upload, active hosts, blocked count, packets
- Table footer with totals; idle rows (>45s) are dimmed
- **ARP scan** (background, does not freeze the UI)
- **nft rules** in a copyable dialog
- Switch interface directly from the header
- **Pause polling** (`P`), toggle theme (`T`), help (`?`)
- Polling stops automatically while the browser tab is in the background

![Blocked device](assets/blocked.png)

**Bulk actions** — select several devices, then block them all at once:

![Bulk actions](assets/bulk.png)

Light theme (the sun button in the header):

![Light theme](assets/light.png)

#### Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `/` | Focus the search box |
| `Ctrl`+`A` | Select every visible device |
| `Esc` | Close a dialog / clear the search |
| `S` | ARP scan |
| `R` | Show nftables rules |
| `P` | Pause / resume polling |
| `T` | Toggle theme |

### REST API

| Endpoint | Method | Body | Purpose |
|---|---|---|---|
| `/api/hosts` | GET | — | host snapshot + rates |
| `/api/rules` | GET | — | active nftables rules |
| `/api/block` | POST | `{"ip":"..."}` | block a host |
| `/api/unblock` | POST | `{"ip":"..."}` | unblock a host |
| `/api/limit` | POST | `{"ip":"...","kbps":512}` | limit bandwidth |
| `/api/unlimit` | POST | `{"ip":"..."}` | remove limit |
| `/api/bulk` | POST | `{"ips":[...],"action":"block\|unblock\|limit\|unlimit","kbps":512}` | bulk action (processed in parallel) |
| `/api/scan` | POST | `{"net":"..."}` | ARP scan (background) |
| `/api/iface` | POST | `{"iface":"..."}` | switch interface |

### System tray

The tray icon shows a live tooltip: `netcut - <SSID>: <host count>` (plus how
many devices are blocked or limited). The icon switches to an attention state
while devices are blocked. Right-click menu:

- **Open Dashboard** — open the web GUI in your browser
- **ARP Scan** — scan the active subnet
- **Quick block…** — a zenity checklist, pick many devices and block them at once
- **Unblock / remove limit…** — a checklist for lifting blocks and limits
- **nftables Rules** — show the active ruleset
- **Remove All Blocks** — clear blocks & limits
- **Quit** — stop

The tray uses `AppIndicator3` (StatusNotifier protocol) — on Wayland that is
the only way to get a tray icon. Desktop notifications appear when the network
changes or a host is blocked/limited.

### niri keybind

Add to `~/.config/niri/config.kdl`:

```
Mod+Shift+N hotkey-overlay-title="NetCut" {
    spawn "/home/aryoks/.local/bin/netcut";
}
```

## How it works

![How it works](assets/architecture.png)

For rules on your laptop to affect another device's traffic, that traffic has
to pass through the laptop first. That is achieved with ARP spoofing: the
victim is told the gateway lives at the laptop's MAC, so its traffic is
redirected to the laptop — and only then can it be dropped or rate-limited
here.

- **Block** mode → packets reach the laptop and are dropped
- **Limit** mode → packets reach the laptop, are forwarded to the gateway,
  but rate-limited

## Known limitations

- **WiFi access points drop frames with a foreign source MAC.** Because of
  that, an ARP reply from the gateway's MAC never reaches the victim, and
  relay frames must use the laptop's own MAC. As a result, when a block is
  removed the victim's ARP cache has to expire on its own before things return
  to normal.

- **Routers with ARP spoofing protection** (e.g. some ISP routers) reject
  spoofing towards the router side. Download replies from the internet are then
  sent straight to the device, bypassing the laptop — so **limiting only
  applies to the upload direction** on such routers. The tool detects this
  automatically and shows a warning badge. To cap total traffic, use **Block**.

- **Limiting uses a token bucket**, so there is a burst at the start. The
  actual average ends up slightly below the nominal value.

- nftables rules apply to **this machine's own traffic**. To permanently
  constrain other devices, put rules on the router.

## Automatic WiFi switching

The tool watches for network changes every 3 seconds. As soon as you switch
WiFi or change hotspot, it restores the victims' ARP caches, removes old
rules, drops the host list from the previous subnet, and runs an ARP scan on
the new subnet.

## Tests

```bash
python3 test_parser.py     # 9 unit tests, no root required
sudo python3 test_suite.py # 28 end-to-end tests on an isolated virtual network
python3 tools/ui_test.py --serve   # 44 dashboard UI tests (needs playwright)
```

The end-to-end tests use `veth` + network namespaces so they never touch the
host network, and they are skipped automatically when `CAP_NET_ADMIN` is not
available.

The UI tests drive Chromium (Playwright) against a demo server filled with
synthetic data — they never touch a real network.

## Regenerating screenshots

The images in this README are rendered from the real dashboard HTML using
synthetic demo data, so they contain no one's SSID or MAC addresses:

```bash
python3 tools/make_screenshots.py   # requires firefox + Pillow
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

> ARP spoofing is a MITM technique that can be abused.
> Use it only on devices you own, on your own network.
