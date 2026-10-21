#!/usr/bin/env python3
"""netcut-app - launcher GUI + system tray untuk netcut-linux.

Fitur:
  - Jalankan web GUI dan buka browser
  - System tray icon: klik untuk buka dashboard, menu untuk aksi cepat
  - Notifikasi desktop saat jaringan berubah / host diblokir
  - Graceful shutdown (restore ARP cache korban)

Dipakai oleh netcut.desktop dan tray.sh.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

APP_DIR = os.path.dirname(os.path.abspath(__file__))
NETCUT_PY = os.path.join(APP_DIR, "netcut.py")
PID_FILE = os.path.expanduser("~/.cache/netcut/netcut.pid")
LOG_FILE = os.path.expanduser("~/.cache/netcut/server.log")
PORT = int(os.environ.get("NETCUT_PORT", "8080"))
BASE = f"http://127.0.0.1:{PORT}"


# ---------------------------------------------------------------- output
class C:
    """Warna ANSI. Nonaktif kalau stdout bukan tty atau NO_COLOR diset."""

    _ok = "\033[32m"
    _err = "\033[31m"
    _warn = "\033[33m"
    _dim = "\033[2m"
    _b = "\033[1m"
    _off = "\033[0m"

    @classmethod
    def _on(cls) -> bool:
        return sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    @classmethod
    def dim(cls, s: str) -> str:
        return f"{cls._dim}{s}{cls._off}" if cls._on() else s

    @classmethod
    def bold(cls, s: str) -> str:
        return f"{cls._b}{s}{cls._off}" if cls._on() else s

    @classmethod
    def green(cls, s: str) -> str:
        return f"{cls._ok}{s}{cls._off}" if cls._on() else s

    @classmethod
    def red(cls, s: str) -> str:
        return f"{cls._err}{s}{cls._off}" if cls._on() else s

    @classmethod
    def yellow(cls, s: str) -> str:
        return f"{cls._warn}{s}{cls._off}" if cls._on() else s


def log(msg: str) -> None:
    print(f"{C.dim('[netcut]')} {msg}", flush=True)


def _open_log():
    """Buka file log server. Output subprocess dicatat di sini supaya
    pesan error (mis. scapy kurang) tidak hilang begitu saja."""
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        return open(LOG_FILE, "ab", buffering=0)
    except OSError:
        return subprocess.DEVNULL


def log_tail(lines: int = 12) -> str:
    """Ambil beberapa baris terakhir dari log server."""
    try:
        with open(LOG_FILE, "rb") as fh:
            data = fh.read().decode(errors="replace").splitlines()
        return "\n".join(data[-lines:])
    except OSError:
        return ""


def show_server_error() -> None:
    """Tampilkan kenapa server gagal start, kalau ada petalanya."""
    state = {}
    try:
        with open(PID_FILE) as fh:
            state = json.loads(fh.read() or "{}")
    except (OSError, ValueError):
        state = {}

    if state.get("mode") == "docker":
        try:
            r = subprocess.run(["docker", "logs", "--tail", "12", "netcut-app"],
                               capture_output=True, text=True, timeout=15)
            out = (r.stdout + r.stderr).strip()
            if out:
                print(C.red("  output container:"))
                for line in out.splitlines():
                    print(C.dim("    " + line))
                return
        except (OSError, subprocess.SubprocessError):
            pass

    tail = log_tail()
    if tail.strip():
        print(C.red("  output server:"))
        for line in tail.splitlines():
            print(C.dim("    " + line))


USAGE = f"""\
{C.bold('netcut-linux')} - monitor bandwidth per host & kontrol trafik jaringan lokal

{C.bold('Pakai:')} netcut [opsi]

  {C.bold('--tray')}            jalankan hanya di system tray (tanpa buka browser)
  {C.bold('--doctor')}           cek environment: dependency, hak akses, mode
  {C.bold('--status')}          cek status server (URL, mode, jumlah host)
  {C.bold('--stop')}            hentikan server
  {C.bold('--port')} PORT       porta web GUI (default {PORT}, atau env NETCUT_PORT)
  {C.bold('--no-tray')}         jalankan server tanpa ikon system tray
  {C.bold('-h, --help')}        tampilkan bantuan ini

Dashboard web  : {C.bold(BASE)}
Aturan nft    : sudo nft list table inet netcut
"""



# ---------------------------------------------------------------- server
class Server:
    """Menjalankan netcut.py --web sebagai proses anak.

    Capture per-host butuh CAP_NET_RAW. Tanpa itu tool hanya bisa
    menampilkan mode fallback (total interface + daftar host, tanpa
    kontrol blokir/limit).

    Karena user umumnya ada di grup `docker`, server dijalankan di dalam
    container dengan --cap-add=NET_RAW --cap-add=NET_ADMIN bila
    memungkinkan. Dengan begitu seluruh fitur (blokir, limit, ARP spoof)
    bekerja tanpa perlu sudo, dan container berbagi network namespace
    dengan host sehingga aturannya nftables langsung berlaku di host.
    """

    IMAGE = "docker.io/library/fedora:44"
    CONTAINER = "netcut-app"

    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.container = False

    # -- kapabilitas ---------------------------------------------------
    @staticmethod
    def has_capture_privs() -> bool:
        """Cek apakah proses ini punya CAP_NET_RAW."""
        if os.geteuid() == 0:
            return True
        try:
            with open("/proc/self/status") as fh:
                for line in fh:
                    if line.startswith("CapEff:"):
                        caps = int(line.split()[1], 16)
                        return bool(caps & (1 << 13))  # CAP_NET_RAW
        except OSError:
            pass
        return False

    @staticmethod
    def docker_usable() -> bool:
        try:
            p = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                               capture_output=True, text=True, timeout=10)
            return p.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    # -- start ----------------------------------------------------------
    def start(self) -> bool:
        if self.is_running():
            return True
        os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)

        if self.has_capture_privs():
            ok = self._start_native()
            if ok:
                return True
        if self.docker_usable():
            log("menjalankan via docker (privilege penuh, tanpa sudo)")
            if self._start_docker():
                return True
        log("menjalankan natively (mode fallback: tanpa kontrol blokir/limit)")
        return self._start_native()

    def _start_native(self) -> bool:
        cmd = [sys.executable, NETCUT_PY, "--web", "--web-port", str(PORT)]
        log(f"menjalankan: {' '.join(cmd)}")
        self.proc = subprocess.Popen(
            cmd, stdout=_open_log(), stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self._save_state({"mode": "native", "pid": self.proc.pid})
        return self.wait_ready()

    def _start_docker(self) -> bool:
        try:
            subprocess.run(["docker", "rm", "-f", self.CONTAINER],
                           capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            pass
        # /usr, /lib, /lib64 di-mount dari host, jadi interpreter Python di
        # dalam container sama dengan milik host. Karena itu pakai
        # sys.executable, bukan path hardcode - kalau host pakai Python 3.13,
        # path 3.14 tidak ada dan container gagal start.
        py_bin = sys.executable or "python3"
        py_tag = f"python{sys.version_info.major}.{sys.version_info.minor}"
        user_site = os.path.join(os.path.expanduser("~"), ".local", "lib",
                                  py_tag, "site-packages")
        cmd = [
            "docker", "run", "-d",
            "--name", self.CONTAINER,
            "--network=host",
            "--cap-add=NET_RAW",
            "--cap-add=NET_ADMIN",
            "--restart", "unless-stopped",
            "-v", "/usr:/usr:ro", "-v", "/lib:/lib:ro", "-v", "/lib64:/lib64:ro",
            "-v", f"{os.path.expanduser('~')}/.local:"
                  f"{os.path.expanduser('~')}/.local:ro",
            "-v", f"{APP_DIR}:/app",
            "-w", "/app",
            "-e", "PYTHONPATH=" + user_site,
            self.IMAGE,
            py_bin, "/app/netcut.py", "--web", "--web-port", str(PORT),
        ]
        log(f"menjalankan: {' '.join(cmd[:8])} … (docker)")
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as exc:
            log(f"docker gagal: {exc}")
            return False
        if p.returncode != 0:
            log(f"docker gagal: {p.stderr.strip()[:200]}")
            return False
        self.container = True
        self._save_state({"mode": "docker", "container": self.CONTAINER})
        return self.wait_ready()

    def _save_state(self, state: dict) -> None:
        try:
            os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
            with open(PID_FILE, "w") as fh:
                json.dump(state, fh)
        except OSError:
            pass

    def _load_state(self) -> dict:
        """Baca state server. Toleran terhadap format lama (PID polos)."""
        try:
            with open(PID_FILE) as fh:
                raw = fh.read().strip()
        except OSError:
            return {}
        if not raw:
            return {}
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
        except ValueError:
            pass
        # format lama: isi file hanya PID
        try:
            return {"mode": "native", "pid": int(raw)}
        except ValueError:
            return {}

    def is_running(self) -> bool:
        state = self._load_state()
        if state.get("mode") == "docker":
            try:
                p = subprocess.run(
                    ["docker", "inspect", "-f", "{{.State.Running}}", self.CONTAINER],
                    capture_output=True, text=True, timeout=10)
                return p.stdout.strip() == "true"
            except (OSError, subprocess.SubprocessError):
                return False
        pid = state.get("pid")
        if not pid:
            return False
        try:
            os.kill(int(pid), 0)
            return True
        except (OSError, ValueError):
            return False

    def wait_ready(self, timeout: float = 25.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            try:
                with urllib.request.urlopen(f"{BASE}/api/hosts", timeout=2) as r:
                    if r.status == 200:
                        return True
            except (urllib.error.URLError, OSError):
                time.sleep(0.5)
        return False

    def stop(self) -> None:
        state = self._load_state()
        if state.get("mode") == "docker" or self.container:
            log("menghentikan container...")
            try:
                subprocess.run(["docker", "rm", "-f", self.CONTAINER],
                               capture_output=True, timeout=30)
            except (OSError, subprocess.SubprocessError):
                pass
            self.container = False
        if self.proc and self.proc.poll() is None:
            log("menghentikan server...")
            self.proc.terminate()
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        try:
            os.unlink(PID_FILE)
        except OSError:
            pass


# ---------------------------------------------------------------- API
def api(path: str, body: dict | None = None) -> dict:
    try:
        if body is None:
            req = urllib.request.Request(f"{BASE}{path}")
        else:
            req = urllib.request.Request(
                f"{BASE}{path}",
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}


def snapshot() -> dict:
    return api("/api/hosts")


# ---------------------------------------------------------------- notify
def notify(title: str, body: str, icon: str = "network-wireless") -> None:
    try:
        subprocess.run(["notify-send", "-a", "netcut", "-i", icon, title, body],
                       capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass


# ---------------------------------------------------------------- GUI
def run_gui(server: Server, tray_only: bool = False) -> int:
    """Jalankan web GUI, buka browser, dan (kalau bisa) system tray."""
    if not server.start():
        log(C.red("gagal menjalankan server web"))
        show_server_error()
        print(C.dim(f"  log lengkap: {LOG_FILE}"))
        notify("netcut", "Gagal menjalankan web GUI", "dialog-error")
        return 1

    def open_dashboard() -> None:
        try:
            subprocess.run(["xdg-open", BASE], capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            pass

    if not tray_only:
        open_dashboard()
        notify("netcut", f"Web GUI berjalan di {BASE}", "network-wired")

    # Tray icon (GTK4 + AppIndicator) - opsional, kalau tidak tersedia
    # aplikasi tetap jalan sebagai service.
    try:
        from tray import TrayIcon
        tray = TrayIcon(server, open_dashboard)
        return tray.run()
    except Exception as exc:
        log(f"system tray tidak tersedia ({exc}), aplikasi berjalan di background")
        # tetap jalankan service + monitor
        try:
            while True:
                time.sleep(2)
                snap = snapshot()
                if not snap.get("ok", True) and "error" in snap:
                    continue
        except KeyboardInterrupt:
            pass
        finally:
            server.stop()
    return 0


def _kill_other_instances() -> None:
    """Matikan instance netcut_app.py lain (meninggalkan proses ini)."""
    me = os.getpid()
    try:
        out = subprocess.run(["pgrep", "-f", "netcut_app.py"],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return
    for line in out.split():
        try:
            pid = int(line.strip())
        except ValueError:
            continue
        if pid in (me, os.getppid()):
            continue
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"proses {pid} dihentikan")
        except OSError:
            pass


def doctor() -> int:
    """Cek environment: dependency, hak akses, dan mode yang akan dipakai.

    Dipakai user yang mau cek "kenapa belum jalan?" sebelum mulai.
    """
    problems = 0
    print(f"{C.bold('netcut-linux')}  {C.dim('doctor')}\n")

    print(f"  {C.bold('dependency')}")
    try:
        r = subprocess.run([sys.executable, "-c",
                            "import scapy; print(scapy.__version__)"],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            print(f"    scapy       : {C.green('OK')} {C.dim(r.stdout.strip())}")
        else:
            problems += 1
            print(f"    scapy       : {C.red('hilang')}")
            print(f"      {C.dim('sudo dnf install python3-scapy')}")
    except (OSError, subprocess.SubprocessError):
        problems += 1
        print(f"    scapy       : {C.red('tidak bisa dicek')}")
    for cmd, label in (("nft", "nftables"),):
        if shutil.which(cmd):
            print(f"    {label:<11} : {C.green('OK')}")
        else:
            problems += 1
            print(f"    {label:<11} : {C.red('hilang')}")
            print(f"      {C.dim('sudo dnf install ' + cmd)}")
    if os.path.exists("/usr/share/hwdata/oui.txt"):
        print(f"    {'OUI':<11} : {C.green('OK')}")
    else:
        print(f"    {'OUI':<11} : {C.yellow('hilang')}"
              f" {C.dim('(vendor akan tampil unknown)')}")

    print(f"\n  {C.bold('hak akses')}")
    if os.geteuid() == 0:
        print(f"    euid         : {C.green('root')}"
              f" {C.dim('- semua fitur aktif')}")
    else:
        print(f"    euid         : {C.dim(str(os.geteuid()))}")
    caps = Server.has_capture_privs()
    if caps:
        print(f"    CAP_NET_RAW  : {C.green('ada')}")
    else:
        print(f"    CAP_NET_RAW  : {C.dim('tidak ada')}")
    docker_ok = Server.docker_usable()
    if docker_ok:
        print(f"    docker       : {C.green('OK')}"
              f" {C.dim('- mode penuh via container')}")
    else:
        print(f"    docker       : {C.yellow('tidak ada / tidak bisa dipakai')}")

    print(f"\n  {C.bold('mode yang akan dipakai')}")
    if caps:
        print(f"    {C.green('capture')}"
              f" {C.dim('- blokir, limit, dan ARP spoof aktif')}")
    elif docker_ok:
        print(f"    {C.green('capture')} {C.dim('via container docker')}")
        print(f"    {C.dim('container memakai --network=host --cap-add=NET_RAW ')}")
        print(f"    {C.dim('--cap-add=NET_ADMIN, jadi aturannya kena di host.')}")
    else:
        print(f"    {C.yellow('fallback-no-root')}"
              f" {C.dim('- hanya monitoring, tanpa kontrol')}")
        print(f"    {C.dim('Supaya penuh: pakai docker, atau jalankan dengan sudo.')}")

    print(f"\n  {C.bold('server')}")
    srv = Server()
    running = srv.is_running()
    print(f"    status       : {C.green('running') if running else C.dim('stopped')}")
    print(f"    dashboard    : {BASE}")
    if running:
        snap = snapshot()
        if "hosts" in snap:
            print(f"    mode         : {snap.get('mode', '?')}")
            print(f"    interface    : {snap.get('iface', '?')}")

    if problems:
        print(f"\n  {C.red(str(problems) + ' masalah ditemukan di atas.')}")
        print(f"  {C.dim('Perbaiki dulu, lalu jalankan: netcut')}")
        return 1
    print(f"\n  {C.green('Semua siap.')} Jalankan: {C.bold('netcut')}")
    return 0


def main() -> int:
    args = sys.argv[1:]

    if "-h" in args or "--help" in args:
        print(USAGE)
        return 0

    # --port bisa muncul di mana saja dalam argumen
    if "--port" in args:
        try:
            idx = args.index("--port")
            globals()["PORT"] = int(args[idx + 1])
            globals()["BASE"] = f"http://127.0.0.1:{globals()['PORT']}"
        except (IndexError, ValueError):
            print(C.red("nilai --port tidak valid"))
            return 2

    if "--stop" in args:
        srv = Server()
        if srv.is_running():
            srv.stop()
            print(C.green("server dihentikan"))
        else:
            print(C.dim("server tidak berjalan"))
        # matikan juga proses app lain (tray) yang sedang jalan
        _kill_other_instances()
        return 0

    if "--doctor" in args:
        return doctor()

    if "--status" in args:
        srv = Server()
        state = srv._load_state()
        running = srv.is_running()
        mode = state.get("mode", "?")
        print(f"{C.bold('netcut-linux')}  {C.dim('status')}")
        print(f"  server     : {C.green('running') if running else C.red('stopped')}"
              f"  {C.dim('(' + mode + ')')}")
        print(f"  dashboard  : {BASE}")
        if running:
            snap = snapshot()
            if "hosts" in snap:
                hosts = len(snap.get("hosts", []))
                blk = len(snap.get("blocked", []))
                lim = len(snap.get("limited", {}))
                net = snap.get("net", {})
                print(f"  jaringan   : {net.get('ssid') or net.get('iface', '?')}"
                      f"  {C.dim(str(net.get('gateway', '')))}")
                print(f"  host       : {hosts} terlihat"
                      + (f", {blk} diblokir" if blk else "")
                      + (f", {lim} limited" if lim else ""))
                print(f"  interface  : {snap.get('iface', '?')}"
                      f"  {C.dim('mode ' + str(snap.get('mode', '?')))}")
        return 0 if running else 1

    server = Server()
    tray_only = "--tray" in args
    no_tray = "--no-tray" in args
    try:
        if no_tray:
            if not server.start():
                log(C.red("gagal menjalankan server web"))
                show_server_error()
                print(C.dim(f"  log lengkap: {LOG_FILE}"))
                notify("netcut", "Gagal menjalankan web GUI", "dialog-error")
                return 1
            print(f"{C.green('netcut-linux')} berjalan di {C.bold(BASE)}"
                  f"  {C.dim('(Ctrl-C untuk berhenti)')}")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print()
            finally:
                server.stop()
            return 0
        return run_gui(server, tray_only=tray_only)
    except KeyboardInterrupt:
        server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
