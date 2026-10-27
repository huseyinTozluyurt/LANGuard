"""
Shared core for LANGuard: configuration, alerting, network helpers, state.
"""

import copy
import errno
import ipaddress
import json
import logging
import os
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

CONFIG_PATH = Path(os.environ.get("LANGUARD_CONFIG", "/etc/languard/config.json"))
STATE_DIR = Path(os.environ.get("LANGUARD_STATE", "/var/lib/languard"))
# Errors that only mean we are offline (Wi-Fi off, cable out, resume from sleep).
NET_DOWN = {errno.ENETDOWN, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENODEV}

DEFAULTS = {
    "interface": None,            # auto-detected from the default route
    "gateway": None,              # auto-detected from the default route
    "log_file": "/var/log/languard.log",
    "json_log": None,             # e.g. /var/log/languard.jsonl for a SIEM
    "notify": False,              # desktop popups via notify-send
    "alert_cooldown": 60,         # seconds between identical alerts
    # modules `languard monitor` runs by default
    "modules": ["arp", "devices", "dhcp", "dns", "scan", "ipv6", "mitm",
                "path", "tls", "strip", "filewatch", "host", "localdns",
                "netid"],
    "arp": {
        "flood_window": 10, "flood_threshold": 30,
        "multi_ip_threshold": 3, "multi_ip_window": 300,
        "verify": True,
    },
    "devices": {
        "alert_unknown": True,
        "scan_interval": 300,     # active ARP sweep every N seconds (0 = off)
        "mac_flood_window": 60, "mac_flood_threshold": 50,
        # macof-style floods: distinct unknown source MACs in any frame
        "frame_watch": True,
        "frame_flood_window": 10, "frame_flood_threshold": 500,
    },
    "dhcp": {
        "trusted_servers": [],    # IPs; empty = trust the gateway only
        "starvation_window": 60, "starvation_threshold": 30,
    },
    "ipv6": {
        "trusted_routers": [],    # link-local IPs or MACs; empty = learn first
        "trusted_dhcp6": [],
    },
    "mitm": {
        "honeypot_interval": 300, # LLMNR/NBNS bait query every N seconds
    },
    "path": {
        "interval": 60,
        "probe_target": "1.1.1.1",
    },
    "tls": {
        "interval": 300,
        "sites": ["www.google.com", "github.com", "www.wikipedia.org",
                  "www.cloudflare.com"],
        "check_http_redirect": True,
        "probe_learned": 6,       # also probe your N most used HTTPS sites
        "captive_portal_check": True,
    },
    # SSL stripping, judged on this machine's own browser traffic
    "strip": {
        "sites": [],              # extra hosts that must never be plain HTTP
        "upgrade_window": 6,      # seconds for http -> https to happen
        "hsts_preload": True,     # every HSTS-preloaded site counts (hsts.py)
    },
    "filewatch": {
        "scan_dirs": ["~/Downloads", "~/Desktop", "/tmp", "/var/tmp", "/dev/shm"],
        "max_scan_mb": 100,
        "quarantine": True,
        "scanner": "auto",        # auto | clamdscan | clamscan | none
    },
    "host": {
        "interval": 15,
    },
    # Your own encrypted DNS (dnscrypt-proxy...): watched, never changed
    "localdns": {
        "interval": 120,
        "probe_interval": 300,    # ask it for a random name (0 = never)
        "probe_failures": 3,      # failed checks in a row before a warning
    },
    # pcap of the packets around each CRITICAL alert, for later analysis
    "evidence": {
        "enabled": True,
        "seconds": 60,            # packets kept from before the alert
        "after": 5,               # and after it
        "max_packets": 20000,
        "max_mb": 200,            # oldest captures are deleted beyond this
    },
    "dns": {
        "window": 5,
        "plain_ok": [],           # servers allowed plain DNS beside dnscrypt
        "alert_private_answers": True,
        "internal_suffixes": [".local", ".lan", ".home", ".arpa",
                              ".internal", ".localdomain", ".home.arpa"],
    },
    "scan": {
        "window": 10,
        "port_threshold": 15,     # distinct ports from one source
        "conn_threshold": 20,     # SYNs to one watched port from one source
        "watch_ports": [21, 22, 23, 25, 445, 3306, 3389, 5900],
        "block": False,           # auto-block offenders with UFW
        "never_block": [],
    },
    # Active protection (on since 1.4; "enabled": false turns it all off).
    # Every action is logged with its undo command (languard protect).
    "protect": {
        "enabled": True,
        "pin_gateway": True,      # static ARP entry for the verified router
        "isolate": True,          # drop every frame from a confirmed attacker
        "isolate_minutes": 60,
        "never_isolate": [],      # MACs never to isolate
        "repair_dhcp": True,      # renew the lease after a rogue DHCP answer
        "ipv6_lockdown": True,    # stop accepting RAs after a rogue RA
        "https_guard": True,      # upgrade plain HTTP to your HTTPS sites
        "block_ips": True,        # reject traffic to/from an attacker's IPs
        "block_max": 20,          # more IPs in 10 min: stop blocking IPs
        "never_block": [],        # IPs never to block
        "cut_connections": True,  # end live connections through an attacker
        "flush_dns": True,        # drop forged answers from the DNS cache
        "llmnr_off": True,        # LLMNR off after name poisoning (Responder)
        "block_redirects": True,  # ignore ICMP redirects after an attack
        "isolate_max": 3,         # more devices named in 10 min: stop isolating
        "kill_switch": False,     # disconnect on a confirmed gateway MITM
        "block_wpad": True,       # block a LAN host that pushes a WPAD proxy
        "pin_devices": True,      # keep pinned devices (NAS, printer) pinned
        "pin_router6": True,      # pin the verified IPv6 router too
        # On networks marked public (languard network --public) or open
        # Wi-Fi: ignore ICMP redirects and turn LLMNR off from the start,
        # put back on networks marked home. Runtime only, no DNS change.
        "public_hardening": True,
        # Only the verified DHCP server may hand out leases and only the
        # verified router may send IPv6 router advertisements (nftables).
        "pin_dhcp": True,
        "pin_ra": True,
        # HTTPS guard upgrades every public site, not only known HTTPS ones
        # (like a browser's HTTPS-Only mode; sites without HTTPS break).
        "https_only": False,
    },
    # Is this the network you think it is? (Wi-Fi identity, router HTTPS key)
    "netid": {
        "interval": 120,
    },
    # Sensor health: flood budget per device, kernel drop and error alerts
    "sensor": {
        "per_mac_pps": 200,       # packets/s one MAC may feed the detectors
        "drop_alert": 100,        # kernel drops per minute before a warning
        "error_alert": 50,        # detector errors per minute before a warning
    },
    "wifi": {
        "monitor_interface": None,
        "ssids": [],              # your network names to protect
        "trusted_bssids": [],     # your access points' MACs
        "deauth_window": 10, "deauth_threshold": 20,
    },
}


# ------------------------------------------------------------------ config --
def _merge(base, override):
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path=None):
    path = Path(path) if path else CONFIG_PATH
    user = {}
    try:
        with open(path) as f:
            user = json.load(f)
    except FileNotFoundError:
        pass
    except PermissionError:
        import sys
        print(f"(can't read {path}; using defaults. Try with sudo)",
              file=sys.stderr)
    except json.JSONDecodeError as e:
        import sys
        print(f"Config error in {path}: {e}. Using defaults.", file=sys.stderr)
    return _merge(DEFAULTS, user)


# ------------------------------------------------------------------- state --
def load_state(name, default=None):
    p = STATE_DIR / f"{name}.json"
    try:
        with open(p) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default if default is not None else {}


def save_state(name, data):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    p = STATE_DIR / f"{name}.json"
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, p)


# ----------------------------------------------------------------- alerting --
log = logging.getLogger("languard")


def setup_logging(log_file=None, verbose=False):
    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s")
    root = logging.getLogger("languard")
    root.handlers.clear()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)
    if log_file:
        try:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(log_file)
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except PermissionError:
            root.warning("Cannot write %s (run as root or use --log)", log_file)


def _notify(title, msg, urgency="critical"):
    """Desktop popup. Works from root/systemd by reaching each logged-in user's bus."""
    cmd = ["notify-send", "-u", urgency, "-a", "LANGuard", title, msg]
    try:
        if os.geteuid() != 0:
            subprocess.run(cmd, timeout=3, capture_output=True)
            return
        run = Path("/run/user")
        for d in run.iterdir() if run.exists() else []:
            bus = d / "bus"
            if not bus.exists() or d.name == "0":
                continue
            import pwd
            try:
                user = pwd.getpwuid(int(d.name)).pw_name
            except (KeyError, ValueError):
                continue
            subprocess.run(
                ["runuser", "-u", user, "--", "env",
                 f"DBUS_SESSION_BUS_ADDRESS=unix:path={bus}"] + cmd,
                timeout=3, capture_output=True)
    except Exception:
        pass


class Alerter:
    LEVELS = {"INFO": logging.INFO, "WARNING": logging.WARNING,
              "CRITICAL": logging.CRITICAL}

    def __init__(self, cooldown=60, notify=False, json_log=None):
        self.cooldown = cooldown
        self.notify = notify
        self.json_log = json_log
        self._last = {}
        self._lock = threading.Lock()
        self.history = []          # kept for tests and summaries
        self.hooks = []            # f(module, key, level, msg, data), e.g. evidence

    def __call__(self, module, key, level, msg, **data):
        """Raise an alert. Returns True if emitted, False if suppressed."""
        now = time.time()
        with self._lock:
            full_key = f"{module}:{key}"
            if now - self._last.get(full_key, 0) < self.cooldown:
                return False
            self._last[full_key] = now
            self.history.append((module, level, msg))
        log.log(self.LEVELS[level], "[%s] %s", module, msg)
        if self.json_log:
            try:
                with open(self.json_log, "a") as f:
                    f.write(json.dumps({"ts": now, "module": module,
                                        "level": level, "msg": msg,
                                        **data}) + "\n")
            except OSError:
                pass
        if self.notify and level in ("WARNING", "CRITICAL"):
            threading.Thread(target=_notify,
                             args=(f"LANGuard {level}: {module}", msg),
                             daemon=True).start()
        for hook in self.hooks:
            try:
                hook(module, key, level, msg, data)
            except Exception as e:
                log.debug("alert hook failed: %s", e)
        return True


# ----------------------------------------------------------------- network --
def default_route():
    """(interface, gateway_ip) from /proc/net/route."""
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if p[1] == "00000000" and int(p[3], 16) & 2:
                    return p[0], socket.inet_ntoa(struct.pack("<L", int(p[2], 16)))
    except OSError:
        pass
    return None, None


def kernel_arp_table():
    """{ip: mac} from the kernel neighbour cache."""
    table = {}
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if p[2] != "0x0" and p[3] != "00:00:00:00:00:00":
                    table[p[0]] = p[3].lower()
    except OSError:
        pass
    return table


def iface_info(iface):
    """(ip, mac, network) for an interface."""
    ip = net = None
    mac = None
    try:
        out = subprocess.run(["ip", "-j", "-4", "addr", "show", "dev", iface],
                             capture_output=True, text=True, timeout=5).stdout
        for entry in json.loads(out or "[]"):
            for a in entry.get("addr_info", []):
                ip = a["local"]
                net = ipaddress.ip_network(f"{ip}/{a['prefixlen']}", strict=False)
                break
    except Exception:
        pass
    try:
        mac = Path(f"/sys/class/net/{iface}/address").read_text().strip().lower()
    except OSError:
        pass
    return ip, mac, net


def is_randomized_mac(mac):
    """Locally administered bit set: phones/laptops with MAC privacy enabled."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


_OUI = None


def vendor(mac):
    """Best-effort vendor lookup from the IEEE list (ieee-data on Debian,
    hwdata on Fedora/openSUSE) or Wireshark's manuf file."""
    global _OUI
    if _OUI is None:
        _OUI = {}
        from .distro import MANUF_FILES, OUI_FILES
        for path in OUI_FILES:
            try:
                with open(path, errors="ignore") as f:
                    for line in f:
                        if "(hex)" in line:
                            pre, _, name = line.partition("(hex)")
                            _OUI[pre.strip().replace("-", ":").lower()] = name.strip()
            except OSError:
                pass
        for path in MANUF_FILES:
            try:
                with open(path, errors="ignore") as f:
                    for line in f:
                        p = line.split("\t")
                        if len(p) >= 2 and len(p[0]) == 8:
                            _OUI.setdefault(p[0].lower(), p[-1].strip())
            except OSError:
                pass
    if is_randomized_mac(mac):
        return "randomized (private) MAC"
    return _OUI.get(mac[:8].lower(), "")


class Context:
    """Everything a module needs: config, alerter, and local network facts."""

    def __init__(self, cfg, alerter, iface=None, gateway=None):
        auto_iface, auto_gw = default_route()
        self.cfg = cfg
        self.alert = alerter
        self.iface = iface or cfg.get("interface") or auto_iface
        self.gateway = gateway or cfg.get("gateway") or auto_gw
        self.my_ip, self.my_mac, self.network = (
            iface_info(self.iface) if self.iface else (None, None, None))
        self.protect = None       # a Protector when active protection runs


def sd_notify(msg):
    """Tell systemd we're ready / alive (Type=notify + WatchdogSec)."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(addr)
            s.sendall(msg.encode())
    except OSError:
        pass


def human_homes():
    """[(user, uid, home)] for real login users (UID 1000-59999)."""
    out = []
    try:
        with open("/etc/passwd") as f:
            for line in f:
                p = line.strip().split(":")
                if len(p) < 7:
                    continue
                uid = int(p[2])
                if 1000 <= uid < 60000 and os.path.isdir(p[5]) \
                        and not p[6].endswith(("nologin", "false")):
                    out.append((p[0], uid, p[5]))
    except (OSError, ValueError):
        pass
    return out


def expand_paths(paths):
    """Expand ~ to every human user's home; drop paths that don't exist."""
    out = []
    homes = [h for _, _, h in human_homes()] or [os.path.expanduser("~")]
    for p in paths:
        if p.startswith("~"):
            out += [h + p[1:] for h in homes]
        else:
            out.append(p)
    return [p for p in dict.fromkeys(out) if os.path.exists(p)]


class Module:
    """Base class.

    Packet modules set `bpf` and implement `handle(pkt)`.
    Loop modules set `threaded = True` and implement `tick()`, which runs
    every `interval` seconds in its own supervised thread.
    """
    name = "module"
    bpf = None
    threaded = False
    interval = 60

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg.get(self.name, {})

    def alert(self, key, level, msg, **data):
        return self.ctx.alert(self.name, key, level, msg, **data)

    def respond(self, event, **info):
        """Hand a confirmed attack to active protection, if it's running."""
        p = getattr(self.ctx, "protect", None)
        if p is not None:
            p.respond(event, **info)

    def start(self):
        """Optional setup / extra background threads. Called once."""

    def handle(self, pkt):
        raise NotImplementedError

    def tick(self):
        """One iteration of a loop module."""

    def run(self):
        """Thread body for loop modules: tick forever, never die on errors."""
        while True:
            try:
                self.tick()
            except OSError as e:
                if e.errno in NET_DOWN:
                    log.info("[%s] check skipped, no network: %s", self.name, e)
                else:
                    log.warning("[%s] check failed: %s", self.name, e)
            except Exception as e:
                log.warning("[%s] check failed: %s", self.name, e)
            time.sleep(self.interval)
