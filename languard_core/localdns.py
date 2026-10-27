"""
Works alongside an encrypted DNS resolver you set up yourself (dnscrypt-proxy,
and also stubby, cloudflared or dnsproxy).

LANGuard never changes DNS settings: not resolv.conf, not systemd-resolved's
servers, not NetworkManager connections, not the resolver's own config, and
it never restarts or signals the resolver. It only reads them to find out
whether your DNS really stays encrypted, and tells you when it doesn't:

  * which resolver runs and where it listens (127.0.2.1:53 on Ubuntu's
    dnscrypt-proxy package, 127.0.0.1:53 by default upstream)
  * the chain from /etc/resolv.conf to it: when systemd-resolved sits in
    between and a connection also hands it the network's own DNS servers
    (from DHCP), resolved asks those too, in plain text, and a man in the
    middle can read and forge those answers ("leak risk")
  * plain-DNS queries that actually leave this machine while the resolver
    runs (dns.py raises those as leaks)
  * the resolver stopping, or not getting answers any more: someone in the
    middle can block encrypted DNS to push a machine back to plain DNS

Read-only by design; every fix it suggests is a command for you to run.
"""

import ipaddress
import os
import random
import re
import socket
import string
import struct
import subprocess
import time
from pathlib import Path

from .core import Module, log

# process name -> what to call it
ENCRYPTED = {
    "dnscrypt-proxy": "dnscrypt-proxy",
    "stubby": "stubby (DNS over TLS)",
    "cloudflared": "cloudflared (DNS over HTTPS)",
    "dnsproxy": "dnsproxy",
}
REFRESH = 300                       # seconds a detection is reused
TOML_PATHS = ("/etc/dnscrypt-proxy/dnscrypt-proxy.toml",
              "/usr/local/etc/dnscrypt-proxy/dnscrypt-proxy.toml",
              "/opt/dnscrypt-proxy/dnscrypt-proxy.toml")


def _run(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def is_loopback(addr):
    try:
        return ipaddress.ip_address(addr.split("%")[0]).is_loopback
    except ValueError:
        return False


# ---------------------------------------------------------------- readers --
def find_resolver(proc="/proc"):
    """{"name", "label", "pid", "config"} of the running encrypted resolver,
    or None. Reads /proc only."""
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        return None
    for pid in sorted(pids, key=int):
        try:
            comm = Path(proc, pid, "comm").read_text().strip()
        except OSError:
            continue
        if comm not in ENCRYPTED:
            continue
        config = None
        try:
            args = Path(proc, pid, "cmdline").read_bytes().split(b"\0")
            args = [a.decode(errors="replace") for a in args if a]
            for i, a in enumerate(args):
                if a in ("-config", "--config") and i + 1 < len(args):
                    config = args[i + 1]
                elif a.startswith(("-config=", "--config=")):
                    config = a.split("=", 1)[1]
        except OSError:
            pass
        if comm == "dnscrypt-proxy" and not config:
            config = next((p for p in TOML_PATHS if os.path.exists(p)), None)
        return {"name": comm, "label": ENCRYPTED[comm], "pid": int(pid),
                "config": config}
    return None


def listen_addrs(name, ss_out=None):
    """['127.0.2.1:53', ...] where the resolver (or systemd's socket for it)
    listens for DNS, from `ss`."""
    if ss_out is None:
        ss_out = _run(["ss", "-H", "-ulnp"])[1]
    out = []
    for line in ss_out.splitlines():
        if f'"{name}"' not in line:
            continue
        p = line.split()
        local = next((x for x in p if re.search(r":\d+$", x) and x != "*:*"), None)
        if local and local not in out:
            out.append(local)
    return out


def toml_settings(path):
    """The few dnscrypt-proxy settings LANGuard needs, read-only: the
    listen addresses and the plain-DNS servers it may use for bootstrapping."""
    try:
        text = Path(path).read_text(errors="replace")
    except (OSError, TypeError):
        return {}
    out = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line.startswith("["):
            break                       # only top-level keys
        m = re.match(r"(\w+)\s*=\s*(.+)$", line)
        if not m:
            continue
        key, val = m.groups()
        if key in ("listen_addresses", "bootstrap_resolvers",
                   "fallback_resolvers", "netprobe_address"):
            out[key] = re.findall(r"['\"]([^'\"]+)['\"]", val)
        elif key == "fallback_resolver":
            out["fallback_resolvers"] = re.findall(r"['\"]([^'\"]+)['\"]", val)
    return out


def host_of(addr):
    """'9.9.9.11:53' -> '9.9.9.11', '[2620:fe::11]:53' -> '2620:fe::11'."""
    return split_addr(addr)[0]


def split_addr(addr, default=53):
    """'127.0.2.1:53' / '[::1]:5353' / '::1' -> (host, port)."""
    addr = addr.strip()
    if addr.startswith("["):
        host, _, rest = addr[1:].partition("]")
        port = rest.lstrip(":")
    elif addr.count(":") == 1:
        host, _, port = addr.partition(":")
    else:
        host, port = addr, ""
    return host, int(port) if port.isdigit() else default


def resolv_conf(path="/etc/resolv.conf"):
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return []
    return [l.split()[1] for l in text.splitlines()
            if l.startswith("nameserver") and len(l.split()) > 1]


def resolved_servers(out=None):
    """{"Global": [...], "wlp2s0": [...]} from `resolvectl dns`."""
    if out is None:
        rc, out = _run(["resolvectl", "dns"])
        if rc != 0:
            return {}
    res = {}
    for line in out.splitlines():
        head, _, servers = line.partition(":")
        if not _:
            continue
        m = re.match(r"\s*Link \d+ \(([^)]+)\)", head)
        name = m.group(1) if m else head.strip()
        res[name] = [s.split("#")[0].split("%")[0] for s in servers.split()]
    return res


# ------------------------------------------------------------- the picture --
def inspect(proc="/proc", ss_out=None, resolv="/etc/resolv.conf",
            resolved_out=None):
    """Everything LANGuard knows about local DNS, as a dict (never changes
    anything)."""
    r = find_resolver(proc)
    conf = resolv_conf(resolv)
    info = {"resolver": None, "label": None, "listen": [], "resolv_conf": conf,
            "via_resolved": False, "resolved": {}, "plain_servers": [],
            "bootstrap": [], "leak_risk": [], "checked": time.time()}
    if not r:
        return info
    info.update(resolver=r["name"], label=r["label"], pid=r["pid"],
                config=r["config"])
    toml = toml_settings(r["config"]) if r["name"] == "dnscrypt-proxy" else {}
    info["listen"] = listen_addrs(r["name"], ss_out) or toml.get("listen_addresses", [])
    info["bootstrap"] = sorted({host_of(a) for k in ("bootstrap_resolvers",
                                                     "fallback_resolvers",
                                                     "netprobe_address")
                                for a in toml.get(k, [])})
    stub = "127.0.0.53" in conf
    info["via_resolved"] = stub
    if stub:
        servers = resolved_servers(resolved_out)
        info["resolved"] = servers
        plain = sorted({s for v in servers.values() for s in v
                        if not is_loopback(s)})
        info["plain_servers"] = plain
        if plain and not any(is_loopback(s) for v in servers.values() for s in v):
            info["leak_risk"].append(
                f"it isn't used: systemd-resolved sends lookups to "
                f"{', '.join(plain)}, not to {r['name']}")
            servers = {}
        for link, v in servers.items():
            bad = [s for s in v if not is_loopback(s)]
            if bad:
                info["leak_risk"].append(
                    f"systemd-resolved also uses {', '.join(bad)} "
                    f"({'global setting' if link == 'Global' else 'from ' + link})")
    else:
        bad = [s for s in conf if not is_loopback(s)]
        if bad:
            info["plain_servers"] = bad
            info["leak_risk"].append(
                f"/etc/resolv.conf also lists {', '.join(bad)}"
                if len(bad) < len(conf) else
                f"it isn't used: /etc/resolv.conf sends lookups to "
                f"{', '.join(bad)}")
    if not info["listen"]:              # ss hides other users' sockets
        local = conf + [s for v in info["resolved"].values() for s in v]
        info["listen"] = list(dict.fromkeys(
            f"[{s}]:53" if ":" in s else f"{s}:53" for s in local
            if is_loopback(s) and s != "127.0.0.53"))
    return info


_cache = {}


def get(force=False):
    """inspect(), reused for REFRESH seconds (dns.py asks per packet)."""
    now = time.time()
    if force or not _cache or now - _cache.get("checked", 0) > REFRESH:
        try:
            _cache.clear()
            _cache.update(inspect())
        except Exception as e:                  # never break detection
            log.debug("[localdns] inspect failed: %s", e)
            _cache.update(resolver=None, checked=now)
    return _cache


def probe(addr, timeout=4):
    """Ask the resolver on loopback for a random name. True if it answered
    (an answer or 'no such name'), False on SERVFAIL or silence. The random
    name keeps a cached answer from hiding a blocked upstream."""
    host, port = split_addr(addr)
    label = "lg-" + "".join(random.choice(string.ascii_lowercase)
                            for _ in range(12))
    qid = random.randint(0, 0xffff)
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for part in (label, "example", "com"):
        q += bytes([len(part)]) + part.encode()
    q += b"\0" + struct.pack("!HH", 1, 1)
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(q, (host, port))
            data, _ = s.recvfrom(4096)
        except OSError:
            return False
    if len(data) < 4 or struct.unpack("!H", data[:2])[0] != qid:
        return False
    return (data[3] & 0x0f) in (0, 3)            # NOERROR or NXDOMAIN


def advice(info, conn=None):
    """How to close a leak, for the user to run (LANGuard never does)."""
    if info.get("via_resolved"):
        c = conn or "<connection>"
        return (f"if you want DNS to go only through {info.get('label')}, stop "
                f"the connection handing its DNS to systemd-resolved: nmcli "
                f"connection modify \"{c}\" ipv4.ignore-auto-dns yes "
                f"ipv6.ignore-auto-dns yes, then reconnect")
    return "remove the extra nameserver lines from /etc/resolv.conf"


# ----------------------------------------------------------------- module --
class LocalDNSMonitor(Module):
    """Loop module: watches that encrypted DNS keeps working, read-only."""
    name = "localdns"
    threaded = True

    def __init__(self, ctx):
        super().__init__(ctx)
        self.interval = int(self.cfg.get("interval", 120))
        self.probe_every = int(self.cfg.get("probe_interval", 300))
        self.fail_after = int(self.cfg.get("probe_failures", 3))
        self.seen = None              # resolver name last time
        self.fails = 0
        self._last_probe = 0
        self._risk = None

    def start(self):
        info = get(force=True)
        self.ctx.local_dns = info
        if info.get("resolver"):
            self.seen = info["resolver"]
            log.info("[localdns] %s is your DNS resolver (listening on %s). "
                     "LANGuard leaves your DNS settings alone and warns about "
                     "plain-DNS leaks", info["label"],
                     ", ".join(info["listen"]) or "?")

    def tick(self):
        info = get(force=True)
        self.ctx.local_dns = info
        name = info.get("resolver")
        if self.seen and not name:
            self.alert("gone", "WARNING",
                       f"{ENCRYPTED.get(self.seen, self.seen)} stopped: DNS "
                       f"lookups may now go out unencrypted (or fail). LANGuard "
                       f"doesn't restart it; check: systemctl status "
                       f"{self.seen}")
        elif name and not self.seen:
            log.info("[localdns] %s is running again", info["label"])
        self.seen = name
        if not name:
            return
        risk = "; ".join(info["leak_risk"]) or None
        if risk and risk != self._risk:
            self.alert(f"risk:{risk}", "WARNING",
                       f"DNS leak risk next to {info['label']}: {risk}. Those "
                       f"servers are asked in plain text, so someone in the "
                       f"middle can read and forge the answers. LANGuard "
                       f"doesn't change DNS settings; {advice(info, self._conn())}",
                       servers=info["plain_servers"])
        self._risk = risk
        self.check_answers(info)

    def check_answers(self, info, prober=probe, now=None):
        now = now or time.time()
        if not self.probe_every or not info.get("listen") \
                or now - self._last_probe < self.probe_every:
            return None
        self._last_probe = now
        ok = any(prober(a) for a in info["listen"][:2])
        if ok:
            if self.fails >= self.fail_after:
                log.info("[localdns] %s answers again", info["label"])
            self.fails = 0
            return True
        self.fails += 1
        if self.fails == self.fail_after:
            self.alert("blocked", "WARNING",
                       f"{info['label']} hasn't been able to answer for "
                       f"{self.fails} checks in a row while this machine is "
                       f"online. Its encrypted connections may be blocked: an "
                       f"attacker in the middle does this to push machines "
                       f"back to plain DNS. Don't switch to the network's DNS "
                       f"to 'fix' it on an untrusted network",
                       failures=self.fails)
        return False

    def _conn(self):
        label = getattr(self.ctx, "net_label", None)
        if label:
            return label
        from .baseline import _connection_name
        return _connection_name(self.ctx.iface)
