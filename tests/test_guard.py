#!/usr/bin/env python3
"""Tests for blocking (1.4): the HTTPS guard against SSL stripping, DHCPv6
repair, and the safeguard against forged-MAC framing.
Run: python3 tests/test_guard.py   (no root needed; as root with nftables and
iproute2 it also runs the guard for real inside a throwaway network namespace)"""

import ipaddress
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

STATE = tempfile.mkdtemp(prefix="languard-test-")
os.environ["LANGUARD_STATE"] = STATE
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from languard_core import baseline, core, protect    # noqa: E402
from languard_core.core import Alerter, load_config  # noqa: E402
from languard_core.guard import HttpsGuard           # noqa: E402
from languard_core.protect import Protector          # noqa: E402
from languard_core.strip import StripMonitor         # noqa: E402

core.setup_logging(None)
fails = 0
GW, GW_MAC, ME = "192.168.1.1", "aa:aa:aa:aa:aa:aa", "02:00:00:00:00:50"
FF = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
APT = "Debian APT-HTTP/1.3 (2.4.11)"


class Ctx:
    pass


def ctx(cfg=None):
    c = Ctx()
    c.cfg = cfg or load_config("/nonexistent")
    c.alert = Alerter(cooldown=0)
    c.iface, c.gateway, c.my_ip, c.my_mac = "eth0", GW, "192.168.1.50", ME
    c.network = ipaddress.ip_network("192.168.1.0/24")
    c.net_label, c.protect = "home", None
    return c


def check(name, cond):
    global fails
    print(("  ok  " if cond else "  FAIL ") + name)
    fails += not cond


def said(c, text, level=None):
    return any(text in m and (level is None or lv == level)
               for _, lv, m in c.alert.history)


class FakeRun:
    def __init__(self, dns="192.168.1.1"):
        self.cmds, self.dns = [], dns

    def __call__(self, cmd, stdin=None, timeout=15):
        self.cmds.append((cmd, stdin))
        if cmd[0] == "nmcli" and "GENERAL.CONNECTION" in cmd:
            return 0, "home"
        if cmd[:2] == ["resolvectl", "dns"]:
            return 0, f"Link 2 (eth0): {self.dns}"
        return 0, ""

    def ran(self, *words):
        return [c for c, _ in self.cmds if all(w in c for w in words)]


def units():
    print("== Guard verdicts (what is upgraded, blocked, passed)")
    c = ctx(); s = StripMonitor(c)
    s.https_seen("bank.example.com", now=time.time())
    v = s.verdict
    check("browser to a site you use over HTTPS: upgrade", v("GET", "bank.example.com", "/", FF)[0] == "upgrade")
    check("login POST too (307 keeps it a POST, now over HTTPS)", v("POST", "bank.example.com", "/login", FF)[0] == "upgrade")
    check("HSTS-preloaded site never visited: upgrade", v("GET", "mail.google.com", "/", FF)[0] == "upgrade")
    check("look-alike of an HTTPS site: block", v("GET", "google.corn", "/", FF) == ("block", "google.com"))
    check("plain-HTTP-only site: pass", v("GET", "neverssl.com", "/", FF)[0] == "pass")
    check("apt / updaters: pass", v("GET", "accounts.google.com", "/", APT)[0] == "pass")
    check("certificate checks (OCSP/CRL): pass", v("POST", "www.microsoft.com", "/pkiops/crl/x.crl", FF)[0] == "pass")
    check("browser captive-portal checks: pass",
          v("GET", "connectivitycheck.gstatic.com", "/generate_204", FF)[0] == "pass"
          and v("GET", "www.google.com", "/gen_204", FF)[0] == "pass")
    check("bare IPs (router admin pages): pass", v("GET", "192.168.1.1", "/", FF)[0] == "pass")
    c.captive_portal = True
    check("while a captive portal is active: everything passes", v("GET", "bank.example.com", "/", FF)[0] == "pass")

    print("== Guard firewall rule")
    g = HttpsGuard(ctx(), FakeRun(), port=8079)
    g.v6 = True
    r = g.rules()
    check("only this machine's own port-80 traffic (nat output hook)", "hook output" in r and "tcp dport 80" in r)
    check("loopback is never redirected", "127.0.0.0/8" in r and "::1" in r)
    check("the proxy's own connections skip the rule (mark)", "meta mark 0x4c47 return" in r)
    check("table is replaced atomically, not stacked", r.startswith("table inet languard_guard\ndelete table"))

    print("== Protector wiring")
    protect.default_route = lambda: ("eth0", GW)
    cfg = load_config("/nonexistent")
    check("1.4 defaults: protection on, HTTPS guard on, kill switch off",
          cfg["protect"]["enabled"] and cfg["protect"]["https_guard"] and not cfg["protect"]["kill_switch"])
    c = ctx(cfg); run = FakeRun()
    p = Protector(c, run=run, sync=True)
    p.state["guard"] = {"since": 1}            # left over from a crash
    p.start()
    check("CLI/sync mode never starts the proxy", p.guard is None and "guard" not in p.state)
    p.undo_all()
    check("--undo-all / --off remove the guard rule",
          p.run.ran("nft", "delete", "table", "inet", "languard_guard"))

    print("== Rogue DHCPv6 (mitm6) is blocked and repaired")
    c = ctx(cfg); b = baseline.get(c); b.learn_gateway([[GW_MAC]] * 3)
    run = FakeRun(dns="192.168.1.1 fe80::bad")
    p = Protector(c, run=run, sync=True); c.protect = p
    p.respond("rogue_dhcp6", mac="66:66:66:66:66:01", src_ip="fe80::bad",
              dns=["fe80::bad"], v6=True)
    check("rogue DHCPv6 server isolated", "66:66:66:66:66:01" in p.state["blocked"])
    check("connection renewed because its DNS was in use", run.ran("nmcli", "connection", "up"))
    check("poisoned DNS cache flushed", run.ran("resolvectl", "flush-caches"))
    check("alert says DHCPv6", said(c, "rogue DHCPv6 server", "WARNING"))
    run2 = FakeRun(dns="192.168.1.1")
    c2 = ctx(cfg); p2 = Protector(c2, run=run2, sync=True)
    p2.respond("rogue_dhcp6", mac="66:66:66:66:66:02", src_ip="fe80::bad2",
               dns=["fe80::bad2"], v6=True)
    check("rogue DNS not in use: isolated, no needless reconnect",
          "66:66:66:66:66:02" in p2.state["blocked"] and not run2.ran("nmcli", "connection", "up"))

    print("== Forged MACs can't get innocent devices cut off")
    c = ctx(cfg); baseline.get(c).learn_gateway([[GW_MAC]] * 3)
    run = FakeRun(); p = Protector(c, run=run, sync=True); c.protect = p
    for i in range(1, 4):
        p.respond("rogue_ra", mac=f"10:00:00:00:00:0{i}")
    check("up to 3 devices named in 10 min are isolated",
          all(f"10:00:00:00:00:0{i}" in p.state["blocked"] for i in range(1, 4)))
    p.respond("rogue_ra", mac="10:00:00:00:00:04")
    check("a 4th: isolation pauses instead (forgery or false alarm)",
          "10:00:00:00:00:04" not in p.state["blocked"] and said(c, "forging packets", "CRITICAL"))
    p.respond("rogue_ra", mac="10:00:00:00:00:05")
    check("...and stays paused", "10:00:00:00:00:05" not in p.state["blocked"])
    check("the router, this machine and trusted devices are never isolated",
          not p.isolate(GW_MAC, "x") and not p.isolate(ME, "x"))
    check("IPv6 lockdown still applied (it only changes this machine)",
          run.ran("sysctl", "-w", "net.ipv6.conf.eth0.accept_ra=0"))


# ------------------------------------------------- real end-to-end run --
def e2e():
    """Inside a private network namespace: a web server on 10.9.9.1:80, the
    guard's real nftables rule and proxy, and real client connections."""
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "addr", "add", "10.9.9.1/32", "dev", "lo"], check=True)
    hits = []

    def server():
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("10.9.9.1", 80))
        srv.listen(16)
        while True:
            conn, _ = srv.accept()
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            hits.append(data.split(b"\r\n")[0])
            body = b"hello from the real server"
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                         b"Connection: close\r\n\r\n%s" % (len(body), body))
            conn.close()

    threading.Thread(target=server, daemon=True).start()
    time.sleep(0.2)
    c = ctx(); s = StripMonitor(c); c.strip = s
    s.https_seen("bank.example.com", now=time.time())
    g = HttpsGuard(c, protect._run, port=18079)
    check("guard starts: proxy listening and nftables rule loaded", g.start())

    def get(host, ua, path="/"):
        k = socket.create_connection(("10.9.9.1", 80), timeout=5)
        k.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}"
                  f"\r\n\r\n".encode())
        out = b""
        while True:
            chunk = k.recv(4096)
            if not chunk:
                break
            out += chunk
        k.close()
        return out.decode("latin-1")

    r = get("bank.example.com", FF, "/account?id=7")
    check("browser -> HTTPS site: answered 307 https:// locally",
          r.startswith("HTTP/1.1 307") and "Location: https://bank.example.com/account?id=7" in r)
    check("...and nothing reached the network", not hits)
    r = get("neverssl.com", FF)
    check("plain-HTTP site: passed through to the real server",
          "hello from the real server" in r and hits[-1:] == [b"GET / HTTP/1.1"])
    r = get("bank.example.com", APT, "/pool/x.deb")
    check("apt to the same host: passed through", "hello from the real server" in r)
    n = len(hits)
    r = get("google.corn", FF)
    check("look-alike: blocked with a warning page, never sent",
          r.startswith("HTTP/1.1 403") and "google.com" in r and len(hits) == n)
    check("look-alike raises the CRITICAL alert", said(c, "look-alike of 'google.com'", "CRITICAL"))
    direct = socket.create_connection(("127.0.0.1", 18079), timeout=5)
    direct.sendall(b"GET / HTTP/1.1\r\nHost: neverssl.com\r\nUser-Agent: x\r\n\r\n")
    try:
        answer = direct.recv(100)
    except ConnectionResetError:
        answer = b""
    check("direct connections to the proxy are refused (not an open relay)",
          answer == b"")
    direct.close()
    g.stop()
    rc = subprocess.run(["nft", "list", "table", "inet", "languard_guard"],
                        capture_output=True).returncode
    check("stop removes the rule", rc != 0)
    r = get("bank.example.com", FF)
    check("after stop, traffic flows normally again", "hello from the real server" in r)


if "--netns" in sys.argv:
    e2e()
    sys.exit(fails)
units()
# Root inside an unprivileged container can't make network namespaces.
NETNS = os.geteuid() == 0 and all(shutil.which(t) for t in ("nft", "ip", "unshare")) and \
    subprocess.run(["unshare", "-n", "true"], capture_output=True).returncode == 0
if NETNS:
    print("== End to end (real nftables + proxy, private network namespace)")
    r = subprocess.run(["unshare", "-n", sys.executable, __file__, "--netns"],
                       capture_output=True, text=True, timeout=120)
    out = "\n".join(line for line in r.stdout.splitlines() if line.startswith("  "))
    print(out)
    fails += out.count("FAIL") + (r.returncode != 0 and "FAIL" not in out)
    if r.returncode and "FAIL" not in out:
        print(r.stderr[-2000:])
else:
    print("(not root, nft/ip/unshare missing, or no network namespaces: end-to-end guard test skipped)")

print(f"\n{'ALL PASSED' if not fails else f'{fails} FAILED'}")
sys.exit(fails)
