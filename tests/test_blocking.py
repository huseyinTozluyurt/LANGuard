#!/usr/bin/env python3
"""Tests for 1.5's blocking responses: every man-in-the-middle detection now
ends what the attack set up (IP blocks, live connections, DNS cache, LLMNR,
ICMP redirects, evil-twin Wi-Fi), with the anti-abuse limits.
Run: python3 tests/test_blocking.py   (no root needed; as root with nftables
and iproute2 it also blocks and cuts for real in a private network namespace)"""

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
from languard_core.protect import Protector          # noqa: E402

core.setup_logging(None)
fails = 0
GW, GW_MAC, ME = "192.168.1.1", "aa:aa:aa:aa:aa:aa", "02:00:00:00:00:50"
protect.default_route = lambda: ("eth0", GW)
EVIL, EVIL_IP = "66:66:66:66:66:66", "192.168.1.66"


class Ctx:
    pass


def ctx(cfg=None, net="192.168.1.0/24", my_ip="192.168.1.50"):
    c = Ctx()
    c.cfg = cfg or load_config("/nonexistent")
    c.alert = Alerter(cooldown=0)
    c.iface, c.gateway, c.my_ip, c.my_mac = "eth0", GW, my_ip, ME
    c.network = ipaddress.ip_network(net)
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
    def __init__(self, killed=2, wifi=""):
        self.cmds, self.killed, self.wifi = [], killed, wifi

    def __call__(self, cmd, stdin=None, timeout=15):
        self.cmds.append((cmd, stdin))
        if cmd[0] == "ss":
            return 0, "\n".join(["Recv-Q Send-Q Local Peer"] +
                                ["0 0 a b"] * self.killed)
        if cmd[:2] == ["resolvectl", "llmnr"] and len(cmd) == 3:
            return 0, "Link 2 (eth0): yes"
        if cmd[:2] == ["sysctl", "-n"]:
            return 0, "1"
        if cmd[0] == "nmcli" and "wifi" in cmd:
            return 0, self.wifi
        return 0, ""

    def ran(self, *words):
        return [c for c, _ in self.cmds if all(w in c for w in words)]


def protector(run=None, cfg=None):
    c = ctx(cfg)
    baseline.get(c).learn_gateway([[GW_MAC]] * 3)
    p = Protector(c, run=run or FakeRun(), sync=True)
    c.protect = p
    return c, p


print("== ARP spoofing of the router: connections through the attacker end")
c, p = protector()
p.respond("gateway_spoof", mac=EVIL)
check("attacker isolated and router pinned", EVIL in p.state["blocked"] and p.run.ran("ip", "neigh", "replace"))
cut = p.run.ran("ss", "-K", "-4")
check("every IPv4 connection that left via the router is ended (not LAN, not loopback)",
      cut and "127.0.0.0/8" in cut[0] and "192.168.1.0/24" in cut[0])
check("DNS cache flushed (answers may have been forged)", p.run.ran("resolvectl", "flush-caches"))
check("the user is told what was ended", said(c, "Ended 2 connection(s)", "WARNING"))

print("== Rogue IPv6 router / NDP spoofing: routed IPv6 connections end")
c, p = protector()
p.respond("rogue_ra", mac=EVIL, src_ip="fe80::66")
check("IPv6 connections ended (link-local and loopback kept)",
      any("fe80::/10" in c_ and "-6" in c_ for c_ in p.run.ran("ss", "-K")))

print("== Rogue DHCP: the attacker's own addresses are blocked, public DNS is not")
c, p = protector()
p.respond("rogue_dhcp", mac=EVIL, server_ip=EVIL_IP, router=EVIL_IP,
          dns=[EVIL_IP, "8.8.8.8"])
check("rogue server's IP blocked", EVIL_IP in p.state["blocked_ips"])
check("8.8.8.8 handed out by the attacker is not blocked", "8.8.8.8" not in p.state["blocked_ips"])
check("live connections to it ended", p.run.ran("ss", "-K", "dst", EVIL_IP))
c, p = protector()
baseline.get(c).learn_dhcp("192.168.1.2", "dd:dd:dd:dd:dd:dd")
p.respond("rogue_dhcp", mac=EVIL, server_ip="192.168.1.2", router=None, dns=[])
check("impersonated real DHCP server's IP is not blocked", "192.168.1.2" not in p.state["blocked_ips"])

print("== mitm6 (rogue DHCPv6)")
c, p = protector()
p.respond("rogue_dhcp6", mac=EVIL, src_ip="fe80::66", dns=["fe80::66"], v6=True)
check("attacker's IPv6 address blocked", "fe80::66" in p.state["blocked_ips"])
check("IPv6 cut uses an address prefix ss accepts", p.run.ran("ss", "-K", "-6", "fe80::66/128"))

print("== LLMNR/NBT-NS poisoning (Responder)")
c, p = protector()
p.respond("name_poisoning", mac=EVIL, src_ip=EVIL_IP)
check("responder isolated and its IP blocked", EVIL in p.state["blocked"] and EVIL_IP in p.state["blocked_ips"])
check("LLMNR turned off on the interface", p.run.ran("resolvectl", "llmnr", "eth0", "no") and p.state["llmnr"]["old"] == "yes")
p.undo_all()
check("undo turns LLMNR back to what it was", p.run.ran("resolvectl", "llmnr", "eth0", "yes"))

print("== ICMP redirects")
c, p = protector()
p.respond("icmp_redirect", mac=EVIL, src_ip=EVIL_IP)
check("kernel stops accepting redirects (IPv4 and IPv6)",
      p.run.ran("sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0")
      and p.run.ran("sysctl", "-w", "net.ipv6.conf.eth0.accept_redirects=0"))
check("routes the redirect created are dropped", p.run.ran("ip", "route", "flush", "cache"))
p.undo_all()
check("undo restores the old sysctl values", p.run.ran("sysctl", "-w", "net.ipv4.conf.all.accept_redirects=1"))

print("== DNS spoofing")
from languard_core.dns import DNSMonitor               # noqa: E402
c, p = protector()
d = DNSMonitor(c)
d.query("192.168.1.50", 5555, 7, "bank.example.com.", "1.1.1.1")
d.response("192.168.1.50", 5555, 7, "bank.example.com.", "1.1.1.1", {"192.168.1.66"}, mac=EVIL)
check("reply for an internet resolver not sent by the router's MAC = forged",
      said(c, "not your router", "CRITICAL"))
check("forged answer blocked, sender isolated, cache flushed",
      "192.168.1.66" in p.state["blocked_ips"] and EVIL in p.state["blocked"]
      and p.run.ran("resolvectl", "flush-caches"))
c, p = protector()
d = DNSMonitor(c)
d.query("192.168.1.50", 5556, 8, "nas.lan.", "192.168.1.5")
check("a LAN resolver (Pi-hole) answering from its own MAC is fine",
      not d.response("192.168.1.50", 5556, 8, "nas.lan.", "192.168.1.5", {"192.168.1.20"}, mac="bb:bb:bb:bb:bb:bb"))
d.query("192.168.1.50", 5557, 9, "example.com.", "1.1.1.1")
d.response("192.168.1.50", 5557, 9, "example.com.", "1.1.1.1", {"93.184.215.14"}, mac=GW_MAC)
d.response("192.168.1.50", 5557, 9, "example.com.", "1.1.1.1", {"10.6.6.6"}, mac=GW_MAC)
check("conflicting answers: cache flushed and connections to both ended, nothing blocked",
      p.run.ran("ss", "-K", "dst", "10.6.6.6") and p.run.ran("ss", "-K", "dst", "93.184.215.14")
      and "10.6.6.6" not in p.state["blocked_ips"])

print("== SSL stripping and look-alikes")
from languard_core.strip import StripMonitor          # noqa: E402
FF = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
c, p = protector()
s = StripMonitor(c)
s.https_seen("bank.example.com", now=1000)
s.http_request("POST", "bank.example.com", "/login", ip="203.0.113.10", ua=FF, now=2000)
check("stripped plain-HTTP session is ended", p.run.ran("ss", "-K", "dst", "203.0.113.10", ":80"))
s.http_request("GET", "google.corn", ip="203.0.113.99", ua=FF, now=2001)
check("look-alike site's address blocked", "203.0.113.99" in p.state["blocked_ips"])

print("== TLS interception, port scans, evil twin")
c, p = protector()
from languard_core.tls import TLSMonitor               # noqa: E402
t = TLSMonitor(c, fetch=None, redirect=None, portal=lambda: False)
t.evaluate("github.com", {"ok": False, "issuer": None, "error": "self signed", "kind": "verify"})
check("TLS interception flushes the DNS cache", p.run.ran("resolvectl", "flush-caches"))
check("...kill switch only if you turned it on", not p.run.ran("nmcli", "device", "disconnect"))
from languard_core.scan import ScanMonitor            # noqa: E402
sc = ScanMonitor(c)
for port in range(1, 40):
    sc.observe("192.168.1.77", port, 0x02)
check("port scanner blocked in nftables (expires)", "192.168.1.77" in p.state["blocked_ips"])
for port in range(1, 40):
    sc.observe(GW, port, 0x02)
check("...but never the router", GW not in p.state["blocked_ips"])
run = FakeRun(wifi="yes:66\\:66\\:66\\:66\\:66\\:01:wlan0\nno:aa\\:bb\\:cc\\:dd\\:ee\\:ff:wlan0")
c, p = protector(run)
p.respond("evil_twin", bssid="66:66:66:66:66:01", ssid="Home")
check("connected to the evil twin: Wi-Fi disconnected", run.ran("nmcli", "device", "disconnect", "wlan0")
      and said(c, "evil twin", "CRITICAL"))
run = FakeRun(wifi="yes:aa\\:bb\\:cc\\:dd\\:ee\\:ff:wlan0")
c, p = protector(run)
p.respond("evil_twin", bssid="66:66:66:66:66:01", ssid="Home")
check("not connected to it: nothing is disconnected", not run.ran("nmcli", "device", "disconnect"))

print("== Can't be turned against innocent devices")
c, p = protector()
check("router, this machine, loopback and multicast are never blocked",
      not any(p.block_ip(ip, "x") for ip in (GW, "192.168.1.50", "127.0.0.1", "224.0.0.251", "::1")))
cfg = load_config("/nonexistent"); cfg["protect"]["never_block"] = ["192.168.1.9"]
c, p = protector(cfg=cfg)
check("never_block is respected", not p.block_ip("192.168.1.9", "x"))
for i in range(20):
    p.block_ip(f"203.0.113.{i + 1}", "x")
check("up to block_max (20) addresses in 10 min are blocked",
      all(f"203.0.113.{i + 1}" in p.state["blocked_ips"] for i in range(20)))
check("the 21st pauses IP blocking instead", not p.block_ip("203.0.113.200", "x") and said(c, "stopped blocking", "CRITICAL"))
c, p = protector()
p.block_ip("203.0.113.5", "x")
p.unblock("203.0.113.5")
check("--unblock IP removes it", "203.0.113.5" not in p.state["blocked_ips"]
      and p.run.ran("nft", "delete", "element", "inet", "languard_ip"))
cfg = load_config("/nonexistent"); cfg["protect"]["cut_connections"] = False
c, p = protector(cfg=cfg)
p.respond("gateway_spoof", mac=EVIL)
check("each response has its own switch (cut_connections off: nothing ended)", not p.run.ran("ss", "-K"))


# ------------------------------------------------- real end-to-end run --
def e2e():
    """Private network namespace: real nftables blocks and real ss -K cuts."""
    for cmd in (["ip", "link", "set", "lo", "up"],
                ["ip", "addr", "add", "10.9.9.1/32", "dev", "lo"],
                ["ip", "addr", "add", "203.0.113.7/32", "dev", "lo"],
                ["ip", "addr", "add", "192.168.1.50/24", "dev", "lo"]):
        subprocess.run(cmd, check=True)
    keep = []
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 9000))
    srv.listen(16)
    threading.Thread(target=lambda: [keep.append(srv.accept()[0]) for _ in iter(int, 1)],
                     daemon=True).start()

    def alive(k):
        try:
            k.send(b"x")
            time.sleep(0.05)
            k.send(b"x")
            return True
        except OSError:
            return False

    c = ctx(net="192.168.1.0/24", my_ip="192.168.1.50")
    baseline.get(c).learn_gateway([[GW_MAC]] * 3)
    p = Protector(c, run=protect._run, sync=True)
    p.state["blocked_ips"] = {}             # not the unit tests' fake blocks
    check("nftables IP block table created", p.setup_ipblock())
    a = socket.create_connection(("10.9.9.1", 9000))
    b = socket.create_connection(("192.168.1.50", 9000))
    lo = socket.create_connection(("127.0.0.1", 9000))
    time.sleep(0.2)
    n = p.cut(scope="offlink", why="test")
    check("gateway MITM: off-LAN connection ended for real", not alive(a) and n >= 1)
    check("...LAN and loopback connections untouched", alive(b) and alive(lo))
    x = socket.create_connection(("203.0.113.7", 9000))
    time.sleep(0.2)
    check("block_ip on a real address", p.block_ip("203.0.113.7", "test"))
    check("...its live connection was ended", not alive(x))
    try:
        socket.create_connection(("203.0.113.7", 9000), timeout=2)
        refused = False
    except OSError:
        refused = True
    check("...and new connections to it are refused", refused)
    p.unblock("203.0.113.7")
    try:
        socket.create_connection(("203.0.113.7", 9000), timeout=2).close()
        ok = True
    except OSError:
        ok = False
    check("unblock lets it through again", ok)
    p.undo_all()
    rc = subprocess.run(["nft", "list", "table", "inet", "languard_ip"],
                        capture_output=True).returncode
    check("undo removes the table", rc != 0)


if "--netns" in sys.argv:
    import faulthandler
    faulthandler.dump_traceback_later(100, exit=True)
    print("== E2E")
    fails = 0
    e2e()
    sys.exit(fails)
# Root inside an unprivileged container can't make network namespaces.
NETNS = os.geteuid() == 0 and all(shutil.which(t) for t in ("nft", "ip", "unshare", "ss")) and \
    subprocess.run(["unshare", "-n", "true"], capture_output=True).returncode == 0
if NETNS:
    print("== End to end (real nftables + ss -K, private network namespace)")
    r = subprocess.run(["unshare", "-n", sys.executable, __file__, "--netns"],
                       capture_output=True, text=True, timeout=120)
    lines = [ln for ln in r.stdout.split("== E2E", 1)[-1].splitlines()
             if ln.startswith("  ")]
    print("\n".join(lines))
    bad = sum("FAIL" in ln for ln in lines)
    fails += bad or (r.returncode != 0)
    if r.returncode and not bad:
        print(r.stderr[-2000:])
else:
    print("(not root, nft/ip/unshare/ss missing, or no network namespaces: end-to-end test skipped)")

print(f"\n{'ALL PASSED' if not fails else f'{fails} FAILED'}")
sys.exit(fails)
