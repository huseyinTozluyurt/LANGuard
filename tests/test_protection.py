#!/usr/bin/env python3
"""Tests for per-network baselines, the closed detection gaps and active
protection. Run: python3 tests/test_protection.py   (no root, no scapy)"""

import ipaddress
import os
import sys
import tempfile
from pathlib import Path

STATE = tempfile.mkdtemp(prefix="languard-test-")
os.environ["LANGUARD_STATE"] = STATE
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from languard_core import core                       # noqa: E402
from languard_core.core import Alerter, load_config  # noqa: E402

core.setup_logging(None)
fails = 0
GW, GW_MAC, ME = "192.168.1.1", "aa:aa:aa:aa:aa:aa", "02:00:00:00:00:50"
EVIL = "66:66:66:66:66:66"


class Ctx:
    pass


def ctx(label="home", cfg=None, protect=None):
    c = Ctx()
    c.cfg = cfg or load_config("/nonexistent")
    c.alert = Alerter(cooldown=0)
    c.iface, c.gateway, c.my_ip, c.my_mac = "eth0", GW, "192.168.1.50", ME
    c.network = ipaddress.ip_network("192.168.1.0/24")
    c.net_label = label
    c.protect = protect
    return c


def check(name, cond):
    global fails
    print(("  ok  " if cond else "  FAIL ") + name)
    fails += not cond


def said(c, text, level=None):
    return any(text in m and (level is None or lv == level)
               for _, lv, m in c.alert.history)


class FakeRun:
    """Records commands instead of running them."""

    def __init__(self, neigh=""):
        self.cmds = []
        self.neigh = neigh

    def __call__(self, cmd, stdin=None, timeout=15):
        self.cmds.append((cmd, stdin))
        if cmd[:3] == ["ip", "neigh", "show"]:
            return 0, self.neigh
        if cmd[:3] == ["ip", "neigh", "replace"]:
            self.neigh = f"{cmd[3]} dev eth0 lladdr {cmd[5]} PERMANENT"
        if cmd[0] == "nmcli" and "GENERAL.CONNECTION" in cmd:
            return 0, "home"
        if cmd[0] == "resolvectl":
            return 0, "Link 2 (eth0): 192.168.1.1"
        return 0, ""

    def ran(self, *words):
        return [c for c, _ in self.cmds if all(w in c for w in words)]


print("== Baseline: verified, per network")
from languard_core import baseline                   # noqa: E402
c = ctx("home"); b = baseline.get(c)
check("nothing verified at first", not b.gw_verified and b.gw_mac is None)
check("two MACs answering is a conflict, not learned",
      b.learn_gateway([[GW_MAC, EVIL]])[0] == "conflict" and not b.gw_verified)
check("no answer learns nothing", b.learn_gateway([[], []])[0] == "none")
check("one consistent MAC is verified",
      b.learn_gateway([[GW_MAC], [GW_MAC], [GW_MAC]]) == ("verified", GW_MAC))
check("verified MAC survives a restart", baseline.Baseline(ctx("home")).gw_mac == GW_MAC)
check("other networks don't share it", baseline.Baseline(ctx("cafe")).gw_mac is None)
check("a different MAC later is 'changed'",
      baseline.get(ctx("home")).learn_gateway([[EVIL]])[0] == "changed")

print("== ARP: poisoned before start, request floods")
from languard_core.arp import ARPMonitor             # noqa: E402
c = ctx("home"); a = ARPMonitor(c)
a.bindings.clear(); c.alert.history.clear()
a.seed({GW: EVIL, "192.168.1.7": "07:07:07:07:07:07"})   # as if read from the kernel
check("cache poisoned before start is caught against the verified MAC",
      said(c, "before LANGuard started", "CRITICAL") and a.gateway_mac == GW_MAC)
c.alert.history.clear()
check("real router's replies are quiet", not a.observe(GW, GW_MAC, True))
check("each new poisoning packet alerts", a.observe(GW, EVIL, True) and a.observe(GW, EVIL, True)
      and sum("GATEWAY SPOOFING" in m for _, _, m in c.alert.history) == 2)
t = 2000.0
for i in range(30):
    a.observe("192.168.1.80", "80:80:80:80:80:80", now=t + i * .1, gratuitous=True)
check("gratuitous ARP request flood", said(c, "ARP flood from 80:80"))
c.alert.history.clear()
for i in range(40):
    a.observe(f"192.168.1.{100 + i}", ME, now=t + i * .01)
check("our own ARP sweep is not a flood", not said(c, "ARP flood"))

c = ctx("lab2"); a = ARPMonitor(c); a.bindings.clear(); a.seed({GW: EVIL})
check("unverified start trusts the cache only provisionally", a.gateway_mac == EVIL)
check("probes then verify the real router and expose the poisoned start",
      a.verify_gateway([[GW_MAC], [GW_MAC]]) == "verified" and a.gateway_mac == GW_MAC
      and said(c, "before LANGuard started", "CRITICAL"))

print("== DHCP: impersonation, DNS changes, chaddr starvation")
from languard_core.dhcp import DHCPMonitor           # noqa: E402
c = ctx("home"); h = DHCPMonitor(c)
check("real router's offer is fine and teaches DNS",
      not h.observe(5, GW, GW_MAC, GW, ["192.168.1.1"]) and h.base.dns == ["192.168.1.1"])
check("rogue server claiming the router's IP is CRITICAL",
      h.observe(5, GW, EVIL, GW, ["6.6.6.6"]) and said(c, "claiming to be the trusted server", "CRITICAL"))
c.alert.history.clear()
check("router now handing out different DNS is a WARNING",
      h.observe(5, GW, GW_MAC, GW, ["9.9.9.9"]) and said(c, "now hands out DNS 9.9.9.9", "WARNING"))
check("string DNS still accepted", not h.observe(2, GW, GW_MAC, GW, "192.168.1.1"))
h2 = DHCPMonitor(ctx("home")); t = 3000.0
for i in range(30):
    h2.discover(f"de:ad:00:00:00:{i:02x}", now=t + i * .1, eth_src="11:22:33:44:55:66")
check("starvation by varying chaddr from one sender",
      said(h2.ctx, "all sent by 11:22:33:44:55:66", "CRITICAL"))

print("== MAC flooding in any frame")
from languard_core.devices import DeviceMonitor     # noqa: E402
c = ctx("home"); d = DeviceMonitor(c); t = 4000.0
check("normal traffic quiet", not any(d.frame_src(m, now=t) for m in (GW_MAC, ME, "01:01:01:01:01:01")))
hit = False
for i in range(600):
    hit |= d.frame_src(f"5e:{i >> 8:02x}:{i & 255:02x}:00:00:01", now=t + i * .005)
check("macof-style random sources caught", hit and said(c, "MAC FLOODING", "CRITICAL"))
c = ctx("home"); d = DeviceMonitor(c)
check("slow trickle of new MACs stays quiet",
      not any(d.frame_src(f"5e:00:{i:02x}:00:00:02", now=t + i * 1.0) for i in range(200)))

print("== IPv6 baselines per network")
from languard_core.ipv6 import IPv6Monitor          # noqa: E402
v = IPv6Monitor(ctx("home"))
v.router_advert("fe80::1", GW_MAC)
check("router learned on home", "fe80::1" in IPv6Monitor(ctx("home")).routers)
check("not trusted on another network", "fe80::1" not in IPv6Monitor(ctx("cafe")).routers)

print("== Protection: off by default")
from languard_core import protect                  # noqa: E402
from languard_core.protect import Protector        # noqa: E402
protect.default_route = lambda: ("eth0", GW)       # this test machine's route is irrelevant
cfg = load_config("/nonexistent"); cfg["protect"]["enabled"] = False
c = ctx("home", cfg); run = FakeRun(); p = Protector(c, run=run, sync=True); c.protect = p
p.start(); p.respond("gateway_spoof", mac=EVIL)
check("disabled config runs no commands", not run.cmds)

print("== Protection: enabled")
cfg = load_config("/nonexistent"); cfg["protect"]["enabled"] = True
c = ctx("home", cfg); run = FakeRun(f"{GW} dev eth0 lladdr {EVIL} REACHABLE")
p = Protector(c, run=run, sync=True); c.protect = p
p.start()
check("netdev ingress table created", any("ingress device \"eth0\"" in (s or "") for _, s in run.cmds))
check("poisoned router entry re-pinned to verified MAC",
      run.ran("ip", "neigh", "replace", GW, GW_MAC, "permanent") and said(c, "Restored your router's ARP entry"))
p.respond("gateway_spoof", mac=EVIL)
check("attacker MAC isolated", run.ran("nft", "add", "element") and EVIL in p.state["blocked"])
n = len(run.ran("nft", "add", "element"))
p.respond("gateway_spoof", mac=EVIL)
check("no duplicate isolation", len(run.ran("nft", "add", "element")) == n)
for mac in (GW_MAC, ME, "ff:ff:ff:ff:ff:ff", "not-a-mac"):
    check(f"never isolates {mac}", not p.isolate(mac, "test"))
p.cfg["never_isolate"] = ["77:77:77:77:77:77"]
check("never_isolate respected", not p.isolate("77:77:77:77:77:77", "test"))
check("kill switch off by default", not run.ran("nmcli", "device", "disconnect"))

c2 = ctx("cafe", cfg); run2 = FakeRun(); p2 = Protector(c2, run=run2, sync=True); p2.start()
p2.respond("gateway_spoof", mac=EVIL)
check("no isolation or pin when the router isn't verified",
      not run2.ran("nft", "add", "element") and not run2.ran("ip", "neigh", "replace"))

print("== Protection: rogue DHCP repair, IPv6 lockdown, kill switch")
run.cmds.clear()
p.respond("rogue_dhcp", mac="88:88:88:88:88:88", dns=["6.6.6.6"], for_me=True)
check("rogue DHCP server isolated and lease renewed",
      "88:88:88:88:88:88" in p.state["blocked"] and run.ran("nmcli", "connection", "up", "home"))
run.cmds.clear(); p._last.clear()
p.respond("rogue_dhcp", mac="89:89:89:89:89:89", dns=["6.6.6.6"], for_me=False)
check("offer to another client: isolate, no renewal",
      "89:89:89:89:89:89" in p.state["blocked"] and not run.ran("nmcli", "connection", "up"))
p.respond("rogue_ra", mac="99:99:99:99:99:99", src_ip="fe80::bad")
check("rogue RA: routes removed and RAs ignored",
      run.ran("ip", "-6", "route", "del", "default", "fe80::bad")
      and run.ran("sysctl", "-w", "net.ipv6.conf.eth0.accept_ra=0"))
p.cfg["kill_switch"] = True
p.respond("mitm_route", mac=GW_MAC)
check("kill switch never fires on the router's own MAC", not run.ran("nmcli", "device", "disconnect"))
p.respond("gateway_spoof", mac="12:12:12:12:12:12")
check("one signal alone only arms the kill switch", not run.ran("nmcli", "device", "disconnect"))
p.respond("rogue_dhcp", mac="12:12:12:12:12:12", dns=["6.6.6.6"], for_me=False)
check("kill switch disconnects on a confirmed gateway MITM",
      run.ran("nmcli", "device", "disconnect", "eth0") and said(c, "KILL SWITCH", "CRITICAL"))

print("== Protection: undo")
run.cmds.clear()
p.undo_all()
check("undo removes isolation, pin and IPv6 lockdown",
      run.ran("nft", "delete", "table") and run.ran("ip", "neigh", "del", GW)
      and run.ran("sysctl", "-w", "net.ipv6.conf.eth0.accept_ra=1") and not p.state["blocked"] and "pin" not in p.state)
c3 = ctx("cafe", cfg); run3 = FakeRun(); p3 = Protector(c3, run=run3, sync=True)
p3.state["pin"] = {"ip": GW, "mac": GW_MAC, "iface": "eth0", "network": "home|x|y"}
p3.start()
check("pin from a previous network is removed on start", run3.ran("ip", "neigh", "del", GW))

print("== Detectors hand attacks to protection")
c = ctx("home", cfg); run = FakeRun(f"{GW} dev eth0 lladdr {GW_MAC} PERMANENT")
c.protect = Protector(c, run=run, sync=True); c.protect.start()
h = DHCPMonitor(c); h.observe(5, "192.168.1.66", "66:66:66:66:66:01", "192.168.1.66", ["192.168.1.66"])
v = IPv6Monitor(c); v.router_advert("fe80::bad", "66:66:66:66:66:02")
from languard_core.mitm import MitmMonitor          # noqa: E402
m = MitmMonitor(c); m.name_answer(m.new_bait(), "192.168.1.67", "LLMNR", mac="66:66:66:66:66:03")
blocked = c.protect.state["blocked"]
check("rogue DHCP, rogue RA and Responder all isolated",
      all(f"66:66:66:66:66:0{i}" in blocked for i in (1, 2, 3)))

print(f"\n{'ALL PASSED' if not fails else f'{fails} FAILED'}")
sys.exit(fails)
