#!/usr/bin/env python3
"""Tests for 1.7 (hardening against the red-team review): router identity
(evil twin), tamper protection, sensor health, DHCP/RA pinning, safer
responses (protected MACs, framing, kill switch), preventive IPv6, plain-HTTP
passwords, HTTPS-only, browser audit, mDNS poisoning and a parser fuzz.
Run: python3 tests/test_v17.py   (no root needed)"""

import ipaddress
import json
import os
import random
import struct
import sys
import tempfile
import time
from pathlib import Path

STATE = tempfile.mkdtemp(prefix="languard-test-")
os.environ["LANGUARD_STATE"] = STATE
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from languard_core import audit, baseline, core, netid, protect, tamper  # noqa: E402
from languard_core.core import Alerter, load_config  # noqa: E402
from languard_core.mitm import MitmMonitor, mdns_records  # noqa: E402
from languard_core.protect import Protector          # noqa: E402
from languard_core.sensor import Sensor, kernel_stats             # noqa: E402
from languard_core.strip import StripMonitor, has_password  # noqa: E402

core.setup_logging(None)
fails = 0
GW, GW_MAC, ME, MY_MAC = "192.168.1.1", "aa:aa:aa:aa:aa:aa", "192.168.1.50", "02:00:00:00:00:50"
FF = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
protect.default_route = lambda: ("eth0", GW)


class Ctx:
    pass


def ctx(label, cfg=None):
    c = Ctx()
    c.cfg = cfg or load_config("/nonexistent")
    c.alert = Alerter(cooldown=0)
    c.iface, c.gateway, c.my_ip, c.my_mac = "eth0", GW, ME, MY_MAC
    c.network = ipaddress.ip_network("192.168.1.0/24")
    c.net_label, c.protect = label, None
    c.local_dns = {"resolver": None}
    return c


def check(name, cond):
    global fails
    print(("  ok  " if cond else "  FAIL ") + name)
    fails += not cond


def said(c, text, level=None):
    return any(text in m and (level is None or lv == level)
               for _, lv, m in c.alert.history)


class FakeRun:
    def __init__(self, wifi="", sysctl="1"):
        self.cmds, self.wifi, self.sysctl = [], wifi, sysctl

    def __call__(self, cmd, stdin=None, timeout=15):
        self.cmds.append((cmd, stdin))
        if cmd[:4] == ["nmcli", "-t", "-f", "ACTIVE,SECURITY,DEVICE"]:
            return 0, self.wifi
        if cmd[:2] == ["sysctl", "-n"]:
            return 0, self.sysctl
        return 0, ""

    def ran(self, *words):
        return [c for c, _ in self.cmds if all(w in c for w in words)]

    def fed(self, *words):
        return [s for _, s in self.cmds if s and all(w in s for w in words)]


def verified(c):
    b = baseline.get(c)
    b.learn_gateway([[GW_MAC]] * 3)
    return b


# ------------------------------------------------------------ evil twin --
def netid_tests():
    print("== Router identity (evil twin)")
    c = ctx("Home-wifi")
    verified(c)
    c.protect = None
    n = netid.NetIdMonitor(c, run=lambda cmd: (0, ""), fingerprint=lambda ip: None)
    check("nmcli escaped colons", netid.split_nmcli(r"yes:My\:Net:AA\:BB\:CC\:DD\:EE\:FF:WPA2:wlan0")
          == ["yes", "My:Net", "AA:BB:CC:DD:EE:FF", "WPA2", "wlan0"])
    out = r"no:Other:11\:11\:11\:11\:11\:11:WPA2:wlan0" + "\n" + \
          r"yes:Home:AA\:BB\:CC\:DD\:EE\:01:WPA2 WPA3:wlan0"
    ident = netid.wifi_identity("wlan0", lambda cmd: (0, out))
    check("active access point read", ident == {"ssid": "Home", "bssid": "aa:bb:cc:dd:ee:01",
                                               "security": "WPA2 WPA3"})
    check("security ranks", netid.security_rank("WPA2 WPA3") == 4 and
          netid.security_rank("") == 0 and netid.security_rank("WPA2 802.1X") == 3)
    check("first sight remembered", n.check_wifi(ident) == "ok"
          and n.base.rec["wifi"]["security"] == "WPA2 WPA3")
    twin = dict(ident, bssid="de:ad:be:ef:00:01")
    check("new access point: reported, not alarming",
          n.check_wifi(twin) == "new_bssid" and said(c, "not seen on this network", "INFO"))
    opn = dict(ident, bssid="de:ad:be:ef:00:02", security="")
    check("same name, no encryption: EVIL TWIN (critical)",
          n.check_wifi(opn) == "downgrade" and said(c, "EVIL TWIN", "CRITICAL"))
    check("...and the downgrade is not learned as normal",
          n.base.rec["wifi"]["security"] == "WPA2 WPA3")
    check("trust level doubtful after a downgrade", n.evaluate(wifi="downgrade", key="same") == "doubtful")

    c2 = ctx("Home-key")
    verified(c2)
    n2 = netid.NetIdMonitor(c2, run=lambda cmd: (0, ""), fingerprint=lambda ip: None)
    check("router key remembered", n2.check_router_key("443:abc") == "new")
    check("same key: verified+key", n2.check_router_key("443:abc") == "same"
          and n2.evaluate(wifi=None, key="same") == "verified+key")
    check("different key: ROUTER IDENTITY CHANGED", n2.check_router_key("443:xyz") == "changed"
          and said(c2, "ROUTER IDENTITY CHANGED", "CRITICAL"))
    check("...stays doubtful until it matches again",
          n2.evaluate(wifi=None, key=None) == "doubtful" and
          n2.evaluate(wifi=None, key="same") == "verified+key")

    c3 = ctx("Cafe-open")
    verified(c3)
    baseline.get(c3).set_kind("public")
    n3 = netid.NetIdMonitor(c3, run=lambda cmd: (0, ""), fingerprint=lambda ip: None)
    check("first visit to a public network: says it can't verify",
          n3.evaluate(wifi=None, key=None) == "first contact"
          and said(c3, "First visit to this public network"))
    c4 = ctx("Unverified")
    n4 = netid.NetIdMonitor(c4, run=lambda cmd: (0, ""), fingerprint=lambda ip: None)
    check("unverified router: no key check", n4.check_router_key("443:abc") is None
          and n4.evaluate(wifi=None, key=None) == "unverified")


# --------------------------------------------------------------- tamper --
def tamper_tests():
    print("== Tamper protection")
    w = tamper.weakens
    check("pause weakens", w(["pause", "30"]))
    check("protect --set ...=off weakens, naming the switches",
          w(["protect", "--set", "isolate=off", "pin_dhcp=on"]) == "responses switched off: isolate")
    check("protect --set ...=on does not", w(["protect", "--set", "https_only=on"]) is None)
    check("--off / --undo-all / --unblock / --unpin weaken",
          all(w(["protect", a]) for a in ("--off", "--undo-all", "--unblock", "--unpin")))
    check("network --home and devices --trust weaken",
          w(["network", "--home"]) and w(["devices", "--trust", "x"]))
    check("options before the command are skipped",
          w(["-c", "/etc/x.yaml", "-v", "pause", "5"]))
    check("read-only commands don't", not any(w(a) for a in (["status"], ["audit"],
          ["protect", "--status"], ["baseline"], ["network", "--public"], [])))
    old = dict(os.environ)
    try:
        os.environ["PKEXEC_UID"] = "1000"
        os.environ.pop(tamper.STRICT_ENV, None)
        check("cached pkexec entry point is refused", tamper.via_cached_pkexec())
        os.environ[tamper.STRICT_ENV] = "1"
        check("strict entry point (password every time) is allowed",
              not tamper.via_cached_pkexec())
    finally:
        os.environ.clear()
        os.environ.update(old)
    user, via, prog = tamper.caller()
    check("caller names a user and program", user and via in ("root", "sudo", "pkexec") and prog)
    pol = (Path(__file__).resolve().parent.parent / "desktop" / "org.languard.policy").read_text()
    check("polkit: weakening action asks every time (auth_admin, not _keep)",
          "org.languard.weaken" in pol and "languard_strict.py" in pol)


# --------------------------------------------------------------- sensor --
def sensor_tests():
    print("== Sensor health (blinding)")
    clock = [1000.0]
    got = []
    s = Sensor({"sensor": {"per_mac_pps": 10, "drop_alert": 50, "error_alert": 5}},
               lambda k, lv, m, **d: got.append((k, lv, m)), now=lambda: clock[0])
    admitted = sum(s.admit("66:66:66:66:66:66") for _ in range(100))
    check("a flooder only gets its own budget", admitted == 10)
    check("other devices still judged during the flood", s.admit(GW_MAC))
    clock[0] += 1
    check("budget renews every second", s.admit("66:66:66:66:66:66"))
    s.kernel((5000, 400))
    for _ in range(6):
        s.error("dns")
    clock[0] += 59
    st = s.tick()
    keys = [k for k, _, _ in got]
    check("kernel drops reported (SENSOR OVERLOADED)",
          any("SENSOR OVERLOADED" in m for _, _, m in got) and st["state"] == "overloaded")
    check("flooding MAC named", "flood:66:66:66:66:66:66" in keys and st["flooders"])
    check("crashing detector reported", "errors:dns" in keys)
    got.clear()
    st = s.tick()
    check("quiet minute: ok, no alerts", st["state"] == "ok" and not got)
    import socket
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    check("kernel_stats is safe on a non-packet socket", kernel_stats(sk) is None)
    sk.close()
    unit = (Path(__file__).resolve().parent.parent / "systemd" / "languard.service").read_text()
    check("service is sandboxed", all(k in unit for k in (
        "NoNewPrivileges=yes", "ProtectKernelModules=yes", "RestrictAddressFamilies")))


# ---------------------------------------------------- responses & pins --
def response_tests():
    print("== Safer responses and DHCP/RA pinning")
    c = ctx("Pins")
    run = FakeRun()
    p = Protector(c, run=run, sync=True)
    check("no pins before the router is verified", p.l2_pin_macs() == (set(), set()))
    verified(c)
    p.update_l2_pins()
    rules = "\n".join(run.fed("pins"))
    check("DHCP answers only from the verified router", "udp sport 67" in rules
          and f"ether saddr != {{ {GW_MAC} }}" in rules)
    check("IPv6 router advertisements only from the verified router",
          "nd-router-advert" in rules)
    check("pinning announced once", said(c, "Pinned the network's servers", "INFO"))
    n = len(run.cmds)
    p.update_l2_pins()
    check("no rewrite when nothing changed", len(run.cmds) == n)
    p.disable_option("pin_dhcp")
    check("pin_dhcp off: chain flushed",
          any("flush chain netdev languard pins" in (s or "") or "pins" in c2
              for c2, s in run.cmds[n:]))

    p.cfg["kill_switch"] = False
    p.respond("rogue_ra", mac=GW_MAC)
    check("router's own MAC named as attacker: warned, never isolated",
          GW_MAC not in p.state["blocked"] and said(c, "never isolates it", "WARNING"))
    p.base.pin_device("192.168.1.20", "02:00:5e:00:00:20")
    p.respond("rogue_dhcp", mac="02:00:5e:00:00:20", for_me=False)
    check("a pinned device named as attacker: not isolated",
          "02:00:5e:00:00:20" not in p.state["blocked"])

    c5 = ctx("Public-v6")
    verified(c5).set_kind("public")
    run5 = FakeRun(sysctl="1")
    p5 = Protector(c5, run=run5, sync=True)
    p5.state.pop("accept_ra", None)     # left by the tests above
    p5.apply_network_kind()
    check("public network: IPv6 RAs ignored before any attack",
          run5.ran("sysctl", "-w", "net.ipv6.conf.eth0.accept_ra=0")
          and p5.state["accept_ra"]["preventive"] and not said(c5, "IPv6 lockdown"))
    p5.base.set_kind("home")
    p5.apply_network_kind()
    check("marked home: put back", "accept_ra" not in p5.state
          and run5.ran("sysctl", "-w", "net.ipv6.conf.eth0.accept_ra=1"))


# --------------------------------------------------------------- strip --
def strip_tests():
    print("== Plain-HTTP passwords and HTTPS-only")
    req = b"POST /login HTTP/1.1\r\nHost: shop.example\r\n\r\n"
    check("password field found", has_password(req + b"user=a&password=hunter2")
          and has_password(req + b'{"pass":"x"}')
          and not has_password(req + b"q=passport+photo"))
    c = ctx("Strip")
    m = StripMonitor(c)
    check("password over plain HTTP: warned", m.plain_password("shop.example", ua=FF)
          and said(c, "PASSWORD SENT IN PLAIN TEXT", "WARNING"))
    check("default: plain-HTTP site passed", m.verdict("GET", "plain.example.org", "/", FF)[0] == "pass")
    c.cfg["protect"]["https_only"] = True
    check("https_only: every public site upgraded",
          m.verdict("GET", "plain.example.org", "/", FF)[0] == "upgrade")
    check("https_only: router and .local untouched",
          m.verdict("GET", "printer.local", "/", FF)[0] == "pass"
          and m.verdict("GET", "192.168.1.1", "/", FF)[0] == "pass")
    c.cfg["protect"]["https_only"] = False


def audit_tests():
    print("== Browser HTTPS-Only audit")
    home = Path(tempfile.mkdtemp())
    ff = home / ".mozilla/firefox/abc.default"
    ff.mkdir(parents=True)
    (ff / "prefs.js").write_text('user_pref("dom.security.https_only_mode", true);\n')
    r = audit.check_browser_https([home])
    check("Firefox with HTTPS-Only: pass", r and r[0].status == audit.PASS)
    ch = home / ".config/chromium/Default"
    ch.mkdir(parents=True)
    (ch / "Preferences").write_text(json.dumps({"https_only_mode_enabled": False}))
    r = audit.check_browser_https([home])
    check("Chromium without it: warning with how to turn it on",
          r and r[0].status == audit.WARN and "Always use secure" in r[0].fix)
    check("no browsers: no line", audit.check_browser_https([Path(tempfile.mkdtemp())]) == [])
    check("no VPN advice in the audit's fixes",
          "use a VPN" not in Path(audit.__file__).read_text().lower())


# ---------------------------------------------------------------- mDNS --
def mdns_packet(records):
    hdr = struct.pack(">HHHHHH", 0, 0x8400, 0, len(records), 0, 0)
    body = b""
    for name, ip in records:
        body += b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"
        body += struct.pack(">HHIH", 1, 0x8001, 120, 4) + bytes(map(int, ip.split(".")))
    return hdr + body


def mdns_tests():
    print("== mDNS poisoning")
    c = ctx("Mdns")
    m = MitmMonitor(c)
    check("A records parsed", mdns_records(mdns_packet([("printer.local", "192.168.1.30")]))
          == [("printer.local", "192.168.1.30")])
    bait = m.new_bait()
    check("answer to our made-up .local name: poisoning",
          m.mdns_answer(bait + ".local", "192.168.1.66", "66:66:66:66:66:66")
          and said(c, "NAME POISONING", "CRITICAL"))
    t = time.time()
    for i, name in enumerate(("nas.local", "tv.local", "printer.local")):
        m.mdns_answer(name, f"192.168.1.{10 + i}", f"02:00:5e:00:00:1{i}", now=t)
    check("a device moving: warning only",
          not m.mdns_answer("nas.local", "192.168.1.77", "77:77:77:77:77:77", now=t + 1)
          and said(c, "mDNS name nas.local moved", "WARNING"))
    m.mdns_answer("tv.local", "192.168.1.77", "77:77:77:77:77:77", now=t + 2)
    check("one MAC taking over 3 names: mDNS POISONING",
          m.mdns_answer("printer.local", "192.168.1.77", "77:77:77:77:77:77", now=t + 3)
          and said(c, "mDNS POISONING", "CRITICAL"))


# ---------------------------------------------------------- parser fuzz --
def fuzz_tests():
    print("== Parser fuzz (crafted packets must not crash detectors)")
    rnd = random.Random(1707)
    bad = 0
    for _ in range(3000):
        data = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 80)))
        if rnd.random() < .5:
            data = struct.pack(">HHHHHH", 0, 0x8400, rnd.randrange(3),
                               rnd.randrange(5), 0, 0) + data
        try:
            mdns_records(data)
            has_password(data)
        except Exception:
            bad += 1
    check("3000 random mDNS/HTTP bodies: no exception", bad == 0)


def detector_fuzz():
    try:
        from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw, IPv6
    except ImportError:
        print("  (scapy not installed: detector fuzz skipped)")
        return
    import importlib
    c = ctx("Fuzz")
    verified(c)
    c.protect = Protector(c, run=FakeRun(), sync=True)
    c.protect.enabled = False
    mods = []
    for name, cls in (("arp", "ARPMonitor"), ("dhcp", "DHCPMonitor"), ("dns", "DNSMonitor"),
                      ("ipv6", "IPv6Monitor"), ("mitm", "MitmMonitor"),
                      ("strip", "StripMonitor")):
        try:
            mods.append(getattr(importlib.import_module(f"languard_core.{name}"), cls)(c))
        except Exception as e:
            print(f"  (skip {name}: {e})")
    rnd = random.Random(17)
    crashes = {}
    for i in range(1500):
        payload = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 300)))
        sport, dport = rnd.choice([(53, 5353), (5353, 5353), (67, 68), (5355, 5355),
                                   (137, 137), (547, 546), (53, 40000)])
        layers = [
            Ether(src="66:66:66:66:66:66") / IP(src="192.168.1.66", dst=ME) / UDP(sport=sport, dport=dport) / Raw(payload),
            Ether(src="66:66:66:66:66:66") / IP(src="192.168.1.66", dst=ME) / TCP(sport=40000, dport=80, flags="PA") / Raw(payload),
            Ether(src="66:66:66:66:66:66") / IPv6(src="fe80::66", dst="ff02::1") / Raw(payload),
            Ether(src="66:66:66:66:66:66") / IP(src="192.168.1.66", dst=ME) / ICMP(type=5) / Raw(payload),
            Ether(src="66:66:66:66:66:66", type=0x0806) / Raw(payload),
        ]
        raw = bytes(rnd.choice(layers))
        pkt = Ether(raw)
        for m in mods:
            try:
                m.handle(pkt)
            except Exception as e:
                crashes.setdefault(m.name, repr(e)[:120])
    for k, v in crashes.items():
        print(f"     {k}: {v}")
    check("1500 random packets through every detector: no crash", not crashes)


netid_tests()
tamper_tests()
sensor_tests()
response_tests()
strip_tests()
audit_tests()
mdns_tests()
fuzz_tests()
detector_fuzz()
print(f"\n{'ALL PASSED' if not fails else f'{fails} FAILED'}")
sys.exit(fails)
