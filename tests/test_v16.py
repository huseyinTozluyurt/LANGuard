#!/usr/bin/env python3
"""Tests for 1.6: working next to dnscrypt-proxy (read-only, leak and block
warnings), the HSTS preload list, home/public networks, device and IPv6
router pinning, attacker IPs from MACs, WPAD, SMB/NTLM audit, evidence
capture and the selftest.
Run: python3 tests/test_v16.py   (no root needed)"""

import ipaddress
import os
import socket
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path

STATE = tempfile.mkdtemp(prefix="languard-test-")
os.environ["LANGUARD_STATE"] = STATE
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from languard_core import audit, baseline, core, hsts, localdns, protect  # noqa: E402
from languard_core.arp import ARPMonitor             # noqa: E402
from languard_core.core import Alerter, load_config  # noqa: E402
from languard_core.dhcp import DHCPMonitor, _url_host  # noqa: E402
from languard_core.dns import DNSMonitor             # noqa: E402
from languard_core.evidence import Evidence          # noqa: E402
from languard_core.ipv6 import IPv6Monitor           # noqa: E402
from languard_core.protect import Protector          # noqa: E402
from languard_core.strip import StripMonitor         # noqa: E402

core.setup_logging(None)
fails = 0
GW, GW_MAC, ME, MY_MAC = "192.168.1.1", "aa:aa:aa:aa:aa:aa", "192.168.1.50", "02:00:00:00:00:50"
ATT_MAC = "66:66:66:66:66:66"
FF = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
protect.default_route = lambda: ("eth0", GW)


class Ctx:
    pass


def ctx(cfg=None, label="home"):
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
    def __init__(self, wifi=""):
        self.cmds, self.wifi = [], wifi
        self.neigh = {}

    def __call__(self, cmd, stdin=None, timeout=15):
        self.cmds.append((cmd, stdin))
        if cmd[:4] == ["nmcli", "-t", "-f", "ACTIVE,SECURITY,DEVICE"]:
            return 0, self.wifi
        if cmd[:3] == ["ip", "neigh", "show"] and cmd[3] in self.neigh:
            return 0, f"{cmd[3]} dev eth0 lladdr {self.neigh[cmd[3]]} REACHABLE"
        if cmd[:3] == ["resolvectl", "llmnr", "eth0"] and len(cmd) == 3:
            return 0, "Link 2 (eth0): yes"
        if cmd[:2] == ["sysctl", "-n"]:
            return 0, "1"
        return 0, ""

    def ran(self, *words):
        return [c for c, _ in self.cmds if all(w in c for w in words)]


def verified(c):
    b = baseline.get(c)
    b.learn_gateway([[GW_MAC]] * 3)
    return b


# ------------------------------------------------------- dnscrypt-proxy --
SS = """UNCONN 0 0 127.0.2.1:53 0.0.0.0:* users:(("dnscrypt-proxy",pid=812,fd=7),("systemd",pid=1,fd=60))
UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=600,fd=13))
UNCONN 0 0 [::1]:53 [::]:* users:(("dnscrypt-proxy",pid=812,fd=8))"""
TOML = """# dnscrypt-proxy
server_names = ['cloudflare', 'quad9-dnscrypt-ip4-filter-pri']
listen_addresses = []
bootstrap_resolvers = ['9.9.9.11:53', '8.8.8.8:53']
netprobe_address = '9.9.9.9:53'
[sources]
  [sources.public-resolvers]
  bootstrap_resolvers = ['6.6.6.6:53']
"""


def fake_proc(comm="dnscrypt-proxy", config=None):
    d = tempfile.mkdtemp()
    for pid, name in (("1", "systemd"), ("812", comm)):
        Path(d, pid).mkdir()
        Path(d, pid, "comm").write_text(name + "\n")
        args = [name] + (["-config", config] if config and pid == "812" else [])
        Path(d, pid, "cmdline").write_bytes(b"\0".join(a.encode() for a in args))
    return d


def localdns_tests():
    print("== dnscrypt-proxy: found and read, never changed")
    toml = Path(tempfile.mkdtemp(), "dnscrypt-proxy.toml")
    toml.write_text(TOML)
    proc = fake_proc(config=str(toml))
    r = localdns.find_resolver(proc)
    check("dnscrypt-proxy found from /proc, with its -config file",
          r and r["name"] == "dnscrypt-proxy" and r["config"] == str(toml))
    check("no resolver running: None", localdns.find_resolver(fake_proc("bash")) is None)
    check("listen addresses from ss, systemd socket activation included",
          localdns.listen_addrs("dnscrypt-proxy", SS) == ["127.0.2.1:53", "[::1]:53"])
    t = localdns.toml_settings(str(toml))
    check("bootstrap/netprobe servers read from the top level only",
          t["bootstrap_resolvers"] == ["9.9.9.11:53", "8.8.8.8:53"]
          and t["netprobe_address"] == ["9.9.9.9:53"])
    check("address parsing", localdns.split_addr("[::1]:5353") == ("::1", 5353)
          and localdns.split_addr("127.0.2.1:53") == ("127.0.2.1", 53)
          and localdns.split_addr("::1") == ("::1", 53))
    rc = Path(tempfile.mkdtemp(), "resolv.conf")
    rc.write_text("nameserver 127.0.0.53\noptions edns0 trust-ad\n")
    good = localdns.inspect(proc, SS, str(rc), "Global: 127.0.2.1\nLink 2 (wlp2s0):")
    check("resolved -> dnscrypt only: no leak risk",
          good["resolver"] == "dnscrypt-proxy" and not good["leak_risk"]
          and good["bootstrap"] == ["8.8.8.8", "9.9.9.11", "9.9.9.9"])
    leaky = localdns.inspect(proc, SS, str(rc),
                             "Global: 127.0.2.1\nLink 2 (wlp2s0): 192.168.1.1 fe80::1%2")
    check("the connection's DHCP DNS next to dnscrypt: leak risk named",
          leaky["plain_servers"] == ["192.168.1.1", "fe80::1"]
          and "wlp2s0" in leaky["leak_risk"][0])
    check("advice is a command for the user, with ignore-auto-dns",
          "ignore-auto-dns yes" in localdns.advice(leaky, "Home WiFi"))
    rc.write_text("nameserver 127.0.2.1\n")
    direct = localdns.inspect(proc, SS, str(rc), "")
    check("resolv.conf straight to dnscrypt: fine", not direct["leak_risk"])
    rc.write_text("nameserver 127.0.2.1\nnameserver 1.1.1.1\n")
    check("a second plain nameserver in resolv.conf: leak risk",
          localdns.inspect(proc, SS, str(rc), "")["leak_risk"])
    rc.write_text("nameserver 1.1.1.1\n")
    check("resolv.conf not pointing at it at all: 'isn't used'",
          "isn't used" in localdns.inspect(proc, SS, str(rc), "")["leak_risk"][0])
    rc.write_text("nameserver 127.0.0.53\n")
    check("resolved not forwarding to it: 'isn't used'",
          "isn't used" in localdns.inspect(proc, SS, str(rc),
                                           "Global:\nLink 2 (eth0): 192.168.1.1")["leak_risk"][0])

    print("== Plain-DNS leaks while dnscrypt-proxy runs")
    c = ctx()
    c.local_dns = good
    d = DNSMonitor(c)
    d.query(ME, 5000, 1, "bank.example.com.", "192.168.1.1", now=1000)
    check("a lookup sent in plain text to the router: DNS LEAK warning",
          said(c, "DNS LEAK: bank.example.com", "WARNING"))
    check("...that says LANGuard doesn't change DNS settings",
          said(c, "doesn't change DNS settings"))
    n = len(c.alert.history)
    d.query(ME, 5001, 2, "other.example.com.", "192.168.1.1", now=1010)
    check("one warning per server per hour", len(c.alert.history) == n)
    check("dnscrypt-proxy's own bootstrap lookups: not a leak",
          not d.leak("raw.githubusercontent.com.", "9.9.9.11", now=2000))
    check("local names (printer.lan, bare names): not a leak",
          not d.leak("printer.lan.", "192.168.1.9", 2000)
          and not d.leak("nas.", "192.168.1.9", 2000))
    c.cfg["dns"]["plain_ok"] = ["192.168.1.53"]
    check("servers in dns.plain_ok: not a leak", not d.leak("x.example.com.", "192.168.1.53", 2000))
    c2 = ctx()
    d2 = DNSMonitor(c2)
    d2.query(ME, 5000, 1, "bank.example.com.", "192.168.1.1")
    check("no encrypted resolver: plain DNS is normal, no leak warning",
          not said(c2, "DNS LEAK"))
    d.query("192.168.1.77", 5000, 3, "y.example.com.", "8.8.4.4", now=5000)
    check("other devices' lookups are theirs: not judged", not said(c, "8.8.4.4"))

    print("== Encrypted DNS blocked / stopped")
    c = ctx()
    m = localdns.LocalDNSMonitor(c)
    info = dict(good, listen=["127.0.2.1:53"])
    for i in range(3):
        m.check_answers(info, prober=lambda a: False, now=10000 + i * 400)
    check("3 failed checks in a row: warning about blocked encrypted DNS",
          said(c, "may be blocked", "WARNING"))
    check("...that says not to fall back to the network's DNS",
          said(c, "Don't switch to the network's DNS"))
    check("answers again: counter reset",
          m.check_answers(info, prober=lambda a: True, now=20000) and m.fails == 0)

    # a real (tiny) DNS server on loopback for probe()
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    rcode = {"v": 3}

    def answer():
        while True:
            try:
                q, a = srv.recvfrom(512)
            except OSError:
                return
            srv.sendto(q[:2] + bytes([0x81, 0x80 | rcode["v"]]) + q[4:], a)
    threading.Thread(target=answer, daemon=True).start()
    check("probe: NXDOMAIN for the random name = resolver works",
          localdns.probe(f"127.0.0.1:{port}"))
    rcode["v"] = 2
    check("probe: SERVFAIL = upstream unreachable", not localdns.probe(f"127.0.0.1:{port}"))
    srv.close()
    check("probe: silence = not working", not localdns.probe("127.0.0.1:9", timeout=1))

    m.seen = "dnscrypt-proxy"
    localdns._cache.clear()
    localdns._cache.update(resolver=None, checked=time.time() + 10**6)
    orig = localdns.get
    localdns.get = lambda force=False: {"resolver": None, "leak_risk": []}
    m.tick()
    localdns.get = orig
    check("dnscrypt-proxy stopping is reported (and not restarted)",
          said(c, "dnscrypt-proxy stopped", "WARNING") and said(c, "doesn't restart it"))

    print("== Audit: encrypted DNS check is read-only")
    r = audit.check_local_dns(leaky)[0]
    check("leak risk: WARN with the user's own command", r.status == "WARN"
          and "Your call" in r.fix)
    check("all through dnscrypt: PASS", audit.check_local_dns(good)[0].status == "PASS")
    check("no resolver: INFO only (your DNS choice)",
          audit.check_local_dns({"resolver": None})[0].status == "INFO")


# ------------------------------------------------------------------ HSTS --
INC = "const PRTime x = 1;\n%%\nexample-bank.com, 1\nexact-only.org, 0\n" + \
    "".join(f"site{i}.example, 1\n" for i in range(12000)) + "%%\n"


def hsts_tests():
    print("== HSTS preload list")
    t = hsts.parse(INC)
    check("parses Mozilla's nsSTSPreloadList.inc", len(t) == 12002 and t["exact-only.org"] is False)
    check("include_subdomains entries cover subdomains",
          hsts.preloaded("login.example-bank.com", t) and hsts.preloaded("example-bank.com", t))
    check("exact-only entries don't", hsts.preloaded("exact-only.org", t)
          and not hsts.preloaded("www.exact-only.org", t))
    check("unlisted sites aren't", not hsts.preloaded("neverssl.com", t))
    try:
        hsts.update(fetch=lambda url: "%%\nfoo.com, 1\n%%\n")
        short = False
    except OSError:
        short = True
    check("a truncated download is refused (keeps the old list)", short)
    seen = []

    def fetch(url):
        seen.append(url)
        if "hg.mozilla.org" in url:
            raise OSError("unreachable")
        return INC
    check("update falls back to the second source and stores the list",
          hsts.update(fetch=fetch) == 12002 and len(seen) == 2 and hsts.path().exists())
    check("stored list reloads", hsts.preloaded("a.example-bank.com"))
    c = ctx()
    s = StripMonitor(c)
    check("guard upgrades a preloaded site never visited before",
          s.verdict("GET", "www.example-bank.com", "/", FF)[0] == "upgrade")
    c.cfg["strip"]["hsts_preload"] = False
    check("strip.hsts_preload false: only the built-in list",
          StripMonitor(c).verdict("GET", "www.example-bank.com", "/", FF)[0] == "pass")
    os.utime(hsts.path(), (time.time() - 8 * 86400,) * 2)
    calls = []
    orig = hsts.update
    hsts.update = lambda fetch=None: calls.append(1) or 5
    check("weekly refresh when older than 7 days", hsts.refresh_if_old() and calls)
    check("...and at most every 6 hours if it keeps failing", not hsts.refresh_if_old())
    hsts.update = orig
    hsts.path().unlink()
    hsts._table = None


# ----------------------------------------------------- networks, pinning --
def network_tests():
    print("== Home and public networks")
    cfg = load_config("/nonexistent")
    c = ctx(cfg, label="Cafe")
    verified(c)
    run = FakeRun(wifi="yes::eth0\nno:WPA2:eth0")
    p = Protector(c, run=run, sync=True)
    p.state.pop("llmnr", None); p.state.pop("redirects", None)
    p.state.pop("redirects_how", None)
    check("open Wi-Fi counts as public", p.network_kind() == ("public", "open Wi-Fi"))
    p.apply_network_kind()
    check("public: ICMP redirects ignored before any attack",
          run.ran("sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0"))
    check("public: LLMNR off before any attack",
          run.ran("resolvectl", "llmnr", "eth0", "no"))
    check("...recorded as preventive", p.state["llmnr"]["preventive"]
          and p.state["redirects_how"]["preventive"])
    check("...without an alarming alert", not said(c, "Turned LLMNR off"))
    check("never a DNS server change", not run.ran("resolvectl", "dns")
          and not run.ran("nmcli", "connection", "modify"))
    p.base.set_kind("home")
    p.apply_network_kind()
    check("marked home: LLMNR and redirects put back",
          run.ran("resolvectl", "llmnr", "eth0", "yes") and "llmnr" not in p.state
          and "redirects" not in p.state)
    p.base.set_kind("public")
    p.apply_network_kind()
    p.llmnr_off()                       # then Responder shows up
    p.base.set_kind("home")
    p.apply_network_kind()
    check("after a real attack it stays off, even at home",
          "llmnr" in p.state and not p.state["llmnr"]["preventive"])
    p.llmnr_restore(); p.redirects_restore()
    c2 = ctx(cfg, label="Office")
    p2 = Protector(c2, run=FakeRun(wifi="yes:WPA2:eth0"), sync=True)
    check("WPA2 and not marked: no preventive change",
          p2.network_kind() == (None, "not marked") and p2.apply_network_kind() is None)
    check("wifi_open parser", baseline.wifi_open("eth0", lambda cmd: (0, "yes:--:eth0"))
          and not baseline.wifi_open("eth0", lambda cmd: (0, "yes:WPA3:eth0")))
    b = baseline.get(c)
    b.pin_device("192.168.1.20", "bb:bb:bb:bb:bb:20")
    baseline.reset(b.key)
    kept = core.load_state("networks")[b.key]
    check("baseline --reset keeps the home/public mark and pinned devices",
          kept.get("kind") == "home" and "192.168.1.20" in kept.get("pinned", {}))

    print("== Pinned devices (NAS, printer) and the IPv6 router")
    c = ctx(cfg, label="pins")
    verified(c)
    run = FakeRun()
    run.neigh["192.168.1.20"] = "bb:bb:bb:bb:bb:20"
    p = Protector(c, run=run, sync=True)
    c.protect = p
    check("pin a device with the MAC it has now",
          p.pin_device("192.168.1.20") == "bb:bb:bb:bb:bb:20"
          and run.ran("ip", "neigh", "replace", "192.168.1.20", "bb:bb:bb:bb:bb:20"))
    try:
        p.pin_device("192.168.1.21")
        nomac = False
    except ValueError:
        nomac = True
    check("no MAC known: refused with a hint", nomac)
    run.neigh["10.0.0.5"] = GW_MAC
    try:
        p.pin_device("10.0.0.5")
        gwmac = False
    except ValueError:
        gwmac = True
    check("refuses to pin a device to the router's MAC", gwmac)
    arp = ARPMonitor(c)
    arp.observe("192.168.1.20", ATT_MAC)
    check("someone else claiming the pinned device: CRITICAL",
          said(c, "DEVICE SPOOFING", "CRITICAL"))
    check("...isolated and re-pinned", ATT_MAC in p.state["blocked"]
          and len(run.ran("ip", "neigh", "replace", "192.168.1.20")) >= 2)
    check("...the binding stays on the real device",
          arp.bindings["192.168.1.20"] == "bb:bb:bb:bb:bb:20")
    p.unpin_device("192.168.1.20")
    check("unpin removes it", "192.168.1.20" not in baseline.get(c).pinned()
          and run.ran("ip", "neigh", "del", "192.168.1.20"))
    v6 = IPv6Monitor(c)
    v6.router_advert("fe80::1", GW_MAC)
    check("verified IPv6 router pinned",
          run.ran("ip", "neigh", "replace", "fe80::1", GW_MAC, "permanent")
          and p.state["pin6"]["ip"] == "fe80::1")
    check("...with an INFO note and an undo", said(c, "Pinned IPv6 router", "INFO"))
    p.unpin()
    check("--unpin removes the IPv6 pin too", "pin6" not in p.state
          and run.ran("ip", "-6", "neigh", "del", "fe80::1"))
    c3 = ctx(cfg, label="unverified")
    p3 = Protector(c3, run=FakeRun(), sync=True)
    check("no IPv6 pin before the router is verified",
          not p3.pin_router6("fe80::1", GW_MAC))

    print("== Attacker IPs come from its MAC, never from addresses it claimed")
    c = ctx(cfg, label="macips")
    verified(c)
    run = FakeRun()
    p = Protector(c, run=run, sync=True)
    c.protect = p
    arp = ARPMonitor(c)
    arp.observe("192.168.1.30", "cc:cc:cc:cc:cc:30")      # an innocent PC
    arp.observe("192.168.1.66", ATT_MAC)                  # the attacker
    arp.observe("192.168.1.30", ATT_MAC)                  # attacker claims the PC
    check("own_ips: only the attacker's first-seen address",
          arp.own_ips(ATT_MAC) == ["192.168.1.66"])
    p.state["blocked_ips"] = {}
    arp.observe(GW, ATT_MAC, is_reply=True)               # gateway spoofing
    check("gateway spoofing blocks the attacker's own IP",
          "192.168.1.66" in p.state["blocked_ips"])
    check("...not the innocent PC it impersonated, not the router",
          "192.168.1.30" not in p.state["blocked_ips"] and GW not in p.state["blocked_ips"])

    print("== WPAD (proxy auto-config) pushers are blocked")
    check("WPAD URL host", _url_host("http://192.168.1.88/wpad.dat") == "192.168.1.88"
          and _url_host("http://wpad.corp/wpad.dat") is None)
    c = ctx(cfg, label="wpad")
    verified(c)
    p = Protector(c, run=FakeRun(), sync=True)
    c.protect = p
    p.state["blocked_ips"] = {}
    DHCPMonitor(c).observe(5, GW, GW_MAC, router=GW, wpad="http://192.168.1.88/wpad.dat")
    check("DHCP option 252 pointing at a LAN host: that host blocked",
          "192.168.1.88" in p.state["blocked_ips"])
    d = DNSMonitor(c)
    d.query(ME, 6000, 9, "wpad.lan.", GW)
    d.response(ME, 6000, 9, "wpad.lan.", GW, {"192.168.1.89"})
    check("a wpad DNS answer to a LAN host: blocked", "192.168.1.89" in p.state["blocked_ips"])
    d.query(ME, 6001, 10, "wpad.lan.", GW)
    d.response(ME, 6001, 10, "wpad.lan.", GW, {GW})
    check("the router itself is never blocked", GW not in p.state["blocked_ips"])
    c.cfg["protect"]["block_wpad"] = False
    p.respond("wpad", ips=["192.168.1.90"])
    check("protect.block_wpad false: alert only", "192.168.1.90" not in p.state["blocked_ips"])


# ------------------------------------------------------------- SMB, misc --
def option_tests():
    print("== Switching one response off undoes only what it did")
    cfg = load_config("/nonexistent")
    cfg["protect"]["enabled"] = True
    c = ctx(cfg, label="opts")
    verified(c)
    run = FakeRun()
    p = Protector(c, run=run, sync=True)
    p.state.update(pin={"ip": GW, "mac": GW_MAC, "iface": "eth0"},
                   pin6={"ip": "fe80::1", "mac": GW_MAC, "iface": "eth0"},
                   blocked={ATT_MAC: {"until": time.time() + 600}},
                   blocked_ips={"192.168.1.66": {"until": time.time() + 600}})
    p.disable_option("pin_router6")
    check("pin_router6 off: IPv6 pin gone, router pin and blocks kept",
          "pin6" not in p.state and p.state.get("pin") and p.state["blocked"]
          and run.ran("-6", "neigh", "del", "fe80::1"))
    p.disable_option("block_ips")
    check("block_ips off: IP blocks gone, MAC isolation kept",
          not p.state["blocked_ips"] and ATT_MAC in p.state["blocked"])
    p.disable_option("https_guard")
    p.disable_option("pin_gateway")
    check("pin_gateway off: router pin removed",
          "pin" not in p.state and run.ran("neigh", "del", GW))
    check("no response touched DNS settings",
          not [cm for cm, _ in run.cmds if cm[:2] in (["resolvectl", "dns"],
                                                      ["resolvectl", "domain"])
               or "dnscrypt-proxy" in " ".join(cm)])


def smb_tests():
    print("== SMB signing / NTLM relay audit")
    weak = {"client signing": "default", "ntlm auth": "ntlmv1-permitted",
            "client min protocol": "nt1", "server signing": "default",
            "server min protocol": "smb2_02"}
    r = audit.check_smb(weak, server=True, mounts="")
    check("weak Samba settings: WARN naming each", r[0].status == "WARN"
          and all(k in r[0].detail for k in ("client signing", "ntlm auth",
                                              "client min protocol", "server signing")))
    good = {"client signing": "required", "ntlm auth": "ntlmv2-only",
            "client min protocol": "smb2_02", "server signing": "mandatory",
            "server min protocol": "smb2_02"}
    check("hardened: PASS", audit.check_smb(good, server=True, mounts="")[0].status == "PASS")
    check("client only: server settings not judged",
          audit.check_smb(dict(good, **{"server signing": "default"}), server=False,
                          mounts="")[0].status == "PASS")
    m = audit.check_smb({}, server=False,
                        mounts="//nas/share /mnt/nas cifs rw,vers=1.0,sec=ntlm 0 0\n"
                               "//nas/b /mnt/b cifs rw,vers=3.1.1 0 0\n")
    check("SMB1/NTLMv1 mount: FAIL; unencrypted SMB3 mount: INFO",
          [x.status for x in m] == ["FAIL", "INFO"])
    conf = Path(tempfile.mkdtemp(), "smb.conf")
    original = "[global]\n   workgroup = WORKGROUP\n   client signing = auto\n[share]\n   path = /srv\n"
    conf.write_text(original)
    bak = audit.fix_smb(True, str(conf), vals=weak, server=True, validate=lambda: True)
    text = conf.read_text()
    check("--fix: backup written first", bak and Path(bak).read_text() == original)
    check("--fix: settings added to [global], old line commented",
          "client signing = required   # LANGuard" in text
          and "; client signing = auto   # replaced by LANGuard" in text
          and text.index("# LANGuard") < text.index("[share]"))
    conf.write_text(original)
    audit.fix_smb(True, str(conf), vals=weak, server=True, validate=lambda: False)
    check("--fix: rejected by testparm -> put back unchanged", conf.read_text() == original)
    conf.write_text(original)
    import builtins
    orig_input = builtins.input
    builtins.input = lambda prompt="": "n"
    audit.fix_smb(False, str(conf), vals=weak, server=True, validate=lambda: True)
    builtins.input = orig_input
    check("--fix without your yes: nothing changed", conf.read_text() == original)


def evidence_tests():
    print("== Evidence capture")
    now = [1000.0]
    ev = Evidence({"evidence": {"seconds": 60, "after": 5, "max_mb": 1}},
                  now=lambda: now[0])
    ev.feed(b"A" * 100, t=900)                  # too old: dropped
    ev.feed(b"B" * 100, t=990)
    ev.feed(b"C" * 100, t=1003)
    check("only CRITICAL alerts capture", not ev.on_alert("arp", "k", "WARNING", "x", {}, sync=True))
    check("a CRITICAL alert saves a capture",
          ev.on_alert("arp", "k", "CRITICAL", "GATEWAY SPOOFING", {}, sync=True))
    pcap = Path(ev.saved[-1])
    raw = pcap.read_bytes()
    magic, _, _, _, _, snap, link = struct.unpack("<IHHiIII", raw[:24])
    check("valid pcap (Ethernet), only packets in the window",
          magic == 0xa1b2c3d4 and link == 1 and raw.count(b"B" * 100) == 1
          and b"A" * 100 not in raw and raw.count(b"C" * 100) == 1)
    check("root-only files and folder", pcap.stat().st_mode & 0o077 == 0
          and pcap.parent.stat().st_mode & 0o077 == 0
          and pcap.with_suffix(".txt").stat().st_mode & 0o077 == 0)
    check("note has the alert", "GATEWAY SPOOFING" in pcap.with_suffix(".txt").read_text())
    check("at most one capture a minute",
          not ev.on_alert("arp", "k2", "CRITICAL", "again", {}, sync=True))
    for i in range(3):
        now[0] += 120
        for _ in range(7):
            ev.feed(b"Z" * 60000, t=now[0])
        ev.on_alert(f"m{i}", "k", "CRITICAL", "big", {}, sync=True)
    total = sum(p.stat().st_size for p in pcap.parent.glob("*.pcap"))
    check("oldest captures deleted beyond max_mb", total <= 1024 * 1024
          and not pcap.exists())
    a = Alerter(cooldown=0)
    got = []
    a.hooks.append(lambda *x: got.append(x))
    a.hooks.append(lambda *x: 1 / 0)            # a broken hook can't break alerts
    a("arp", "k", "CRITICAL", "msg", ip="1.2.3.4")
    check("Alerter hooks get every alert (and survive errors)",
          got and got[0][:4] == ("arp", "k", "CRITICAL", "msg") and got[0][4] == {"ip": "1.2.3.4"})


def selftest_tests():
    print("== languard selftest")
    from languard_core import selftest
    out = []
    before = core.STATE_DIR
    selftest.main(load_config("/nonexistent"), out=out.append)
    sim = out[out.index("== Simulated attacks (nothing is sent or changed)"):]
    check("every simulated attack passes (environment lines depend on the "
          "machine)", len([l for l in sim if "[PASS]" in l]) >= 20
          and not any("[FAIL]" in l for l in sim))
    check("includes the DNS-settings guarantee",
          any("No response changed DNS" in l and "[PASS]" in l for l in out))
    check("state dir put back afterwards", core.STATE_DIR == before)


localdns_tests()
hsts_tests()
network_tests()
option_tests()
smb_tests()
evidence_tests()
selftest_tests()
print(f"\n{'ALL PASSED' if not fails else f'{fails} FAILED'}")
sys.exit(fails)
