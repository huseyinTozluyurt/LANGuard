#!/usr/bin/env python3
"""Simulated-attack tests for every detector. Run: python3 tests/test_detectors.py (no root, no scapy)."""
import ipaddress, sys, os
import tempfile; from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
STATE = tempfile.mkdtemp(prefix="languard-test-")
os.environ["LANGUARD_STATE"] = STATE
from languard_core import core
core.STATE_DIR = __import__("pathlib").Path(STATE)
core.setup_logging(None)
from languard_core.core import Alerter, load_config

cfg = load_config("/nonexistent")
class Ctx:
    pass
def ctx():
    c = Ctx(); c.cfg = cfg; c.alert = Alerter(cooldown=60)
    c.iface = "eth0"; c.gateway = "192.168.1.1"; c.my_ip = "192.168.1.50"
    c.my_mac = "02:00:00:00:00:50"; c.network = ipaddress.ip_network("192.168.1.0/24")
    return c

fails = 0
def check(name, cond):
    global fails
    print(("  ok  " if cond else "  FAIL ") + name); fails += not cond

print("== ARP")
from languard_core.arp import ARPMonitor
c = ctx(); a = ARPMonitor(c); a.seed({"192.168.1.1": "aa:aa:aa:aa:aa:aa"})
check("normal traffic is quiet", not a.observe("192.168.1.10", "bb:bb:bb:bb:bb:bb", True))
check("gateway spoof is CRITICAL", a.observe("192.168.1.1", "cc:cc:cc:cc:cc:cc", True) and c.alert.history[-1][1] == "CRITICAL")
check("forged frame flagged", a.observe("192.168.1.11", "dd:dd:dd:dd:dd:01", eth_src="ee:ee:ee:ee:ee:ee"))
for i in range(20, 24): a.observe(f"192.168.1.{i}", "dd:dd:dd:dd:dd:dd")
check("one MAC many IPs", any("claims" in h[2] for h in c.alert.history))
t = 1000.0
for i in range(30): a.observe("192.168.1.60", "ff:00:00:00:00:01", True, now=t + i * 0.1)
check("reply flood", any("flood" in h[2] for h in c.alert.history))
check("probe conflict", a.conflict("192.168.1.1", ["aa:aa:aa:aa:aa:aa", "cc:cc:cc:cc:cc:cc"]))
check("cooldown suppresses repeats", not c.alert("arp", "gw:cc:cc:cc:cc:cc:cc", "CRITICAL", "x"))

print("== Devices")
from languard_core.devices import DeviceMonitor
c = ctx(); d = DeviceMonitor(c, learning=True)
d.observe("10:10:10:10:10:10", "192.168.1.2", "laptop"); d.flush()
check("learning mode is silent", not c.alert.history)
d2 = DeviceMonitor(c)
check("known device silent", not d2.observe("10:10:10:10:10:10", "192.168.1.2"))
check("unknown device flagged", d2.observe("66:77:88:99:aa:bb", "192.168.1.99", "kali"))
check("randomized MAC noted", "randomized" in core.vendor("da:11:22:33:44:55"))
check("off-subnet IP ignored", d2.db.get("66:77:88:99:aa:bb") and DeviceMonitor(c).observe("12:12:12:12:12:12", "8.8.8.8") and "8.8.8.8" not in d2.db.get("12:12:12:12:12:12", {"ips": []})["ips"])

print("== DHCP")
from languard_core.dhcp import DHCPMonitor
c = ctx(); h = DHCPMonitor(c)
check("router's offer is fine", not h.observe(2, "192.168.1.1", "aa:aa:aa:aa:aa:aa", "192.168.1.1", "192.168.1.1"))
check("rogue server CRITICAL", h.observe(2, "192.168.1.66", "66:66:66:66:66:66", "192.168.1.66", "192.168.1.66"))
check("fake gateway flagged", any("pushes gateway" in x[2] for x in c.alert.history))
check("client requests ignored", not h.observe(3, "192.168.1.66", "x", None))

print("== DNS")
from languard_core.dns import DNSMonitor
c = ctx(); n = DNSMonitor(c); t = 5000.0
n.query("192.168.1.50", 40000, 1, "example.com.", "192.168.1.1", now=t)
check("legit reply quiet", not n.response("192.168.1.50", 40000, 1, "example.com.", "192.168.1.1", {"93.184.216.34"}, now=t + .1))
check("conflicting reply CRITICAL", n.response("192.168.1.50", 40000, 1, "example.com.", "192.168.1.1", {"6.6.6.6"}, now=t + .2))
n.query("192.168.1.50", 40001, 2, "bank.com.", "192.168.1.1", now=t)
check("wrong source CRITICAL", n.response("192.168.1.50", 40001, 2, "bank.com.", "192.168.1.66", {"1.2.3.4"}, now=t + .1))
check("unsolicited flagged", n.response("192.168.1.50", 40002, 9, "x.com.", "192.168.1.1", {"1.1.1.1"}, now=t + .3))
n.query("192.168.1.50", 40003, 3, "google.com.", "192.168.1.1", now=t)
check("public name -> LAN IP flagged", n.response("192.168.1.50", 40003, 3, "google.com.", "192.168.1.1", {"192.168.1.66"}, now=t + .1))
n.query("192.168.1.50", 40004, 4, "nas.local.", "192.168.1.1", now=t)
check(".local -> LAN IP fine", not n.response("192.168.1.50", 40004, 4, "nas.local.", "192.168.1.1", {"192.168.1.5"}, now=t + .1))
check("expired query becomes unsolicited", n.response("192.168.1.50", 40004, 4, "nas.local.", "192.168.1.1", {"192.168.1.5"}, now=t + 60))

print("== Scan")
from languard_core.scan import ScanMonitor, SYN, FIN, PSH, URG, ACK
c = ctx(); s = ScanMonitor(c); t = 9000.0
check("bpf scoped to this host", s.bpf == "tcp and dst host 192.168.1.50")
check("single connection quiet", not s.observe("192.168.1.8", 443, SYN, now=t))
for p in range(1, 20): s.observe("192.168.1.66", p, SYN, now=t + p * .01)
check("SYN port scan", any("Port scan" in x[2] for x in c.alert.history))
check("XMAS scan", s.observe("192.168.1.67", 80, FIN | PSH | URG, now=t))
check("NULL scan", s.observe("192.168.1.68", 80, 0, now=t))
check("normal ACK quiet", not s.observe("192.168.1.69", 80, ACK, now=t))
for i in range(25): s.observe("192.168.1.70", 22, SYN, now=t + i * .2)
check("SSH brute force CRITICAL", any("brute force" in x[2] and x[1] == "CRITICAL" for x in c.alert.history))
check("slow connects stay quiet", not any(s.observe("192.168.1.71", 22, SYN, now=t + i * 5) for i in range(25)))

print("== Wi-Fi")
from languard_core.wifi import WifiMonitor
c = ctx(); cfg["wifi"]["ssids"] = ["HomeNet"]; w = WifiMonitor(c); t = 100.0
check("first AP learned", not w.beacon("HomeNet", "11:11:11:11:11:11", {"WPA2/PSK"}, 6, now=t))
check("open twin CRITICAL", w.beacon("HomeNet", "22:22:22:22:22:22", {"OPN"}, 6, now=t) and c.alert.history[-1][1] == "CRITICAL")
check("same-security extender only WARNING", not w.beacon("HomeNet", "33:33:33:33:33:33", {"WPA2/PSK"}, 11, now=t))
check("other SSIDs ignored", not w.beacon("Neighbor", "44:44:44:44:44:44", {"OPN"}, 1, now=t))
for i in range(25): w.deauth("66:66:66:66:66:66", "aa:bb:cc:dd:ee:ff", "11:11:11:11:11:11", now=t + i * .1)
check("deauth flood", any("DEAUTH FLOOD" in x[2] for x in c.alert.history))
c = ctx(); cfg["wifi"]["trusted_bssids"] = ["11:11:11:11:11:11"]; w = WifiMonitor(c)
check("trusted BSSID quiet", not w.beacon("HomeNet", "11:11:11:11:11:11", {"WPA2/PSK"}, 6))
check("untrusted BSSID = evil twin", w.beacon("HomeNet", "55:55:55:55:55:55", {"WPA2/PSK"}, 6))

print("== Audit parsers")
from languard_core import audit
ss = ('tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
      'tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:* users:(("cupsd",pid=2,fd=7))\n'
      'udp UNCONN 0 0 [::]:5353 [::]:* users:(("avahi-daemon",pid=3,fd=12))')
r = audit.check_listening(parse=ss)[0]
check("exposed sshd + avahi found, localhost cups ignored", "22 (sshd)" in r.detail and "avahi" in r.detail and "631" not in r.detail)
vals = {"net.ipv4.conf.all.accept_redirects": "1", "net.ipv4.conf.all.rp_filter": "2", "net.ipv4.ip_forward": "1"}
r = audit.check_sysctl(lambda k: vals.get(k, dict((a, b) for a, b, _ in audit.SYSCTLS).get(k)))
check("bad sysctl caught, rp_filter=2 accepted", r[0].status == "FAIL" and "accept_redirects" in r[0].detail and "rp_filter" not in r[0].detail)
check("ip_forward warned", any(x.check == "IP forwarding" for x in r))

print("== Regressions from a real Ubuntu run")
c = ctx(); c.my_mac = "74:4c:a1:a8:ce:81"; dm = DeviceMonitor(c)
check("own machine is never an unknown device", not dm.observe("74:4c:a1:a8:ce:81", "192.168.1.5") and not c.alert.history)
real_ss = ('udp UNCONN 0 0 0.0.0.0:44189 0.0.0.0:* users:(("avahi-daemon",pid=1,fd=14))\n'
           'udp UNCONN 0 0 0.0.0.0:46840 0.0.0.0:* users:(("firefox",pid=2,fd=90))\n'
           'udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("avahi-daemon",pid=1,fd=12))\n'
           'tcp LISTEN 0 151 127.0.0.1:3306 0.0.0.0:* users:(("mysqld",pid=3,fd=21))\n'
           'tcp LISTEN 0 511 127.0.0.1:80 0.0.0.0:* users:(("apache2",pid=4,fd=3))\n'
           'tcp LISTEN 0 200 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=5,fd=6))')
r = audit.check_listening(parse=real_ss)[0]
check("ephemeral UDP client sockets ignored, mDNS 5353 kept", "5353" in r.detail and "firefox" not in r.detail and "44189" not in r.detail)
exp = audit.exposed_sockets(parse=real_ss)
r = audit.check_services(active={"apache2", "mysql", "postgresql", "avahi-daemon", "cups-browsed"}, exposed=exp)
warn = [x for x in r if x.status == "WARN"][0].detail
ok = [x for x in r if x.check == "Local-only services"][0].detail
check("localhost-only apache/mysql/postgres not warned", "apache2" not in warn and "mysql" in ok and "postgresql" in ok)
check("avahi (exposed) and cups-browsed still warned", "avahi-daemon" in warn and "cups-browsed" in warn)

print(f"\n{'ALL PASSED' if not fails else f'{fails} FAILED'}")
sys.exit(fails)
