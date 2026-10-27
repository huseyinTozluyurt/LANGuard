#!/usr/bin/env python3
"""Packet-level tests: real attack packets built with scapy, fed through each
module's handle(), the code path the live service uses.
Run: python3 tests/test_packets.py   (needs python3-scapy, no root)"""

import ipaddress
import os
import sys
import tempfile
from pathlib import Path

STATE = tempfile.mkdtemp(prefix="languard-test-")
os.environ["LANGUARD_STATE"] = STATE
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from scapy.all import (ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, ICMP, IP, UDP,
                           Ether, IPv6, mac2str)
    from scapy.layers import dhcp6 as d6
    from scapy.layers import inet6 as i6
except ImportError:
    print("scapy not installed (sudo apt install python3-scapy): skipped")
    sys.exit(0)

from languard_core import core                       # noqa: E402
from languard_core.core import Alerter, load_config  # noqa: E402

core.setup_logging(None)
fails = 0
GW, GW_MAC, ME_IP, ME = "192.168.1.1", "aa:aa:aa:aa:aa:aa", "192.168.1.50", "02:00:00:00:00:50"
EVIL = "66:66:66:66:66:66"


class Ctx:
    pass


def ctx():
    c = Ctx()
    c.cfg = load_config("/nonexistent")
    c.alert = Alerter(cooldown=0)
    c.iface, c.gateway, c.my_ip, c.my_mac = "eth0", GW, ME_IP, ME
    c.network = ipaddress.ip_network("192.168.1.0/24")
    c.net_label, c.protect = "lab", None
    return c


def check(name, cond):
    global fails
    print(("  ok  " if cond else "  FAIL ") + name)
    fails += not cond


def said(c, text, level=None):
    return any(text in m and (level is None or lv == level)
               for _, lv, m in c.alert.history)


def roundtrip(p):
    """Serialize and re-parse, like a packet off the wire."""
    return Ether(bytes(p))


print("== ARP (arpspoof / bettercap)")
from languard_core.arp import ARPMonitor             # noqa: E402
c = ctx(); a = ARPMonitor(c); a.bindings.clear(); a.seed({GW: GW_MAC})
a.cfg["verify"] = False
a.handle(roundtrip(Ether(src=EVIL, dst=ME) / ARP(op=2, hwsrc=EVIL, psrc=GW, hwdst=ME, pdst=ME_IP)))
check("arpspoof reply for the gateway is CRITICAL", said(c, "GATEWAY SPOOFING", "CRITICAL"))
a.handle(roundtrip(Ether(src="ee:ee:ee:ee:ee:ee", dst=ME) / ARP(op=2, hwsrc="dd:dd:dd:dd:dd:dd", psrc="192.168.1.9")))
check("Ethernet/ARP sender mismatch", said(c, "Forged-looking ARP"))
for _ in range(31):
    a.handle(roundtrip(Ether(src="80:80:80:80:80:80", dst="ff:ff:ff:ff:ff:ff") /
                       ARP(op=1, hwsrc="80:80:80:80:80:80", psrc="192.168.1.80", pdst="192.168.1.80")))
check("gratuitous ARP request flood", said(c, "ARP flood from 80:80"))

print("== DHCP (rogue server, yersinia starvation)")
from languard_core.dhcp import DHCPMonitor           # noqa: E402


def offer(src_mac, server, router, dns, client=ME, mt="ack"):
    return roundtrip(Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
                     IP(src=server, dst="255.255.255.255") / UDP(sport=67, dport=68) /
                     BOOTP(op=2, yiaddr="192.168.1.77", chaddr=mac2str(client)) /
                     DHCP(options=[("message-type", mt), ("server_id", server),
                                   ("router", router), ("name_server", *dns), "end"]))


c = ctx(); h = DHCPMonitor(c)
h.handle(offer(GW_MAC, GW, GW, ["192.168.1.1", "1.1.1.1"]))
check("real router quiet; both DNS servers learned",
      not c.alert.history and h.base.dns == ["1.1.1.1", "192.168.1.1"])
h.handle(offer("66:66:66:66:66:01", "192.168.1.66", "192.168.1.66", ["192.168.1.66"]))
check("rogue DHCP server CRITICAL", said(c, "ROGUE DHCP SERVER: 192.168.1.66", "CRITICAL"))
h.handle(offer(EVIL, GW, GW, ["6.6.6.6"]))
check("rogue server spoofing the router's IP caught by MAC", said(c, "claiming to be the trusted server"))
for i in range(30):
    h.handle(roundtrip(Ether(src="11:22:33:44:55:66", dst="ff:ff:ff:ff:ff:ff") /
                       IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
                       BOOTP(chaddr=mac2str(f"de:ad:be:ef:00:{i:02x}")) /
                       DHCP(options=[("message-type", "discover"), "end"])))
check("starvation with spoofed chaddr from one sender", said(c, "DHCP STARVATION", "CRITICAL"))

print("== DNS spoofing")
from languard_core.dns import DNSMonitor             # noqa: E402
c = ctx(); n = DNSMonitor(c)
n.handle(roundtrip(Ether() / IP(src=ME_IP, dst=GW) / UDP(sport=40000, dport=53) /
                   DNS(id=7, rd=1, qd=DNSQR(qname="bank.com"))))
n.handle(roundtrip(Ether() / IP(src="192.168.1.66", dst=ME_IP) / UDP(sport=53, dport=40000) /
                   DNS(id=7, qr=1, qd=DNSQR(qname="bank.com"), an=DNSRR(rrname="bank.com", rdata="192.168.1.66"))))
check("reply from the wrong server CRITICAL", said(c, "DNS SPOOFING", "CRITICAL"))
check("public name to LAN IP flagged", said(c, "resolved to private address"))
c = ctx(); n = DNSMonitor(c)
n.handle(roundtrip(Ether() / IPv6(src="fe80::50", dst="fe80::1") / UDP(sport=40001, dport=53) /
                   DNS(id=9, rd=1, qd=DNSQR(qname="bank.com"))))
n.handle(roundtrip(Ether() / IPv6(src="fe80::66", dst="fe80::50") / UDP(sport=53, dport=40001) /
                   DNS(id=9, qr=1, qd=DNSQR(qname="bank.com"), an=DNSRR(rrname="bank.com", rdata="192.168.1.66"))))
check("DNS over IPv6 (mitm6's DNS) is inspected too", said(c, "DNS SPOOFING", "CRITICAL"))

print("== IPv6 (mitm6, rogue RA)")
from languard_core.ipv6 import IPv6Monitor          # noqa: E402
from languard_core import baseline                   # noqa: E402
c = ctx(); v = IPv6Monitor(c)
baseline.get(c).learn_gateway([[GW_MAC]] * 3)
ra = lambda mac, ip: roundtrip(Ether(src=mac) / IPv6(src=ip, dst="ff02::1") / i6.ICMPv6ND_RA(routerlifetime=1800) /
                               i6.ICMPv6NDOptSrcLLAddr(lladdr=mac) / i6.ICMPv6NDOptPrefixInfo(prefix="2001:db8::", prefixlen=64))
v.handle(ra(GW_MAC, "fe80::1"))
v.handle(ra(EVIL, "fe80::bad"))
check("rogue Router Advertisement CRITICAL", said(c, "ROGUE IPv6 ROUTER", "CRITICAL"))
v.handle(roundtrip(Ether(src="66:66:66:66:66:02", dst=ME) / IPv6(src="fe80::66", dst="fe80::50") /
                   UDP(sport=547, dport=546) / d6.DHCP6_Reply() / d6.DHCP6OptDNSServers(dnsservers=["fe80::66"])))
check("mitm6 DHCPv6 reply CRITICAL", said(c, "ROGUE DHCPv6 SERVER", "CRITICAL"))

print("== ICMP redirect")
from languard_core.mitm import MitmMonitor          # noqa: E402
c = ctx(); m = MitmMonitor(c)
m.handle(roundtrip(Ether(src=EVIL) / IP(src="192.168.1.66", dst=ME_IP) / ICMP(type=5, code=1, gw="192.168.1.66") /
                   IP(src=ME_IP, dst="8.8.8.8") / UDP()))
check("ICMP redirect CRITICAL", said(c, "ICMP REDIRECT", "CRITICAL"))

print(f"\n{'ALL PASSED' if not fails else f'{fails} FAILED'}")
sys.exit(fails)
