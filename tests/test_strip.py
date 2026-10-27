#!/usr/bin/env python3
"""Tests for SSL-stripping detection (strip.py), the on-demand and learned
TLS probes and captive-portal handling (tls.py).
Run: python3 tests/test_strip.py   (no root; the packet part needs scapy)"""

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
from languard_core.strip import (StripMonitor, parse_http_request,  # noqa: E402
                                 parse_sni)
from languard_core.tls import TLSMonitor             # noqa: E402

core.setup_logging(None)
fails = 0
ME_IP = "192.168.1.50"
FF = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"


class Ctx:
    pass


def ctx():
    c = Ctx()
    c.cfg = load_config("/nonexistent")
    c.alert = Alerter(cooldown=0)
    c.iface, c.gateway, c.my_ip, c.my_mac = "eth0", "192.168.1.1", ME_IP, "02:00:00:00:00:50"
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


def client_hello(host):
    """A minimal TLS 1.2 ClientHello record carrying an SNI extension."""
    name = host.encode()
    sni = (b"\x00\x00" + (len(name) + 5).to_bytes(2, "big") +
           (len(name) + 3).to_bytes(2, "big") + b"\x00" +
           len(name).to_bytes(2, "big") + name)
    exts = len(sni).to_bytes(2, "big") + sni
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01" +
            b"\x01\x00" + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def http_get(host, method="GET", path="/", ua=FF):
    return (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
            f"Accept: */*\r\n\r\n").encode()


print("== Parsers")
check("SNI read from a ClientHello", parse_sni(client_hello("Bank.Example.com")) == "bank.example.com")
check("garbage is not a ClientHello", parse_sni(b"\x16\x03\x01\x00") is None and parse_sni(b"GET /") is None)
check("HTTP request parsed (method, host without port, path, UA)",
      parse_http_request(http_get("shop.example.com:8080", "POST", "/login")) ==
      ("POST", "shop.example.com", "/login", FF))
check("non-HTTP payload ignored", parse_http_request(b"\x00\x01binary") is None)

print("== Stripping of sites you use over HTTPS")
T = 1_000_000.0
c = ctx(); s = StripMonitor(c)
s.https_seen("bank.example.com", "203.0.113.10", now=T)
# Normal browsing: http link, server redirects, browser opens HTTPS at once.
s.http_request("GET", "bank.example.com", ip="203.0.113.10", ua=FF, now=T + 400)
s.https_seen("bank.example.com", "203.0.113.10", now=T + 400.3)
s.tick_expire(); s._expire(T + 420)
check("http -> https redirect followed: quiet", not c.alert.history)
# Stripped: the browser keeps talking plain HTTP, no HTTPS handshake follows.
s.http_request("GET", "bank.example.com", ip="203.0.113.10", ua=FF, now=T + 1000)
s._expire(T + 1003)
check("still inside the upgrade window: quiet", not c.alert.history)
s._expire(T + 1010)
check("no HTTPS after the plain-HTTP request = SSL STRIPPING (CRITICAL)",
      said(c, "SSL STRIPPING", "CRITICAL") and said(c, "bank.example.com"))

c = ctx(); s = StripMonitor(c)
s.https_seen("bank.example.com", now=T)
check("plain-HTTP POST (login form) to an HTTPS site flagged at once",
      s.http_request("POST", "bank.example.com", "/login", ua=FF, now=T + 900)
      and said(c, "POST", "CRITICAL"))

c = ctx(); s = StripMonitor(c)
s.https_seen("mail.example.org", "198.51.100.7", now=T)
s.http_request("GET", "mail.example.org", ip="198.51.100.7", ua=FF, now=T + 30)
s._expire(T + 60)
check("pooled HTTPS connection reused for the redirect: one request is quiet", not c.alert.history)
for i in range(3):
    s.http_request("GET", "mail.example.org", f"/static/{i}.js", ua=FF, now=T + 61 + i)
check("...but a page loading over plain HTTP is flagged", said(c, "SSL STRIPPING", "CRITICAL"))

c = ctx(); s = StripMonitor(c)
s.http_request("GET", "accounts.google.com", ua=FF, now=T)
s._expire(T + 10)
check("HSTS-preloaded site never seen before: stripping still caught", said(c, "accounts.google.com", "CRITICAL"))

c = ctx(); s = StripMonitor(c)
s.https_seen("www.github.com", "140.82.121.4", now=T)
s.http_request("GET", "www.github.com", ip="140.82.121.4", ua=FF, now=T + 400)
s.https_seen(None, "140.82.121.4", now=T + 400.2)       # QUIC/HTTP3, no SNI to read
s._expire(T + 410)
check("upgrade over QUIC to the same IP counts as HTTPS", not c.alert.history)

print("== Look-alike hosts (sslstrip2 / hstshijack)")
c = ctx(); s = StripMonitor(c)
s.https_seen("webmail.example.com", now=T)
check("google.corn imitating google.com is CRITICAL",
      s.http_request("GET", "google.corn", ua=FF, now=T + 1) and said(c, "look-alike of 'google.com'", "CRITICAL"))
check("wwebmail.example.com flagged (same domain: WARNING)",
      s.http_request("GET", "wwebmail.example.com", ua=FF, now=T + 2) and said(c, "wwebmail", "WARNING"))
s.https_seen("cdn1.example.net", now=T)
check("cdn2 vs cdn1 (numbering) is not a look-alike", not s.http_request("GET", "cdn2.example.net", ua=FF, now=T + 3))

print("== No false alarms from normal plain HTTP")
c = ctx(); s = StripMonitor(c)
s.https_seen("www.microsoft.com", now=T)
check("apt / updaters (non-browser User-Agent) ignored",
      not s.http_request("GET", "accounts.google.com", ua="Debian APT-HTTP/1.3 (2.4.11)", now=T + 400))
check("certificate revocation (CRL/OCSP) over HTTP ignored",
      not s.http_request("GET", "www.microsoft.com", "/pkiops/crl/Microsoft.crl", ua=FF, now=T + 400))
check("plain-HTTP site never used over HTTPS ignored",
      not s.http_request("GET", "neverssl.com", ua=FF, now=T + 400))
check("bare IP addresses ignored", not s.http_request("GET", "192.168.1.1", ua=FF, now=T + 400))
s._expire(T + 500)
check("none of those raised anything", not c.alert.history)

print("== Captive portals")
c = ctx(); c.captive_portal = True; s = StripMonitor(c)
s.http_request("POST", "accounts.google.com", ua=FF, now=T)
check("during a captive portal, findings are INFO",
      said(c, "captive portal active", "INFO") and not said(c, "STRIPPING", "CRITICAL"))

state = {"portal": True}
c = ctx()
tm = TLSMonitor(c, fetch=lambda h: {"ok": False, "issuer": None, "error": "bad", "kind": "verify"},
                redirect=lambda h: False, portal=lambda: state["portal"])
tm.tick()
check("portal on joining: checks wait, nothing CRITICAL",
      c.captive_portal and said(c, "Captive portal detected", "INFO") and not said(c, "TLS INTERCEPTION"))
state["portal"] = False
tm.tick()
check("after login: portal cleared and checks run again",
      not c.captive_portal and said(c, "Captive portal gone") and said(c, "TLS INTERCEPTION", "CRITICAL"))
state["portal"] = True
c.alert.history.clear()
tm.tick()
check("portal appearing later on a working network: WARNING, checks keep running",
      not c.captive_portal and said(c, "faking a captive portal", "WARNING") and said(c, "TLS INTERCEPTION", "CRITICAL"))

c = ctx()
tm = TLSMonitor(c, fetch=lambda h: {"ok": True, "issuer": "X", "error": None, "kind": None},
                redirect=lambda h: True, portal=lambda: True)
tm.check_portal(now=T)
check("portal pause starts", c.captive_portal)
tm.check_portal(now=T + 21 * 60)
check("portal pause never lasts more than 20 min", not c.captive_portal and said(c, "after 20 min", "WARNING"))

print("== Strip and TLS work together")
c = ctx()
checked = []
tm = TLSMonitor(c, fetch=lambda h: checked.append(h) or {"ok": True, "issuer": "X", "error": None, "kind": None},
                redirect=lambda h: True, portal=lambda: False)
s = StripMonitor(c); s.start()
for h in ("bank.example.com", "mail.example.org"):
    s.https_seen(h, now=T)
check("your most-used HTTPS sites join the active probes",
      {"bank.example.com", "mail.example.org"} <= set(tm.sites()) and "github.com" in tm.sites())
s.http_request("POST", "bank.example.com", ua=FF, now=T + 900)
check("a stripping sign queues an immediate probe of that site", "bank.example.com" in tm.urgent)
tm.tick(regular=False)
check("urgent probe runs only the flagged site", checked == ["bank.example.com"])
tm.tick()
check("learned sites are probed without CA pinning", "bank.example.com" not in tm.issuers and "github.com" in tm.issuers)

print("== Learned hosts persist")
s.flush()
check("HTTPS hosts survive a restart", "bank.example.com" in StripMonitor(ctx()).secure)

try:
    from scapy.all import IP, TCP, Ether, raw
except ImportError:
    print("scapy not installed: packet tests skipped")
else:
    print("== Real packets through handle()")
    c = ctx(); s = StripMonitor(c)
    pkt = lambda p: Ether(raw(Ether() / p))
    s.handle(pkt(IP(src=ME_IP, dst="203.0.113.10") / TCP(sport=40000, dport=443, flags="PA") /
                 client_hello("bank.example.com")))
    check("ClientHello on the wire teaches the HTTPS host", "bank.example.com" in s.secure)
    s.handle(pkt(IP(src=ME_IP, dst="203.0.113.10") / TCP(sport=40001, dport=80, flags="PA") /
                 http_get("bank.example.com", "POST", "/login")))
    check("plain-HTTP POST on the wire flagged", said(c, "SSL STRIPPING", "CRITICAL"))
    try:
        from scapy.arch.common import compile_filter
        compile_filter(s.bpf)
        check("kernel filter (BPF) compiles", True)
    except ImportError:
        print("  (libpcap not available: BPF compile check skipped)")
    except Exception as e:
        check(f"kernel filter (BPF) compiles: {e}", False)

print(f"\n{'ALL PASSED' if not fails else f'{fails} FAILED'}")
sys.exit(fails)
