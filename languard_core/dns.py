"""
DNS spoofing detection.

Tracks this machine's DNS queries and checks the replies:
  * a reply from a different IP than the one queried
  * two replies to the same query with different answers (spoofing race)
  * a reply nobody asked for
  * a public domain resolving to a private LAN address (attacker's box)
  * an answer from a resolver behind your router that did not come from your
    router's (verified) MAC: someone on the LAN forged it

When you run an encrypted resolver of your own (dnscrypt-proxy, see
localdns.py), this machine should send no plain DNS at all, so a plain query
leaving it is a leak: its answer can be read and forged on the LAN. Leaks are
reported with how to close them; LANGuard never changes DNS settings.
Queries dnscrypt-proxy itself makes to its bootstrap resolvers, local names
(.lan, .local, ...) and servers in dns.plain_ok are not leaks.

Confirmed forgeries go to active protection (dns_spoof / dns_race): the DNS
cache is flushed, the forged addresses are blocked and connections to them
ended, and the sender's MAC is isolated.
"""

import ipaddress
import time

from . import baseline, localdns
from .core import Module


class DNSMonitor(Module):
    name = "dns"
    bpf = "udp port 53"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.pending = {}     # (client_ip, client_port, id) -> query record
        self.my_ips6 = _my_ipv6(ctx.iface)
        self.base = baseline.get(ctx)
        self._leaks = {}      # server -> last leak alert

    def _expire(self, now):
        w = self.cfg["window"]
        for k in [k for k, q in self.pending.items() if now - q["t"] > w]:
            del self.pending[k]

    # ---- pure logic ----
    def query(self, client_ip, client_port, qid, qname, server, now=None):
        now = now or time.time()
        self._expire(now)
        self.pending[(client_ip, client_port, qid)] = {
            "t": now, "qname": qname, "server": server, "answers": None}
        if client_ip == self.ctx.my_ip or client_ip in self.my_ips6:
            self.leak(qname, server, now)

    def leak(self, qname, server, now=None):
        """A plain query left this machine while an encrypted resolver runs.
        Returns True if it was reported as a leak."""
        info = getattr(self.ctx, "local_dns", None) or localdns.get()
        if not info.get("resolver") or localdns.is_loopback(server):
            return False
        name = (qname or "").rstrip(".").lower()
        if not name or "." not in name or \
                any(name.endswith(x) for x in self.cfg["internal_suffixes"]):
            return False                 # local names: meant for the LAN
        if server in info.get("bootstrap", []) or \
                server in (self.cfg.get("plain_ok") or []):
            return False
        now = now or time.time()
        last = self._leaks.get(server)
        if last is not None and now - last < 3600:
            return False
        self._leaks[server] = now
        self.alert(f"leak:{server}", "WARNING",
                   f"DNS LEAK: {name} was looked up in plain text at {server}, "
                   f"bypassing {info.get('label')}. Anyone in the middle can "
                   f"read and forge this answer. LANGuard doesn't change DNS "
                   f"settings; {localdns.advice(info, getattr(self.ctx, 'net_label', None))}"
                   f". If an app uses its own DNS on purpose, add {server} to "
                   f"dns.plain_ok", qname=name, server=server)
        return True

    def _via_router(self, server):
        """Replies from this resolver must arrive from the router's MAC."""
        if server == self.ctx.gateway:
            return True
        try:
            a = ipaddress.ip_address(server)
            return a.version == 4 and not (self.ctx.network and a in self.ctx.network)
        except ValueError:
            return False

    def response(self, client_ip, client_port, qid, qname, src, answers,
                 now=None, mac=None):
        """Inspect a reply. Returns True if suspicious."""
        now = now or time.time()
        self._expire(now)
        answers = frozenset(answers)
        q = self.pending.get((client_ip, client_port, qid))
        bad = False

        if q is None:
            if client_ip == self.ctx.my_ip or client_ip in self.my_ips6:
                bad = True
                self.alert(f"unsolicited:{qname}", "WARNING",
                           f"Unsolicited DNS reply from {src} for {qname} -> "
                           f"{_fmt(answers)}", qname=qname, src=src)
        else:
            forged = False
            if src != q["server"]:
                bad = forged = True
                self.alert(f"src:{qname}:{src}", "CRITICAL",
                           f"DNS SPOOFING: reply for {qname} came from {src}, "
                           f"but the query went to {q['server']}",
                           qname=qname, src=src, expected=q["server"])
            mac = (mac or "").lower()
            if mac and self.base.gw_verified and mac != self.base.gw_mac \
                    and self._via_router(q["server"]):
                bad = forged = True
                self.alert(f"mac:{qname}:{mac}", "CRITICAL",
                           f"DNS SPOOFING: the reply for {qname} "
                           f"({_fmt(answers)}) claims to be from {src} but was "
                           f"sent by {mac}, not your router "
                           f"({self.base.gw_mac})", qname=qname, mac=mac)
            if forged:
                self.respond("dns_spoof", mac=mac or None, qname=qname,
                             answers=sorted(answers))
            elif q["answers"] is not None and answers != q["answers"]:
                bad = True
                self.alert(f"race:{qname}", "CRITICAL",
                           f"DNS SPOOFING: conflicting replies for {qname}: "
                           f"{_fmt(q['answers'])} vs {_fmt(answers)}",
                           qname=qname)
                self.respond("dns_race", qname=qname,
                             answers=sorted(q["answers"] | answers))
            q["answers"] = q["answers"] if q["answers"] is not None else answers

        if qname and qname.lower().startswith("wpad.") and answers:
            bad = True
            self.alert(f"wpad:{qname}", "WARNING",
                       f"Someone answered a WPAD lookup ({qname} -> "
                       f"{_fmt(answers)}): a proxy auto-config attack can "
                       f"route your web traffic through that host",
                       qname=qname)
            self.respond("wpad", ips=sorted(answers), source="DNS")

        if self.cfg.get("alert_private_answers") and qname:
            name = qname.rstrip(".").lower()
            internal = any(name.endswith(s) for s in self.cfg["internal_suffixes"]) \
                or "." not in name
            private = [a for a in answers if _is_private(a)]
            if private and not internal:
                bad = True
                self.alert(f"private:{name}", "WARNING",
                           f"{name} resolved to private address "
                           f"{', '.join(sorted(private))} (redirect to a LAN "
                           f"host? fine if it's your own local server)",
                           qname=name)
        return bad

    # ---- scapy glue ----
    def handle(self, pkt):
        from scapy.all import DNS, IP, UDP, Ether, IPv6
        if not (pkt.haslayer(DNS) and pkt.haslayer(UDP)):
            return
        # DNS over IPv6 too: mitm6 moves your DNS to an IPv6 server.
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6] if pkt.haslayer(IPv6) else None
        if ip is None:
            return
        d, udp = pkt[DNS], pkt[UDP]
        qname = _qname(d)
        if d.qr == 0 and udp.dport == 53:
            self.query(ip.src, udp.sport, d.id, qname, ip.dst)
        elif d.qr == 1 and udp.sport == 53:
            mac = pkt[Ether].src if pkt.haslayer(Ether) else None
            self.response(ip.dst, udp.dport, d.id, qname, ip.src, _answers(d),
                          mac=mac)


def _qname(d):
    """The question's name; '' for a missing or malformed question (crafted
    packets must not crash the detector)."""
    q = d.qd
    if isinstance(q, list):                 # newer scapy: a list of DNSQR
        q = q[0] if q else None
    name = getattr(q, "qname", b"") if q else b""
    return name.decode(errors="ignore") if isinstance(name, bytes) else str(name or "")


def _answers(d):
    rrs = d.an
    if rrs is None:
        return set()
    if not isinstance(rrs, list):            # older scapy: chained layers
        chain, rr = [], rrs
        while rr is not None and hasattr(rr, "rrname"):
            chain.append(rr)
            rr = rr.payload if rr.payload else None
        rrs = chain
    out = set()
    for rr in rrs:
        if getattr(rr, "type", None) in (1, 28):      # A, AAAA
            v = getattr(rr, "rdata", None)
            if v is None:
                continue
            out.add(v.decode() if isinstance(v, bytes) else str(v))
    return out


def _my_ipv6(iface):
    """This machine's IPv6 addresses on iface (for 'unsolicited reply')."""
    out = set()
    try:
        with open("/proc/net/if_inet6") as f:
            for line in f:
                p = line.split()
                if len(p) >= 6 and p[5] == iface:
                    out.add(str(ipaddress.ip_address(int(p[0], 16))))
    except (OSError, ValueError):
        pass
    return out


def _is_private(addr):
    try:
        a = ipaddress.ip_address(addr)
        return a.is_private and not a.is_loopback
    except ValueError:
        return False


def _fmt(answers):
    return ", ".join(sorted(answers)) or "(no address)"
