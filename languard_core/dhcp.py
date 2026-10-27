"""
Rogue DHCP server detection.

A rogue DHCP server can hand clients a fake gateway or DNS server and
silently man-in-the-middle the whole network. This watches DHCP offers/acks
and can actively probe with a DHCPDISCOVER to list every server that answers.

A server is trusted by IP *and* MAC: the IP in a DHCP reply is whatever the
sender writes, so a rogue server can claim to be the router. The DNS servers
the real server hands out are remembered per network, and a change is flagged.
Starvation is counted by the client MAC inside the DHCP packet (chaddr), which
is what tools like yersinia and dhcpstarv vary.
"""

import random
import time
from collections import deque

from . import baseline
from .core import Module, log

MSG_TYPES = {1: "discover", 2: "offer", 3: "request", 5: "ack", 6: "nak"}


class DHCPMonitor(Module):
    name = "dhcp"
    bpf = "udp and (port 67 or port 68)"

    def __init__(self, ctx):
        super().__init__(ctx)
        trusted = set(self.cfg.get("trusted_servers") or [])
        if not trusted and ctx.gateway:
            trusted = {ctx.gateway}
        self.trusted = trusted
        self.seen = {}                 # server_ip -> mac
        self.discovers = deque()       # (time, client_mac, eth_src)
        self.base = baseline.get(ctx)

    # ---- pure logic ----
    def discover(self, client_mac, now=None, eth_src=None):
        """DHCPDISCOVER seen. Many distinct client MACs fast = starvation.

        `client_mac` is the chaddr inside the packet; `eth_src` the frame's
        sender. One sender using many chaddrs is a starvation tool for sure."""
        now = now or time.time()
        c = self.cfg
        self.discovers.append((now, client_mac, eth_src or client_mac))
        while self.discovers and now - self.discovers[0][0] > c["starvation_window"]:
            self.discovers.popleft()
        macs = {m for _, m, _ in self.discovers}
        if len(macs) >= c["starvation_threshold"]:
            senders = {e for _, _, e in self.discovers}
            one = next(iter(senders)) if len(senders) == 1 else None
            self.alert("starvation", "CRITICAL",
                       f"DHCP STARVATION: {len(macs)} different MACs requested "
                       f"addresses in {c['starvation_window']}s"
                       f"{f', all sent by {one}' if one else ''}. Attackers "
                       f"exhaust the pool, then run a rogue DHCP server",
                       count=len(macs), sender=one)
            if one:
                self.respond("dhcp_starvation", mac=one)
            return True
        return False

    def observe(self, msg_type, server_ip, server_mac, router=None,
                dns=None, offered_ip=None, wpad=None, for_me=False):
        """Inspect one server reply. Returns True if it looks rogue.

        `dns` is a server or list of servers; `for_me` is True when the reply
        is addressed to this machine (so its lease may be affected)."""
        if msg_type not in (2, 5):
            return False
        if isinstance(dns, str):
            dns = [dns]
        dns = [d for d in (dns or []) if d]
        bad = False
        if wpad:
            bad = True
            self.alert(f"wpad:{server_ip}", "WARNING",
                       f"DHCP {MSG_TYPES[msg_type]} from {server_ip} pushes a "
                       f"WPAD proxy config ({wpad}): browsers may send all "
                       f"web traffic through it", wpad=str(wpad))
            host = _url_host(wpad)
            if host:
                self.respond("wpad", ips=[host], source="DHCP")
        self.seen[server_ip] = server_mac
        kind = MSG_TYPES[msg_type]
        dns_txt = ", ".join(dns) or None
        rogue = False
        if server_ip not in self.trusted:
            rogue = True
            self.alert(f"rogue:{server_ip}", "CRITICAL",
                       f"ROGUE DHCP SERVER: {server_ip} ({server_mac}) sent a "
                       f"{kind} (gateway={router}, dns={dns_txt}, ip={offered_ip}). "
                       f"Trusted: {', '.join(sorted(self.trusted)) or 'none'}",
                       server_ip=server_ip, server_mac=server_mac,
                       router=router, dns=dns)
        else:
            expected = self.base.dhcp_mac(server_ip)
            if expected and server_mac and server_mac != expected:
                rogue = True
                self.alert(f"impersonate:{server_mac}", "CRITICAL",
                           f"ROGUE DHCP SERVER: {server_mac} sent a {kind} "
                           f"claiming to be the trusted server {server_ip}, "
                           f"whose real MAC is {expected} (gateway={router}, "
                           f"dns={dns_txt})", server_ip=server_ip,
                           server_mac=server_mac, expected=expected, dns=dns)
            elif not expected and server_mac:
                self.base.learn_dhcp(server_ip, server_mac)
                log.info("[dhcp] Learned DHCP server %s at %s",
                         server_ip, server_mac)
        if router and self.ctx.gateway and router != self.ctx.gateway:
            rogue = True
            self.alert(f"router:{server_ip}:{router}", "CRITICAL",
                       f"DHCP {kind} from {server_ip} pushes gateway {router}, "
                       f"expected {self.ctx.gateway}", router=router)
        if not rogue and dns:
            known = self.base.dns
            if known is None:
                self.base.learn_dns(dns)
            elif set(dns) - set(known):
                bad = True
                self.alert(f"dns:{','.join(sorted(dns))}", "WARNING",
                           f"Your DHCP server now hands out DNS {dns_txt} "
                           f"(this network used {', '.join(known)}). If you "
                           f"didn't change your router's settings, it may be "
                           f"hijacked. Accept with 'sudo languard baseline "
                           f"--reset'", dns=dns, known=known)
        if rogue:
            self.respond("rogue_dhcp", mac=server_mac, server_ip=server_ip,
                         router=router, dns=dns, for_me=for_me)
        return bad or rogue

    # ---- scapy glue ----
    def handle(self, pkt):
        from scapy.all import BOOTP, DHCP, IP, Ether
        if not (pkt.haslayer(DHCP) and pkt.haslayer(IP)):
            return
        opts = _opts(pkt[DHCP])
        mt = opts.get("message-type")
        mac = pkt[Ether].src.lower() if pkt.haslayer(Ether) else "?"
        chaddr = _mac(pkt[BOOTP].chaddr) if pkt.haslayer(BOOTP) else mac
        if mt == 1:
            self.discover(chaddr or mac, eth_src=mac)
            return
        if mt not in (2, 5):
            return
        server = opts.get("server_id") or pkt[IP].src
        wpad = opts.get("wpad") or opts.get(252)
        if isinstance(wpad, bytes):
            wpad = wpad.decode(errors="ignore").strip("\x00")
        self.observe(mt, server, mac, _first(opts.get("router")),
                     _all(opts.get("name_server")), pkt[BOOTP].yiaddr, wpad,
                     for_me=bool(chaddr and chaddr == self.ctx.my_mac))

    def probe(self, timeout=5):
        """Send a DHCPDISCOVER and report every server that offers."""
        from scapy.all import (BOOTP, DHCP, IP, UDP, Ether, conf, mac2str,
                               srp)
        conf.checkIPaddr = False
        mac = self.ctx.my_mac
        xid = random.randint(1, 0xFFFFFFFF)
        disc = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac2str(mac), xid=xid, flags=0x8000) /
                DHCP(options=[("message-type", "discover"),
                              ("param_req_list", [1, 3, 6]), "end"]))
        ans, _ = srp(disc, iface=self.ctx.iface, timeout=timeout, multi=True,
                     verbose=0)
        servers = {}
        for _, r in ans:
            if r.haslayer(BOOTP) and r[BOOTP].xid == xid:
                opts = _opts(r[DHCP])
                sid = opts.get("server_id") or r[IP].src
                servers[sid] = (r[Ether].src.lower(),
                                _first(opts.get("router")),
                                _first(opts.get("name_server")))
                self.observe(2, sid, r[Ether].src.lower(),
                             _first(opts.get("router")),
                             _all(opts.get("name_server")))
        print(f"DHCP servers that answered on {self.ctx.iface}:")
        for sid, (m, router, dns) in servers.items():
            tag = "trusted" if sid in self.trusted else "ROGUE?"
            print(f"  {sid:<16} {m}  gateway={router} dns={dns}  [{tag}]")
        if not servers:
            print("  none (no DHCP server on this segment, or it ignored us)")
        elif len(servers) > 1:
            log.warning("[dhcp] %d DHCP servers answered: expect only one",
                        len(servers))
        return servers


def _url_host(url):
    """Host part of a WPAD URL, if it is an IP address (names aren't blocked:
    they are resolved later, by whoever answers)."""
    import ipaddress
    from urllib.parse import urlsplit
    try:
        host = urlsplit(str(url).strip()).hostname or ""
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def _opts(dhcp_layer):
    # scapy spells a multi-value option as ("name_server", ip1, ip2, ...)
    return {o[0]: (o[1] if len(o) == 2 else list(o[1:]))
            for o in dhcp_layer.options if isinstance(o, tuple) and len(o) >= 2}


def _mac(raw):
    if isinstance(raw, bytes) and len(raw) >= 6:
        return ":".join(f"{b:02x}" for b in raw[:6])
    return None


def _all(v):
    if v is None:
        return []
    return [str(x) for x in (v if isinstance(v, (list, tuple)) else [v])]


def _first(v):
    if isinstance(v, (list, tuple)):
        return v[0] if v else None
    return v
