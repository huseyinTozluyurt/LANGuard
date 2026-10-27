"""
IPv6 man-in-the-middle detection.

Even "IPv4-only" home networks run IPv6, and Linux accepts it by default.
Tools like mitm6 and THC-IPv6 exploit that:
  * rogue Router Advertisements: become everyone's IPv6 gateway (SLAAC MITM)
  * rogue DHCPv6 replies: hand out an attacker DNS server (mitm6)
  * NDP spoofing: the IPv6 equivalent of ARP spoofing
  * ICMPv6 redirects: reroute a destination through the attacker

Learned routers and DHCPv6 servers are kept per network (see baseline.py).
They are never learned on trust: an IPv6 router or DHCPv6 server is accepted
only when it is the verified IPv4 router (same MAC, the usual home router) or
listed in ipv6.trusted_routers / trusted_dhcp6. Before 1.3 the first one seen
was trusted, which let mitm6 (often the only DHCPv6 server on IPv4-only
networks) become "trusted" itself.
"""

from . import baseline, core
from .core import Module, load_state, log


class IPv6Monitor(Module):
    name = "ipv6"
    bpf = "icmp6 or (udp and (port 546 or port 547))"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.base = baseline.get(ctx)
        self._migrate()
        self._forget_unverified()
        self.routers = set(x.lower() for x in self.cfg.get("trusted_routers") or [])
        self.routers |= self.base.ipv6("ipv6_routers")
        self.dhcp6 = set(x.lower() for x in self.cfg.get("trusted_dhcp6") or [])
        self.dhcp6 |= self.base.ipv6("dhcp6")
        self.neighbors = {}            # ipv6 -> mac
        self.router_ips = set()        # link-local addresses of trusted routers

    def _migrate(self):
        """LANGuard <= 1.1 kept one global ipv6.json: adopt it for this network."""
        old = core.STATE_DIR / "ipv6.json"
        if not old.exists() or self.base.ipv6("ipv6_routers"):
            return
        state = load_state("ipv6", {})
        self.base.learn_ipv6("ipv6_routers", state.get("routers", []))
        self.base.learn_ipv6("dhcp6", state.get("dhcp6", []))
        try:
            old.rename(old.with_suffix(".json.migrated"))
        except OSError:
            pass

    def _forget_unverified(self):
        """Routers learned by LANGuard <= 1.2 were trusted on first sight:
        forget them once; the real router is relearned from its verified MAC."""
        if self.base.rec.get("ipv6_verified_learning"):
            return
        with self.base._lock:
            dropped = self.base.rec.pop("ipv6_routers", []) + \
                self.base.rec.pop("dhcp6", [])
            self.base.rec["ipv6_verified_learning"] = True
        self.base.save()
        if dropped:
            log.info("[ipv6] Relearning IPv6 routers for this network from "
                     "the verified router (was: %s)", ", ".join(dropped))

    def _save(self):
        self.base.learn_ipv6("ipv6_routers", self.routers)
        self.base.learn_ipv6("dhcp6", self.dhcp6)

    # ---- pure logic ----
    def _is_gateway(self, mac):
        """The verified IPv4 router's MAC: the same box usually routes IPv6."""
        gw = self.base.gw_mac
        return bool(gw and mac and mac == gw)

    def _pin(self, src_ip, mac):
        """Pin the verified IPv6 router like the IPv4 one (protect.py)."""
        p = getattr(self.ctx, "protect", None)
        trusted = {x.lower() for x in self.cfg.get("trusted_routers") or []}
        if p is None or not mac or not (self._is_gateway(mac) or mac in trusted):
            return
        if (p.state.get("pin6") or {}).get("ip") == src_ip:
            return                          # protect re-checks it every 30 s
        p.pin_router6(src_ip, mac)

    def router_advert(self, src_ip, mac, lifetime=1800, prefixes=(), rdnss=()):
        """Returns True if the RA comes from an unknown router."""
        src_ip, mac = src_ip.lower(), (mac or "").lower()
        if src_ip in self.routers or mac in self.routers:
            self.router_ips.add(src_ip)
            self._pin(src_ip, mac)
            return False
        if self._is_gateway(mac):
            self.routers |= {src_ip, mac}
            self.router_ips.add(src_ip)
            self._save()
            log.info("[ipv6] Learned IPv6 router %s (%s): it is your verified "
                     "router", src_ip, mac)
            self._pin(src_ip, mac)
            return False
        if not self.base.gw_verified:
            # Can't tell yet; RAs repeat every few minutes, judge them then.
            log.debug("[ipv6] RA from %s (%s) held until the router is "
                      "verified", src_ip, mac)
            return False
        extra = []
        if prefixes:
            extra.append(f"prefix {', '.join(prefixes)}")
        if rdnss:
            extra.append(f"DNS {', '.join(rdnss)}")
        detail = f" ({'; '.join(extra)})" if extra else ""
        if lifetime == 0:
            self.alert(f"ra0:{mac}", "WARNING",
                       f"Router Advertisement from unknown {src_ip} ({mac}) "
                       f"with lifetime 0: may be trying to kill the real "
                       f"router's route{detail}", src=src_ip, mac=mac)
        else:
            self.alert(f"ra:{mac}", "CRITICAL",
                       f"ROGUE IPv6 ROUTER: {src_ip} ({mac}) is advertising "
                       f"itself as a gateway{detail}, and it is not your "
                       f"router. IPv6 traffic can be intercepted (SLAAC "
                       f"attack). If your network really has a separate IPv6 "
                       f"router, add {mac} to ipv6.trusted_routers",
                       src=src_ip, mac=mac)
        self.respond("rogue_ra", mac=mac, src_ip=src_ip)
        return True

    def dhcp6_reply(self, src_ip, mac, dns=()):
        """Returns True if a DHCPv6 server we don't know answered."""
        src_ip, mac = src_ip.lower(), (mac or "").lower()
        if src_ip in self.dhcp6 or mac in self.dhcp6:
            return False
        # The router itself often runs DHCPv6.
        if src_ip in self.routers or mac in self.routers or self._is_gateway(mac):
            self.dhcp6 |= {src_ip, mac} - {""}
            self._save()
            return False
        dns_txt = ", ".join(dns) or "(none listed)"
        if not self.base.gw_verified:
            # Most home networks run no DHCPv6 server at all, so an unknown one
            # is worth a look even before the router is verified; no action.
            self.alert(f"dhcp6u:{mac}", "WARNING",
                       f"Unverified DHCPv6 server {src_ip} ({mac}) is handing "
                       f"out DNS {dns_txt}. mitm6 works this way; LANGuard "
                       f"decides once your router's MAC is verified",
                       src=src_ip, mac=mac, dns=list(dns))
            return True
        self.alert(f"dhcp6:{mac}", "CRITICAL",
                   f"ROGUE DHCPv6 SERVER: {src_ip} ({mac}) is handing out "
                   f"DNS {dns_txt}, and it is not your router. This is how "
                   f"mitm6 hijacks DNS (and then strips HTTPS). If it is a "
                   f"real server on your network, add {mac} to "
                   f"ipv6.trusted_dhcp6", src=src_ip, mac=mac, dns=list(dns))
        self.respond("rogue_dhcp6", mac=mac, src_ip=src_ip, dns=list(dns),
                     v6=True)
        return True

    def neighbor_adv(self, target, mac):
        """NDP: 'target is at mac'. Returns True if a binding changed."""
        if not target or not mac:
            return False
        target, mac = target.lower(), mac.lower()
        old = self.neighbors.get(target)
        self.neighbors[target] = mac
        if not old or old == mac:
            return False
        if target in self.router_ips or old in self.routers:
            self.alert(f"ndp-gw:{mac}", "CRITICAL",
                       f"NDP SPOOFING of your IPv6 router {target}: "
                       f"{old} -> {mac}", target=target, old=old, new=mac)
            self.respond("ndp_gateway_spoof", mac=mac)
        else:
            self.alert(f"ndp:{target}:{mac}", "WARNING",
                       f"IPv6 neighbor {target} changed MAC {old} -> {mac}",
                       target=target)
        return True

    def redirect(self, src_ip, target, dest, mac=None):
        self.alert(f"redir6:{src_ip}:{dest}", "CRITICAL",
                   f"ICMPv6 REDIRECT from {src_ip}: traffic to {dest} should "
                   f"go via {target}. Classic MITM rerouting", src=src_ip)
        if src_ip.lower() not in self.routers and (mac or "").lower() not in self.routers:
            self.respond("icmp_redirect", mac=mac, src_ip=src_ip)
        return True

    # ---- scapy glue ----
    def handle(self, pkt):
        from scapy.all import IPv6, Ether
        if not pkt.haslayer(IPv6):
            return
        from scapy.layers import inet6 as i6
        src = pkt[IPv6].src
        mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
        if pkt.haslayer(i6.ICMPv6ND_RA):
            ra = pkt[i6.ICMPv6ND_RA]
            prefixes, dns = [], []
            if pkt.haslayer(i6.ICMPv6NDOptSrcLLAddr):
                mac = pkt[i6.ICMPv6NDOptSrcLLAddr].lladdr
            if pkt.haslayer(i6.ICMPv6NDOptPrefixInfo):
                pi = pkt[i6.ICMPv6NDOptPrefixInfo]
                prefixes.append(f"{pi.prefix}/{pi.prefixlen}")
            if pkt.haslayer(i6.ICMPv6NDOptRDNSS):
                dns = list(pkt[i6.ICMPv6NDOptRDNSS].dns)
            self.router_advert(src, mac, ra.routerlifetime, prefixes, dns)
        elif pkt.haslayer(i6.ICMPv6ND_NA):
            na = pkt[i6.ICMPv6ND_NA]
            lla = mac
            if pkt.haslayer(i6.ICMPv6NDOptDstLLAddr):
                lla = pkt[i6.ICMPv6NDOptDstLLAddr].lladdr
            self.neighbor_adv(na.tgt, lla)
        elif pkt.haslayer(i6.ICMPv6ND_Redirect):
            r = pkt[i6.ICMPv6ND_Redirect]
            self.redirect(src, r.tgt, r.dst, mac)
        else:
            from scapy.layers import dhcp6 as d6
            if pkt.haslayer(d6.DHCP6_Advertise) or pkt.haslayer(d6.DHCP6_Reply):
                dns = []
                if pkt.haslayer(d6.DHCP6OptDNSServers):
                    dns = list(pkt[d6.DHCP6OptDNSServers].dnsservers)
                self.dhcp6_reply(src, mac, dns)
