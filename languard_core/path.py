"""
Routing path check: is something sitting between you and your router?

An ARP/NDP spoofer that forwards your traffic is a router the packets pass
through. Every minute LANGuard sends a packet with TTL=1 towards the internet:
the device that answers "time exceeded" is your real first hop. It must be
your gateway, at your gateway's MAC. It also tracks the TTL of the gateway's
ping replies; an extra hop between you and the router lowers it by one.
"""

from . import baseline
from .core import Module, kernel_arp_table, log


class PathMonitor(Module):
    name = "path"
    threaded = True

    def __init__(self, ctx):
        super().__init__(ctx)
        self.interval = self.cfg.get("interval", 60)
        self.base = baseline.get(ctx)
        self.gw_mac = self.base.gw_mac or kernel_arp_table().get(ctx.gateway)
        self.gw_ttl = None

    # ---- pure logic ----
    def first_hop(self, hop_ip, hop_mac):
        """Result of the TTL=1 probe. Returns True if suspicious."""
        if not hop_ip:
            return False
        gw = self.ctx.gateway
        hop_mac = (hop_mac or "").lower()
        if hop_ip != gw:
            self.alert(f"hop:{hop_ip}", "CRITICAL",
                       f"MITM ROUTING: your traffic's first hop is {hop_ip} "
                       f"({hop_mac}), not your gateway {gw}. Another device "
                       f"is forwarding your packets", hop=hop_ip, mac=hop_mac)
            self.respond("mitm_route", mac=hop_mac)
            return True
        if self.base.gw_mac:          # verified since we started
            self.gw_mac = self.base.gw_mac
        if self.gw_mac and hop_mac and hop_mac != self.gw_mac:
            self.alert(f"hopmac:{hop_mac}", "CRITICAL",
                       f"MITM ROUTING: gateway {gw} answered from MAC {hop_mac}"
                       f", expected {self.gw_mac}", mac=hop_mac)
            self.respond("mitm_route", mac=hop_mac)
            return True
        if not self.gw_mac and hop_mac:
            self.gw_mac = hop_mac
        return False

    def gateway_ttl(self, ttl):
        """TTL of the gateway's echo reply. Returns True if it dropped."""
        if ttl is None:
            return False
        if self.gw_ttl is None:
            self.gw_ttl = ttl
            log.info("[path] Gateway reply TTL baseline: %s", ttl)
            return False
        if ttl < self.gw_ttl:
            self.alert(f"ttl:{ttl}", "WARNING",
                       f"Gateway replies now arrive with TTL {ttl} (was "
                       f"{self.gw_ttl}): an extra hop appeared between you "
                       f"and your router", ttl=ttl, baseline=self.gw_ttl)
            return True
        if ttl > self.gw_ttl:       # router rebooted / changed: re-baseline
            self.gw_ttl = ttl
        return False

    # ---- probes ----
    def tick(self):
        from scapy.all import ICMP, IP, UDP, Ether, srp1
        iface, gw = self.ctx.iface, self.ctx.gateway
        if not gw:
            return
        # Address frames to the MAC the kernel uses for the gateway, so we
        # test the path your real traffic takes.
        dst_mac = kernel_arp_table().get(gw) or self.gw_mac or "ff:ff:ff:ff:ff:ff"
        probe = (Ether(dst=dst_mac) /
                 IP(dst=self.cfg.get("probe_target", "1.1.1.1"), ttl=1) /
                 UDP(dport=33434))
        r = srp1(probe, iface=iface, timeout=3, verbose=0)
        if r is not None and r.haslayer(ICMP) and r[ICMP].type == 11:
            self.first_hop(r[IP].src, r[Ether].src)
        r = srp1(Ether(dst=dst_mac) / IP(dst=gw) / ICMP(), iface=iface,
                 timeout=3, verbose=0)
        if r is not None and r.haslayer(IP):
            self.gateway_ttl(r[IP].ttl)
