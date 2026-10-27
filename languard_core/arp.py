"""
ARP spoofing / poisoning detection.

Flags: gateway MAC changes, IP->MAC changes, one MAC claiming many IPs,
ARP reply and gratuitous-request floods, Ethernet/ARP sender mismatches, and
(by active probe) two devices answering for the same IP.

Devices you pinned (`languard protect --pin-device IP`, a NAS or printer) are
judged the same way as the router: anyone else claiming their address is a
spoofer (device_spoof).

The MAC an IP was first seen with is remembered, so active protection can
block an attacker's own addresses without blocking addresses it only claimed
(own_ips).

The router's MAC comes from the per-network baseline once it is verified by
active probes, so a cache poisoned before LANGuard started is not trusted.
"""

import threading
import time
from collections import defaultdict, deque

from . import baseline
from .core import Module, kernel_arp_table, log

BOGUS_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


class ARPMonitor(Module):
    name = "arp"
    bpf = "arp"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.bindings = {}                     # ip -> mac
        self.first_mac = {}                    # ip -> MAC it was first seen at
        self.mac_first_seen = {}               # mac -> when first seen at all
        self.mac_ips = defaultdict(dict)       # mac -> {ip: last_seen}
        self.replies = defaultdict(deque)      # mac -> reply timestamps
        self.gateway_mac = None
        self._verifying = set()
        self.base = baseline.get(ctx)
        self.seed(kernel_arp_table())
        ctx.arp = self

    def own_ips(self, mac):
        """IPs first seen at mac: the device's own, not ones it claimed later."""
        mac = (mac or "").lower()
        skip = {self.ctx.gateway, self.ctx.my_ip}
        return [ip for ip, m in self.first_mac.items()
                if m == mac and ip not in skip]

    def seed(self, table):
        now = time.time()
        gw = self.ctx.gateway
        for ip, mac in table.items():
            self.bindings[ip] = mac
            self.mac_first_seen.setdefault(mac, now - 3600)   # in the cache: known
            self.first_mac.setdefault(ip, mac)
            self.mac_ips[mac][ip] = now
        cached = self.bindings.get(gw)
        if self.base.gw_verified:
            self.gateway_mac = self.base.gw_mac
            log.info("[arp] Baseline: gateway %s is at %s (verified)",
                     gw, self.gateway_mac)
            if cached and cached != self.gateway_mac:
                self.bindings[gw] = self.gateway_mac
                self._gateway_spoofed(cached, cached, startup=True)
        else:
            self.gateway_mac = cached
            if cached:
                log.info("[arp] Gateway %s is at %s (not verified yet)",
                         gw, cached)

    def _gateway_spoofed(self, old, mac, eth_src=None, startup=False):
        gw = self.ctx.gateway
        if startup:
            msg = (f"GATEWAY SPOOFING: the ARP cache maps your router {gw} "
                   f"to {mac}, but its verified MAC is {self.gateway_mac}. "
                   f"Your traffic was being redirected before LANGuard started")
        else:
            msg = (f"GATEWAY SPOOFING: {gw} moved {old} -> {mac}. "
                   f"Likely man-in-the-middle attack!")
        self.alert(f"gw:{mac}", "CRITICAL", msg, ip=gw, old_mac=old, new_mac=mac)
        if self.base.gw_verified:
            self.respond("gateway_spoof", mac=mac, eth_src=eth_src)

    # ---- pure detection logic (testable without scapy) ----
    def observe(self, ip, mac, is_reply=False, eth_src=None, now=None,
                gratuitous=False):
        """Feed one claim 'ip is at mac'. Returns True if suspicious."""
        if not ip or ip == "0.0.0.0" or mac in BOGUS_MACS:
            return False
        now = now or time.time()
        c = self.cfg
        gw = self.ctx.gateway
        bad = False

        if eth_src and eth_src != mac:
            bad = True
            self.alert(f"mismatch:{mac}", "WARNING",
                       f"Forged-looking ARP: Ethernet source {eth_src} sent an "
                       f"ARP claiming {ip} is at {mac}", ip=ip, mac=mac)

        self.first_mac.setdefault(ip, mac)
        self.mac_first_seen.setdefault(mac, now)
        pinned = self.base.rec.get("pinned", {}).get(ip)
        old = self.bindings.get(ip)
        if pinned and mac != pinned and ip != gw:
            self.alert(f"pinned:{ip}:{mac}", "CRITICAL",
                       f"DEVICE SPOOFING: {mac} claims to be {ip}, which you "
                       f"pinned to {pinned}. Someone is trying to intercept "
                       f"traffic to that device", ip=ip, mac=mac,
                       expected=pinned)
            self.respond("device_spoof", mac=mac, ip=ip)
            bad = True
        elif ip == gw and self.gateway_mac:
            # Judge every gateway claim against the known router MAC, not the
            # last binding, so repeated poisoning keeps alerting and the real
            # router's answers never look like an attack.
            if mac != self.gateway_mac:
                bad = True
                self._gateway_spoofed(old if old != mac else self.gateway_mac,
                                      mac, eth_src)
        elif old and old != mac:
            bad = True
            if ip == gw:
                self._gateway_spoofed(old, mac, eth_src)
            else:
                self.alert(f"chg:{ip}:{mac}", "WARNING",
                           f"{ip} changed MAC {old} -> {mac} "
                           f"(spoofing, or a DHCP reassignment). If {ip} is a "
                           f"device you rely on (NAS, printer), pin it on the "
                           f"app's Network page so this counts as spoofing",
                           ip=ip, old_mac=old, new_mac=mac)
        elif not old:
            log.debug("[arp] new binding %s at %s", ip, mac)
            if ip == gw and not self.gateway_mac:
                self.gateway_mac = mac
        self.bindings[ip] = pinned or mac

        # one MAC answering for many IPs (recently)
        seen = self.mac_ips[mac]
        seen[ip] = now
        for k in [k for k, t in seen.items() if now - t > c["multi_ip_window"]]:
            del seen[k]
        claimed = set(seen) - {gw}
        if len(claimed) >= c["multi_ip_threshold"] and mac != self.gateway_mac:
            bad = True
            self.alert(f"multi:{mac}", "WARNING",
                       f"{mac} claims {len(claimed)} IPs: "
                       f"{', '.join(sorted(claimed))}", mac=mac)
        if gw in seen and mac != self.gateway_mac and self.gateway_mac:
            bad = True

        if (is_reply or gratuitous) and mac != self.ctx.my_mac:
            q = self.replies[mac]
            q.append(now)
            while q and now - q[0] > c["flood_window"]:
                q.popleft()
            if len(q) >= c["flood_threshold"]:
                bad = True
                self.alert(f"flood:{mac}", "WARNING",
                           f"ARP flood from {mac}: {len(q)} replies or "
                           f"gratuitous announcements in {c['flood_window']}s "
                           f"(poisoning tool?)", mac=mac)
        return bad

    def conflict(self, ip, macs):
        """Result of an active probe: more than one MAC answered."""
        macs = sorted(set(macs))
        if len(macs) > 1:
            self.alert(f"conflict:{ip}", "CRITICAL",
                       f"CONFLICT: {len(macs)} devices answer for {ip}: "
                       f"{', '.join(macs)}", ip=ip, macs=macs)
            if ip == self.ctx.gateway and self.base.gw_verified:
                for m in macs:
                    if m != self.gateway_mac:
                        self.respond("gateway_spoof", mac=m)
            return True
        return False

    def devices(self, limit=64):
        """[(ip, mac)] LANGuard has seen on this network, for the app."""
        skip = {self.ctx.my_ip, None, ""}
        return sorted(((ip, mac) for ip, mac in self.bindings.items()
                       if ip not in skip and ":" not in ip), key=lambda x: (
                           tuple(int(p) if p.isdigit() else 0
                                 for p in x[0].split("."))))[:limit]

    # ---- scapy glue ----
    def handle(self, pkt):
        from scapy.all import ARP, Ether
        if not pkt.haslayer(ARP):
            return
        a = pkt[ARP]
        # Truncated or malformed ARP: some scapy versions leave these None.
        if not isinstance(a.hwsrc, str) or not isinstance(a.psrc, str):
            return
        mac = a.hwsrc.lower()
        eth = pkt[Ether].src.lower() if pkt.haslayer(Ether) else None
        grat = a.op == 1 and a.psrc == a.pdst
        if self.observe(a.psrc, mac, is_reply=(a.op == 2), eth_src=eth,
                        gratuitous=grat) and self.cfg.get("verify", True):
            self._verify_async(a.psrc)

    # ---- gateway verification ----
    def verify_gateway(self, rounds):
        """Judge active probes of the gateway (see Baseline.learn_gateway)."""
        gw = self.ctx.gateway
        verdict, macs = self.base.learn_gateway(rounds)
        if verdict == "verified":
            prev, self.gateway_mac = self.gateway_mac, macs
            self.bindings[gw] = macs
            if prev and prev != macs:         # we started on a poisoned cache
                self._gateway_spoofed(prev, prev, startup=True)
            p = getattr(self.ctx, "protect", None)
            if p is not None:
                p.pin_gateway()
                p.update_l2_pins()
        elif verdict == "conflict":
            self.conflict(gw, macs)
        elif verdict == "changed":
            self.alert(f"gwchanged:{macs[0]}", "CRITICAL",
                       f"Your router {gw} now answers from {macs[0]}, but its "
                       f"verified MAC on this network is {self.base.gw_mac}. "
                       f"Either the router was replaced (then run 'sudo "
                       f"languard baseline --reset') or this is spoofing",
                       ip=gw, mac=macs[0], expected=self.base.gw_mac)
            self.respond("gateway_spoof", mac=macs[0])
        return verdict

    def start(self):
        if not self.ctx.gateway or not self.ctx.iface:
            return

        def run():
            time.sleep(2)
            for _ in range(5):
                try:
                    if self.verify_gateway(baseline.probe_gateway(self.ctx)) != "none":
                        return
                except Exception as e:
                    log.debug("[arp] gateway verification failed: %s", e)
                time.sleep(30)
        threading.Thread(target=run, name="arp-verify", daemon=True).start()

    def _verify_async(self, ip):
        if ip in self._verifying:
            return
        self._verifying.add(ip)

        def run():
            try:
                from scapy.all import ARP, Ether, srp
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                             iface=self.ctx.iface, timeout=2, multi=True,
                             verbose=0)
                self.conflict(ip, [r.hwsrc.lower() for _, r in ans])
            except Exception as e:
                log.debug("[arp] verify %s failed: %s", ip, e)
            finally:
                self._verifying.discard(ip)
        threading.Thread(target=run, daemon=True).start()
