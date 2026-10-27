"""
Active protection (opt-in): stop LAN attacks, not only report them.

Detectors hand confirmed attacks to `Protector.respond()`. Depending on
`protect` in the config it can:

  * pin the router: a permanent ARP entry for the *verified* router MAC, which
    ARP spoofing cannot overwrite, put back if anything changes it
  * isolate an attacker: an nftables netdev/ingress set drops every frame
    (ARP, IPv4, IPv6) from the attacker's MAC before the kernel processes it.
    Entries expire on their own (isolate_minutes)
  * repair after rogue DHCP: renew the lease once the rogue server is isolated,
    if this machine's gateway or DNS was taken over
  * IPv6 lockdown: remove routes a rogue router advertised and stop accepting
    Router Advertisements on the interface
  * HTTPS guard: plain-HTTP requests to sites you use over HTTPS are upgraded
    to https:// before they leave this machine, and look-alikes of them are
    blocked, so SSL stripping has nothing to strip (guard.py)
  * repair after rogue DHCPv6 (mitm6): renew the connection and flush the DNS
    cache if this machine took the rogue server's DNS
  * end what the attack set up (cutoff.py): block the attacker's IP
    addresses, end live connections that went through the attacker or to a
    forged DNS answer, flush the DNS cache, turn LLMNR off after Responder-style
    poisoning, stop accepting ICMP redirects, leave an evil-twin Wi-Fi
  * pin devices you choose (NAS, printer: `languard protect --pin-device IP`)
    and the verified IPv6 router the same way as the IPv4 router; anyone
    claiming a pinned device's address is isolated (device_spoof)
  * block a LAN host that pushes a WPAD proxy config (DHCP option 252 or a
    wpad DNS answer): it would see all your web traffic
  * public networks (marked with `languard network --public`, or open Wi-Fi):
    ignore ICMP redirects and turn LLMNR off from the start, not only after an
    attack; put back on networks marked home. DNS servers are never changed
  * kill switch: disconnect the interface on a confirmed gateway MITM

Safety rules: nothing happens unless `protect.enabled` is true; isolation and
pinning need a *verified* router MAC (see baseline.py), so a wrong baseline can
never cut you off from your router; the router, this machine, every MAC the
network's baseline trusts and `never_isolate` are never isolated.

Isolation acts on a source MAC, which an attacker can forge to get an innocent
device cut off. Isolation only drops frames on *this* machine (the device keeps
working for everyone else), entries expire, and if more than `isolate_max`
different devices are named as attackers within 10 minutes LANGuard stops
isolating for 30 minutes and says so: that pattern is forgery or a false
alarm, not several real attackers. The pin, IPv6 lockdown and HTTPS guard only
change this machine's own settings, so they can't be turned against anyone.

Every action is logged with its undo command, recorded in
/var/lib/languard/protect.json and listed by `languard protect`.
"""

import atexit
import queue
import shutil
import subprocess
import threading
import time

import ipaddress

from . import baseline, distro, guard
from .cutoff import IPTABLE, Responses, ip_family
from .core import default_route, load_state, log, save_state

TABLE = "languard"
BOGUS = {"", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}

# event -> what to do with the MAC it names
ISOLATE_EVENTS = {"gateway_spoof", "rogue_dhcp", "rogue_ra", "rogue_dhcp6",
                  "ndp_gateway_spoof", "icmp_redirect", "name_poisoning",
                  "mitm_route", "dhcp_starvation", "dns_spoof", "device_spoof"}
# Events that name only a MAC: block the IPs that MAC used as its own (first
# seen with it), never ones it only claimed (see arp.py own_ips).
MAC_IP_EVENTS = {"gateway_spoof", "mitm_route", "ndp_gateway_spoof", "rogue_ra",
                 "dhcp_starvation", "dns_spoof", "device_spoof", "rogue_dhcp6"}
# Everything sent off the LAN went through the attacker: end it all.
OFFLINK_EVENTS = {"gateway_spoof", "mitm_route"}
IPV6_EVENTS = {"rogue_ra", "ndp_gateway_spoof"}
FLUSH_EVENTS = {"gateway_spoof", "mitm_route", "ndp_gateway_spoof", "rogue_dhcp",
                "rogue_dhcp6", "name_poisoning", "dns_spoof", "dns_race",
                "tls_intercept"}
REPAIR_EVENTS = {"rogue_dhcp", "rogue_dhcp6"}
FRAME_WINDOW, FRAME_PAUSE = 600, 1800
KNOWN_AFTER = 600               # a MAC seen this long before counts as a device
UNKNOWN_MAX = 30                # isolations of never-seen MACs per FRAME_WINDOW
KILL_EVENTS = {"gateway_spoof", "mitm_route", "ndp_gateway_spoof"}
# Independent signs of a router MITM; the kill switch needs two of them.
KILL_SIGNALS = KILL_EVENTS | {"rogue_dhcp", "rogue_ra", "rogue_dhcp6",
                              "dns_spoof", "tls_intercept", "ssl_strip",
                              "icmp_redirect"}
KILL_WINDOW = 120


# Switches and their defaults (core.py has the same defaults).
OPTIONS = {"pin_gateway": True, "isolate": True, "block_ips": True,
           "cut_connections": True, "flush_dns": True, "repair_dhcp": True,
           "ipv6_lockdown": True, "llmnr_off": True, "block_redirects": True,
           "https_guard": True, "block_wpad": True, "pin_devices": True,
           "pin_router6": True, "public_hardening": True, "kill_switch": False,
           "pin_dhcp": True, "pin_ra": True, "https_only": False}


def _run(cmd, stdin=None, timeout=15):
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


def _valid_mac(mac):
    parts = (mac or "").split(":")
    return len(parts) == 6 and all(len(p) == 2 and
                                   all(c in "0123456789abcdef" for c in p)
                                   for p in parts)


class Protector(Responses):
    def __init__(self, ctx, run=None, sync=False):
        self.ctx = ctx
        self.cfg = ctx.cfg.get("protect", {})
        self.enabled = bool(self.cfg.get("enabled"))
        self.run = run or _run
        self.sync = sync                    # tests: act immediately
        self.base = baseline.get(ctx)
        self.state = load_state("protect", {})
        self.state.setdefault("blocked", {})
        self.state.setdefault("blocked_ips", {})
        self._lock = threading.RLock()
        self._q = queue.Queue()
        self._nft = False
        self._last = {}                     # rate limits: name -> time
        self._warned = set()
        self._recent = []                   # (mac, time) of recent isolations
        self._unknown = []                  # times never-seen MACs were isolated
        self._frame_until = 0
        self._signals = []                  # (event, mac, time) for the kill switch
        self._l2pins = None                 # (dhcp macs, ra macs) in nftables
        self.guard = None
        self._ipt = False
        self._ip_recent = []                # (ip, time) of recent IP blocks
        self._ipblock_until = 0
        self.kind = None                    # home / public, once applied

    # ---------------------------------------------------------- lifecycle --
    def start(self):
        if not self.enabled:
            return
        log.info("[protect] Active protection on (%s)", ", ".join(
            k for k in OPTIONS if self.cfg.get(k)))
        self._forget_other_networks()
        if self.cfg.get("isolate", True):
            self.setup_nft()
        if self.cfg.get("block_ips", True):
            self.setup_ipblock()
        self.pin_gateway()
        self.pin_devices()
        self.update_l2_pins()
        self.apply_network_kind()
        with self._lock:                    # a crash may have left this behind
            self.state.pop("guard", None)
            self._save()
        if not self.sync and self.cfg.get("https_guard", True):
            self.start_guard()
        if not self.sync:
            threading.Thread(target=self._worker, name="protect",
                             daemon=True).start()
            threading.Thread(target=self._watch_pin, name="protect-pin",
                             daemon=True).start()

    def start_guard(self):
        g = guard.HttpsGuard(self.ctx, self.run,
                             port=self.cfg.get("guard_port", guard.PORT))
        if not g.start():
            self._warn_once("guard", "HTTPS guard is off (see the log above); "
                            "SSL stripping is still detected")
            return False
        self.guard = g
        atexit.register(g.stop)
        with self._lock:
            self.state["guard"] = {"since": time.time(), "port": g.port}
            self._save()
        return True

    def _worker(self):
        while True:
            event, info = self._q.get()
            try:
                self._handle(event, info)
            except Exception as e:
                log.warning("[protect] %s response failed: %s", event, e)

    def _watch_pin(self):
        while True:
            time.sleep(30)
            try:
                self.pin_gateway()
                self.pin_devices()
                pin6 = self.state.get("pin6")
                if pin6:
                    self.pin_router6(pin6["ip"], pin6["mac"])
                self.update_l2_pins()
            except Exception as e:
                log.debug("[protect] pin check failed: %s", e)

    def _save(self):
        try:
            save_state("protect", self.state)
        except OSError as e:
            log.debug("[protect] save failed: %s", e)

    def _alert(self, key, level, msg, **data):
        self.ctx.alert("protect", key, level, msg, **data)

    def _once(self, name, every):
        now = time.time()
        if now - self._last.get(name, 0) < every:
            return False
        self._last[name] = now
        return True

    def _warn_once(self, key, msg):
        if key not in self._warned:
            self._warned.add(key)
            log.warning("[protect] %s", msg)

    # ------------------------------------------------------------- events --
    def respond(self, event, **info):
        """Called by detectors for a confirmed attack. Never blocks capture."""
        if not self.enabled:
            return
        if self.sync:
            self._handle(event, info)
        else:
            self._q.put((event, info))

    def _handle(self, event, info):
        mac = (info.get("mac") or "").lower()
        if not mac and info.get("src_ip"):
            mac = self._mac_of(info["src_ip"])
        isolated = False
        now = time.time()
        self._signals = [x for x in self._signals if now - x[2] < KILL_WINDOW]
        if event in KILL_SIGNALS:
            self._signals.append((event, mac, now))
        if event in ISOLATE_EVENTS and mac:
            if self.is_protected(mac) and mac != (self.ctx.my_mac or "").lower():
                what = ("your router" if mac == (self.base.gw_mac or "")
                        else "a device you pinned" if mac in self._pinned_macs()
                        else "a trusted device")
                self._alert(f"forged:{mac}", "WARNING",
                            f"{mac} ({what}) was named as the attacker in "
                            f"{event}. LANGuard never isolates it: its MAC is "
                            f"most likely being forged to get it cut off",
                            mac=mac, event=event)
            else:
                isolated = self.isolate(mac, event)
        if event == "gateway_spoof":
            self.pin_gateway(force=True)
        if event == "device_spoof":
            self.pin_devices()
            if info.get("ip"):              # sessions to it may have gone
                self.cut(dst=info["ip"], why=event)     # through the attacker
        if event in REPAIR_EVENTS:
            self.repair_dhcp(info)
        if event == "rogue_ra":
            self.ipv6_lockdown(info.get("src_ip"))
        # End what the attack already set up.
        if event in FLUSH_EVENTS:
            self.flush_dns(event)
        if event in OFFLINK_EVENTS:
            self.cut(scope="offlink", why=event)
        if event in IPV6_EVENTS:
            self.cut(scope="ipv6", why=event)
        for ip in self._attacker_ips(event, info):
            self.block_ip(ip, event)
        if event == "dns_race":             # can't tell which answer is forged:
            for ip in list(info.get("answers") or [])[:16]:
                self.cut(dst=ip, why=event)  # reconnect after a fresh lookup
        if event == "name_poisoning":
            self.llmnr_off()
        if event == "icmp_redirect":
            self.no_redirects()
        if event == "ssl_strip" and info.get("ip"):
            self.cut(dst=info["ip"], port=80, why=event)
        if event == "evil_twin":
            self.leave_twin(info.get("bssid"), info.get("ssid", ""))
        if event == "tls_intercept":
            self.kill_switch(event, info.get("host", "?"), False)
        if mac and not self.is_protected(mac) and (
                event in KILL_EVENTS or (event in KILL_SIGNALS and any(
                    e in KILL_EVENTS and m == mac for e, m, _ in self._signals))):
            self.kill_switch(event, mac, isolated)

    def _onlink(self, ip):
        try:
            a = ipaddress.ip_address(ip)
            net = self.ctx.network
            return a.is_link_local or (net is not None and a in net)
        except (ValueError, TypeError):
            return False

    def _attacker_ips(self, event, info):
        """Addresses that belong to the attacker, never ones it pretends to be
        (the router, a forged DNS source) or public servers it hands out."""
        src = info.get("src_ip")
        mac = (info.get("mac") or "").lower()
        out = self._mac_ips(mac) if event in MAC_IP_EVENTS and mac else []
        return list(dict.fromkeys(out + self._event_ips(event, info, src)))

    def _mac_ips(self, mac):
        arp = getattr(self.ctx, "arp", None)
        if arp is None or self.is_protected(mac):
            return []
        return [ip for ip in arp.own_ips(mac) if self._onlink(ip)][:4]

    def _event_ips(self, event, info, src):
        if event == "wpad":
            if not self.cfg.get("block_wpad", True):
                return []
            return [ip for ip in info.get("ips") or []
                    if ip and self._onlink(ip)][:4]
        if event in ("name_poisoning", "icmp_redirect", "port_scan",
                     "lookalike"):
            return [ip for ip in (src or info.get("ip"),) if ip]
        if event == "rogue_dhcp":
            server = info.get("server_ip")
            out = [] if self.base.dhcp_mac(server) else [server]
            out += [ip for ip in [info.get("router")] + list(info.get("dns") or [])
                    if ip and ip != self.ctx.gateway and self._onlink(ip)]
            return [ip for ip in out if ip]
        if event == "rogue_dhcp6":
            return [ip for ip in [src] + list(info.get("dns") or [])
                    if ip and self._onlink(ip)]
        if event == "dns_spoof":
            return list(info.get("answers") or [])[:8]
        return []

    def _mac_of(self, ip):
        rc, out = self.run(["ip", "neigh", "show", ip])
        p = out.split()
        if rc == 0 and "lladdr" in p:
            return p[p.index("lladdr") + 1].lower()
        return ""

    # ------------------------------------------------------- safety check --
    def is_protected(self, mac):
        mac = (mac or "").lower()
        never = {m.lower() for m in self.cfg.get("never_isolate") or []}
        return (mac in BOGUS or mac == (self.ctx.my_mac or "").lower()
                or mac in never or mac in self.base.trusted_macs()
                or mac in self._pinned_macs())

    def _pinned_macs(self):
        return {m.lower() for m in self.base.pinned().values()}

    def _known_device(self, mac):
        """Seen on this network well before now (ARP), so a real device:
        forging its MAC can hurt someone. A never-seen MAC (random, made up
        to trip the framing safeguard) can be isolated at no cost."""
        arp = getattr(self.ctx, "arp", None)
        first = getattr(arp, "mac_first_seen", {}).get(mac) if arp else None
        if first is None:
            return arp is None              # no ARP data: assume it's real
        return time.time() - first >= KNOWN_AFTER

    # ---------------------------------------------------------- isolation --
    def setup_nft(self):
        """(Re)create the netdev table on the current interface."""
        iface = self.ctx.iface
        rules = (f"table netdev {TABLE}\n"
                 f"delete table netdev {TABLE}\n"
                 f"table netdev {TABLE} {{\n"
                 f"  set blocked {{ type ether_addr; flags timeout; }}\n"
                 f"  chain ingress {{\n"
                 f"    type filter hook ingress device \"{iface}\" priority -500; "
                 f"policy accept;\n"
                 f"    ether saddr @blocked counter drop\n"
                 f"  }}\n"
                 f"  chain pins {{\n"
                 f"    type filter hook ingress device \"{iface}\" priority -499; "
                 f"policy accept;\n"
                 f"  }}\n"
                 f"}}\n")
        rc, out = self.run(["nft", "-f", "-"], stdin=rules)
        if rc != 0:
            hint = f" ({distro.install_hint('nftables')})" if rc == 127 else ""
            self._warn_once("nftfail", f"attacker isolation is off: could not "
                            f"create the nftables table{hint}: {out}")
            return False
        self._nft = True
        self._l2pins = None
        now = time.time()
        with self._lock:                    # restore still-valid blocks
            for mac, b in list(self.state["blocked"].items()):
                left = int(b.get("until", 0) - now)
                if left > 60 and b.get("network") == self.base.key:
                    self._nft_add(mac, left)
                else:
                    del self.state["blocked"][mac]
            self._save()
        return True

    def _nft_add(self, mac, seconds):
        return self.run(["nft", "add", "element", "netdev", TABLE, "blocked",
                         f"{{ {mac} timeout {int(seconds)}s }}"])

    def isolate(self, mac, reason):
        mac = mac.lower()
        if not (self.enabled and self.cfg.get("isolate", True)):
            return False
        if not _valid_mac(mac) or self.is_protected(mac):
            return False
        if not self.base.gw_verified:
            self._warn_once("unverified", "not isolating attackers yet: the "
                            "router's MAC on this network isn't verified")
            return False
        with self._lock:
            b = self.state["blocked"].get(mac)
            if b and b.get("until", 0) > time.time():
                return True
            if self._framed(mac):
                return False
            if not self._nft and not self.setup_nft():
                return False
            minutes = int(self.cfg.get("isolate_minutes", 60))
            rc, out = self._nft_add(mac, minutes * 60)
            if rc != 0:
                log.warning("[protect] isolating %s failed: %s", mac, out)
                return False
            self._recent.append((mac, time.time()))
            self.state["blocked"][mac] = {
                "until": time.time() + minutes * 60, "reason": reason,
                "since": time.time(), "network": self.base.key}
            self._save()
        self._alert(f"isolate:{mac}", "WARNING",
                    f"Isolated {mac} for {minutes} min ({reason}): this "
                    f"machine now drops every frame it sends. Undo: sudo "
                    f"languard protect --unblock {mac}", mac=mac, reason=reason)
        return True

    def _framed(self, mac):
        """True if isolating mac now could be someone framing a real device.

        Only devices seen on the network before (_known_device) count toward
        `isolate_max`: forging made-up MACs no longer trips the safeguard,
        and made-up MACs stay isolatable (at most UNKNOWN_MAX per window, so
        a flood of them can't keep nft busy). While real devices are being
        framed, isolation of known devices pauses, and protection tightens
        instead (public-network hardening and IPv6 lockdown)."""
        now = time.time()
        self._recent = [(m, t) for m, t in self._recent if now - t < FRAME_WINDOW]
        self._unknown = [t for t in self._unknown if now - t < FRAME_WINDOW]
        if not self._known_device(mac):
            if len(self._unknown) >= UNKNOWN_MAX:
                self._warn_once("unknownflood", f"over {UNKNOWN_MAX} never-seen "
                                f"MACs named as attackers in {FRAME_WINDOW // 60}"
                                f" min: not isolating more of them for now")
                return True
            self._unknown.append(now)
            return False
        if now < self._frame_until:
            return True
        named = {m for m, _ in self._recent if self._known_device(m)} | {mac}
        if len(named) <= int(self.cfg.get("isolate_max", 3)):
            return False
        self._frame_until = now + FRAME_PAUSE
        with self._lock:
            self.state["framed_until"] = self._frame_until
            self._save()
        self._alert("framing", "CRITICAL",
                    f"{len(named)} different known devices were named as "
                    f"attackers within {FRAME_WINDOW // 60} min. Someone is "
                    f"likely forging packets in their names to get them cut "
                    f"off, or to switch isolation off. For {FRAME_PAUSE // 60} "
                    f"min LANGuard won't isolate known devices; it keeps "
                    f"isolating unknown ones and tightens instead: LLMNR off, "
                    f"ICMP redirects ignored, IPv6 lockdown (the router pin and "
                    f"HTTPS guard stay on). Last named: {mac}",
                    macs=sorted(named))
        if self.sync:
            self.tighten("framing")
        else:
            threading.Thread(target=self.tighten, args=("framing",),
                             daemon=True).start()
        return True

    def tighten(self, why):
        """Harden like a public network, until LANGuard restarts or the
        network is marked again (all preventive, so undone on a home one)."""
        try:
            self.no_redirects(preventive=True)
            self.llmnr_off(preventive=True)
            self.ipv6_lockdown(None, preventive=True)
            log.info("[protect] tightened protection (%s)", why)
        except Exception as e:
            log.warning("[protect] tightening failed: %s", e)

    def unblock(self, mac):
        if mac != "all" and ip_family(mac):
            return self.unblock_ip(mac)
        if mac == "all":
            self.unblock_ip("all")
        with self._lock:
            if mac == "all":
                self.run(["nft", "flush", "set", "netdev", TABLE, "blocked"])
                self.state["blocked"] = {}
            else:
                mac = mac.lower()
                self.run(["nft", "delete", "element", "netdev", TABLE,
                          "blocked", f"{{ {mac} }}"])
                self.state["blocked"].pop(mac, None)
            self._save()

    # ------------------------------------------------------------ pinning --
    def _neigh(self):
        """(mac, permanent) of the kernel's entry for the gateway."""
        rc, out = self.run(["ip", "neigh", "show", self.ctx.gateway,
                            "dev", self.ctx.iface])
        p = out.split()
        mac = p[p.index("lladdr") + 1].lower() if "lladdr" in p else None
        return mac, "PERMANENT" in p

    def pin_gateway(self, force=False):
        if not (self.enabled and self.cfg.get("pin_gateway", True)):
            return False
        gw, iface, mac = self.ctx.gateway, self.ctx.iface, self.base.gw_mac
        if not (gw and iface and mac):
            return False
        cur, permanent = self._neigh()
        if cur == mac and permanent:
            return True
        rc, out = self.run(["ip", "neigh", "replace", gw, "lladdr", mac,
                            "dev", iface, "nud", "permanent"])
        if rc != 0:
            log.warning("[protect] pinning %s failed: %s", gw, out)
            return False
        with self._lock:
            first = not self.state.get("pin")
            self.state["pin"] = {"ip": gw, "mac": mac, "iface": iface,
                                 "network": self.base.key}
            self._save()
        if cur and cur != mac:
            self._alert(f"repin:{cur}", "WARNING",
                        f"Restored your router's ARP entry: {gw} pointed to "
                        f"{cur}, now pinned to the verified MAC {mac}",
                        ip=gw, bad=cur, mac=mac)
        elif first:
            self._alert("pin", "INFO",
                        f"Pinned router {gw} to {mac}: ARP spoofing can't "
                        f"redirect your traffic now. Undo: sudo languard "
                        f"protect --unpin", ip=gw, mac=mac)
        return True

    def unpin(self):
        with self._lock:
            pin = self.state.pop("pin", None)
            pin6 = self.state.pop("pin6", None)
            self._save()
        if pin:
            self.run(["ip", "neigh", "del", pin["ip"], "dev", pin["iface"]])
        if pin6:
            self.run(["ip", "-6", "neigh", "del", pin6["ip"], "dev",
                      pin6["iface"]])
        return pin

    def _forget_other_networks(self):
        """A pin from a network we've left would break this one."""
        pin = self.state.get("pin") or self.state.get("pin6")
        if pin and pin.get("network") != self.base.key:
            self.unpin()
            log.info("[protect] Removed router pin from previous network")
        with self._lock:
            for key in ("blocked", "blocked_ips"):
                for k, b in list(self.state[key].items()):
                    if b.get("network") != self.base.key:
                        del self.state[key][k]
            self._save()

    # ---------------------------------------------- pinned devices, IPv6 --
    def _neigh_entry(self, ip):
        """(mac, permanent) of the kernel's neighbour entry for ip."""
        rc, out = self.run(["ip", "neigh", "show", ip, "dev", self.ctx.iface])
        p = out.split()
        mac = p[p.index("lladdr") + 1].lower() if "lladdr" in p else None
        return mac, "PERMANENT" in p

    def _pin_entry(self, ip, mac, what):
        cur, permanent = self._neigh_entry(ip)
        if cur == mac and permanent:
            return True
        rc, out = self.run(["ip", "neigh", "replace", ip, "lladdr", mac,
                            "dev", self.ctx.iface, "nud", "permanent"])
        if rc != 0:
            log.warning("[protect] pinning %s %s failed: %s", what, ip, out)
            return False
        if cur and cur != mac:
            self._alert(f"repin:{ip}:{cur}", "WARNING",
                        f"Restored the ARP/NDP entry of {what} {ip}: it "
                        f"pointed to {cur}, now pinned to {mac}",
                        ip=ip, bad=cur, mac=mac)
        return True

    def pin_devices(self):
        """Pin every device pinned on this network. Returns how many hold."""
        if not (self.enabled and self.cfg.get("pin_devices", True)):
            return 0
        return sum(self._pin_entry(ip, mac, "pinned device")
                   for ip, mac in self.base.pinned().items())

    def pin_device(self, ip, mac=None):
        """CLI: pin ip to mac (default: the MAC it has now). Returns the MAC."""
        if not ip_family(ip):
            raise ValueError(f"{ip} is not an IP address")
        mac = (mac or self._neigh_entry(ip)[0] or "").lower()
        if not _valid_mac(mac):
            raise ValueError(f"no MAC known for {ip}: ping it first or give "
                             f"the MAC (printed on the device's label)")
        if mac == (self.base.gw_mac or "") and ip != self.ctx.gateway:
            raise ValueError(f"{mac} is your router's MAC, not {ip}'s: "
                             f"{ip} may be off-LAN or this cache is poisoned")
        self.base.pin_device(ip, mac)
        self._pin_entry(ip, mac, "pinned device")
        return mac

    def unpin_device(self, ip):
        mac = self.base.unpin_device(ip)
        if mac:
            self.run(["ip", "neigh", "del", ip, "dev", self.ctx.iface])
        return mac

    def pin_router6(self, ip, mac):
        """Pin the IPv6 router (ipv6.py calls this for the verified one)."""
        if not (self.enabled and self.cfg.get("pin_router6", True)):
            return False
        if not (ip and _valid_mac((mac or "").lower()) and self.base.gw_verified):
            return False
        ip, mac = ip.lower(), mac.lower()
        if not self._pin_entry(ip, mac, "IPv6 router"):
            return False
        with self._lock:
            first = self.state.get("pin6") != {"ip": ip, "mac": mac,
                                               "iface": self.ctx.iface,
                                               "network": self.base.key}
            if first:
                self.state["pin6"] = {"ip": ip, "mac": mac,
                                      "iface": self.ctx.iface,
                                      "network": self.base.key}
                self._save()
        if first:
            self._alert("pin6", "INFO",
                        f"Pinned IPv6 router {ip} to {mac}: NDP spoofing "
                        f"can't redirect your IPv6 traffic now. Undo: sudo "
                        f"languard protect --unpin", ip=ip, mac=mac)
        return True

    # --------------------------------------------------- network kinds --
    def network_kind(self):
        """('home' | 'public' | None, why)."""
        if self.base.kind:
            return self.base.kind, "marked"
        if baseline.wifi_open(self.ctx.iface, self.run):
            return "public", "open Wi-Fi"
        return None, "not marked"

    def apply_network_kind(self):
        """Public network: harden before any attack. Anything else: put back
        what was only done because a network was public."""
        if not self.enabled:
            return None
        kind, why = self.network_kind()
        self.kind = kind
        if kind == "public" and self.cfg.get("public_hardening", True):
            self.no_redirects(preventive=True)
            self.llmnr_off(preventive=True)
            if not (self.base.ipv6("ipv6_routers") or self.state.get("pin6")):
                self.ipv6_lockdown(None, preventive=True)
            log.info("[protect] %s is a public network (%s): ICMP redirects "
                     "ignored, LLMNR off and (with no known IPv6 router) IPv6 "
                     "router advertisements ignored from the start",
                     self.base.key, why)
            return kind
        ll = self.state.get("llmnr")
        if ll and ll.get("preventive"):
            self.llmnr_restore()
        how = self.state.get("redirects_how")
        if how and how.get("preventive"):
            self.redirects_restore()
        ra = self.state.get("accept_ra")
        if ra and ra.get("preventive"):
            self.ipv6_unlock()
        if kind is None:
            log.info("[protect] Tip: tell LANGuard what this network is: "
                     "sudo languard network --home (or --public)")
        return kind

    # ------------------------------------------------------- DHCP repair --
    def repair_dhcp(self, info):
        if not self.cfg.get("repair_dhcp", True):
            return False
        gw_now = default_route()[1]
        rogue_dns = set(info.get("dns") or [])
        hijacked = (info.get("for_me") or (gw_now and gw_now != self.ctx.gateway)
                    or bool(rogue_dns & self._current_dns()))
        if not hijacked or not self._once("repair", 300):
            return False
        cmd = self._renew_cmd()
        if not cmd:
            self._warn_once("renew", "no way to renew the DHCP lease "
                            "(nmcli/networkctl/dhclient not found)")
            return False
        if not self.sync:
            time.sleep(2)               # let isolation take effect first
        rc, out = self.run(cmd, timeout=60)
        if rc == 0:                         # drop answers the rogue DNS gave
            self.run(["resolvectl", "flush-caches"])
        self._alert("repair", "WARNING" if rc == 0 else "CRITICAL",
                    f"A rogue {'DHCPv6' if info.get('v6') else 'DHCP'} server "
                    f"targeted this machine; "
                    f"{'renewed the lease from the real server' if rc == 0 else 'lease renewal FAILED: ' + out}"
                    f". Check 'resolvectl status' and 'ip route'",
                    cmd=" ".join(cmd))
        return rc == 0

    def _current_dns(self):
        rc, out = self.run(["resolvectl", "dns", self.ctx.iface])
        return set(out.split(":", 1)[-1].split()) if rc == 0 else set()

    def _renew_cmd(self):
        iface = self.ctx.iface
        rc, conn = self.run(["nmcli", "-t", "-g", "GENERAL.CONNECTION",
                             "device", "show", iface])
        if rc == 0 and conn and conn != "--":
            return ["nmcli", "connection", "up", conn.splitlines()[0]]
        if shutil.which("networkctl"):
            return ["networkctl", "renew", iface]
        if shutil.which("dhclient"):
            return ["sh", "-c", f"dhclient -r {iface}; dhclient {iface}"]
        return None

    # ---------------------------------------------------- IPv6 lockdown --
    def ipv6_lockdown(self, rogue_ip, preventive=False):
        """preventive: before any attack (public network with no known IPv6
        router, or while devices are being framed); undone on a home network."""
        if not self.cfg.get("ipv6_lockdown", True):
            return False
        iface = self.ctx.iface
        if rogue_ip:
            self.run(["ip", "-6", "route", "del", "default", "via", rogue_ip,
                      "dev", iface])
        key = f"net.ipv6.conf.{iface}.accept_ra"
        with self._lock:
            if "accept_ra" in self.state:
                if not preventive and self.state["accept_ra"].get("preventive"):
                    self.state["accept_ra"]["preventive"] = False   # keep it
                    self._save()
                return True
            rc, out = self.run(["sysctl", "-n", key])
            old = out.strip() if rc == 0 and out.strip() else "1"
            if old == "0":
                return True
            rc, out = self.run(["sysctl", "-w", f"{key}=0"])
            if rc != 0:
                log.warning("[protect] IPv6 lockdown failed: %s", out)
                return False
            self.state["accept_ra"] = {"iface": iface, "old": old,
                                       "preventive": preventive}
            self._save()
        if preventive:
            log.info("[protect] IPv6 router advertisements ignored on %s from "
                     "the start (no trusted IPv6 router here)", iface)
            return True
        self._alert("ipv6lock", "WARNING",
                    f"IPv6 lockdown on {iface}: removed routes via {rogue_ip} "
                    f"and stopped accepting Router Advertisements. IPv4 is "
                    f"unaffected. Undo: sudo languard protect --undo-all",
                    iface=iface)
        return True

    # ------------------------------------------------ DHCP / RA pinning --
    def l2_pin_macs(self):
        """(DHCP server MACs, IPv6 router MACs) allowed to answer on this
        network, or empty sets when they aren't known and verified yet."""
        if not (self.enabled and self.base.gw_verified):
            return set(), set()
        dhcp = set()
        if self.cfg.get("pin_dhcp", True):
            dhcp = {m.lower() for m in self.base.trusted_macs() if _valid_mac(m.lower())}
        ra = set()
        if self.cfg.get("pin_ra", True):
            ra = {self.base.gw_mac}
            pin6 = self.state.get("pin6")
            if pin6 and pin6.get("network") == self.base.key:
                ra.add(pin6["mac"])
            ra |= {m.lower() for m in self.ctx.cfg.get("ipv6", {}).get(
                "trusted_routers") or [] if _valid_mac(m.lower())}
        return dhcp, ra

    def update_l2_pins(self):
        """Only the verified DHCP server(s) may hand out leases and only the
        verified router may advertise itself for IPv6: everything else is
        dropped in the netdev table before the kernel sees it. LANGuard's
        capture still sees (and reports) the dropped packets."""
        dhcp, ra = self.l2_pin_macs()
        want = (tuple(sorted(dhcp)), tuple(sorted(ra)))
        if want == self._l2pins:
            return want
        if not (dhcp or ra) and self._l2pins is None and not self._nft:
            return want
        if not self._nft and not self.setup_nft():
            return None
        lines = [f"flush chain netdev {TABLE} pins"]
        if dhcp:
            lines.append(f"add rule netdev {TABLE} pins ether type ip udp sport 67 "
                         f"udp dport 68 ether saddr != {{ {', '.join(sorted(dhcp))} }} "
                         f"counter drop")
        if ra:
            lines.append(f"add rule netdev {TABLE} pins ether type ip6 icmpv6 type "
                         f"nd-router-advert ether saddr != {{ {', '.join(sorted(ra))} }} "
                         f"counter drop")
        rc, out = self.run(["nft", "-f", "-"], stdin="\n".join(lines) + "\n")
        if rc != 0:
            self._warn_once("l2pins", f"DHCP/RA pinning failed: {out}")
            return None
        first = self._l2pins is None or self._l2pins == ((), ())
        self._l2pins = want
        with self._lock:
            self.state["l2pins"] = {"dhcp": list(want[0]), "ra": list(want[1]),
                                    "network": self.base.key}
            self._save()
        if first and (dhcp or ra):
            self._alert("l2pins", "INFO",
                        f"Pinned the network's servers: DHCP answers only from "
                        f"{', '.join(sorted(dhcp)) or '-'}, IPv6 router "
                        f"advertisements only from {', '.join(sorted(ra)) or '-'}. "
                        f"A rogue DHCP server or IPv6 router can't reach this "
                        f"machine now (still detected). New router? sudo "
                        f"languard baseline --reset", dhcp=sorted(dhcp), ra=sorted(ra))
        return want

    def ipv6_unlock(self):
        with self._lock:
            ra = self.state.pop("accept_ra", None)
            self._save()
        if ra:
            self.run(["sysctl", "-w",
                      f"net.ipv6.conf.{ra['iface']}.accept_ra={ra['old']}"])
        return ra

    # -------------------------------------------------------- kill switch --
    def kill_switch(self, event, mac, isolated):
        if not self.cfg.get("kill_switch") or not self.base.gw_verified:
            return False
        # One forged packet must not be enough to take you offline: wait for
        # two different signs of the MITM (same attacker, or unattributed).
        now = time.time()
        signs = {e for e, m, t in self._signals
                 if now - t < KILL_WINDOW and (not m or not mac or m == mac)}
        if len(signs | {event}) < 2:
            log.info("[protect] kill switch armed by %s (%s); waiting for a "
                     "second sign of the attack", event, mac)
            return False
        if not self._once("kill", 600):
            return False
        iface = self.ctx.iface
        rc, out = self.run(["nmcli", "device", "disconnect", iface])
        if rc != 0:
            rc, out = self.run(["ip", "link", "set", iface, "down"])
        self._alert("kill", "CRITICAL",
                    f"KILL SWITCH: disconnected {iface} because of a confirmed "
                    f"man-in-the-middle ({event} by {mac}). Reconnect when the "
                    f"network is safe: nmcli device connect {iface}"
                    f"{'' if rc == 0 else ' (disconnect FAILED: ' + out + ')'}",
                    event=event, mac=mac)
        return rc == 0

    # ---------------------------------------------------------------- CLI --
    def stop_guard(self):
        if self.guard:
            self.guard.stop()
            self.guard = None
        else:                               # CLI: the service's rule, if any
            self.run(["nft", "delete", "table", "inet", guard.TABLE])
        with self._lock:
            self.state.pop("guard", None)
            self._save()

    def disable_option(self, key):
        """Undo what one response did when the user switches it off (the
        others, and their blocks, stay as they are)."""
        if key == "pin_gateway":
            with self._lock:
                pin = self.state.pop("pin", None)
                self._save()
            if pin:
                self.run(["ip", "neigh", "del", pin["ip"], "dev", pin["iface"]])
        elif key == "pin_router6":
            with self._lock:
                pin6 = self.state.pop("pin6", None)
                self._save()
            if pin6:
                self.run(["ip", "-6", "neigh", "del", pin6["ip"], "dev",
                          pin6["iface"]])
        elif key == "isolate":
            with self._lock:
                self.state["blocked"] = {}
                self._save()
            self.run(["nft", "delete", "table", "netdev", TABLE])
        elif key == "block_ips":
            self.unblock_ip("all")
            self.run(["nft", "delete", "table", "inet", IPTABLE])
        elif key == "https_guard":
            self.stop_guard()
        elif key == "ipv6_lockdown":
            self.ipv6_unlock()
        elif key == "llmnr_off":
            self.llmnr_restore()
        elif key == "block_redirects":
            self.redirects_restore()
        elif key == "pin_devices":
            for ip in self.base.pinned():
                self.run(["ip", "neigh", "del", ip, "dev", self.ctx.iface])
        elif key == "public_hardening":
            if self.state.get("llmnr", {}).get("preventive"):
                self.llmnr_restore()
            if self.state.get("redirects_how", {}).get("preventive"):
                self.redirects_restore()
            if self.state.get("accept_ra", {}).get("preventive"):
                self.ipv6_unlock()
        elif key in ("pin_dhcp", "pin_ra"):
            self.cfg[key] = False
            self.run(["nft", "flush", "chain", "netdev", TABLE, "pins"])
            self._l2pins = None
            with self._lock:
                self.state.pop("l2pins", None)
                self._save()

    def undo_all(self):
        self.unblock("all")
        self.run(["nft", "delete", "table", "netdev", TABLE])
        self.run(["nft", "delete", "table", "inet", IPTABLE])
        self.stop_guard()
        for ip in self.base.pinned():       # kernel entries; the list stays
            self.run(["ip", "neigh", "del", ip, "dev", self.ctx.iface])
        self.llmnr_restore()
        self.redirects_restore()
        pin = self.unpin()
        ra = self.ipv6_unlock()
        self._nft, self._l2pins = False, None
        with self._lock:
            self.state.pop("l2pins", None)
            self.state.pop("framed_until", None)
            self._save()
        return pin, ra


def print_status(cfg):
    state = load_state("protect", {})
    p = cfg.get("protect", {})
    on = "ON" if p.get("enabled") else "off (set protect.enabled in the config)"
    print(f"Active protection: {on}")
    if p.get("enabled"):
        print("  " + ", ".join(f"{k}={'yes' if p.get(k, OPTIONS[k]) else 'no'}"
                               for k in OPTIONS))
    pin = state.get("pin")
    print(f"Router pin: {pin['ip']} -> {pin['mac']} on {pin['iface']}"
          if pin else "Router pin: none")
    now = time.time()
    blocked = {m: b for m, b in state.get("blocked", {}).items()
               if b.get("until", 0) > now}
    print(f"Isolated devices: {len(blocked) or 'none'}")
    for mac, b in sorted(blocked.items()):
        print(f"  {mac}  {b.get('reason', '?'):<18} "
              f"{int((b['until'] - now) / 60)} min left")
    ips = {i: b for i, b in state.get("blocked_ips", {}).items()
           if b.get("until", 0) > now}
    print(f"Blocked addresses: {len(ips) or 'none'}")
    for ip, b in sorted(ips.items()):
        print(f"  {ip:<17}  {b.get('reason', '?'):<18} "
              f"{int((b['until'] - now) / 60)} min left")
    if state.get("llmnr"):
        why = ("public network" if state["llmnr"].get("preventive")
               else "after name poisoning")
        print(f"LLMNR: off on {state['llmnr']['iface']} ({why})")
    if state.get("redirects") is not None:
        print("ICMP redirects: ignored (after a redirect attack)")
    g = state.get("guard")
    print("HTTPS guard: on (plain HTTP to your HTTPS sites is upgraded)"
          if g else "HTTPS guard: off")
    pin6 = state.get("pin6")
    if pin6:
        print(f"IPv6 router pin: {pin6['ip']} -> {pin6['mac']}")
    if state.get("llmnr", {}).get("preventive") or \
            state.get("redirects_how", {}).get("preventive"):
        print("Public-network hardening: on (LLMNR off, ICMP redirects ignored)")
    ra = state.get("accept_ra")
    if ra:
        print(f"IPv6 lockdown: Router Advertisements ignored on {ra['iface']}"
              f"{' (public network, preventive)' if ra.get('preventive') else ''}")
    l2 = state.get("l2pins")
    if l2 and (l2.get("dhcp") or l2.get("ra")):
        print(f"DHCP answers only from: {', '.join(l2.get('dhcp') or []) or '-'}; "
              f"IPv6 router advertisements only from: "
              f"{', '.join(l2.get('ra') or []) or '-'}")
    fu = state.get("framed_until", 0)
    if fu > time.time():
        print(f"Framing safeguard: known devices aren't isolated until "
              f"{time.strftime('%H:%M', time.localtime(fu))} (someone forged "
              f"attacks in their names)")
