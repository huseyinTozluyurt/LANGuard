"""
Rogue / unknown device detection.

Keeps an inventory of devices seen on the LAN (from ARP and DHCP traffic plus
a periodic active ARP sweep) and alerts when an unknown device appears.
Use `languard devices --learn` once to mark everything currently present as
trusted, then new arrivals are flagged.

MAC flooding (macof and similar) sends random-source frames of any kind, not
ARP or DHCP, so a separate lightweight raw socket also counts distinct unknown
source MACs in every frame. Its receive buffer is small on purpose: during a
flood the kernel drops what Python can't keep up with, which is fine because a
small sample of a flood is still thousands of new MACs.
"""

import ipaddress
import socket
import threading
import time

from .core import Module, load_state, log, save_state, vendor


class DeviceMonitor(Module):
    name = "devices"
    bpf = "arp or (udp and (port 67 or port 68))"

    def __init__(self, ctx, learning=False):
        super().__init__(ctx)
        self.learning = learning
        self.db = load_state("devices", {})
        self._dirty = False
        self._last_save = 0
        self._lock = threading.Lock()
        self._new_macs = []            # timestamps of first sightings
        self._frame_macs = {}          # unknown frame source MAC -> last seen
        self._frame_prune = 0

    def _mac_flood(self, now):
        c = self.cfg
        w = c.get("mac_flood_window", 60)
        self._new_macs = [t for t in self._new_macs if now - t <= w] + [now]
        if len(self._new_macs) >= c.get("mac_flood_threshold", 50):
            self.alert("macflood", "CRITICAL",
                       f"MAC FLOODING: {len(self._new_macs)} new MAC addresses "
                       f"in {w}s. This overflows switch tables so traffic "
                       f"leaks to everyone (sniffing)", count=len(self._new_macs))
            return True
        return False

    def frame_src(self, mac, now=None):
        """Source MAC of any frame. Returns True when a MAC flood is seen."""
        if mac in self.db or mac == self.ctx.my_mac:
            return False
        now = now or time.time()
        c = self.cfg
        w = c.get("frame_flood_window", 10)
        fm = self._frame_macs
        fm[mac] = now
        if now - self._frame_prune > 1:
            self._frame_prune = now
            for k in [k for k, t in fm.items() if now - t > w]:
                del fm[k]
        if len(fm) >= c.get("frame_flood_threshold", 500):
            n = len(fm)
            fm.clear()
            self.alert("macflood", "CRITICAL",
                       f"MAC FLOODING: {n}+ unknown source MAC addresses in "
                       f"{w}s of traffic (macof-style). This overflows switch "
                       f"tables so traffic leaks to everyone (sniffing)",
                       count=n)
            return True
        return False

    def _frame_loop(self):
        while True:
            try:
                with socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                   socket.htons(0x0003)) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 16)
                    s.bind((self.ctx.iface, 0))
                    while True:
                        data = s.recv(64)
                        if len(data) >= 12:
                            self.frame_src(data[6:12].hex(":"))
            except OSError as e:
                log.debug("[devices] frame watch stopped (%s); retrying", e)
                time.sleep(10)

    # ---- pure logic ----
    def observe(self, mac, ip=None, hostname=None, now=None):
        """Record a sighting. Returns True if this is an unknown device."""
        if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return False
        if mac == self.ctx.my_mac:          # this machine itself
            return False
        if ip and self.ctx.network:
            try:
                if ipaddress.ip_address(ip) not in self.ctx.network:
                    ip = None
            except ValueError:
                ip = None
        now = now or time.time()
        with self._lock:
            d = self.db.get(mac)
            new = d is None
            if new:
                d = self.db[mac] = {
                    "first_seen": now, "ips": [], "hostname": "",
                    "vendor": vendor(mac), "trusted": self.learning,
                }
            d["last_seen"] = now
            if ip and ip not in d["ips"]:
                d["ips"] = (d["ips"] + [ip])[-5:]
            if hostname and not d["hostname"]:
                d["hostname"] = hostname
            self._dirty = True

        if new and not self.learning:
            self._mac_flood(now)
        if new and not self.learning and self.cfg.get("alert_unknown", True):
            desc = ", ".join(x for x in (ip, hostname, d["vendor"]) if x)
            self.alert(f"new:{mac}", "WARNING",
                       f"Unknown device joined: {mac} ({desc or 'no details'})",
                       mac=mac, ip=ip, hostname=hostname)
        self._maybe_save(now)
        return new and not d["trusted"]

    def _maybe_save(self, now, force=False):
        if self._dirty and (force or now - self._last_save > 30):
            try:
                save_state("devices", self.db)
                self._dirty = False
                self._last_save = now
            except OSError as e:
                log.debug("[devices] save failed: %s", e)

    def flush(self):
        self._maybe_save(time.time(), force=True)

    # ---- scapy glue ----
    def handle(self, pkt):
        from scapy.all import ARP, DHCP, Ether
        if pkt.haslayer(ARP):
            a = pkt[ARP]
            self.observe(a.hwsrc.lower(), a.psrc)
        elif pkt.haslayer(DHCP) and pkt.haslayer(Ether):
            opts = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}
            if opts.get("message-type") in (1, 3):     # discover / request
                host = opts.get("hostname")
                if isinstance(host, bytes):
                    host = host.decode(errors="ignore")
                ip = opts.get("requested_addr")
                self.observe(pkt[Ether].src.lower(), ip, host)

    def sweep(self):
        """Active ARP sweep of the local subnet (capped at /22)."""
        from scapy.all import ARP, Ether, srp
        net = self.ctx.network
        if not net:
            return []
        if net.prefixlen < 22:
            net = ipaddress.ip_network(f"{self.ctx.my_ip}/22", strict=False)
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)),
                     iface=self.ctx.iface, timeout=3, verbose=0)
        found = [(r.hwsrc.lower(), r.psrc) for _, r in ans]
        for mac, ip in found:
            self.observe(mac, ip)
        self.flush()
        return found

    def start(self):
        if self.cfg.get("frame_watch", True) and self.ctx.iface:
            threading.Thread(target=self._frame_loop, name="devices-frames",
                             daemon=True).start()
        interval = self.cfg.get("scan_interval", 0)
        if not interval:
            return

        def loop():
            while True:
                try:
                    self.sweep()
                except Exception as e:
                    log.debug("[devices] sweep failed: %s", e)
                time.sleep(interval)
        threading.Thread(target=loop, daemon=True).start()


# ---- inventory helpers used by the CLI ----
def list_devices():
    db = load_state("devices", {})
    rows = sorted(db.items(), key=lambda kv: kv[1].get("last_seen", 0),
                  reverse=True)
    print(f"{'MAC':<18} {'TRUST':<6} {'IP':<16} {'LAST SEEN':<17} "
          f"{'HOSTNAME / VENDOR'}")
    for mac, d in rows:
        last = time.strftime("%Y-%m-%d %H:%M", time.localtime(d.get("last_seen", 0)))
        ip = (d.get("ips") or ["-"])[-1]
        name = " / ".join(x for x in (d.get("hostname"), d.get("vendor")) if x)
        print(f"{mac:<18} {'yes' if d.get('trusted') else 'NO':<6} {ip:<16} "
              f"{last:<17} {name}")
    print(f"\n{len(rows)} devices, "
          f"{sum(1 for _, d in rows if not d.get('trusted'))} untrusted")


def set_trust(macs, trusted=True, forget=False):
    db = load_state("devices", {})
    for mac in macs:
        mac = mac.lower()
        if mac == "all":
            for d in db.values():
                d["trusted"] = trusted
            continue
        if mac not in db:
            print(f"Unknown MAC {mac}")
            continue
        if forget:
            del db[mac]
        else:
            db[mac]["trusted"] = trusted
    save_state("devices", db)
