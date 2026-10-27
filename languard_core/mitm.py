"""
General MITM detection.

  * ICMP redirects (IPv4): an attacker telling you to route via them
  * LLMNR / NBT-NS poisoning (Responder): LANGuard periodically asks the LAN
    for a random name that cannot exist. Honest devices stay silent; a
    poisoning tool answers everything, and that answer exposes it.
  * Unsolicited LLMNR/NBNS answers for names this machine never asked about
  * mDNS (.local names: printers, AirPlay, file shares): the same bait, sent
    as an mDNS query for a random .local name; and a device that takes over
    names other devices answered for (CRITICAL from three names on, when it
    is one device grabbing them: poisoning, not a device renamed)
"""

import random
import socket
import string
import struct
import threading
import time

from .core import Module, log

LLMNR_GROUP, LLMNR_PORT = "224.0.0.252", 5355
NBNS_PORT = 137
MDNS_GROUP, MDNS_PORT = "224.0.0.251", 5353
TAKEOVER_WINDOW, TAKEOVER_NAMES = 600, 3


def random_name():
    # Looks like a plausible host so tools don't skip it, but can't exist.
    return "srv-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))


def llmnr_query(name, txid):
    hdr = struct.pack(">HHHHHH", txid, 0, 1, 0, 0, 0)
    q = bytes([len(name)]) + name.encode() + b"\x00" + struct.pack(">HH", 1, 1)
    return hdr + q


def nbns_encode(name):
    name = name.upper()[:15].ljust(15) + "\x00"
    out = bytearray([32])
    for ch in name.encode():
        out += bytes([((ch >> 4) & 0xF) + 0x41, (ch & 0xF) + 0x41])
    return bytes(out) + b"\x00"


def nbns_query(name, txid):
    hdr = struct.pack(">HHHHHH", txid, 0x0110, 1, 0, 0, 0)
    return hdr + nbns_encode(name) + struct.pack(">HH", 0x20, 1)


class MitmMonitor(Module):
    name = "mitm"
    bpf = ("(icmp and icmp[icmptype] == 5) or "
           "(udp and (port 5355 or port 137 or port 5353))")

    def __init__(self, ctx):
        super().__init__(ctx)
        self.baits = {}          # name -> time sent
        self.mdns_owner = {}     # .local name -> (mac, ip, last seen)
        self.takeovers = {}      # mac -> [(name, time)] names it took over

    # ---- pure logic ----
    def icmp_redirect(self, src, gw, dest=None, mac=None):
        self.alert(f"redir:{src}:{gw}", "CRITICAL",
                   f"ICMP REDIRECT from {src}: told to send traffic"
                   f"{' for ' + dest if dest else ''} via {gw}. Classic MITM "
                   f"rerouting (your kernel now ignores these)", src=src, gw=gw)
        if src != self.ctx.gateway:
            self.respond("icmp_redirect", mac=mac, src_ip=src)
        return True

    def name_answer(self, name, responder, proto, now=None, mac=None):
        """An LLMNR/NBNS answer was seen. Returns True if poisoning."""
        now = now or time.time()
        n = name.lower().rstrip(".").strip()
        if responder == self.ctx.my_ip:
            return False
        if n in self.baits:
            self.alert(f"poison:{responder}", "CRITICAL",
                       f"NAME POISONING: {responder} answered our {proto} bait "
                       f"query for '{n}', a name that does not exist. A tool "
                       f"like Responder is running there and can steal "
                       f"credentials", src=responder, proto=proto)
            self.respond("name_poisoning", mac=mac, src_ip=responder)
            return True
        return False

    def mdns_answer(self, name, ip, mac, now=None):
        """An mDNS answer record 'name is at ip', sent by mac. Returns True
        if it looks like poisoning."""
        now = now or time.time()
        n = name.lower().rstrip(".")
        if n.endswith(".local"):
            short = n[:-6]
        else:
            short = n
        mac = (mac or "").lower()
        if not mac or ip == self.ctx.my_ip or mac == (self.ctx.my_mac or "").lower():
            return False
        if short in self.baits:
            return self.name_answer(short, ip, "mDNS", now=now, mac=mac)
        old = self.mdns_owner.get(n)
        self.mdns_owner[n] = (mac, ip, now)
        if not old or old[0] == mac or now - old[2] > 86400:
            return False
        q = [(x, t) for x, t in self.takeovers.get(mac, [])
             if now - t < TAKEOVER_WINDOW and x != n] + [(n, now)]
        self.takeovers[mac] = q
        if len(q) >= TAKEOVER_NAMES:
            self.alert(f"mdns:{mac}", "CRITICAL",
                       f"mDNS POISONING: {mac} ({ip}) took over {len(q)} .local "
                       f"names other devices answered for "
                       f"({', '.join(x for x, _ in q[:5])}). A spoofing tool "
                       f"is redirecting printers, shares and AirPlay to itself",
                       src=ip, mac=mac, names=[x for x, _ in q])
            self.respond("name_poisoning", mac=mac, src_ip=ip)
            return True
        self.alert(f"mdnschg:{n}:{mac}", "WARNING",
                   f"mDNS name {n} moved from {old[0]} ({old[1]}) to {mac} "
                   f"({ip}). A device that changed network adapter, or a "
                   f"spoof", name=n, mac=mac, old_mac=old[0])
        return False

    def new_bait(self, now=None):
        now = now or time.time()
        for k in [k for k, t in self.baits.items() if now - t > 3600]:
            del self.baits[k]
        n = random_name()
        self.baits[n] = now
        return n

    # ---- active honeypot ----
    def send_bait(self):
        name = self.new_bait()
        txid = random.randint(0, 0xFFFF)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                s.sendto(llmnr_query(name, txid), (LLMNR_GROUP, LLMNR_PORT))
            if self.ctx.network:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    s.sendto(nbns_query(name, txid),
                             (str(self.ctx.network.broadcast_address), NBNS_PORT))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
                s.sendto(mdns_query(name + ".local", 0), (MDNS_GROUP, MDNS_PORT))
            log.debug("[mitm] sent LLMNR/NBNS/mDNS bait for %s", name)
        except OSError as e:
            log.debug("[mitm] bait failed: %s", e)

    def start(self):
        interval = self.cfg.get("honeypot_interval", 300)
        if not interval:
            return

        def loop():
            time.sleep(10)
            while True:
                self.send_bait()
                time.sleep(interval + random.randint(-30, 30))
        threading.Thread(target=loop, name="mitm-bait", daemon=True).start()

    # ---- scapy glue ----
    def handle(self, pkt):
        from scapy.all import ICMP, IP, UDP, Ether
        mac = pkt[Ether].src.lower() if pkt.haslayer(Ether) else None
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 5:
            inner = pkt[ICMP].payload
            dest = inner.dst if hasattr(inner, "dst") else None
            self.icmp_redirect(pkt[IP].src, pkt[ICMP].gw, dest, mac)
            return
        if not (pkt.haslayer(UDP) and pkt.haslayer(IP)):
            return
        udp = pkt[UDP]
        data = bytes(udp.payload)
        if len(data) < 12:
            return
        flags = struct.unpack(">H", data[2:4])[0]
        is_resp = bool(flags & 0x8000)
        if udp.sport == LLMNR_PORT and is_resp:
            name = _llmnr_name(data)
            if name:
                self.name_answer(name, pkt[IP].src, "LLMNR", mac=mac)
        elif udp.sport == NBNS_PORT and is_resp:
            name = _nbns_name(data)
            if name:
                self.name_answer(name, pkt[IP].src, "NBT-NS", mac=mac)
        elif udp.sport == MDNS_PORT and is_resp:
            for name, ip in mdns_records(data):
                self.mdns_answer(name, ip, mac)


def mdns_query(name, txid):
    hdr = struct.pack(">HHHHHH", txid, 0, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p)
    return hdr + q + b"\x00" + struct.pack(">HH", 1, 1)


def _dns_name(data, off, depth=0):
    """(name, offset after it) from a DNS message, following compression."""
    labels = []
    while True:
        if off >= len(data) or depth > 10:
            raise ValueError("bad name")
        ln = data[off]
        if ln == 0:
            return ".".join(labels), off + 1
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            name, _ = _dns_name(data, ptr, depth + 1)
            return ".".join(labels + ([name] if name else [])), off + 2
        labels.append(data[off + 1:off + 1 + ln].decode("utf-8", "replace"))
        off += 1 + ln


def mdns_records(data, limit=32):
    """[(name, ipv4)] from the A records of an mDNS response (malformed
    packets give what could be read, never an exception)."""
    out = []
    try:
        qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
        off = 12
        for _ in range(min(qd, limit)):
            _, off = _dns_name(data, off)
            off += 4
        for _ in range(min(an + ns + ar, limit)):
            name, off = _dns_name(data, off)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 1 and rdlen == 4 and off + 4 <= len(data):
                out.append((name, socket.inet_ntoa(data[off:off + 4])))
            off += rdlen
    except (ValueError, struct.error, IndexError):
        pass
    return out


def _llmnr_name(data):
    try:
        ln = data[12]
        return data[13:13 + ln].decode(errors="ignore")
    except IndexError:
        return None


def _nbns_name(data):
    try:
        enc = data[13:13 + 32]
        raw = bytes(((enc[i] - 0x41) << 4) | (enc[i + 1] - 0x41)
                    for i in range(0, 32, 2))
        return raw[:15].decode(errors="ignore").strip()
    except (IndexError, ValueError):
        return None
