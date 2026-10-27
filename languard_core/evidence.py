"""
Evidence capture: the packets around every CRITICAL alert, saved as a pcap
you can open in Wireshark (or hand to someone who investigates).

The capture thread already sees the packets LANGuard's detectors filter for
(ARP, DHCP, DNS, ICMPv6, LLMNR/NBNS, TCP handshakes, plain-HTTP request
heads). The last `evidence.seconds` of them are kept in memory; when a
CRITICAL alert fires, they and the next `evidence.after` seconds are written
to /var/lib/languard/evidence/<time>-<module>.pcap next to a .txt with the
alert. Files are readable by root only (they can contain your own traffic),
at most one capture a minute is written, and the oldest are deleted beyond
`evidence.max_mb`.

List them: sudo languard evidence
"""

import os
import struct
import threading
import time
from collections import deque

from . import core
from .core import log

DIR = "evidence"
LINKTYPE_ETHERNET = 1
MIN_GAP = 60                    # seconds between two captures


def directory():
    return core.STATE_DIR / DIR


def write_pcap(path, packets, linktype=LINKTYPE_ETHERNET):
    """packets: [(time, bytes)]. Classic libpcap format, created 0600."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for t, data in packets:
            sec = int(t)
            f.write(struct.pack("<IIII", sec, int((t - sec) * 1e6),
                                len(data), len(data)))
            f.write(data)


class Evidence:
    def __init__(self, cfg, now=time.time):
        c = cfg.get("evidence", {})
        self.enabled = bool(c.get("enabled", True))
        self.seconds = float(c.get("seconds", 60))
        self.after = float(c.get("after", 5))
        self.max_bytes = int(float(c.get("max_mb", 200)) * 1024 * 1024)
        self.ring = deque(maxlen=int(c.get("max_packets", 20000)))
        self._now = now
        self._lock = threading.Lock()
        self._last = 0
        self.saved = []                 # paths written (tests, status)

    # -------------------------------------------------------------- feed --
    def feed(self, pkt, t=None):
        """Called for every captured packet (scapy packet or raw bytes)."""
        if not self.enabled:
            return
        try:
            data = pkt if isinstance(pkt, (bytes, bytearray)) else bytes(pkt)
        except Exception:
            return
        t = t or getattr(pkt, "time", None) or self._now()
        with self._lock:
            self.ring.append((float(t), bytes(data[:65535])))
            cut = self._now() - self.seconds - self.after
            while self.ring and self.ring[0][0] < cut:
                self.ring.popleft()

    # ------------------------------------------------------------ alerts --
    def on_alert(self, module, key, level, msg, data, sync=False):
        """Alerter hook: CRITICAL alerts save a capture."""
        if not self.enabled or level != "CRITICAL" or module == "evidence":
            return False
        now = self._now()
        with self._lock:
            if now - self._last < MIN_GAP:
                return False
            self._last = now
        if sync:
            self.save(module, msg, now)
        else:
            threading.Thread(target=self._save_later, args=(module, msg, now),
                             daemon=True).start()
        return True

    def _save_later(self, module, msg, when):
        time.sleep(self.after)
        try:
            self.save(module, msg, when)
        except Exception as e:
            log.warning("[evidence] saving the capture failed: %s", e)

    def save(self, module, msg, when):
        with self._lock:
            pkts = [(t, d) for t, d in self.ring
                    if when - self.seconds <= t <= when + self.after]
        d = directory()
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(when))
        safe = "".join(c if c.isalnum() else "-" for c in module)[:20]
        base = d / f"{stamp}-{safe}"
        write_pcap(f"{base}.pcap", pkts)
        fd = os.open(f"{base}.txt", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(when))}"
                    f" [{module}] {msg}\n{len(pkts)} packets from "
                    f"{self.seconds:.0f}s before to {self.after:.0f}s after\n")
        self.saved.append(f"{base}.pcap")
        self.trim()
        log.info("[evidence] saved %d packets around the alert to %s.pcap",
                 len(pkts), base)
        return f"{base}.pcap"

    def trim(self):
        """Delete the oldest captures beyond max_mb."""
        files = sorted(directory().glob("*.pcap"), key=lambda p: p.stat().st_mtime)
        total = sum(p.stat().st_size for p in files)
        while files and total > self.max_bytes:
            p = files.pop(0)
            total -= p.stat().st_size
            p.unlink(missing_ok=True)
            p.with_suffix(".txt").unlink(missing_ok=True)


def list_evidence():
    d = directory()
    files = sorted(d.glob("*.pcap")) if d.exists() else []
    if not files:
        print("No evidence captured yet (saved on CRITICAL alerts).")
        return
    for p in files:
        note = p.with_suffix(".txt")
        first = note.read_text().splitlines()[0] if note.exists() else ""
        print(f"{p}  ({p.stat().st_size // 1024} KB)\n    {first[:160]}")
    print("\nOpen with: wireshark FILE   (or: tcpdump -r FILE -n)")
