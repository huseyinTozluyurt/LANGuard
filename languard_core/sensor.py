"""
Sensor health: notice when someone tries to blind LANGuard.

An attacker who can't beat the detectors can try to make them miss the
attack: flood the capture with packets so the real spoof is dropped, or send
malformed packets that make a detector fail. The capture already filters in
the kernel (BPF); on top of that this:

  * reads the capture socket's kernel counters (PACKET_STATISTICS): packets
    the kernel dropped because LANGuard couldn't keep up are reported
    ("sensor overloaded"), so a blind spot is never silent
  * limits each source MAC to `per_mac_pps` packets a second into the
    detectors. A flooder only wastes its own budget; everyone else's packets
    (the router's, a real attacker's) are still judged
  * counts detector errors per module: a burst of failures on packets is
    reported as possible crafted packets

Status (packets/s, kernel drops, skipped, errors) is shown in the app.
"""

import struct
import threading
import time
from collections import defaultdict

from .core import log

SOL_PACKET, PACKET_STATISTICS = 263, 6


def kernel_stats(sock):
    """(received, dropped) since the last call, from an AF_PACKET socket."""
    try:
        return struct.unpack("II", sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))
    except (OSError, AttributeError, struct.error):
        return None


class Sensor:
    def __init__(self, cfg, alert, now=time.monotonic):
        c = cfg.get("sensor", {})
        self.per_mac = int(c.get("per_mac_pps", 200))
        self.drop_alert = int(c.get("drop_alert", 100))
        self.error_alert = int(c.get("error_alert", 50))
        self.alert = alert              # alert(key, level, msg, **data)
        self.now = now
        self._lock = threading.Lock()
        self._sec = 0
        self._per_mac = defaultdict(int)
        self.flooders = {}              # mac -> packets skipped this minute
        self.errors = defaultdict(int)  # module -> errors this minute
        self.total = self.skipped = self.drops = 0
        self._window = [0, 0, 0]        # packets, skipped, drops this minute
        self._win_start = now()
        self.stats = {"pps": 0, "drops": 0, "skipped": 0, "errors": 0,
                      "flooders": [], "state": "ok"}

    def admit(self, mac):
        """True if a packet from mac goes to the detectors."""
        t = self.now()
        with self._lock:
            sec = int(t)
            if sec != self._sec:
                self._sec = sec
                self._per_mac.clear()
            self.total += 1
            self._window[0] += 1
            if not mac:
                return True
            self._per_mac[mac] += 1
            if self._per_mac[mac] <= self.per_mac:
                return True
            self.skipped += 1
            self._window[1] += 1
            self.flooders[mac] = self.flooders.get(mac, 0) + 1
            return False

    def error(self, module):
        with self._lock:
            self.errors[module] += 1

    def kernel(self, received_dropped):
        if received_dropped:
            with self._lock:
                self.drops += received_dropped[1]
                self._window[2] += received_dropped[1]

    def tick(self):
        """Once a minute (or so): publish stats and alert."""
        t = self.now()
        with self._lock:
            span = max(1.0, t - self._win_start)
            pkts, skipped, drops = self._window
            flooders = sorted(self.flooders.items(), key=lambda kv: -kv[1])[:5]
            errors = dict(self.errors)
            self._window = [0, 0, 0]
            self._win_start = t
            self.flooders.clear()
            self.errors.clear()
        state = "ok"
        if drops >= self.drop_alert:
            state = "overloaded"
            self.alert("drops", "WARNING",
                       f"SENSOR OVERLOADED: the kernel dropped {drops} packets "
                       f"LANGuard couldn't process in the last {int(span)} s "
                       f"({int(pkts / span)}/s). A flood can be used to hide an "
                       f"attack in the noise", drops=drops, pps=int(pkts / span))
        for mac, n in flooders:
            if n >= self.per_mac * 5:
                state = "flooded" if state == "ok" else state
                self.alert(f"flood:{mac}", "WARNING",
                           f"Packet flood from {mac}: {n} of its packets were "
                           f"skipped (over {self.per_mac}/s). Other devices are "
                           f"still checked normally", mac=mac, skipped=n)
        for module, n in errors.items():
            if n >= self.error_alert:
                state = "errors" if state == "ok" else state
                self.alert(f"errors:{module}", "WARNING",
                           f"The {module} detector failed on {n} packets in "
                           f"{int(span)} s: malformed packets, possibly crafted "
                           f"to crash it", module=module, errors=n)
        self.stats = {"pps": int(pkts / span), "drops": drops,
                      "skipped": skipped, "errors": sum(errors.values()),
                      "flooders": [m for m, _ in flooders], "state": state,
                      "total_drops": self.drops}
        if state != "ok":
            log.debug("[sensor] %s", self.stats)
        return self.stats
