"""
Wi-Fi attack detection (needs a card in monitor mode).

  * deauthentication / disassociation floods (used to kick you off Wi-Fi,
    capture handshakes, or push you onto an evil twin)
  * evil twin access points: your SSID broadcast by an unknown BSSID,
    especially with weaker (or no) encryption

Put a card into monitor mode first, e.g.:
    sudo ip link set wlan1 down && sudo iw dev wlan1 set type monitor \
      && sudo ip link set wlan1 up
(A second USB adapter is best; monitor mode on your main card drops your
connection.)
"""

import subprocess
import threading
import time
from collections import defaultdict, deque

from .core import Module, log

BROADCAST = "ff:ff:ff:ff:ff:ff"


class WifiMonitor(Module):
    name = "wifi"
    bpf = ("type mgt subtype deauth or type mgt subtype disassoc "
           "or type mgt subtype beacon")

    def __init__(self, ctx, hop=False):
        super().__init__(ctx)
        self.hop = hop
        self.ssids = set(self.cfg.get("ssids") or [])
        self.trusted = {b.lower() for b in self.cfg.get("trusted_bssids") or []}
        self.aps = defaultdict(dict)     # ssid -> {bssid: {crypto, channel, seen}}
        self.deauths = defaultdict(deque)

    # ---- pure logic ----
    def deauth(self, src, dst, bssid, now=None):
        """Feed one deauth/disassoc frame. Returns True if suspicious."""
        now = now or time.time()
        c = self.cfg
        bad = False
        target = bssid or src
        q = self.deauths[target]
        q.append(now)
        while q and now - q[0] > c["deauth_window"]:
            q.popleft()
        if len(q) >= c["deauth_threshold"]:
            bad = True
            mine = " (YOUR network)" if target in self.trusted else ""
            self.alert(f"flood:{target}", "CRITICAL",
                       f"DEAUTH FLOOD against AP {target}{mine}: {len(q)} "
                       f"frames in {c['deauth_window']}s", bssid=target)
        if dst == BROADCAST and (not self.trusted or target in self.trusted):
            self.alert(f"bcast:{target}", "WARNING",
                       f"Broadcast deauth from {src} on {target}: kicks "
                       f"every client off", bssid=target)
            bad = True
        return bad

    def beacon(self, ssid, bssid, crypto, channel, now=None):
        """Feed one beacon. Returns True if it looks like an evil twin."""
        if not ssid:
            return False
        now = now or time.time()
        crypto = frozenset(crypto or {"OPN"})
        known = self.aps[ssid]
        new = bssid not in known
        known[bssid] = {"crypto": crypto, "channel": channel, "seen": now}
        if ssid not in self.ssids or not new:
            return False

        if self.trusted:
            if bssid in self.trusted:
                return False
            self.alert(f"twin:{ssid}:{bssid}", "CRITICAL",
                       f"EVIL TWIN: '{ssid}' broadcast by untrusted AP {bssid} "
                       f"(ch {channel}, {'/'.join(sorted(crypto))})",
                       ssid=ssid, bssid=bssid)
            self.respond("evil_twin", bssid=bssid, ssid=ssid)
            return True

        others = {b: v for b, v in known.items() if b != bssid}
        if not others:
            log.info("[wifi] Learned '%s' at %s (ch %s, %s)", ssid, bssid,
                     channel, "/".join(sorted(crypto)))
            return False
        weaker = any(_strength(crypto) < _strength(v["crypto"])
                     for v in others.values())
        level = "CRITICAL" if weaker else "WARNING"
        why = ("with WEAKER security than the original" if weaker
               else "(normal for mesh/extenders; add trusted_bssids to be sure)")
        self.alert(f"twin:{ssid}:{bssid}", level,
                   f"New AP {bssid} broadcasting '{ssid}' {why} "
                   f"(ch {channel}, {'/'.join(sorted(crypto))})",
                   ssid=ssid, bssid=bssid)
        if weaker:
            self.respond("evil_twin", bssid=bssid, ssid=ssid)
        return weaker

    # ---- scapy glue ----
    def handle(self, pkt):
        from scapy.all import Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas
        if not pkt.haslayer(Dot11):
            return
        d = pkt[Dot11]
        if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            self.deauth((d.addr2 or "").lower(), (d.addr1 or "").lower(),
                        (d.addr3 or "").lower())
        elif pkt.haslayer(Dot11Beacon):
            try:
                st = pkt[Dot11Beacon].network_stats()
            except Exception:
                return
            ssid = st.get("ssid") or ""
            if isinstance(ssid, bytes):
                ssid = ssid.decode(errors="ignore")
            self.beacon(ssid, (d.addr3 or "").lower(), st.get("crypto"),
                        st.get("channel"))

    def start(self):
        if not self.hop:
            return
        iface = self.ctx.iface

        def loop():
            chans = list(range(1, 14)) + [36, 40, 44, 48, 149, 153, 157, 161]
            while True:
                for ch in chans:
                    subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)],
                                   capture_output=True)
                    time.sleep(0.4)
        threading.Thread(target=loop, daemon=True).start()

    def survey(self):
        print(f"{'SSID':<32} {'BSSID':<18} {'CH':<4} SECURITY")
        for ssid in sorted(self.aps):
            for bssid, v in sorted(self.aps[ssid].items()):
                print(f"{ssid[:31]:<32} {bssid:<18} {str(v['channel']):<4} "
                      f"{'/'.join(sorted(v['crypto']))}")


def _strength(crypto):
    s = " ".join(crypto).upper()
    if "WPA3" in s or "SAE" in s:
        return 4
    if "WPA2" in s:
        return 3
    if "WPA" in s:
        return 2
    if "WEP" in s:
        return 1
    return 0
