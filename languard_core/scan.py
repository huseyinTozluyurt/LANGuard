"""
Port scan and brute-force detection for this host.

  * one source probing many ports in a short window (SYN / connect scans)
  * stealth scans: NULL, FIN and XMAS TCP probes
  * many connection attempts to a sensitive port (SSH, RDP, SMB...)
Optionally blocks offenders with UFW (`scan.block: true` in the config).
"""

import subprocess
import time
from collections import defaultdict, deque

from .core import Module, log

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


class ScanMonitor(Module):
    name = "scan"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.bpf = (f"tcp and dst host {ctx.my_ip}" if ctx.my_ip else "tcp")
        self.ports = defaultdict(deque)          # src -> deque[(t, port)]
        self.conns = defaultdict(deque)          # (src, port) -> deque[t]
        self.blocked = set()
        self.watch = set(self.cfg["watch_ports"])

    # ---- pure logic ----
    def observe(self, src, dport, flags, now=None):
        """Feed one inbound TCP packet. Returns True if suspicious."""
        if src in (self.ctx.my_ip, "127.0.0.1"):
            return False
        now = now or time.time()
        c = self.cfg
        bad = False

        stealth = {0: "NULL", FIN: "FIN", FIN | PSH | URG: "XMAS"}.get(flags & 0x3F)
        if stealth:
            bad = True
            self.alert(f"stealth:{src}", "WARNING",
                       f"{stealth} stealth scan from {src} (port {dport})",
                       src=src, kind=stealth)
            self._maybe_block(src)

        if flags & SYN and not flags & ACK:
            q = self.ports[src]
            q.append((now, dport))
            while q and now - q[0][0] > c["window"]:
                q.popleft()
            distinct = {p for _, p in q}
            if len(distinct) >= c["port_threshold"]:
                bad = True
                sample = ", ".join(str(p) for p in sorted(distinct)[:10])
                self.alert(f"portscan:{src}", "WARNING",
                           f"Port scan from {src}: {len(distinct)} ports in "
                           f"{c['window']}s ({sample}...)", src=src,
                           ports=len(distinct))
                self._maybe_block(src)

            if dport in self.watch:
                cq = self.conns[(src, dport)]
                cq.append(now)
                while cq and now - cq[0] > c["window"]:
                    cq.popleft()
                if len(cq) >= c["conn_threshold"]:
                    bad = True
                    self.alert(f"brute:{src}:{dport}", "CRITICAL",
                               f"Possible brute force: {len(cq)} connection "
                               f"attempts to port {dport} from {src} in "
                               f"{c['window']}s", src=src, port=dport)
                    self._maybe_block(src)
        return bad

    def _maybe_block(self, src):
        # Active protection blocks it in nftables (expires, never the router)
        self.respond("port_scan", src_ip=src)
        if not self.cfg.get("block") or src in self.blocked:
            return
        if src in (self.ctx.gateway, self.ctx.my_ip) or \
                src in self.cfg.get("never_block", []):
            return
        self.blocked.add(src)
        try:
            r = subprocess.run(["ufw", "insert", "1", "deny", "from", src],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                self.alert(f"blocked:{src}", "INFO",
                           f"Blocked {src} with UFW "
                           f"(undo: sudo ufw delete deny from {src})", src=src)
            else:
                log.warning("[scan] ufw block failed: %s", r.stderr.strip())
        except FileNotFoundError:
            log.warning("[scan] ufw not installed; cannot block %s", src)

    # ---- scapy glue ----
    def handle(self, pkt):
        from scapy.all import IP, TCP
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            self.observe(pkt[IP].src, pkt[TCP].dport, int(pkt[TCP].flags))
