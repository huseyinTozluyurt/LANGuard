"""
Network identity: is this really the network (and router) you think it is?

An ARP probe can only show *which* MAC answers for the router. An evil twin
(a fake access point with your Wi-Fi's name) or a box that clones the
router's MAC answers just as well. This module adds checks a clone can't pass
as easily, all read-only:

  * Wi-Fi identity: the access points (BSSIDs) and the security (WPA2, WPA3,
    open) each network was seen with. A known network that suddenly has no
    encryption, or weaker encryption, is an evil twin until proven otherwise
    (CRITICAL, and active protection leaves it). A new BSSID for a network
    you marked home is reported (a new mesh node, or a twin)
  * the router's HTTPS key: most home routers serve their admin page over
    HTTPS with their own certificate. Its fingerprint is remembered per
    network; a clone can copy the MAC but not the router's private key. A
    different certificate means a different box (or a router reset /
    firmware update: then run 'sudo languard baseline --reset')
  * first contact: on a network seen for the first time that is public or
    open Wi-Fi, the router can't be verified against anything. LANGuard says
    so instead of pretending, and keeps public-network hardening on

The result is ctx.router_trust, shown in the app: verified, verified+key,
first contact or doubtful.
"""

import hashlib
import re
import socket
import ssl
import time

from . import baseline
from .core import Module, log

KEY_RECHECK = 1800              # seconds between router key checks
FIRST_CONTACT = 3600            # a network this new has no history to trust
SECURITY_RANK = {"": 0, "--": 0, "WEP": 1, "WPA1": 2, "WPA": 2, "WPA2": 3,
                 "WPA3": 4, "OWE": 2}
_COLON = re.compile(r"(?<!\\):")


def split_nmcli(line):
    """nmcli -t escapes ':' inside values as '\\:'."""
    return [p.replace("\\:", ":").replace("\\\\", "\\") for p in _COLON.split(line)]


def security_rank(sec):
    """Strongest scheme named in nmcli's SECURITY field ('WPA2 WPA3')."""
    words = (sec or "").replace("802.1X", "WPA2").split()
    return max([SECURITY_RANK.get(w, 2) for w in words] or [0])


def wifi_identity(iface, run):
    """{'ssid', 'bssid', 'security'} of the access point iface is on, or None."""
    rc, out = run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,SECURITY,DEVICE",
                   "device", "wifi", "list", "--rescan", "no"])
    if rc != 0:
        return None
    for line in out.splitlines():
        p = split_nmcli(line)
        if len(p) >= 5 and p[0] == "yes" and p[-1] == iface:
            return {"ssid": p[1], "bssid": p[2].lower(),
                    "security": p[3].strip() if p[3].strip() != "--" else ""}
    return None


def tls_fingerprint(ip, ports=(443, 8443), timeout=3):
    """SHA-256 of the certificate the host serves on its HTTPS admin port, or
    None. Not verified (routers use self-signed certificates): only compared
    with the one seen before."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=ip) as t:
                    der = t.getpeercert(binary_form=True)
            if der:
                return f"{port}:{hashlib.sha256(der).hexdigest()}"
        except (OSError, ssl.SSLError, ValueError):
            continue
    return None


def _run(cmd, timeout=8):
    import subprocess
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


class NetIdMonitor(Module):
    name = "netid"
    threaded = True
    interval = 120

    def __init__(self, ctx, run=None, fingerprint=None, now=time.time):
        super().__init__(ctx)
        self.base = baseline.get(ctx)
        self.run_cmd = run or _run
        self.fingerprint = fingerprint or tls_fingerprint
        self.now = now
        self.interval = self.cfg.get("interval", 120)
        self.trust = {"level": "unverified", "detail": "router not verified yet"}
        self.wifi = None
        self._fp_at = -KEY_RECHECK
        self._key_bad = False
        self._first_said = False
        ctx.router_trust = self.trust
        ctx.netid = self

    def _set(self, level, detail):
        self.trust.clear()
        self.trust.update(level=level, detail=detail, wifi=self.wifi)

    # ---- Wi-Fi identity ----
    def check_wifi(self, ident=None):
        """Compare the access point with what this network was seen with.
        Returns 'downgrade', 'new_bssid', 'ok' or None (not on Wi-Fi)."""
        ident = ident if ident is not None else wifi_identity(self.ctx.iface,
                                                              self.run_cmd)
        self.wifi = ident
        if not ident:
            return None
        rec = self.base.rec.get("wifi") or {}
        known = set(rec.get("bssids") or [])
        sec, old = ident["security"], rec.get("security")
        verdict = "ok"
        if old is not None and security_rank(sec) < security_rank(old):
            verdict = "downgrade"
            self.alert(f"downgrade:{ident['bssid']}", "CRITICAL",
                       f"EVIL TWIN: Wi-Fi '{ident['ssid']}' was "
                       f"{old or 'open'} on this network, now it is "
                       f"{sec or 'OPEN (no encryption)'} (access point "
                       f"{ident['bssid']}). A fake access point with your "
                       f"network's name is the usual reason",
                       ssid=ident["ssid"], bssid=ident["bssid"],
                       security=sec, expected=old)
            self.respond("evil_twin", bssid=ident["bssid"], ssid=ident["ssid"])
        elif known and ident["bssid"] not in known:
            verdict = "new_bssid"
            home = self.base.kind == "home"
            self.alert(f"bssid:{ident['bssid']}", "WARNING" if home else "INFO",
                       f"Wi-Fi '{ident['ssid']}' is now served by access point "
                       f"{ident['bssid']}, not seen on this network before "
                       f"({', '.join(sorted(known)[:4])}). Fine for a new "
                       f"mesh node or extender; otherwise it may be an evil "
                       f"twin", ssid=ident["ssid"], bssid=ident["bssid"])
        if verdict != "downgrade":
            with self.base._lock:
                w = self.base.rec.setdefault("wifi", {})
                w["ssid"] = ident["ssid"]
                w["bssids"] = sorted(known | {ident["bssid"]})[-16:]
                if old is None or security_rank(sec) >= security_rank(old):
                    w["security"] = sec
            self.base.save()
        return verdict

    # ---- router key ----
    def check_router_key(self, fp=None):
        """Compare the router's HTTPS certificate with the remembered one.
        Returns 'new', 'same', 'changed' or None (no HTTPS admin page)."""
        gw = self.ctx.gateway
        if not gw or not self.base.gw_verified:
            return None
        fp = fp if fp is not None else self.fingerprint(gw)
        self._fp_at = self.now()
        if not fp:
            return None
        old = self.base.rec.get("gw_key")
        if old is None:
            with self.base._lock:
                self.base.rec["gw_key"] = fp
            self.base.save()
            log.info("[netid] Remembered router %s's HTTPS key (%s)", gw, fp[:20])
            return "new"
        if old == fp:
            self._key_bad = False
            return "same"
        self.alert(f"key:{fp[:16]}", "CRITICAL",
                   f"ROUTER IDENTITY CHANGED: {gw} answers with the verified "
                   f"MAC {self.base.gw_mac}, but its HTTPS certificate is not "
                   f"the one this network's router had. A box that cloned the "
                   f"router's MAC (evil twin) can't copy its key. If you reset "
                   f"or updated the router, accept it: sudo languard baseline "
                   f"--reset", ip=gw, mac=self.base.gw_mac, cert=fp, expected=old)
        self._key_bad = True
        return "changed"

    # ---- verdict ----
    def first_contact(self):
        rec = self.base.rec
        seen = rec.get("first_seen") or self.now()
        public = self.base.kind == "public" or (
            self.wifi is not None and not self.wifi.get("security"))
        return public and self.now() - seen < FIRST_CONTACT \
            and not rec.get("gw_key")

    def evaluate(self, wifi=None, key=None):
        w = self.check_wifi() if wifi is None else wifi
        k = key
        if k is None and (self.now() - self._fp_at > KEY_RECHECK
                          or w == "new_bssid"):
            k = self.check_router_key()
        if k == "same":
            self._key_bad = False
        elif k == "changed":
            self._key_bad = True
        if w == "downgrade" or self._key_bad:
            self._set("doubtful", "the Wi-Fi security or the router's HTTPS key "
                      "changed: possible evil twin")
        elif not self.base.gw_verified:
            self._set("unverified", "router not verified yet")
        elif self.first_contact():
            self._set("first contact", "first visit to a public network: "
                      "the router can't be checked against anything yet")
            if not self._first_said:
                self._first_said = True
                self.alert("first", "INFO",
                           "First visit to this public network: LANGuard "
                           "trusts the router it finds now, and can't tell an "
                           "evil twin from the real hotspot. Public-network "
                           "hardening stays on; prefer networks you know")
        elif self.base.rec.get("gw_key"):
            self._set("verified+key", "MAC verified by probes and the router's "
                      "HTTPS key matches")
        else:
            self._set("verified", "MAC verified by probes (the router has no "
                      "HTTPS admin page to check its key)")
        return self.trust["level"]

    def tick(self):
        self.evaluate()
