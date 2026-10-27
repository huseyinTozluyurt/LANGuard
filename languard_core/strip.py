"""
Real-time SSL-stripping detection, from this machine's own web traffic.

sslstrip and bettercap's hstshijack sit in the middle (after ARP/DHCP/IPv6
spoofing) and rewrite https:// links to http://, so the browser keeps talking
plain HTTP to sites it normally reaches over HTTPS. The active probes in
tls.py only cover a few public sites; this watches every site you visit:

  * learns which hosts this machine reaches over HTTPS (the SNI name in each
    TLS ClientHello); every site on the HSTS preload list (hsts.py) counts
    too, plus a short built-in list of big sites when that isn't downloaded
  * a plain-HTTP request to such a host that is NOT followed within a few
    seconds by an HTTPS connection (the normal http -> https redirect) means
    the upgrade was stripped
  * a plain-HTTP POST to such a host (a login form) is flagged at once
  * a password sent over plain HTTP to *any* site is flagged: that covers the
    first visit to a site LANGuard can't know is HTTPS (`https_only` in
    protect makes the HTTPS guard upgrade every site, like a browser's
    HTTPS-Only mode)
  * a plain-HTTP request to a look-alike of a known HTTPS host
    (wwww.google.com, webmail.examp1e.com, google.corn) is the hstshijack
    trick for getting around HSTS

Only packet headers and the first bytes of requests are read; nothing is
stored but host names. During a captive portal (see tls.py) findings are
logged as INFO, because portals hijack plain HTTP the same way.
"""

import re
import threading
import time
from collections import OrderedDict

from . import hsts
from .core import Module, load_state, log, save_state

# Big sites that are HSTS-preloaded (browsers never use http for them) plus
# their usual login hosts. Suffix match: "mail.google.com" counts.
PRELOADED = (
    "google.com", "gmail.com", "youtube.com", "facebook.com", "instagram.com",
    "whatsapp.com", "twitter.com", "x.com", "linkedin.com", "github.com",
    "gitlab.com", "paypal.com", "microsoft.com", "live.com", "outlook.com",
    "office.com", "microsoftonline.com", "apple.com", "icloud.com",
    "amazon.com", "wikipedia.org", "cloudflare.com", "dropbox.com",
    "proton.me", "protonmail.com", "stackoverflow.com", "reddit.com",
)
UPGRADE_WINDOW = 6          # seconds a browser has to follow http -> https
POOL_SECONDS = 300          # an HTTPS connection may be reused this long
BURST_SECONDS, BURST_COUNT = 30, 3
MAX_HOSTS = 5000            # learned HTTPS hosts kept (least recent dropped)
# Certificate checks (OCSP/CRL) are plain HTTP by design, even to big sites.
PKI_PATHS = (".crl", ".crt", ".cer", ".p7c", "/ocsp", "/pkiops/", "/crl")
# Captive-portal checks are plain HTTP on purpose; the guard never touches them.
CHECK_HOSTS = {"connectivitycheck.gstatic.com", "www.gstatic.com",
               "clients3.google.com", "captive.apple.com",
               "detectportal.firefox.com", "connectivity-check.ubuntu.com",
               "nmcheck.gnome.org", "www.msftconnecttest.com",
               "www.msftncsi.com"}
CHECK_PATHS = ("/generate_204", "/gen_204", "/hotspot-detect.html",
               "/success.txt", "/canonical.html", "/connecttest.txt",
               "/ncsi.txt", "/check_network_status.txt")
PASSWORD_FIELD = re.compile(
    rb'(?:^|[&?"\'\s{,])(?:password|passwd|passwort|pass|pwd|pin|secret)'
    rb'(?:["\']?\s*[:=])', re.I)
INTERNAL = (".local", ".lan", ".home", ".internal", ".localdomain", ".arpa")
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"PATCH ", b"DELETE ",
                b"OPTIONS ")


# ------------------------------------------------------------- parsers --
def parse_sni(data):
    """Server name from a TLS ClientHello record, or None."""
    try:
        if len(data) < 43 or data[0] != 0x16 or data[5] != 0x01:
            return None
        i = 43                                       # after random
        i += 1 + data[i]                             # session id
        i += 2 + int.from_bytes(data[i:i + 2], "big")    # cipher suites
        i += 1 + data[i]                             # compression methods
        end = min(len(data), i + 2 + int.from_bytes(data[i:i + 2], "big"))
        i += 2
        while i + 4 <= end:
            etype = int.from_bytes(data[i:i + 2], "big")
            elen = int.from_bytes(data[i + 2:i + 4], "big")
            if etype == 0:                           # server_name
                j = i + 4 + 2                        # skip list length
                if data[j] == 0:                     # host_name
                    n = int.from_bytes(data[j + 1:j + 3], "big")
                    name = data[j + 3:j + 3 + n].decode("ascii")
                    return name.lower().rstrip(".") or None
                return None
            i += 4 + elen
    except (IndexError, UnicodeDecodeError):
        pass
    return None


def parse_http_request(data):
    """(method, host, path, user_agent) from the start of a plain-HTTP request, or None."""
    if not data.startswith(HTTP_METHODS):
        return None
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 2:
        return None
    host = ua = None
    for line in lines[1:]:
        k, _, v = line.partition(":")
        k = k.strip().lower()
        if k == "host":
            host = v.strip().lower()
        elif k == "user-agent":
            ua = v.strip()
    if not host:
        return None
    if host.startswith("["):                         # [v6]:port
        host = host.split("]")[0] + "]"
    else:
        host = host.split(":")[0]
    return parts[0], host.rstrip("."), parts[1][:200], ua or ""


def has_password(data):
    """True if the body of a plain-HTTP request carries a password field."""
    body = data.split(b"\r\n\r\n", 1)
    return len(body) == 2 and bool(PASSWORD_FIELD.search(body[1][:4096]))


def _pki(path):
    p = (path or "").lower()
    return p.split("?")[0].endswith(PKI_PATHS) or "/ocsp" in p or "/pkiops/" in p


def _edit_distance(a, b, limit=2):
    """Levenshtein distance, giving up (limit + 1) once it exceeds limit."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > limit:
            return limit + 1
        prev = cur
    return prev[-1]


def _clean(text):
    """Host names come off the wire: keep them printable and short."""
    return "".join(c if c.isprintable() else "?" for c in text)[:120]


# ------------------------------------------------------------- module --
class StripMonitor(Module):
    name = "strip"

    def __init__(self, ctx):
        super().__init__(ctx)
        me = ctx.my_ip
        src = f"src host {me} and " if me else ""
        # Only the packets that matter, filtered in the kernel: the first
        # data segment of plain-HTTP requests (GET/POST/PUT/HEAD), TLS
        # ClientHellos, SYNs to 443 and QUIC handshakes (an https upgrade).
        payload = "tcp[((tcp[12:1] & 0xf0) >> 2):4]"
        self.bpf = (
            f"{src}("
            f"(tcp dst port 80 and ({payload} = 0x47455420 or "
            f"{payload} = 0x504f5354 or {payload} = 0x50555420 or "
            f"{payload} = 0x48454144)) or "
            f"(tcp dst port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2)] = 0x16 or "
            f"(tcp[13] & 0x12) = 0x02)) or "
            f"(udp dst port 443 and (udp[8] & 0xc0) = 0xc0))")
        cfg = self.cfg
        self.window = cfg.get("upgrade_window", UPGRADE_WINDOW)
        self.extra = {h.lower().rstrip(".") for h in cfg.get("sites", [])}
        self.extra |= {h.lower() for h in ctx.cfg.get("tls", {}).get("sites", [])}
        self.use_hsts = cfg.get("hsts_preload", True)
        state = load_state("strip", {})
        self.secure = OrderedDict(sorted(state.get("hosts", {}).items(),
                                         key=lambda kv: kv[1]))
        self.https_ips = {}            # dst ip -> last https/quic handshake
        self.https_names = {}          # sni -> last ClientHello
        self.pending = {}              # host -> (time, method, ip, path)
        self.http_times = {}           # secure host -> recent plain-HTTP times
        self._last_save = 0
        self._lock = threading.RLock()

    # ---- what counts as an HTTPS site ----
    def is_secure(self, host):
        if host in self.secure or host in self.extra:
            return True
        if any(host == d or host.endswith("." + d) for d in PRELOADED):
            return True
        return self.use_hsts and hsts.preloaded(host)

    def lookalike(self, host):
        """The known HTTPS host this name imitates, or None."""
        if self.is_secure(host) or len(host) < 6:
            return None
        nodigits = host.translate(str.maketrans("", "", "0123456789"))
        candidates = list(self.secure) + list(self.extra) + list(PRELOADED)
        for good in candidates:
            if len(good) < 8 or host.endswith("." + good) or \
                    good.endswith("." + host):
                continue                  # too short to judge, or a subdomain
            if good.translate(str.maketrans("", "", "0123456789")) == nodigits:
                continue                  # cdn1 vs cdn2: numbering, not a trick
            if _edit_distance(host, good) <= (1 if len(good) < 10 else 2):
                return good
        return None

    def _portal(self):
        return bool(getattr(self.ctx, "captive_portal", False))

    # ---- pure logic ----
    def https_seen(self, host=None, ip=None, now=None):
        """An HTTPS (or QUIC) connection started to ip, for SNI host."""
        with self._lock:
            self._https_seen(host, ip, now or time.time())

    def _https_seen(self, host, ip, now):
        if ip:
            self.https_ips[ip] = now
        if host:
            self.https_names[host] = now
            self.secure[host] = now
            self.secure.move_to_end(host)
            while len(self.secure) > MAX_HOSTS:
                self.secure.popitem(last=False)
            self.pending.pop(host, None)
            self._maybe_save(now)
        if ip:
            for h in [h for h, p in self.pending.items() if p[2] == ip]:
                del self.pending[h]
        self._expire(now)

    def http_request(self, method, host, path="/", ip=None, ua=None, now=None):
        """This machine sent a plain-HTTP request. Returns True if it is a
        stripping sign (raised now or once the upgrade window passes).

        `ua` is the User-Agent: only browsers are judged (sslstrip's victims
        are people at a browser; apt and updaters use plain HTTP by design)."""
        with self._lock:
            return self._http_request(method, host, path, ip, ua,
                                      now or time.time())

    def _http_request(self, method, host, path, ip, ua, now):
        self._expire(now)
        host = (host or "").lower().rstrip(".")
        if not host:
            return False
        if ua is not None and "Mozilla/" not in ua:
            return False
        if _pki(path):
            return False
        if host.replace(".", "").isdigit() or host.startswith("["):
            return False                             # bare IPs: no name to judge
        if self.is_secure(host):
            if method == "POST":
                self._strip(host, method, path, "sent a login/form POST over "
                            "plain HTTP", ip)
                return True
            # A browser that still has a pooled HTTPS connection to the host
            # follows the redirect over it, with no new handshake to see. Then
            # judge by volume: a redirect is one request, a stripped page
            # loads everything over plain HTTP.
            recent = self.https_names.get(host, 0) > now - POOL_SECONDS
            q = self.http_times.setdefault(host, [])
            q[:] = [x for x in q if now - x < BURST_SECONDS] + [now]
            if recent:
                if len(q) >= BURST_COUNT:
                    self._strip(host, method, path, f"was followed by "
                                f"{len(q)} more plain-HTTP requests in "
                                f"{BURST_SECONDS}s instead of a redirect", ip)
                    return True
                return False
            if host not in self.pending:
                self.pending[host] = (now, method, ip, path)
            return True
        good = self.lookalike(host)
        if good:
            # Same registered domain (cdn1 vs cdn2.example.com) is weaker.
            same = host.split(".")[-2:] == good.split(".")[-2:]
            self._raise(f"lookalike:{host}", "WARNING" if same else "CRITICAL",
                        f"SSL STRIPPING (HSTS bypass): your browser is using "
                        f"plain-HTTP '{_clean(host)}', a look-alike of "
                        f"'{good}', which you normally reach over HTTPS. This "
                        f"is how sslstrip2/hstshijack get around HSTS. Don't "
                        f"type passwords; check the address bar for https://",
                        host=_clean(host), imitates=good)
            if ip and not same and not self._portal():
                self.respond("lookalike", ip=ip, host=_clean(host))
            return True
        return False

    def verdict(self, method, host, path="/", ua=None):
        """What the HTTPS guard (guard.py) does with a plain-HTTP request
        before it leaves this machine: ("upgrade", None) sends the browser to
        https://, ("block", imitated_host) stops a look-alike, ("pass", None)
        lets it through. Same rules as detection: browsers only, never
        certificate checks, captive-portal checks or a captive portal."""
        host = (host or "").lower().rstrip(".")
        path = (path or "/").lower().split("?")[0]
        if not host or not ua or "Mozilla/" not in ua or self._portal():
            return "pass", None
        if host in CHECK_HOSTS or path in CHECK_PATHS or _pki(path):
            return "pass", None
        if host.replace(".", "").isdigit() or host.startswith("["):
            return "pass", None
        with self._lock:
            if self.is_secure(host):
                return "upgrade", None
            good = self.lookalike(host)
        if good:
            return "block", good
        if self.ctx.cfg.get("protect", {}).get("https_only") and "." in host \
                and not host.endswith(INTERNAL):
            return "upgrade", None          # HTTPS-only: every public site
        return "pass", None

    def plain_password(self, host, ip=None, ua=None):
        """A request body with a password field went out over plain HTTP."""
        host = (host or "").lower().rstrip(".")
        if not host or (ua is not None and "Mozilla/" not in ua):
            return False
        local = host.endswith(INTERNAL) or "." not in host or \
            host.replace(".", "").isdigit()
        self._raise(f"plainpw:{host}", "WARNING",
                    f"PASSWORD SENT IN PLAIN TEXT to {_clean(host)} over "
                    f"http://: anyone on this network can read it"
                    f"{' (a device on your LAN)' if local else ''}. If this "
                    f"site normally uses https://, your connection may have "
                    f"been stripped; change that password over HTTPS",
                    host=_clean(host))
        return True

    def _expire(self, now):
        for h, (t, method, ip, path) in list(self.pending.items()):
            if now - t < self.window:
                continue
            del self.pending[h]
            upgraded = (self.https_names.get(h, 0) >= t
                        or (ip and self.https_ips.get(ip, 0) >= t))
            if not upgraded:
                self._strip(h, method, path, "was not redirected to HTTPS", ip)
        cut = now - POOL_SECONDS
        for h in [h for h, q in self.http_times.items() if now - q[-1] > BURST_SECONDS]:
            del self.http_times[h]
        for d in (self.https_ips, self.https_names):
            for k in [k for k, t in d.items() if t < cut]:
                del d[k]

    def _strip(self, host, method, path, what, ip=None):
        self._raise(f"strip:{host}", "CRITICAL",
                    f"SSL STRIPPING: a plain-HTTP {method} to {_clean(host)} "
                    f"{what}, but this machine normally reaches it over "
                    f"HTTPS. Someone in the middle may be downgrading your "
                    f"connections. Don't log in; check for https:// and the "
                    f"padlock", host=_clean(host), method=method)
        if ip and not self._portal():       # end the plain-HTTP session
            self.respond("ssl_strip", ip=ip, host=_clean(host))

    def _raise(self, key, level, msg, **data):
        if self._portal():
            level = "INFO"
            msg = "(captive portal active, so expected) " + msg
        self.alert(key, level, msg, **data)
        check = getattr(self.ctx, "tls_check", None)
        if check and level != "INFO":
            check(data.get("imitates") or data.get("host"))

    def tick_expire(self):
        with self._lock:
            self._expire(time.time())

    def _maybe_save(self, now, force=False):
        if force or now - self._last_save > 60:
            self._last_save = now
            try:
                save_state("strip", {"hosts": dict(self.secure)})
            except OSError as e:
                log.debug("[strip] save failed: %s", e)

    def flush(self):
        self._maybe_save(time.time(), force=True)

    def top_hosts(self, n=6):
        """The most recently used HTTPS hosts (for tls.py's active probes)."""
        return list(reversed(self.secure))[:n]

    # ---- scapy glue ----
    def handle(self, pkt):
        from scapy.all import IP, TCP, UDP
        if not pkt.haslayer(IP):
            return
        dst = pkt[IP].dst
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            data = bytes(t.payload)
            if t.dport == 80 and data:
                req = parse_http_request(data)
                if req:
                    self.http_request(req[0], req[1], req[2], ip=dst, ua=req[3])
                    if req[0] in ("POST", "PUT") and has_password(data):
                        self.plain_password(req[1], ip=dst, ua=req[3])
            elif t.dport == 443:
                self.https_seen(parse_sni(data) if data else None, ip=dst)
        elif pkt.haslayer(UDP) and pkt[UDP].dport == 443:
            self.https_seen(None, ip=dst)

    def start(self):
        def loop():                 # pending upgrades expire even when idle
            while True:
                time.sleep(2)
                try:
                    self.tick_expire()
                except Exception as e:
                    log.debug("[strip] expire failed: %s", e)
        threading.Thread(target=loop, name="strip-expire", daemon=True).start()
        self.ctx.strip_hosts = self.top_hosts
        self.ctx.strip = self
