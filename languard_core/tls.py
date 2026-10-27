"""
TLS interception and SSL-stripping detection.

Every few minutes LANGuard connects to well-known HTTPS sites and to the
sites you use most (learned by strip.py) from this machine, the same path
your browser uses:
  * certificate fails validation  -> a MITM proxy is presenting a fake cert
  * issuing CA changed            -> traffic may be going through an
                                     interception proxy with a trusted CA
  * http:// no longer redirects to https:// -> SSL stripping
It also runs at once when strip.py sees a stripping sign.

Captive portals (hotel and café logins) break HTTPS and hijack plain HTTP,
which looks exactly like an attack. A portal found when joining a network
pauses these checks (and turns strip.py's findings into INFO) until you log
in, for at most 20 minutes. A "portal" that appears later on a network that
already had full internet is reported instead: an attacker can fake one to
silence alerts.
No scapy needed; this runs on Python's ssl module.
"""

import http.client
import socket
import ssl
import threading
import time

from .core import Module, load_state, log, save_state

CONNECTIVITY_URL = ("connectivity-check.ubuntu.com", "/")   # answers 204
PORTAL_MAX = 20 * 60        # never pause checks longer than this

# Sites that always answer http:// with a redirect to https:// (HSTS preloaded).
# Others, like www.google.com, may serve plain http to non-browsers, so for
# them we only alert once we have seen them redirect on this machine.
ALWAYS_REDIRECT = {"github.com", "www.wikipedia.org", "www.cloudflare.com"}


def fetch_cert(host, timeout=8):
    """{'ok': bool, 'issuer': str, 'error': str, 'kind': str}"""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        name = issuer.get("organizationName") or issuer.get("commonName", "?")
        return {"ok": True, "issuer": name, "error": None, "kind": None}
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "issuer": None, "error": str(e.verify_message or e),
                "kind": "verify"}
    except (OSError, ssl.SSLError) as e:
        return {"ok": False, "issuer": None, "error": str(e), "kind": "network"}


def http_redirects_to_https(host, timeout=8):
    """True/False, or None when the site can't be reached."""
    try:
        c = http.client.HTTPConnection(host, 80, timeout=timeout)
        c.request("GET", "/", headers={"User-Agent": "LANGuard"})
        r = c.getresponse()
        loc = r.getheader("Location") or ""
        c.close()
        return r.status in (301, 302, 303, 307, 308) and loc.startswith("https://")
    except (OSError, http.client.HTTPException):
        return None


def detect_portal(timeout=6):
    """True when a captive portal intercepts plain HTTP, False when the
    connectivity check answers normally (204), None when offline."""
    host, path = CONNECTIVITY_URL
    try:
        c = http.client.HTTPConnection(host, 80, timeout=timeout)
        c.request("GET", path, headers={"User-Agent": "LANGuard"})
        r = c.getresponse()
        body = r.read(512)
        c.close()
    except (OSError, http.client.HTTPException):
        return None
    return not (r.status == 204 or (r.status == 200 and not body.strip()))


class TLSMonitor(Module):
    name = "tls"
    threaded = True

    def __init__(self, ctx, fetch=fetch_cert, redirect=http_redirects_to_https,
                 portal=detect_portal):
        super().__init__(ctx)
        self.interval = self.cfg.get("interval", 300)
        self.fetch, self.redirect, self.portal = fetch, redirect, portal
        self.issuers = load_state("tls", {})
        self.redirects = load_state("tls_redirect", {})
        self.urgent = set()            # hosts strip.py asked us to check now
        self._wake = threading.Event()
        self._lock = threading.Lock()
        self.full_seen = False         # had normal internet on this network
        self.portal_since = None
        ctx.captive_portal = False
        ctx.tls_check = self.request_check

    # ---- captive portals ----
    def check_portal(self, now=None):
        """Update captive-portal state. Returns True while checks should
        wait (a portal found on joining, for at most PORTAL_MAX)."""
        now = now or time.time()
        if self.portal is None or not self.cfg.get("captive_portal_check", True):
            return False
        found = self.portal()
        if not found:
            if self.portal_since is not None:
                self.alert("portal_end", "INFO", "Captive portal gone (logged "
                           "in); HTTPS checks resumed")
            if found is False:
                self.full_seen = True
            self.portal_since = None
            self.ctx.captive_portal = False
            return False
        if self.portal_since is None:
            self.portal_since = now
            if self.full_seen:
                self.alert("portal_late", "WARNING",
                           "The internet connectivity check is suddenly being "
                           "intercepted on a network that worked normally. "
                           "Either the network wants you to log in again, or "
                           "someone in the middle is faking a captive portal. "
                           "HTTPS checks keep running", )
            else:
                self.alert("portal", "INFO",
                           "Captive portal detected (network login page). "
                           "HTTPS interception and SSL-strip checks wait "
                           "until you log in (at most 20 min)")
        if self.full_seen:
            self.ctx.captive_portal = False          # never silence mid-session
            return False
        if now - self.portal_since > PORTAL_MAX:
            if self.ctx.captive_portal:
                self.alert("portal_long", "WARNING",
                           "Captive portal still there after 20 min; HTTPS "
                           "checks resume, so expect alerts until you log in")
            self.ctx.captive_portal = False
            return False
        self.ctx.captive_portal = True
        return True

    # ---- on-demand checks from strip.py ----
    def request_check(self, host):
        if host:
            with self._lock:
                self.urgent.add(host)
            self._wake.set()

    def sites(self):
        sites = list(self.cfg.get("sites", []))
        learned = getattr(self.ctx, "strip_hosts", None)
        if learned and self.cfg.get("probe_learned", 6):
            try:
                sites += [h for h in learned(self.cfg.get("probe_learned", 6))
                          if h not in sites]
            except Exception as e:
                log.debug("[tls] learned hosts unavailable: %s", e)
        return sites

    # ---- pure logic ----
    def evaluate(self, host, res, pin=True):
        """Returns True if the result indicates interception. `pin` = also
        track the issuing CA (only for configured sites: the sites you
        happen to use change CAs too often for that to mean much)."""
        if res["kind"] == "network":
            log.debug("[tls] %s unreachable: %s", host, res["error"])
            return False
        if not res["ok"]:
            self.alert(f"verify:{host}", "CRITICAL",
                       f"TLS INTERCEPTION: the certificate for {host} failed "
                       f"validation ({res['error']}). Someone is presenting a "
                       f"fake certificate; don't log in anywhere until this "
                       f"is explained", host=host, error=res["error"])
            self.respond("tls_intercept", host=host)
            return True
        if not pin:
            return False
        old = self.issuers.get(host)
        if old is None:
            self.issuers[host] = res["issuer"]
            self._save()
            return False
        if res["issuer"] != old:
            self.alert(f"issuer:{host}:{res['issuer']}", "WARNING",
                       f"{host} is now signed by '{res['issuer']}' instead of "
                       f"'{old}'. Could be a normal CA change, or an "
                       f"interception proxy whose CA was added to this "
                       f"machine", host=host, issuer=res["issuer"], old=old)
            self.issuers[host] = res["issuer"]
            self._save()
            return True
        return False

    def evaluate_redirect(self, host, redirected):
        if redirected is None:
            return False
        if redirected and not self.redirects.get(host):
            self.redirects[host] = True
            try:
                save_state("tls_redirect", self.redirects)
            except OSError:
                pass
        if redirected is False and (host in ALWAYS_REDIRECT or self.redirects.get(host)):
            self.alert(f"strip:{host}", "WARNING",
                       f"SSL STRIPPING? http://{host} no longer redirects to "
                       f"HTTPS. Check that sites you visit show the padlock",
                       host=host)
            return True
        return False

    def _save(self):
        try:
            save_state("tls", self.issuers)
        except OSError:
            pass

    def check_host(self, host):
        self.evaluate(host, self.fetch(host),
                      pin=host in self.cfg.get("sites", []))
        if self.cfg.get("check_http_redirect", True):
            self.evaluate_redirect(host, self.redirect(host))

    def tick(self, regular=True):
        """Check the hosts strip.py flagged, then (regular) every site."""
        with self._lock:
            urgent, self.urgent = self.urgent, set()
        if self.check_portal():
            return
        for host in urgent:
            self.check_host(host)
        if regular:
            for host in self.sites():
                if host not in urgent:
                    self.check_host(host)

    def run(self):
        """Every `interval` seconds, every 30 s during a captive portal, and
        at once when strip.py asks."""
        last = 0
        while True:
            self._wake.clear()
            try:
                if time.time() - last >= self.interval or self.ctx.captive_portal:
                    last = time.time()
                    self.tick()
                elif self.urgent:
                    self.tick(regular=False)
            except Exception as e:
                log.warning("[tls] check failed: %s", e)
            self._wake.wait(30 if self.ctx.captive_portal else
                            max(5, self.interval - (time.time() - last)))

    def report(self):
        """One-off check for the CLI."""
        for host in self.sites():
            res = self.fetch(host)
            red = self.redirect(host)
            status = ("OK" if res["ok"] else
                      "UNREACHABLE" if res["kind"] == "network" else "FAKE CERT")
            print(f"{host:<22} {status:<12} issuer={res['issuer'] or '-':<28} "
                  f"http->https={'yes' if red else 'no' if red is False else '?'}")
            self.evaluate(host, res)
            self.evaluate_redirect(host, red)
