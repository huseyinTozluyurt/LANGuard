"""
HTTPS guard (part of active protection): stop SSL stripping, not only report it.

sslstrip works because the browser sends a plain-HTTP request and the person
in the middle answers it. The guard makes sure such a request never reaches
the network for a site this machine uses over HTTPS:

  * an nftables rule sends this machine's outgoing TCP port 80 connections to
    a small local proxy (127.0.0.1 / ::1, never reachable from the LAN)
  * the proxy reads the request head and asks strip.py for a verdict:
      upgrade - a browser asking for a site you use over HTTPS (or a big
                HSTS-preloaded one): answered locally with a redirect to
                https://, so nothing is sent in clear text and there is no
                plain-HTTP answer for an attacker to rewrite
      block   - a look-alike of such a site (the sslstrip2/hstshijack trick):
                answered with a warning page
      pass    - anything else (apt, updaters, certificate checks, captive
                portal checks, plain-HTTP sites): forwarded unchanged to the
                address it was going to
  * the proxy's own connections carry a firewall mark so they skip the rule

The guard only changes this machine's own traffic, so it can't be used against
other devices. It never answers for sites you have not used over HTTPS, and it
lets everything through while a captive portal is active (see tls.py). The
rule is removed when LANGuard stops (systemd ExecStopPost and at exit) and by
`languard protect --off` / `--undo-all`.
"""

import html
import socket
import struct
import threading

from .core import log

TABLE = "languard_guard"
PORT = 8079
MARK = 0x4c47                       # "LG": connections the proxy makes itself
SO_ORIGINAL_DST = 80                # same value for IPv4 and IPv6
SO_MARK = 36
HEAD_MAX = 32768
MAX_CONN = 512


class HttpsGuard:
    def __init__(self, ctx, run, port=PORT, verdict=None):
        self.ctx = ctx
        self.run = run
        self.port = int(port)
        self._verdict = verdict             # tests: replace strip.py's verdict
        self._fallback = None
        self.active = False
        self.v6 = False
        self.counts = {"upgraded": 0, "blocked": 0, "passed": 0}
        self._slots = threading.BoundedSemaphore(MAX_CONN)
        self._socks = []
        self._logged = set()

    # ---------------------------------------------------------- lifecycle --
    def rules(self):
        v6 = (f"    meta nfproto ipv6 ip6 daddr != ::1 tcp dport 80 "
              f"redirect to :{self.port}\n") if self.v6 else ""
        return (f"table inet {TABLE}\n"
                f"delete table inet {TABLE}\n"
                f"table inet {TABLE} {{\n"
                f"  chain output {{\n"
                f"    type nat hook output priority -100; policy accept;\n"
                f"    meta mark {MARK:#x} return\n"
                f"    meta nfproto ipv4 ip daddr != 127.0.0.0/8 tcp dport 80 "
                f"redirect to :{self.port}\n"
                f"{v6}"
                f"  }}\n"
                f"}}\n")

    def start(self):
        """Listen first, then redirect: never a rule without a proxy behind it."""
        try:
            self._listen(socket.AF_INET, "127.0.0.1")
        except OSError as e:
            log.warning("[guard] HTTPS guard is off: can't listen on "
                        "127.0.0.1:%d: %s", self.port, e)
            return False
        try:
            self._listen(socket.AF_INET6, "::1")
            self.v6 = True
        except OSError:
            self.v6 = False                 # no IPv6 loopback: guard IPv4 only
        rc, out = self.run(["nft", "-f", "-"], stdin=self.rules())
        if rc != 0:
            log.warning("[guard] HTTPS guard is off: nftables rule failed: %s", out)
            self._close()
            return False
        self.active = True
        log.info("[guard] HTTPS guard on: plain-HTTP requests to sites you use "
                 "over HTTPS are upgraded before they leave this machine")
        return True

    def stop(self):
        if self.active:
            self.run(["nft", "delete", "table", "inet", TABLE])
        self.active = False
        self._close()

    def _close(self):
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        self._socks = []

    def _listen(self, family, addr):
        s = socket.socket(family, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            s.bind((addr, self.port))
            s.listen(128)
        except OSError:
            s.close()
            raise
        self._socks.append(s)
        threading.Thread(target=self._accept, args=(s, family),
                         name=f"guard-{family.name}", daemon=True).start()

    def _accept(self, s, family):
        while True:
            try:
                conn, _ = s.accept()
            except OSError:
                return                      # closed by stop()
            if not self._slots.acquire(blocking=False):
                conn.close()                # overloaded: refuse, don't queue
                continue
            threading.Thread(target=self._serve, args=(conn, family),
                             daemon=True).start()

    # ------------------------------------------------------------ verdict --
    def verdict(self, method, host, path, ua):
        if self._verdict:
            return self._verdict(method, host, path, ua)
        strip = getattr(self.ctx, "strip", None)
        if strip is None:                   # strip module off: same rules,
            if self._fallback is None:      # learned hosts from its state file
                from .strip import StripMonitor
                self._fallback = StripMonitor(self.ctx)
            strip = self._fallback
        return strip.verdict(method, host, path, ua)

    # ------------------------------------------------------------- proxy --
    def _orig_dst(self, conn, family):
        """Where the connection was going before the nftables redirect."""
        try:
            if family == socket.AF_INET:
                raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
                dst = (socket.inet_ntop(socket.AF_INET, raw[4:8]),
                       struct.unpack("!H", raw[2:4])[0])
            else:
                raw = conn.getsockopt(socket.IPPROTO_IPV6, SO_ORIGINAL_DST, 28)
                dst = (socket.inet_ntop(socket.AF_INET6, raw[8:24]),
                       struct.unpack("!H", raw[2:4])[0], 0, 0)
        except OSError:
            return None                     # not redirected: a direct connection
        if dst[1] == self.port and dst[0] in ("127.0.0.1", "::1"):
            return None
        return dst

    def _serve(self, conn, family):
        up = None
        try:
            dst = self._orig_dst(conn, family)
            if dst is None:
                return                      # never an open relay
            conn.settimeout(15)
            head = b""
            while b"\r\n\r\n" not in head and len(head) < HEAD_MAX:
                try:
                    chunk = conn.recv(8192)
                except socket.timeout:
                    break                   # not HTTP, or slow: pass it on
                if not chunk:
                    break
                head += chunk
            if not head:
                return
            from .strip import parse_http_request
            req = parse_http_request(head)
            if req and _plain_host(req[1]):
                method, host, path, ua = req
                action, good = self.verdict(method, host, path, ua)
                if action == "upgrade":
                    self._upgrade(conn, host, path)
                    return
                if action == "block":
                    self._block(conn, method, host, path, ua, good, dst)
                    return
            self.counts["passed"] += 1
            up = socket.socket(family, socket.SOCK_STREAM)
            up.setsockopt(socket.SOL_SOCKET, SO_MARK, MARK)
            up.settimeout(15)
            up.connect(dst)
            up.sendall(head)
            up.settimeout(None)
            conn.settimeout(None)
            t = threading.Thread(target=_copy, args=(up, conn), daemon=True)
            t.start()
            _copy(conn, up)
            t.join()
        except OSError:
            pass
        finally:
            for s in (conn, up):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
            self._slots.release()

    def _upgrade(self, conn, host, path):
        if not path.startswith("/"):
            path = "/"
        conn.sendall((f"HTTP/1.1 307 Temporary Redirect\r\n"
                      f"Location: https://{host}{path}\r\n"
                      f"Content-Length: 0\r\nCache-Control: no-store\r\n"
                      f"Connection: close\r\nX-LANGuard: https-guard\r\n\r\n"
                      ).encode("latin-1", "replace"))
        self.counts["upgraded"] += 1
        if host not in self._logged and len(self._logged) < 2000:
            self._logged.add(host)
            log.info("[guard] upgraded plain-HTTP %s to HTTPS before it left "
                     "this machine", host)

    def _block(self, conn, method, host, path, ua, good, dst):
        body = (f"<!doctype html><meta charset=utf-8><title>Blocked by "
                f"LANGuard</title><body style='font-family:sans-serif;"
                f"max-width:40em;margin:3em auto'><h1>Blocked: look-alike "
                f"site</h1><p><b>{html.escape(host)}</b> imitates "
                f"<b>{html.escape(good)}</b>, a site you use over HTTPS. This "
                f"is how SSL-stripping tools (sslstrip2, hstshijack) get around "
                f"HTTPS protection. Someone on this network may be "
                f"intercepting your traffic.</p><p>Go to <a href='https://"
                f"{html.escape(good)}/'>https://{html.escape(good)}/</a> "
                f"directly and don't log in on this network until LANGuard's "
                f"alerts are clear.</p></body>").encode()
        conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; "
                     b"charset=utf-8\r\nCache-Control: no-store\r\nConnection: "
                     b"close\r\nContent-Length: " + str(len(body)).encode() +
                     b"\r\nX-LANGuard: https-guard\r\n\r\n" + body)
        self.counts["blocked"] += 1
        strip = getattr(self.ctx, "strip", None) or self._fallback
        if strip is not None:               # the alert, as detection raises it
            strip.http_request(method, host, path, ip=dst[0], ua=ua)


def _plain_host(host):
    """Only names that are safe to put back into a Location header."""
    return bool(host) and host.isascii() and all(c.isalnum() or c in ".-" for c in host)


def _copy(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass
