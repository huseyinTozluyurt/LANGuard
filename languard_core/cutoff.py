"""
Responses that cut an attacker off at the IP level and end connections that
already went through them (part of active protection, used by protect.py).

Isolating a MAC (protect.py) stops new frames from the attacker. What it does
not do is end what the attack already set up: TCP sessions that were routed
through the attacker while it sat in the middle, connections opened to an
address a forged DNS answer handed out, a poisoned DNS cache, an ICMP
redirect the kernel already took. These do:

  * block_ip  - an nftables inet table rejects everything this machine sends
                to the address and drops everything from it. Entries expire
                (isolate_minutes)
  * cut       - ends live sockets with `ss -K`: to one address (optionally one
                port), or every connection that left through the router
                (after a gateway MITM, all of them went through the attacker)
  * flush_dns - empties systemd-resolved's cache, so forged answers are gone
  * llmnr_off - stops answering/asking LLMNR on the interface (what Responder
                poisons), until undo or the next reconnect
  * no_redirects - stops the kernel accepting ICMP redirects and drops the
                routes they created
  * leave_twin - disconnects Wi-Fi if it is associated with an evil twin

Safety: nothing here touches another device. An IP block only changes what
this machine accepts and sends; the router, this machine, loopback and
`never_block` are never blocked; more than `block_max` addresses in 10 minutes
pauses IP blocking for 30 minutes (forged packets or a false alarm, not that
many attackers). Every action is recorded with its undo command.
"""

import ipaddress
import time

from .core import log

IPTABLE = "languard_ip"
BLOCK_WINDOW, BLOCK_PAUSE = 600, 1800


def ip_family(addr):
    try:
        return ipaddress.ip_address(addr).version
    except ValueError:
        return None


class Responses:
    """Mixin for Protector: needs self.run, self.ctx, self.cfg, self.state,
    self._lock, self._save, self._alert, self._once, self._warn_once."""

    # ------------------------------------------------------- IP blocking --
    def setup_ipblock(self):
        rules = (f"table inet {IPTABLE}\n"
                 f"delete table inet {IPTABLE}\n"
                 f"table inet {IPTABLE} {{\n"
                 f"  set bad4 {{ type ipv4_addr; flags timeout; }}\n"
                 f"  set bad6 {{ type ipv6_addr; flags timeout; }}\n"
                 f"  chain block_out {{\n"
                 f"    type filter hook output priority 0; policy accept;\n"
                 f"    ip daddr @bad4 counter reject\n"
                 f"    ip6 daddr @bad6 counter reject\n"
                 f"  }}\n"
                 f"  chain block_in {{\n"
                 f"    type filter hook input priority 0; policy accept;\n"
                 f"    iif lo accept\n"
                 f"    ip saddr @bad4 counter drop\n"
                 f"    ip6 saddr @bad6 counter drop\n"
                 f"  }}\n"
                 f"}}\n")
        rc, out = self.run(["nft", "-f", "-"], stdin=rules)
        if rc != 0:
            self._warn_once("ipfail", f"IP blocking is off: could not create "
                            f"the nftables table: {out}")
            return False
        self._ipt = True
        now = time.time()
        with self._lock:
            for ip, b in list(self.state["blocked_ips"].items()):
                left = int(b.get("until", 0) - now)
                if left > 60 and b.get("network") == self.base.key:
                    self._ip_add(ip, left)
                else:
                    del self.state["blocked_ips"][ip]
            self._save()
        return True

    def _ip_add(self, ip, seconds):
        s = "bad4" if ip_family(ip) == 4 else "bad6"
        return self.run(["nft", "add", "element", "inet", IPTABLE, s,
                         f"{{ {ip} timeout {int(seconds)}s }}"])

    def ip_protected(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if a.is_loopback or a.is_multicast or a.is_unspecified:
            return True
        own = {self.ctx.gateway, self.ctx.my_ip}
        never = set(self.cfg.get("never_block") or [])
        return str(a) in own or ip in own or str(a) in never or ip in never

    def _ip_flooded(self, ip):
        now = time.time()
        if now < self._ipblock_until:
            return True
        self._ip_recent = [(i, t) for i, t in self._ip_recent
                           if now - t < BLOCK_WINDOW]
        named = {i for i, _ in self._ip_recent} | {ip}
        if len(named) <= int(self.cfg.get("block_max", 20)):
            return False
        self._ipblock_until = now + BLOCK_PAUSE
        self._alert("ipflood", "CRITICAL",
                    f"{len(named)} different addresses were to be blocked "
                    f"within {BLOCK_WINDOW // 60} min. That looks like forged "
                    f"packets or a false alarm, so LANGuard stopped blocking "
                    f"addresses for {BLOCK_PAUSE // 60} min; everything else "
                    f"stays on", count=len(named))
        return True

    def block_ip(self, ip, reason):
        """Reject traffic to and drop traffic from ip, then end live
        connections with it. Returns True if it is blocked."""
        if not (self.enabled and self.cfg.get("block_ips", True)):
            return False
        ip = str(ipaddress.ip_address(ip)) if ip_family(ip) else ""
        if not ip or self.ip_protected(ip):
            return False
        with self._lock:
            b = self.state["blocked_ips"].get(ip)
            if b and b.get("until", 0) > time.time():
                return True
            if self._ip_flooded(ip):
                return False
            if not self._ipt and not self.setup_ipblock():
                return False
            minutes = int(self.cfg.get("isolate_minutes", 60))
            rc, out = self._ip_add(ip, minutes * 60)
            if rc != 0:
                log.warning("[protect] blocking %s failed: %s", ip, out)
                return False
            self._ip_recent.append((ip, time.time()))
            self.state["blocked_ips"][ip] = {
                "until": time.time() + minutes * 60, "reason": reason,
                "since": time.time(), "network": self.base.key}
            self._save()
        n = self.cut(dst=ip, why=reason)
        self._alert(f"blockip:{ip}", "WARNING",
                    f"Blocked {ip} for {minutes} min ({reason}): this machine "
                    f"no longer sends to or accepts anything from it"
                    f"{f'; ended {n} live connection(s) with it' if n else ''}"
                    f". Undo: sudo languard protect --unblock {ip}",
                    ip=ip, reason=reason)
        return True

    def unblock_ip(self, ip):
        with self._lock:
            if ip == "all":
                for s in ("bad4", "bad6"):
                    self.run(["nft", "flush", "set", "inet", IPTABLE, s])
                self.state["blocked_ips"] = {}
            else:
                s = "bad4" if ip_family(ip) == 4 else "bad6"
                self.run(["nft", "delete", "element", "inet", IPTABLE, s,
                          f"{{ {ip} }}"])
                self.state["blocked_ips"].pop(ip, None)
            self._save()

    # ---------------------------------------------------- live sessions --
    def cut(self, dst=None, port=None, scope=None, why=""):
        """End live sockets with `ss -K`. dst: one address (and port);
        scope "offlink": every IPv4 connection that left through the router;
        scope "ipv6": every routed IPv6 connection. Returns how many ended."""
        if not self.cfg.get("cut_connections", True):
            return 0
        cmds = []
        if dst:
            fam = ip_family(dst)
            if fam is None:
                return 0
            f = ["dst", dst if fam == 4 else f"{dst}/128"]
            if port:
                f += ["and", "dport", "=", f":{int(port)}"]
            cmds.append(["ss", "-K", f"-{fam}", "-tn", "state", "established"] + f)
        elif scope == "offlink":
            if not self._once("cut-offlink", 120):
                return 0
            local = [] if self.ctx.network is None else \
                ["and", "!", "dst", str(self.ctx.network)]
            cmds.append(["ss", "-K", "-4", "-tn", "state", "established", "(",
                         "!", "dst", "127.0.0.0/8"] + local + [")"])
        elif scope == "ipv6":
            if not self._once("cut-ipv6", 120):
                return 0
            cmds.append(["ss", "-K", "-6", "-tn", "state", "established", "(",
                         "!", "dst", "::1/128", "and", "!", "dst", "fe80::/10",
                         ")"])
        n = 0
        for cmd in cmds:
            rc, out = self.run(cmd)
            if rc != 0:
                self._warn_once("cut", f"could not end connections ({out}); "
                                "needs a kernel with INET_DIAG_DESTROY")
                continue
            n += sum(1 for line in out.splitlines()
                     if line and not line.startswith(("Recv-Q", "State")))
        if scope and n:
            self._alert(f"cut:{scope}", "WARNING",
                        f"Ended {n} connection(s) that went through the "
                        f"attacker ({why}); apps reconnect over the clean path",
                        count=n, scope=scope)
        return n

    # --------------------------------------------------------- DNS cache --
    def flush_dns(self, why=""):
        if not self.cfg.get("flush_dns", True) or not self._once("flush", 20):
            return False
        rc, out = self.run(["resolvectl", "flush-caches"])
        if rc == 0:
            log.info("[protect] flushed the DNS cache (%s)", why)
        return rc == 0

    # ------------------------------------------------------------- LLMNR --
    def llmnr_off(self, preventive=False):
        """preventive: on a public network, before any attack (see
        protect.apply_network_kind); put back on networks marked home."""
        if not self.cfg.get("llmnr_off", True):
            return False
        iface = self.ctx.iface
        with self._lock:
            if "llmnr" in self.state:
                if not preventive:          # an attack: keep it off at home too
                    self.state["llmnr"]["preventive"] = False
                    self._save()
                return True
            rc, out = self.run(["resolvectl", "llmnr", iface])
            old = out.rsplit(":", 1)[-1].strip() if rc == 0 else ""
            if old == "no":
                return True
            rc, out = self.run(["resolvectl", "llmnr", iface, "no"])
            if rc != 0:
                log.warning("[protect] turning LLMNR off failed: %s", out)
                return False
            self.state["llmnr"] = {"iface": iface, "old": old or "yes",
                                   "preventive": preventive,
                                   "network": self.base.key}
            self._save()
        if preventive:
            log.info("[protect] public network: LLMNR off on %s (Responder "
                     "can't poison it). DNS settings are unchanged", iface)
            return True
        self._alert("llmnr", "WARNING",
                    f"Turned LLMNR off on {iface}: name poisoners like "
                    f"Responder answer these lookups to steal logins. Normal "
                    f"DNS is unaffected. Undo: sudo languard protect --undo-all",
                    iface=iface)
        return True

    def llmnr_restore(self):
        with self._lock:
            ll = self.state.pop("llmnr", None)
            self._save()
        if ll:
            self.run(["resolvectl", "llmnr", ll["iface"], ll["old"]])
        return ll

    # ----------------------------------------------------- ICMP redirects --
    def no_redirects(self, preventive=False):
        if not self.cfg.get("block_redirects", True):
            return False
        iface = self.ctx.iface
        keys = [f"net.ipv4.conf.{k}.{s}" for k in ("all", iface)
                for s in ("accept_redirects", "secure_redirects")]
        keys += [f"net.ipv6.conf.{k}.accept_redirects" for k in ("all", iface)]
        with self._lock:
            if "redirects" not in self.state:
                old = {}
                for k in keys:
                    rc, out = self.run(["sysctl", "-n", k])
                    if rc == 0 and out.strip():
                        old[k] = out.strip()
                for k in old:
                    self.run(["sysctl", "-w", f"{k}=0"])
                self.state["redirects"] = old
                self.state["redirects_how"] = {"preventive": preventive,
                                               "network": self.base.key}
                self._save()
            elif not preventive:
                self.state.setdefault("redirects_how", {})["preventive"] = False
                self._save()
        if preventive:
            log.info("[protect] public network: ICMP redirects ignored")
            return True
        self.run(["ip", "route", "flush", "cache"])
        self.run(["ip", "-6", "route", "flush", "cache"])
        self._alert("redirects", "WARNING",
                    "This machine no longer accepts ICMP redirects, and the "
                    "routes they created were dropped. Undo: sudo languard "
                    "protect --undo-all", iface=iface)
        return True

    def redirects_restore(self):
        with self._lock:
            old = self.state.pop("redirects", None)
            self.state.pop("redirects_how", None)
            self._save()
        for k, v in (old or {}).items():
            self.run(["sysctl", "-w", f"{k}={v}"])
        return old

    # ----------------------------------------------------------- Wi-Fi --
    def leave_twin(self, bssid, ssid=""):
        """Disconnect Wi-Fi if it is associated with bssid."""
        rc, out = self.run(["nmcli", "-t", "-f", "ACTIVE,BSSID,DEVICE",
                            "device", "wifi", "list", "--rescan", "no"])
        if rc != 0:
            return False
        for line in out.splitlines():
            p = line.replace("\\:", "-").split(":")
            if len(p) >= 3 and p[0] == "yes" and \
                    p[1].replace("-", ":").lower() == (bssid or "").lower():
                dev = p[2]
                rc, msg = self.run(["nmcli", "device", "disconnect", dev])
                self._alert(f"twin:{bssid}", "CRITICAL",
                            f"Disconnected {dev} from the evil twin {bssid}"
                            f"{f' posing as {ssid!r}' if ssid else ''}"
                            f"{'' if rc == 0 else ' (FAILED: ' + msg + ')'}. "
                            f"Reconnect only to your real access point "
                            f"(wifi.trusted_bssids)", bssid=bssid)
                return rc == 0
        return False
