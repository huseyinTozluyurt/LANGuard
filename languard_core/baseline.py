"""
Per-network baselines: what "normal" looks like on each network you join.

A baseline holds the router's real MAC, the DHCP servers (IP and MAC) and the
DNS servers they hand out, and the IPv6 routers seen there. It is keyed by
network (connection name, gateway IP and subnet), so moving between home, the
office and a café never mixes their values.

The gateway MAC is only marked *verified* after an active check: several ARP
probes for the gateway, each answered by exactly one MAC. Until then it is
provisional. This closes the hole where an attacker who poisoned the ARP cache
before LANGuard started would be learned as "the router".

It also holds what you told LANGuard about the network: whether it is your
home network or a public one (`languard network --home|--public`), and the
devices you pinned there (`languard protect --pin-device IP`).

Reset a network's baseline after replacing your router:
    sudo languard baseline --reset
"""

import subprocess
import threading
import time

from .core import load_state, log, save_state

STATE_NAME = "networks"


def _connection_name(iface):
    """NetworkManager connection (or Wi-Fi SSID) the interface is on."""
    if not iface:
        return ""
    for cmd in (["nmcli", "-t", "-g", "GENERAL.CONNECTION", "device", "show", iface],
                ["iwgetid", "-r", iface]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=3).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            continue
        if out and out != "--":
            return out.splitlines()[0]
    return ""


def wifi_open(iface, run=None):
    """True if iface is on Wi-Fi without encryption (a café hotspot)."""
    cmd = ["nmcli", "-t", "-f", "ACTIVE,SECURITY,DEVICE", "device", "wifi",
           "list", "--rescan", "no"]
    try:
        if run:
            rc, out = run(cmd)
        else:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            rc, out = r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return False
    if rc != 0:
        return False
    for line in out.splitlines():
        p = line.split(":")
        if len(p) >= 3 and p[0] == "yes" and p[-1] == iface:
            return p[1].strip() in ("", "--")
    return False


def network_key(ctx):
    label = getattr(ctx, "net_label", None)
    if label is None:
        label = _connection_name(getattr(ctx, "iface", None))
    return f"{label or '-'}|{ctx.gateway or '-'}|{ctx.network or '-'}"


class Baseline:
    def __init__(self, ctx):
        self.ctx = ctx
        self.key = network_key(ctx)
        self._lock = threading.Lock()
        self.rec = load_state(STATE_NAME, {}).get(self.key, {})

    # ---- gateway ----
    @property
    def gw_verified(self):
        return bool(self.rec.get("gw_verified") and self.rec.get("gw_mac"))

    @property
    def gw_mac(self):
        """The verified router MAC, or None."""
        return self.rec.get("gw_mac") if self.gw_verified else None

    def learn_gateway(self, rounds):
        """Judge active ARP probes of the gateway.

        `rounds` is a list of MAC lists, one per probe. Returns one of
          ("verified", mac)   every probe answered by the same single MAC
          ("conflict", macs)  two or more MACs answer for the gateway
          ("changed", macs)   one MAC answers, but not the verified one
          ("none", [])        nobody answered
        """
        macs = sorted({m.lower() for r in rounds for m in r})
        if not macs:
            return "none", []
        if len(macs) > 1:
            return "conflict", macs
        mac = macs[0]
        if self.gw_verified and mac != self.rec["gw_mac"]:
            return "changed", macs
        if not self.gw_verified:
            with self._lock:
                self.rec.update(gw_mac=mac, gw_verified=True,
                                gw_verified_at=time.time())
            self.save()
            log.info("[baseline] Verified router %s at %s for network %s",
                     self.ctx.gateway, mac, self.key)
        return "verified", mac

    # ---- DHCP / DNS ----
    def dhcp_mac(self, server_ip):
        """The MAC a trusted DHCP server is expected to answer from."""
        mac = self.rec.get("dhcp", {}).get(server_ip)
        if not mac and server_ip == self.ctx.gateway:
            mac = self.gw_mac
        return mac

    def learn_dhcp(self, server_ip, mac):
        with self._lock:
            self.rec.setdefault("dhcp", {})[server_ip] = mac
        self.save()

    @property
    def dns(self):
        return self.rec.get("dns")

    def learn_dns(self, servers):
        with self._lock:
            self.rec["dns"] = sorted(servers)
        self.save()

    # ---- IPv6 ----
    def ipv6(self, field):
        return set(self.rec.get(field, []))

    def learn_ipv6(self, field, values):
        with self._lock:
            self.rec[field] = sorted(set(self.rec.get(field, [])) | set(values))
        self.save()

    def trusted_macs(self):
        """Every MAC this network's baseline vouches for (never isolated).

        Only the verified router and DHCP servers checked against it. IPv6
        routers and DHCPv6 servers learned by older versions are left out:
        they were learned on trust, so one could be an attacker (mitm6)."""
        out = set(self.rec.get("dhcp", {}).values())
        if self.gw_mac:
            out.add(self.gw_mac)
        return out

    # ---- what you told LANGuard ----
    @property
    def kind(self):
        """'home', 'public' or None (not marked)."""
        return self.rec.get("kind")

    def set_kind(self, kind):
        with self._lock:
            if kind:
                self.rec["kind"] = kind
            else:
                self.rec.pop("kind", None)
        self.save()

    def pinned(self):
        """{ip: mac} of devices pinned on this network (NAS, printer...)."""
        return dict(self.rec.get("pinned", {}))

    def pin_device(self, ip, mac):
        with self._lock:
            self.rec.setdefault("pinned", {})[ip] = mac.lower()
        self.save()

    def unpin_device(self, ip):
        with self._lock:
            mac = self.rec.get("pinned", {}).pop(ip, None)
        self.save()
        return mac

    # ---- storage ----
    def save(self):
        with self._lock:
            self.rec["last_seen"] = time.time()
            self.rec.setdefault("first_seen", self.rec["last_seen"])
            try:
                db = load_state(STATE_NAME, {})
                db[self.key] = self.rec
                save_state(STATE_NAME, db)
            except OSError as e:
                log.debug("[baseline] save failed: %s", e)


def get(ctx):
    """The baseline for ctx's current network (one shared object per ctx)."""
    b = getattr(ctx, "_baseline", None)
    if b is None:
        b = Baseline(ctx)
        try:
            ctx._baseline = b
        except AttributeError:
            pass
    return b


def probe_gateway(ctx, rounds=3, gap=1.0):
    """ARP-probe the gateway `rounds` times; list of answering MACs per round."""
    from scapy.all import ARP, Ether, srp
    out = []
    for i in range(rounds):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ctx.gateway),
                     iface=ctx.iface, timeout=2, multi=True, verbose=0)
        out.append([r.hwsrc.lower() for _, r in ans])
        if i < rounds - 1:
            time.sleep(gap)
    return out


# ---- CLI helpers ----
def show():
    db = load_state(STATE_NAME, {})
    if not db:
        print("No network baselines yet.")
        return
    for key, r in sorted(db.items(), key=lambda kv: -kv[1].get("last_seen", 0)):
        conn, gw, net = (key.split("|") + ["", "", ""])[:3]
        last = time.strftime("%Y-%m-%d %H:%M", time.localtime(r.get("last_seen", 0)))
        state = "verified" if r.get("gw_verified") else "NOT verified"
        print(f"{conn}  (gateway {gw}, {net}, last seen {last})")
        print(f"  router MAC:   {r.get('gw_mac') or '-'} [{state}]")
        dhcp = ", ".join(f"{ip} at {m}" for ip, m in r.get("dhcp", {}).items())
        print(f"  DHCP servers: {dhcp or '-'}")
        print(f"  DNS servers:  {', '.join(r.get('dns') or []) or '-'}")
        v6 = r.get("ipv6_routers") or []
        print(f"  IPv6 routers: {', '.join(v6) or '-'}")
        print(f"  marked as:    {r.get('kind') or 'not marked'}")
        pins = ", ".join(f"{ip} at {m}" for ip, m in r.get("pinned", {}).items())
        if pins:
            print(f"  pinned:       {pins}")


def reset(key=None):
    """Forget one network's baseline (by key), or all with key=None. A single
    network keeps its home/public mark and pinned devices."""
    db = load_state(STATE_NAME, {})
    if key is None:
        db = {}
    else:                       # keep what the user told us about it
        old = db.pop(key, None) or {}
        kept = {k: old[k] for k in ("kind", "pinned") if k in old}
        if kept:
            db[key] = kept
    save_state(STATE_NAME, db)
