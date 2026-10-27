"""
`languard selftest`: show that detection and protection work on this machine,
without an attacker and without changing anything.

  1. Environment: the tools active protection needs (nftables, ss -K with
     kernel support, scapy, iproute2, NetworkManager/resolvectl), your
     encrypted DNS resolver and the HSTS preload list.
  2. Simulated attacks: each detector is fed the packets an attack produces
     (ARP gateway spoofing, rogue DHCP/DHCPv6/RA, DNS forgery, SSL stripping,
     look-alike sites, Responder, device spoofing, WPAD, forged-MAC framing,
     a plain-DNS leak next to dnscrypt-proxy). Protection runs with a fake
     command runner, so every response is checked (isolate, block, cut,
     pin...) but nothing reaches your system. A final check proves no step
     would have changed your DNS settings.
  3. --netns (root): the HTTPS guard and IP blocking run for real inside a
     throwaway network namespace, so your own network is never touched.
"""

import copy
import ipaddress
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from . import core, distro

GW, GW_MAC = "192.0.2.1", "02:00:5e:00:00:01"
ME, MY_MAC = "192.0.2.50", "02:00:5e:00:00:50"
ATT, ATT_MAC = "192.0.2.66", "02:00:5e:00:00:66"
PRINTER, PRINTER_MAC = "192.0.2.20", "02:00:5e:00:00:20"
FF = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
# Commands that would change DNS settings. None may ever run.
DNS_CHANGES = (["resolvectl", "dns"], ["resolvectl", "domain"],
               ["resolvectl", "default-route"], ["resolvectl", "revert"],
               ["nmcli", "connection", "modify"], ["dnscrypt-proxy"],
               ["systemctl", "restart", "dnscrypt-proxy"],
               ["systemctl", "stop", "dnscrypt-proxy"])


class FakeRun:
    """Records commands instead of running them."""

    def __init__(self):
        self.cmds = []
        self.stdin = []

    def __call__(self, cmd, stdin=None, timeout=15):
        self.cmds.append(list(cmd))
        if stdin:
            self.stdin.append(stdin)
        if cmd[:2] == ["resolvectl", "dns"]:
            return 0, f"Link 2 (lg-test0): {ATT}"
        if cmd[0] == "nmcli" and "GENERAL.CONNECTION" in cmd:
            return 0, "selftest-connection"
        return 0, ""

    def ran(self, *words):
        return any(all(w in " ".join(c) for w in words) for c in self.cmds)


class Report:
    def __init__(self, out=print):
        self.out = out
        self.fails = 0
        self.warns = 0

    def line(self, status, text):
        self.out(f"  [{status}] {text}")
        self.fails += status == "FAIL"
        self.warns += status == "WARN"

    def check(self, name, cond):
        self.line("PASS" if cond else "FAIL", name)
        return cond


# ------------------------------------------------------------ environment --
def _ok(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _kernel_diag_destroy():
    try:
        rel = os.uname().release
        text = Path(f"/boot/config-{rel}").read_text()
    except OSError:
        return None
    return "CONFIG_INET_DIAG_DESTROY=y" in text


def environment(rep):
    rep.out("== Environment (read-only)")
    rep.line("INFO", f"system: {distro.info()[1]} ({distro.info()[0]} family)")
    root = os.geteuid() == 0
    rep.line("PASS" if root else "WARN", "running as root" if root else
             "not root: some checks are limited (sudo languard selftest)")
    rep.line("PASS" if shutil.which("nft") else "FAIL",
             "nftables (isolation, IP blocks, HTTPS guard)" if shutil.which("nft")
             else f"nftables missing: {distro.install_hint('nftables')}")
    diag = _kernel_diag_destroy()
    if shutil.which("ss") and diag is not False:
        rep.line("PASS", "ss -K can end live connections"
                 + ("" if diag else " (kernel config not readable; assumed)"))
    else:
        rep.line("WARN", "ending live connections unavailable (ss or kernel "
                 "CONFIG_INET_DIAG_DESTROY missing)")
    try:
        import scapy.all
        rep.line("PASS" if scapy.all.conf else "WARN", "scapy (packet capture)")
    except Exception:
        rep.line("FAIL", f"scapy missing: {distro.install_hint('scapy')}")
    for tool, why in (("ip", "router pinning"), ("nmcli", "DHCP repair, Wi-Fi"),
                      ("resolvectl", "DNS cache flush, LLMNR"),
                      ("unshare", "selftest --netns")):
        rep.line("PASS" if shutil.which(tool) else "WARN",
                 f"{tool} ({why})" + ("" if shutil.which(tool) else ": not found"))
    from . import hsts, localdns
    info = localdns.inspect()
    if info.get("resolver"):
        risk = "; ".join(info["leak_risk"])
        rep.line("WARN" if risk else "PASS",
                 f"encrypted DNS: {info['label']} on "
                 f"{', '.join(info['listen']) or '?'}"
                 + (f"; leak risk: {risk}" if risk else ", no leak risk seen")
                 + " (LANGuard only reads this)")
    else:
        rep.line("INFO", "no local encrypted DNS resolver running")
    try:
        n = len(hsts.load())
        rep.line("PASS" if n else "WARN", hsts.status())
    except OSError:
        rep.line("INFO", "HSTS list not readable (run as root)")


# ---------------------------------------------------------------- attacks --
class _Ctx:
    pass


def _ctx(cfg, alerter):
    c = _Ctx()
    c.cfg = cfg
    c.alert = alerter
    c.iface, c.gateway, c.my_ip, c.my_mac = "lg-test0", GW, ME, MY_MAC
    c.network = ipaddress.ip_network("192.0.2.0/24")
    c.net_label = "languard-selftest"
    c.local_dns = {"resolver": None}
    c.protect = None
    return c


def scenarios(rep, cfg):
    rep.out("== Simulated attacks (nothing is sent or changed)")
    from . import baseline
    from .arp import ARPMonitor
    from .core import Alerter
    from .dhcp import DHCPMonitor
    from .dns import DNSMonitor
    from .evidence import Evidence
    from .ipv6 import IPv6Monitor
    from .mitm import MitmMonitor
    from .protect import Protector
    from .strip import StripMonitor

    cfg = copy.deepcopy(cfg)
    cfg["protect"].update(enabled=True, isolate=True, block_ips=True,
                          cut_connections=True, flush_dns=True,
                          repair_dhcp=True, ipv6_lockdown=True,
                          pin_gateway=True, kill_switch=False, isolate_max=3,
                          block_max=20, never_isolate=[], never_block=[])
    alerter = Alerter(cooldown=0)
    c = _ctx(cfg, alerter)
    run = FakeRun()
    base = baseline.get(c)
    base.learn_gateway([[GW_MAC]] * 3)
    p = Protector(c, run=run, sync=True)
    c.protect = p

    def fresh():
        """Each attack on its own, as if minutes apart: the forged-MAC
        safeguard only counts devices named within 10 minutes."""
        p._recent.clear()
        p._frame_until = 0
        p._last.clear()
        p._unknown.clear()
        p._signals.clear()

    def said(text, level="CRITICAL"):
        return any(text in m and lv == level for _, lv, m in alerter.history)

    arp = ARPMonitor(c)
    arp.observe(ATT, ATT_MAC)                    # the attacker's own address
    arp.observe(GW, ATT_MAC, is_reply=True)
    rep.check("ARP spoofing of the router: detected",
              said("GATEWAY SPOOFING"))
    rep.check("...attacker isolated (nftables MAC drop)",
              run.ran("nft add element netdev languard blocked", ATT_MAC))
    rep.check("...router pinned to its verified MAC",
              run.ran("ip neigh replace", GW, GW_MAC, "permanent"))
    rep.check("...connections that went through it ended (ss -K)",
              run.ran("ss -K -4"))
    rep.check("...its own IP blocked, not the router's",
              run.ran("bad4", ATT) and not run.ran("bad4", "{ " + GW + " "))

    fresh()
    base.pin_device(PRINTER, PRINTER_MAC)
    arp.observe(PRINTER, "02:00:5e:00:00:67")
    rep.check("Spoofing a pinned device (printer/NAS): detected and isolated",
              said("DEVICE SPOOFING") and
              run.ran("blocked", "02:00:5e:00:00:67"))

    fresh()
    dhcp = DHCPMonitor(c)
    dhcp.observe(2, "192.0.2.68", "02:00:5e:00:00:68", router="192.0.2.68",
                 dns=["192.0.2.68"], for_me=True)
    rep.check("Rogue DHCP server: detected, isolated, lease renewed from the "
              "real server", said("ROGUE DHCP SERVER") and
              run.ran("blocked", "02:00:5e:00:00:68") and
              (run.ran("nmcli connection up") or run.ran("networkctl renew")
               or run.ran("dhclient")))
    dhcp.observe(5, GW, GW_MAC, router=GW, wpad="http://192.0.2.88/wpad.dat")
    rep.check("WPAD proxy pushed by DHCP: the proxy host is blocked",
              run.ran("bad4", "192.0.2.88"))

    fresh()
    v6 = IPv6Monitor(c)
    v6.router_advert("fe80::69", "02:00:5e:00:00:69")
    rep.check("Rogue IPv6 router (SLAAC/mitm6): detected, isolated, RAs no "
              "longer accepted", said("ROGUE IPv6 ROUTER") and
              run.ran("blocked", "02:00:5e:00:00:69") and
              run.ran("sysctl -w", "accept_ra=0"))
    v6.router_advert("fe80::1", GW_MAC)
    rep.check("Verified IPv6 router pinned", run.ran("ip neigh replace",
                                                     "fe80::1", GW_MAC))

    fresh()
    dns = DNSMonitor(c)
    dns.query(ME, 5353, 7, "bank.example.", GW)
    dns.response(ME, 5353, 7, "bank.example.", GW, {"203.0.113.9"},
                 mac="02:00:5e:00:00:70")
    rep.check("Forged DNS answer (not from the router's MAC): detected",
              said("DNS SPOOFING"))
    rep.check("...sender isolated, DNS cache flushed, forged address blocked",
              run.ran("blocked", "02:00:5e:00:00:70") and
              run.ran("resolvectl flush-caches") and run.ran("bad4", "203.0.113.9"))

    s = StripMonitor(c)
    c.strip = s
    s.https_seen("bank.example.com", ip="198.51.100.5", now=time.time())
    s.http_request("POST", "bank.example.com", "/login", ip="198.51.100.5", ua=FF)
    rep.check("SSL stripping (login POST over plain HTTP): detected, the "
              "plain-HTTP session ended", said("SSL STRIPPING") and
              run.ran("ss -K", "198.51.100.5", "dport = :80"))
    rep.check("HTTPS guard would upgrade it before it leaves this machine",
              s.verdict("GET", "bank.example.com", "/", FF)[0] == "upgrade")
    rep.check("Look-alike site (sslstrip2/hstshijack): blocked",
              s.verdict("GET", "bank.examp1e.com", "/", FF)[0] == "block")

    fresh()
    mitm = MitmMonitor(c)
    bait = mitm.new_bait()
    mitm.name_answer(bait, "192.0.2.71", "LLMNR", mac="02:00:5e:00:00:71")
    rep.check("Responder (LLMNR/NBNS poisoning): detected, isolated and "
              "blocked, LLMNR turned off", said("NAME POISONING") and
              run.ran("blocked", "02:00:5e:00:00:71") and
              run.ran("bad4", "192.0.2.71") and
              run.ran("resolvectl llmnr", "no"))

    fresh()
    for i in range(4):                  # devices that have been on the LAN a while
        arp.mac_first_seen[f"02:00:5e:00:01:0{i}"] = time.time() - 3600
        p.respond("rogue_ra", mac=f"02:00:5e:00:01:0{i}")
    rep.check("Forged-MAC framing: after 3 devices, isolation pauses instead "
              "of cutting off innocent devices",
              run.ran("blocked", "02:00:5e:00:01:02") and
              not run.ran("blocked", "02:00:5e:00:01:03") and
              said("forging packets"))

    fresh()
    for i in range(5):                  # made-up MACs never seen before
        p.respond("rogue_ra", mac=f"02:00:5e:00:02:0{i}")
    rep.check("Made-up MACs during framing: still isolated (only known "
              "devices pause isolation)",
              all(run.ran("blocked", f"02:00:5e:00:02:0{i}") for i in range(5)))

    p.update_l2_pins()
    rules = "\n".join(run.stdin)
    rep.check("Rogue DHCP / IPv6 router race: only the verified router's "
              "answers reach this machine (nftables pins)",
              "udp sport 67" in rules and "nd-router-advert" in rules and
              GW_MAC in rules)

    fresh()
    p.respond("rogue_ra", mac=GW_MAC)
    rep.check("Framing the router (its MAC named as attacker): never "
              "isolated", not run.ran("blocked", GW_MAC) and
              said("never isolates it", "WARNING"))

    from . import tamper
    rep.check("Malware reusing your password: commands that lower "
              "protection need it again (and are alerted)",
              tamper.weakens(["protect", "--set", "isolate=off"]) and
              tamper.weakens(["pause", "60"]) and not tamper.weakens(["status"]))

    c.local_dns = {"resolver": "dnscrypt-proxy", "label": "dnscrypt-proxy",
                   "bootstrap": ["9.9.9.11"], "via_resolved": True}
    leak = dns.leak("example.com.", "192.0.2.1")
    boot = dns.leak("raw.githubusercontent.com.", "9.9.9.11")
    rep.check("Plain-DNS leak next to dnscrypt-proxy: reported (its own "
              "bootstrap lookups are not)", leak and not boot)

    ev = Evidence({"evidence": {"seconds": 60, "after": 0}})
    ev.feed(b"\x00" * 60)
    alerter.hooks.append(lambda *a: ev.on_alert(*a, sync=True))
    alerter("selftest", "ev", "CRITICAL", "evidence check")
    saved = ev.saved and Path(ev.saved[-1])
    rep.check("Evidence: packets around a critical alert saved (root-only "
              "pcap)", bool(saved) and saved.exists() and
              saved.stat().st_mode & 0o077 == 0)

    changed = [c2 for c2 in run.cmds
               if any(c2[:len(bad)] == bad and
                      not (bad == ["resolvectl", "dns"] and len(c2) <= 3)
                      for bad in DNS_CHANGES)]
    rep.check("No response changed DNS servers, NetworkManager DNS settings "
              "or dnscrypt-proxy", not changed)
    return run


# ------------------------------------------------------------------ netns --
def netns_child():
    """Runs inside `unshare -n`: real nftables, real sockets, private net."""
    rep = Report()
    from . import protect
    from .core import Alerter
    from .guard import HttpsGuard
    from .strip import StripMonitor
    for cmd in (["ip", "link", "set", "lo", "up"],
                ["ip", "addr", "add", "10.9.9.1/32", "dev", "lo"],
                ["ip", "addr", "add", "203.0.113.7/32", "dev", "lo"]):
        subprocess.run(cmd, check=True)

    def server(addr):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((addr, 80))
        srv.listen(16)
        while True:
            k, _ = srv.accept()
            try:
                k.recv(4096)
                k.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                          b"Connection: close\r\n\r\nok")
            finally:
                k.close()

    for a in ("10.9.9.1", "203.0.113.7"):
        threading.Thread(target=server, args=(a,), daemon=True).start()
    time.sleep(0.2)

    def get(addr, host):
        k = socket.create_connection((addr, 80), timeout=5)
        k.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {FF}"
                  f"\r\n\r\n".encode())
        out = b""
        while True:
            chunk = k.recv(4096)
            if not chunk:
                break
            out += chunk
        k.close()
        return out.decode("latin-1")

    cfg = core.load_config("/nonexistent")
    c = _ctx(cfg, Alerter(cooldown=0))
    c.my_ip, c.gateway = "10.9.9.1", "10.9.9.254"
    c.network = ipaddress.ip_network("10.9.9.0/24")
    s = StripMonitor(c)
    c.strip = s
    s.https_seen("bank.example.com", now=time.time())
    g = HttpsGuard(c, protect._run, port=18079)
    rep.check("HTTPS guard starts for real (proxy + nftables rule)", g.start())
    rep.check("...a plain-HTTP request to an HTTPS site is answered with a "
              "redirect to https://, nothing sent",
              get("10.9.9.1", "bank.example.com").startswith("HTTP/1.1 307"))
    rep.check("...a plain-HTTP-only site still works",
              get("10.9.9.1", "neverssl.com").endswith("ok"))
    g.stop()
    p = protect.Protector(c, run=protect._run, sync=True)
    p.state["blocked_ips"] = {}
    from . import baseline
    baseline.get(c).learn_gateway([["02:00:5e:00:00:fe"]] * 3)
    rep.check("IP block table created for real", p.setup_ipblock())
    rep.check("Blocking an attacker address", p.block_ip("203.0.113.7", "selftest"))
    try:
        socket.create_connection(("203.0.113.7", 80), timeout=2).close()
        refused = False
    except OSError:
        refused = True
    rep.check("...connections to it are refused", refused)
    p.undo_all()
    rep.check("...and undo lets it through again",
              get("203.0.113.7", "x.example").endswith("ok"))
    return rep.fails


# ------------------------------------------------------------------- main --
def main(cfg, netns=False, out=print):
    rep = Report(out)
    out("LANGuard selftest: nothing on this machine is changed.\n")
    environment(rep)
    lg = logging.getLogger("languard")
    saved_state, saved_disabled = core.STATE_DIR, lg.disabled
    tmp = tempfile.mkdtemp(prefix="languard-selftest-")
    core.STATE_DIR = Path(tmp)                  # private state for the drill
    lg.disabled = True                          # simulated alerts aren't real
    try:
        scenarios(rep, cfg)
    except Exception as e:
        rep.line("FAIL", f"simulation stopped: {type(e).__name__}: {e}")
    finally:
        core.STATE_DIR = saved_state
        lg.disabled = saved_disabled
        shutil.rmtree(tmp, ignore_errors=True)
    if netns:
        out("== Real run in a throwaway network namespace")
        if os.geteuid() != 0 or not shutil.which("unshare"):
            rep.line("WARN", "needs root and unshare: sudo languard selftest --netns")
        else:
            root = str(Path(__file__).resolve().parent.parent)
            code = ("import sys, os, tempfile; sys.path.insert(0, %r); "
                    "os.environ['LANGUARD_STATE'] = tempfile.mkdtemp(); "
                    "from languard_core import core, selftest; "
                    "core.STATE_DIR = __import__('pathlib').Path("
                    "os.environ['LANGUARD_STATE']); "
                    "sys.exit(selftest.netns_child())" % root)
            try:
                r = subprocess.run(["unshare", "-n", sys.executable, "-c", code],
                                   capture_output=True, text=True, timeout=120)
                lines = [l for l in r.stdout.splitlines() if l.startswith("  [")]
                for l in lines:
                    out(l)
                rep.fails += sum("[FAIL]" in l for l in lines)
                if r.returncode and not any("[FAIL]" in l for l in lines):
                    rep.line("FAIL", "namespace run failed: "
                             + (r.stderr.strip().splitlines() or ["?"])[-1])
            except subprocess.TimeoutExpired:
                rep.line("FAIL", "namespace run timed out")
    out(f"\n{'ALL GOOD' if not rep.fails else f'{rep.fails} FAILED'}"
        f"{f', {rep.warns} warning(s)' if rep.warns else ''}")
    return 1 if rep.fails else 0
