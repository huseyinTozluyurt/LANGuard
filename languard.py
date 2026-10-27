#!/usr/bin/env python3
"""
LANGuard - LAN attack monitor and real-time anti-malware for Linux.

  languard monitor                 run every enabled module (what the service runs)
  languard status                  service health + latest alerts
  languard <module>                run one module: arp devices dhcp dns scan
                                   ipv6 mitm path tls strip filewatch host
                                   localdns
  languard tls --once              check HTTPS interception right now
  languard devices --learn|--list  device inventory
  languard dhcp --probe            list every DHCP server that answers
  languard wifi -w wlan1 --ssid X  deauth floods / evil twins (monitor mode)
  languard audit [--fix]           host hardening audit
  languard avscan [PATH...]        full virus scan (default: all home folders)
  languard quarantine [--restore ID]
  languard protect [--on|--off] [--unblock MAC|IP|all] [--unpin] [--undo-all]
                                   active protection status and undo
  languard protect --pin-device IP [MAC] | --unpin-device IP
                                   pin a NAS/printer like the router
  languard network [--home|--public|--unmark]
                                   tell LANGuard what this network is
  languard dnscheck                your encrypted DNS (dnscrypt-proxy), read-only
  languard hsts [--update]         the HSTS preload list
  languard evidence                packet captures saved on critical alerts
  languard selftest [--netns]      simulated attacks + environment checks
  languard baseline [--reset]      per-network baselines (router MAC, DHCP, DNS)
  languard pause MINUTES | resume  stop protection temporarily
  languard guard                   health check (run by a timer every 5 min)
  languard config                  print the effective configuration
"""

import argparse
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Python packages the installer fetched with pip because the distribution
# doesn't ship them (e.g. scapy on RHEL without EPEL). Distro packages win.
_VENDOR = Path(__file__).resolve().parent / "vendor"
if _VENDOR.is_dir():
    sys.path.append(str(_VENDOR))

from languard_core import __version__, distro                          # noqa: E402
from languard_core.core import (CONFIG_PATH, STATE_DIR, Alerter, Context,  # noqa: E402
                                iface_info, load_config, log, sd_notify,
                                setup_logging)
from languard_core.status import write_pause                            # noqa: E402

MODULES = {
    "arp": ("arp", "ARPMonitor"), "devices": ("devices", "DeviceMonitor"),
    "dhcp": ("dhcp", "DHCPMonitor"), "dns": ("dns", "DNSMonitor"),
    "scan": ("scan", "ScanMonitor"), "ipv6": ("ipv6", "IPv6Monitor"),
    "mitm": ("mitm", "MitmMonitor"), "path": ("path", "PathMonitor"),
    "tls": ("tls", "TLSMonitor"), "strip": ("strip", "StripMonitor"),
    "filewatch": ("filewatch", "FileWatch"),
    "host": ("host", "HostMonitor"), "wifi": ("wifi", "WifiMonitor"),
    "localdns": ("localdns", "LocalDNSMonitor"),
    "netid": ("netid", "NetIdMonitor"),
}
NEEDS_SCAPY = {"arp", "devices", "dhcp", "dns", "scan", "ipv6", "mitm",
               "path", "strip", "wifi"}
PAUSE_FILE = STATE_DIR / "paused_until"
# The ClamAV units differ per distribution (clamav-daemon, clamd@scan,
# clamd...); distro.clamav_units() finds the installed ones.
SERVICES = ["languard"]


def build_module(name, ctx, **kw):
    if name not in MODULES:
        raise SystemExit(f"Unknown module '{name}'. Choose from: "
                         f"{', '.join(MODULES)}")
    mod, cls = MODULES[name]
    return getattr(importlib.import_module(f"languard_core.{mod}"), cls)(ctx, **kw)


def need_root():
    if os.geteuid() != 0:
        sys.exit("This needs root: sudo languard ...")


def need_scapy():
    try:
        importlib.import_module("scapy.all")
    except ImportError:
        sys.exit(f"scapy is missing. Install it: {distro.install_hint('scapy')}")


# ---------------------------------------------------------------- runner --
def sniff_loop(ctx, mods):
    """Capture forever; survive Wi-Fi drops by retrying."""
    from scapy.all import Ether, conf, sniff
    conf.verb = 0
    bpf = " or ".join(f"({m.bpf})" for m in mods)
    evidence = getattr(ctx, "evidence", None)
    sensor = getattr(ctx, "sensor", None)

    def dispatch(pkt):
        if sensor is not None:
            mac = pkt[Ether].src if Ether in pkt else None
            if not sensor.admit(mac):         # a flooder only spends its own budget
                return
        if evidence is not None:
            evidence.feed(pkt)
        for m in mods:
            try:
                m.handle(pkt)
            except Exception as e:
                log.debug("[%s] handler error: %s", m.name, e)
                if sensor is not None:
                    sensor.error(m.name)
    while True:
        try:
            sock = conf.L2listen(iface=ctx.iface, filter=bpf)
            ctx.capture_socket = getattr(sock, "ins", None)   # kernel drop counters
            sniff(opened_socket=sock, prn=dispatch, store=False)
        except OSError as e:
            log.warning("Capture on %s stopped (%s); retrying in 10s",
                        ctx.iface, e)
            time.sleep(10)


def run_monitor(ctx, mods, timeout=None):
    """Start every module, then supervise: watchdog pings, dead-thread and
    IP-change detection. Exiting non-zero makes systemd restart us cleanly."""
    packet = [m for m in mods if m.bpf]
    loops = [m for m in mods if m.threaded]
    for m in mods:
        m.start()
    threads = []
    if packet:
        threads.append(threading.Thread(target=sniff_loop, args=(ctx, packet),
                                        name="sniffer", daemon=True))
    threads += [threading.Thread(target=m.run, name=m.name, daemon=True)
                for m in loops]
    for t in threads:
        t.start()
    log.info("LANGuard %s protecting %s (ip %s, gateway %s): %s",
             __version__, ctx.iface, ctx.my_ip, ctx.gateway,
             ", ".join(m.name for m in mods))
    sd_notify("READY=1")
    started = last_ip_check = last_sensor = time.time()
    code = 0
    from languard_core.status import write_status
    from languard_core.sensor import kernel_stats
    sensor = getattr(ctx, "sensor", None)
    try:
        while True:
            if sensor is not None and time.time() - last_sensor >= 60:
                last_sensor = time.time()
                sensor.kernel(kernel_stats(getattr(ctx, "capture_socket", None)))
                sensor.tick()
            write_status(ctx, mods, started)
            dead = [t.name for t in threads if not t.is_alive()]
            if dead:
                log.error("Worker stopped unexpectedly: %s; restarting",
                          ", ".join(dead))
                code = 1
                break
            if ctx.iface and time.time() - last_ip_check > 60:
                last_ip_check = time.time()
                ip, _, _ = iface_info(ctx.iface)
                if ip and ip != ctx.my_ip:
                    log.info("IP changed %s -> %s; restarting to re-baseline",
                             ctx.my_ip, ip)
                    code = 3
                    break
            sd_notify("WATCHDOG=1")
            if timeout and time.time() - started > timeout:
                break
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    sd_notify("STOPPING=1")
    for m in mods:
        if hasattr(m, "flush"):
            m.flush()
    log.info("Stopped.")
    return code


# --------------------------------------------------------- service tools --
def svc_state(name):
    try:
        return subprocess.run(["systemctl", "is-active", name], capture_output=True,
                              text=True, timeout=5).stdout.strip() or "unknown"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"


def signature_age_days():
    ages = [time.time() - p.stat().st_mtime
            for d in distro.SIGNATURE_DIRS if Path(d).exists()
            for p in Path(d).glob("daily.c[lv]d")]
    return min(ages) / 86400 if ages else None


def paused():
    try:
        return float(PAUSE_FILE.read_text()) > time.time()
    except (OSError, ValueError):
        return False


def guard(alerter):
    """Restart anything that stopped; warn about stale virus signatures."""
    if paused():
        log.info("[guard] protection paused by user; not restarting")
        return
    if PAUSE_FILE.exists():                      # pause just ended
        PAUSE_FILE.unlink(missing_ok=True)
        write_pause(None)
        subprocess.run(["systemctl", "start", "languard"], capture_output=True)
        alerter("guard", "resumed", "INFO", "Pause ended; protection resumed")
    if shutil.which("systemctl") is None:
        return
    for svc in SERVICES + distro.clamav_units():
        if subprocess.run(["systemctl", "cat", svc], capture_output=True).returncode:
            continue                                  # not installed
        if svc_state(svc) != "active":
            r = subprocess.run(["systemctl", "start", svc], capture_output=True,
                               text=True)
            # A start can "succeed" without running (a unit condition such as
            # ClamAV's "signatures downloaded" not met), so look again.
            if r.returncode == 0 and svc_state(svc) not in ("active", "activating"):
                outcome = (f"Started it, but it isn't running (check: systemctl "
                           f"status {svc})")
            elif r.returncode == 0:
                outcome = "Restarted it"
            else:
                outcome = "Restart FAILED: " + r.stderr.strip()
            level = "CRITICAL" if svc == "languard" else "WARNING"
            alerter("guard", f"down:{svc}", level,
                    f"{svc} was not running. {outcome}"
                    f". If you didn't stop it, something else may have")
    from languard_core import hsts
    hsts.refresh_if_old()
    age = signature_age_days()
    if age is not None and age > 3:
        alerter("guard", "sigs", "WARNING",
                f"Virus signatures are {age:.0f} days old: check "
                f"'systemctl status {distro.freshclam_unit() or 'clamav-freshclam'}'")


def set_protect(path, enabled=None, options=None):
    """Flip protect.enabled and/or single responses (options: {key: bool})
    in the config file, keeping everything else."""
    path = Path(path) if path else CONFIG_PATH
    try:
        with open(path) as f:
            user = json.load(f)
    except FileNotFoundError:
        user = {}
    except json.JSONDecodeError as e:
        sys.exit(f"Can't change {path}: it isn't valid JSON ({e})")
    prot = user.setdefault("protect", {})
    if enabled is not None:
        prot["enabled"] = bool(enabled)
    prot.update({k: bool(v) for k, v in (options or {}).items()})
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(user, indent=2) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def status(cfg):
    print(f"LANGuard {__version__}")
    clamav = distro.clamav_units() or ["clamav (not installed)"]
    for svc in SERVICES + clamav + ["languard-guard.timer", "languard-avscan.timer"]:
        st = svc_state(svc) if "(" not in svc else "missing"
        mark = "✔" if st == "active" else "✘"
        print(f"  {mark} {svc:<24} {st}")
    try:
        from languard_core.core import load_state
        st = load_state("protect", {})
        now = time.time()
        n = sum(1 for b in st.get("blocked", {}).values() if b.get("until", 0) > now)
        print(f"  active protection: {'on' if cfg['protect']['enabled'] else 'off'}"
              f"{', router pinned' if st.get('pin') else ''}"
              f"{f', {n} device(s) isolated' if n else ''}")
    except PermissionError:
        pass
    from languard_core import hsts, localdns
    info = localdns.inspect()
    if info.get("resolver"):
        print(f"  DNS: {info['label']} ({', '.join(info['listen']) or '?'})"
              f"{'; leak risk: ' + '; '.join(info['leak_risk']) if info['leak_risk'] else ', no leak risk seen'}")
    else:
        print("  DNS: no local encrypted resolver (plain DNS, watched for forgeries)")
    try:
        print(f"  {hsts.status()}")
    except PermissionError:
        pass
    if paused():
        until = time.strftime("%H:%M", time.localtime(float(PAUSE_FILE.read_text())))
        print(f"  ⏸ paused until {until} (languard resume)")
    age = signature_age_days()
    if age is not None:
        print(f"  virus signatures: updated {age * 24:.0f}h ago")
    try:
        q = STATE_DIR / "quarantine"
        n = len(list(q.glob("*.json"))) if q.exists() else 0
        print(f"  quarantine: {n} file(s)")
    except PermissionError:
        print("  quarantine: (sudo languard quarantine to view)")
    try:
        lines = [l for l in Path(cfg["log_file"]).read_text().splitlines()
                 if re.search(r"\b(WARNING|CRITICAL)\b", l)]
        print("\nLatest alerts:" if lines else "\nNo alerts logged.")
        for l in lines[-10:]:
            print("  " + l)
    except OSError:
        print("\n(run with sudo to read the alert log)")


# ------------------------------------------------------------------ main --
def main():
    p = argparse.ArgumentParser(
        prog="languard", description="LAN attack monitor and real-time "
        "anti-malware for Linux.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("\n", 2)[2])
    p.add_argument("-c", "--config", help="config file "
                   "(default /etc/languard/config.json)")
    p.add_argument("-i", "--iface", help="network interface")
    p.add_argument("-g", "--gateway", help="gateway IP")
    p.add_argument("--log", help="log file (default from config)")
    p.add_argument("--json-log", help="also write alerts as JSON lines")
    p.add_argument("--notify", action="store_true", help="desktop popups")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("monitor", help="run all enabled modules")
    m.add_argument("-m", "--modules", help="comma-separated list")
    m.add_argument("--timeout", type=int, help="stop after N seconds")

    for name in MODULES:
        if name == "wifi":
            continue
        sp = sub.add_parser(name, help=f"run the {name} module alone")
        sp.add_argument("--timeout", type=int)
        if name == "scan":
            sp.add_argument("--block", action="store_true",
                            help="auto-block offenders with UFW")
        if name == "tls":
            sp.add_argument("--once", action="store_true",
                            help="check now, print results, exit")
        if name == "devices":
            sp.add_argument("--learn", action="store_true",
                            help="sweep the LAN and trust everything found")
            sp.add_argument("--list", action="store_true")
            sp.add_argument("--sweep", action="store_true")
            sp.add_argument("--trust", nargs="+", metavar="MAC")
            sp.add_argument("--untrust", nargs="+", metavar="MAC")
            sp.add_argument("--forget", nargs="+", metavar="MAC")
        if name == "dhcp":
            sp.add_argument("--probe", action="store_true",
                            help="send a DHCPDISCOVER and list responders")

    w = sub.add_parser("wifi", help="deauth flood / evil twin detection")
    w.add_argument("-w", "--wifi-iface", help="monitor-mode interface")
    w.add_argument("--ssid", action="append")
    w.add_argument("--trust-bssid", action="append", metavar="MAC")
    w.add_argument("--hop", action="store_true", help="hop channels")
    w.add_argument("--survey", type=int, metavar="SEC")
    w.add_argument("--timeout", type=int)

    a = sub.add_parser("audit", help="host hardening audit")
    a.add_argument("--fix", action="store_true")
    a.add_argument("-y", "--yes", action="store_true")
    a.add_argument("--json", action="store_true")

    s = sub.add_parser("avscan", help="full virus scan")
    s.add_argument("paths", nargs="*")
    qp = sub.add_parser("quarantine", help="list or restore quarantined files")
    qp.add_argument("--restore", metavar="ID")
    pp = sub.add_parser("pause", help="pause protection for N minutes")
    pp.add_argument("minutes", type=int)
    sub.add_parser("resume", help="end a pause")
    pr = sub.add_parser("protect", help="active protection status and undo")
    pr.add_argument("--unblock", nargs="+", metavar="MAC_OR_IP",
                    help="stop isolating these MACs ('all' for every one)")
    pr.add_argument("--unpin", action="store_true",
                    help="remove the router's static ARP entry")
    pr.add_argument("--undo-all", action="store_true",
                    help="undo every protective action")
    pr.add_argument("--pin-device", nargs="+", metavar=("IP", "MAC"),
                    help="pin a device (NAS, printer) on this network to its "
                    "MAC (default: the MAC it has now)")
    pr.add_argument("--unpin-device", metavar="IP")
    pr.add_argument("--set", nargs="+", metavar="RESPONSE=on|off",
                    help="switch single responses on or off, e.g. "
                    "--set https_guard=off (restarts the service)")
    onoff = pr.add_mutually_exclusive_group()
    onoff.add_argument("--on", action="store_true",
                       help="turn active protection on (restarts the service)")
    onoff.add_argument("--off", action="store_true",
                       help="turn active protection off and undo its actions")
    bp = sub.add_parser("baseline", help="per-network baselines")
    bp.add_argument("--reset", action="store_true",
                    help="relearn this network (after replacing your router)")
    bp.add_argument("--reset-all", action="store_true")
    nw = sub.add_parser("network", help="mark this network home or public")
    kind = nw.add_mutually_exclusive_group()
    kind.add_argument("--home", action="store_true",
                      help="your own network: no preventive hardening")
    kind.add_argument("--public", action="store_true",
                      help="café/hotel/office: LLMNR off and ICMP redirects "
                      "ignored from the start")
    kind.add_argument("--unmark", action="store_true")
    sub.add_parser("dnscheck", help="your encrypted DNS resolver (read-only)")
    hp = sub.add_parser("hsts", help="the HSTS preload list")
    hp.add_argument("--update", action="store_true", help="download it now")
    sub.add_parser("evidence", help="list packet captures of critical alerts")
    st = sub.add_parser("selftest", help="simulated attacks and environment "
                        "checks (changes nothing on this machine)")
    st.add_argument("--netns", action="store_true", help="also run the "
                    "HTTPS guard and IP block for real in a throwaway "
                    "network namespace (root)")
    sub.add_parser("guard", help="restart stopped services (timer)")
    sub.add_parser("status", help="health and latest alerts")
    sub.add_parser("config", help="print effective configuration")

    args = p.parse_args()
    from languard_core import tamper
    lowered = tamper.weakens(sys.argv[1:])
    if lowered and tamper.via_cached_pkexec():
        sys.exit(f"This lowers protection ({lowered}), so it asks for your "
                 f"password every time. Use the LANGuard app, or run: pkexec "
                 f"{Path(__file__).resolve().parent / 'languard_strict.py'} "
                 f"{' '.join(sys.argv[1:])}   (or: sudo languard ...)")
    cfg = load_config(args.config)
    if args.cmd == "config":
        print(json.dumps(cfg, indent=2))
        return
    if args.cmd == "status":
        status(cfg)
        return
    if args.cmd == "dnscheck":
        from languard_core import audit, localdns
        info = localdns.inspect()
        print(json.dumps({k: v for k, v in info.items() if k != "checked"},
                         indent=2))
        audit.print_report(audit.check_local_dns(info))
        return
    if args.cmd == "selftest":
        from languard_core import selftest
        sys.exit(selftest.main(cfg, netns=args.netns))

    quiet_cmds = ("audit", "quarantine")
    log_file = args.log or (cfg["log_file"] if os.geteuid() == 0 else None)
    setup_logging(None if args.cmd in quiet_cmds else log_file, args.verbose)
    alerter = Alerter(cfg["alert_cooldown"], args.notify or cfg["notify"],
                      args.json_log or cfg["json_log"])
    if lowered and os.geteuid() == 0:
        user, via, prog = tamper.caller()
        alerter("tamper", f"lower:{lowered}",
                "WARNING" if os.environ.get(tamper.STRICT_ENV) else "CRITICAL",
                f"PROTECTION LOWERED: {lowered}, by {user} via {via} (asked by: "
                f"{prog}). If you didn't do this, something on this computer "
                f"is switching LANGuard off: run 'sudo languard resume' / "
                f"'sudo languard protect --on' and scan it",
                user=user, via=via, program=prog, change=lowered)

    if args.cmd == "audit":
        from languard_core import audit
        ctx = Context(cfg, alerter, args.iface, args.gateway)
        if args.fix:
            audit.apply_fixes(args.yes)
            return
        results = audit.run_audit(ctx.gateway, ctx.iface)
        if args.json:
            print(audit.to_json(results))
            return
        if os.geteuid() != 0:
            print("(tip: run with sudo for firewall and SSH checks)\n")
        counts = audit.print_report(results)
        sys.exit(1 if counts["FAIL"] else 0)

    if args.cmd == "quarantine":
        from languard_core import filewatch
        need_root()
        if args.restore:
            filewatch.restore_quarantine(args.restore)
        else:
            filewatch.list_quarantine()
        return

    if args.cmd == "pause":
        need_root()
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        PAUSE_FILE.write_text(str(time.time() + args.minutes * 60))
        write_pause(time.time() + args.minutes * 60)
        subprocess.run(["systemctl", "stop", "languard"])
        print(f"Protection paused for {args.minutes} min. "
              f"It resumes automatically (or: sudo languard resume).")
        return
    if args.cmd == "resume":
        need_root()
        PAUSE_FILE.unlink(missing_ok=True)
        write_pause(None)
        subprocess.run(["systemctl", "start", "languard"])
        print("Protection resumed.")
        return
    if args.cmd == "guard":
        need_root()
        guard(alerter)
        return
    if args.cmd == "hsts":
        from languard_core import hsts
        if args.update:
            need_root()
            try:
                print(f"Downloaded the HSTS preload list: {hsts.update()} sites.")
            except OSError as e:
                sys.exit(f"Update failed: {e}")
        print(hsts.status())
        return
    if args.cmd == "evidence":
        from languard_core import evidence
        need_root()
        evidence.list_evidence()
        return

    if args.cmd in ("protect", "baseline", "network"):
        from languard_core import baseline, protect
        if args.cmd == "baseline" and not (args.reset or args.reset_all):
            baseline.show()
            return
        need_root()
        ctx = Context(cfg, alerter, args.iface, args.gateway)
        prot = protect.Protector(ctx, sync=True)
        if args.cmd == "network":
            if args.home or args.public or args.unmark:
                prot.base.set_kind("home" if args.home else
                                   "public" if args.public else None)
                prot.apply_network_kind()
            kind, why = prot.network_kind()
            print(f"This network ({prot.base.key}): {kind or 'not marked'}"
                  f"{f' ({why})' if kind and why != 'marked' else ''}")
            if kind == "public":
                print("  LLMNR off and ICMP redirects ignored from the start "
                      "(DNS servers unchanged).")
            elif kind is None:
                print("  Mark it: sudo languard network --home (or --public)")
            return
        if args.cmd == "baseline":
            prot.unpin()                     # the pinned MAC may be stale
            baseline.reset(None if args.reset_all else baseline.network_key(ctx))
            print("Baseline forgotten; LANGuard relearns and re-verifies it. "
                  "Restarting the service.")
            subprocess.run(["systemctl", "try-restart", "languard"])
            return
        if args.on or args.off:
            set_protect(args.config, args.on)
            cfg = load_config(args.config)
            if args.off:
                prot.undo_all()
            subprocess.run(["systemctl", "try-restart", "languard"])
            print(f"Active protection turned {'on' if args.on else 'off'}.")
        if args.set:
            opts = {}
            for item in args.set:
                key, _, val = item.partition("=")
                key = key.strip().replace("-", "_")
                if key not in protect.OPTIONS or val not in ("on", "off"):
                    sys.exit(f"Use RESPONSE=on|off with one of: "
                             f"{', '.join(protect.OPTIONS)}")
                opts[key] = val == "on"
            set_protect(args.config, options=opts)
            cfg = load_config(args.config)
            for key, on in opts.items():
                if not on:
                    prot.disable_option(key)
            subprocess.run(["systemctl", "try-restart", "languard"])
            print("; ".join(f"{k} {'on' if v else 'off'}" for k, v in opts.items()))
        if args.undo_all:
            prot.undo_all()
            print("Undid every protective action (pin, blocks, IPv6 lockdown, LLMNR, redirects, HTTPS guard).")
        for mac in args.unblock or []:
            prot.unblock(mac)
            print(f"No longer blocking {mac}.")
        if args.unpin:
            print("Router pin removed." if prot.unpin() else "No router pin.")
        if args.pin_device:
            ip, mac = args.pin_device[0], (args.pin_device[1:] or [None])[0]
            try:
                mac = prot.pin_device(ip, mac)
            except ValueError as e:
                sys.exit(str(e))
            print(f"Pinned {ip} to {mac} on this network. Make sure that is "
                  f"really the device's MAC (label or its settings page).")
        if args.unpin_device:
            print(f"Unpinned {args.unpin_device}."
                  if prot.unpin_device(args.unpin_device) else "Not pinned.")
        protect.print_status(cfg)
        return

    ctx = Context(cfg, alerter, None if args.cmd == "wifi" else args.iface,
                  args.gateway)

    if args.cmd == "avscan":
        need_root()
        fw = build_module("filewatch", ctx, scanner=lambda p: ("clean", None))
        found = fw.full_scan(args.paths or None)
        print(f"{len(found)} infected file(s).")
        return

    if args.cmd == "devices" and (args.list or args.trust or args.untrust
                                  or args.forget):
        from languard_core import devices
        if args.trust:
            devices.set_trust(args.trust, True)
        if args.untrust:
            devices.set_trust(args.untrust, False)
        if args.forget:
            devices.set_trust(args.forget, forget=True)
        devices.list_devices()
        return

    if args.cmd == "tls" and args.once:
        build_module("tls", ctx).report()
        return

    if args.cmd == "wifi":
        iface = args.wifi_iface or cfg["wifi"]["monitor_interface"]
        if not iface:
            sys.exit("Give a monitor-mode interface: languard wifi -w wlan1")
        if args.ssid:
            cfg["wifi"]["ssids"] = args.ssid
        if args.trust_bssid:
            cfg["wifi"]["trusted_bssids"] = args.trust_bssid
        need_root()
        need_scapy()
        ctx = Context(cfg, alerter, iface, args.gateway)
        mod = build_module("wifi", ctx, hop=args.hop or bool(args.survey))
        run_monitor(ctx, [mod], timeout=args.survey or args.timeout)
        if args.survey:
            mod.survey()
        return

    names = ((args.modules.split(",") if args.modules else cfg["modules"])
             if args.cmd == "monitor" else [args.cmd])
    names = [n.strip() for n in names if n.strip()]
    # Configs written before 1.3 list modules without "strip"; it belongs with
    # "tls" (they share captive-portal state), so add it unless -m was given.
    if args.cmd == "monitor" and not args.modules and "tls" in names \
            and "strip" not in names and "strip" not in cfg.get("modules_off", []):
        names.append("strip")
    # Same for "localdns" (1.6) and "netid" (1.7): they only read, so they
    # join older configs too.
    for extra in ("localdns", "netid"):
        if args.cmd == "monitor" and not args.modules and extra not in names \
                and extra not in cfg.get("modules_off", []):
            names.append(extra)
    need_root()
    if NEEDS_SCAPY & set(names):
        need_scapy()
    if not ctx.iface and NEEDS_SCAPY & set(names):
        sys.exit("No network interface found; pass -i")

    if args.cmd == "devices" and (args.learn or args.sweep):
        from languard_core import devices
        mod = build_module("devices", ctx, learning=args.learn)
        found = mod.sweep()
        if args.learn:
            devices.set_trust(["all"], True)
        print(f"Found {len(found)} devices.\n")
        devices.list_devices()
        return
    if args.cmd == "dhcp" and args.probe:
        build_module("dhcp", ctx).probe()
        return
    if args.cmd == "scan" and args.block:
        cfg["scan"]["block"] = True

    from languard_core.sensor import Sensor
    ctx.sensor = Sensor(cfg, lambda key, level, msg, **d:
                        alerter("sensor", key, level, msg, **d))
    from languard_core.evidence import Evidence
    ctx.evidence = Evidence(cfg)
    alerter.hooks.append(ctx.evidence.on_alert)
    from languard_core.protect import Protector
    ctx.protect = Protector(ctx)
    try:
        ctx.protect.start()
    except Exception as e:                     # never let protection stop detection
        log.error("Active protection failed to start: %s", e)
        ctx.protect = None

    mods = []
    for n in names:
        try:
            mods.append(build_module(n, ctx))
        except Exception as e:                 # one bad module mustn't stop the rest
            log.error("Module %s failed to start: %s", n, e)
    if not mods:
        sys.exit(1)
    sys.exit(run_monitor(ctx, mods, timeout=getattr(args, "timeout", None)))


if __name__ == "__main__":
    main()
