"""
Host hardening audit for a Linux desktop on an untrusted LAN.

Checks the firewall, exposed services, SSH, kernel network settings, Wi-Fi
security, the gateway's ARP entry, automatic updates, SMB signing / NTLM
(relay attacks) and whether your own encrypted DNS (dnscrypt-proxy) covers
every lookup. `--fix` applies the safe kernel settings (a reversible sysctl
file) and, each only after you say yes, LLMNR/mDNS off and Samba signing (with
a backup of smb.conf). It never changes DNS servers or dnscrypt-proxy; for
those it prints what you could run.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from . import distro

SYSCTL_FILE = "/etc/sysctl.d/99-languard.conf"

# (key, wanted, why)
SYSCTLS = [
    ("net.ipv4.conf.all.rp_filter", "1", "drop spoofed source addresses"),
    ("net.ipv4.conf.default.rp_filter", "1", "drop spoofed source addresses"),
    ("net.ipv4.conf.all.accept_redirects", "0", "ignore ICMP redirects (MITM)"),
    ("net.ipv4.conf.default.accept_redirects", "0", "ignore ICMP redirects (MITM)"),
    ("net.ipv4.conf.all.secure_redirects", "0", "ignore 'secure' ICMP redirects"),
    ("net.ipv6.conf.all.accept_redirects", "0", "ignore IPv6 redirects (MITM)"),
    ("net.ipv4.conf.all.send_redirects", "0", "don't act like a router"),
    ("net.ipv4.conf.all.accept_source_route", "0", "reject source-routed packets"),
    ("net.ipv4.conf.all.log_martians", "1", "log impossible source addresses"),
    ("net.ipv4.tcp_syncookies", "1", "survive SYN floods"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "ignore smurf-style pings"),
    ("net.ipv4.conf.all.arp_ignore", "1", "answer ARP only for own IPs"),
    ("net.ipv4.conf.all.arp_announce", "2", "use the best source in ARP"),
]

RISKY_SERVICES = {
    "telnet.socket": "Telnet sends passwords in clear text",
    "inetutils-inetd": "legacy inetd services",
    "vsftpd": "FTP server",
    "smbd": "Windows file sharing (SMB)",
    "nmbd": "NetBIOS name service",
    "rpcbind": "RPC portmapper (NFS)",
    "nfs-server": "NFS file server",
    "avahi-daemon": "mDNS: advertises this machine on the LAN",
    "cups-browsed": "printer discovery (has had remote exploits)",
    "xrdp": "remote desktop",
    "x11vnc": "VNC remote desktop",
    "apache2": "web server",
    "nginx": "web server",
    "mysql": "database server",
    "postgresql": "database server",
}

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 127, ""


class Result:
    def __init__(self, status, check, detail, fix=None):
        self.status, self.check, self.detail, self.fix = status, check, detail, fix

    def as_dict(self):
        return vars(self)


# ----------------------------------------------------------------- checks --
def check_firewalld():
    """Fedora, RHEL and openSUSE ship firewalld instead of UFW."""
    rc, out = _run(["firewall-cmd", "--state"])
    if out.strip() != "running":
        return [Result(FAIL, "Firewall", "firewalld is installed but not running",
                       "sudo systemctl enable --now firewalld")]
    rc, zone = _run(["firewall-cmd", "--get-default-zone"])
    zone = zone.strip()
    if zone in ("trusted",):
        return [Result(WARN, "Firewall", f"firewalld default zone is '{zone}' "
                       "(accepts everything)",
                       "sudo firewall-cmd --set-default-zone=public")]
    return [Result(PASS, "Firewall", f"firewalld running (default zone {zone or '?'})")]


def check_firewall():
    if not shutil.which("ufw") and shutil.which("firewall-cmd"):
        return check_firewalld()
    if not shutil.which("ufw"):
        if distro.info()[0] in ("fedora", "suse"):
            return [Result(FAIL, "Firewall", "No firewall (firewalld) installed",
                           f"{distro.install_hint('firewall')} && sudo systemctl "
                           "enable --now firewalld")]
        return [Result(FAIL, "Firewall", "UFW is not installed",
                       f"{distro.INSTALL_CMD.get(distro.info()[0], 'sudo apt install')} "
                       "ufw && sudo ufw default deny incoming "
                       "&& sudo ufw allow ssh && sudo ufw enable")]
    rc, out = _run(["ufw", "status", "verbose"])
    if rc != 0:
        return [Result(INFO, "Firewall", "Run as root to read UFW status")]
    if "Status: active" not in out:
        return [Result(FAIL, "Firewall", "UFW is installed but inactive",
                       "sudo ufw default deny incoming && sudo ufw default "
                       "allow outgoing && sudo ufw allow ssh && sudo ufw enable")]
    m = re.search(r"Default: (\w+) \(incoming\)", out)
    if m and m.group(1) != "deny":
        return [Result(WARN, "Firewall",
                       f"UFW active but incoming default is '{m.group(1)}'",
                       "sudo ufw default deny incoming")]
    return [Result(PASS, "Firewall", "UFW active, incoming denied by default")]


def _ephemeral_range():
    try:
        lo, hi = Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()
        return int(lo), int(hi)
    except (OSError, ValueError):
        return 32768, 60999


def exposed_sockets(parse=None):
    """[(proto, port, process)] bound to all interfaces, minus UDP client sockets."""
    out = parse if parse is not None else _run(["ss", "-H", "-tulnp"])[1]
    lo, hi = _ephemeral_range()
    found = set()
    for line in out.splitlines():
        p = line.split()
        if len(p) < 5:
            continue
        proto, local = p[0], p[4]
        addr, _, port = local.rpartition(":")
        if not (addr in ("0.0.0.0", "[::]", "*") or addr.startswith("*%")):
            continue
        # Unconnected UDP sockets on ephemeral ports are outgoing client
        # sockets (browsers, mDNS queries), not services waiting for peers.
        if proto == "udp" and port.isdigit() and lo <= int(port) <= hi:
            continue
        proc = re.search(r'users:\(\("([^"]+)"', line)
        found.add((proto, port, proc.group(1) if proc else "?"))
    return sorted(found)


def check_listening(parse=None):
    """Services listening on all interfaces (reachable from the LAN)."""
    exposed = sorted({f"{pr}/{po} ({name})" for pr, po, name in exposed_sockets(parse)})
    if not exposed:
        return [Result(PASS, "Exposed services", "Nothing listens on all interfaces")]
    return [Result(WARN, "Exposed services",
                   "Reachable from the LAN: " + ", ".join(exposed),
                   "Stop what you don't need (sudo systemctl disable --now NAME) "
                   "or bind it to 127.0.0.1; firewall the rest")]


def check_ssh():
    if not shutil.which("sshd"):
        return [Result(PASS, "SSH server", "Not installed")]
    rc, out = _run(["sshd", "-T"])
    if rc != 0:
        return [Result(INFO, "SSH server", "Run as root to read sshd settings")]
    cfg = dict(l.split(None, 1) for l in out.splitlines() if " " in l)
    res = []
    if cfg.get("permitrootlogin", "") not in ("no", "prohibit-password",
                                              "without-password"):
        res.append(Result(FAIL, "SSH root login",
                          f"PermitRootLogin {cfg.get('permitrootlogin')}",
                          "Set 'PermitRootLogin no' in /etc/ssh/sshd_config.d/"
                          "hardening.conf, then sudo systemctl reload ssh"))
    if cfg.get("passwordauthentication") == "yes":
        res.append(Result(WARN, "SSH passwords",
                          "Password login enabled (brute-forceable)",
                          "Set up keys (ssh-copy-id), then set "
                          "'PasswordAuthentication no' and reload ssh"))
    if cfg.get("x11forwarding") == "yes":
        res.append(Result(WARN, "SSH X11 forwarding", "Enabled",
                          "Set 'X11Forwarding no'"))
    if int(cfg.get("maxauthtries", "6")) > 4:
        res.append(Result(WARN, "SSH auth tries",
                          f"MaxAuthTries {cfg.get('maxauthtries')}",
                          "Set 'MaxAuthTries 3'"))
    return res or [Result(PASS, "SSH server", "Hardened settings")]


def read_sysctl(key):
    try:
        return Path("/proc/sys/" + key.replace(".", "/")).read_text().strip()
    except OSError:
        return None


def check_sysctl(reader=read_sysctl):
    bad = []
    for key, want, why in SYSCTLS:
        have = reader(key)
        if have is None:
            continue
        ok = have == want or (key.endswith("rp_filter") and have == "2")
        if not ok:
            bad.append(f"{key}={have} (want {want}: {why})")
    res = []
    if bad:
        res.append(Result(FAIL, "Kernel network settings",
                          f"{len(bad)} unsafe:\n          - " + "\n          - ".join(bad),
                          f"sudo languard audit --fix  (writes {SYSCTL_FILE})"))
    else:
        res.append(Result(PASS, "Kernel network settings", "All hardened"))
    if reader("net.ipv4.ip_forward") == "1":
        res.append(Result(WARN, "IP forwarding",
                          "Enabled: this machine routes packets. Expected only "
                          "for routers, Docker or VPN servers"))
    return res


# service -> process name seen in `ss`. None = risky even without a listening port.
SERVICE_PROCS = {
    "telnet.socket": None, "inetutils-inetd": None, "cups-browsed": None,
    "avahi-daemon": "avahi-daemon", "vsftpd": "vsftpd", "smbd": "smbd",
    "nmbd": "nmbd", "rpcbind": "rpcbind", "nfs-server": None, "xrdp": "xrdp",
    "x11vnc": "x11vnc", "apache2": "apache2", "nginx": "nginx",
    "mysql": "mysqld", "postgresql": "postgres",
}


def check_services(active=None, exposed=None):
    """Risky services: WARN if reachable from the LAN, INFO if local-only."""
    if exposed is None:
        exposed = exposed_sockets()
    exposed_procs = {name for _, _, name in exposed}
    lan, local = [], []
    for svc, why in RISKY_SERVICES.items():
        if active is not None:
            on = svc in active
        else:
            on = _run(["systemctl", "is-active", svc], timeout=5)[1].strip() == "active"
        if not on:
            continue
        proc = SERVICE_PROCS.get(svc)
        if proc is None or proc in exposed_procs:
            lan.append(f"{svc} ({why})")
        else:
            local.append(svc)
    res = []
    if lan:
        res.append(Result(WARN, "Network services",
                          "Reachable from the LAN: " + "; ".join(lan),
                          "Disable anything unused: sudo systemctl disable --now NAME "
                          "(for socket-activated ones like avahi, also NAME.socket)"))
    if local:
        res.append(Result(PASS, "Local-only services",
                          f"{', '.join(local)} running but bound to localhost"))
    return res or [Result(PASS, "Network services", "No commonly risky services running")]


def check_wifi():
    if not shutil.which("nmcli"):
        return []
    rc, out = _run(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi"])
    for line in out.splitlines():
        parts = line.split(":")
        if parts[0] != "yes":
            continue
        ssid, sec = parts[1], ":".join(parts[2:])
        if not sec or sec == "--":
            return [Result(FAIL, "Wi-Fi security",
                           f"Connected to OPEN network '{ssid}': anyone nearby "
                           f"can read unencrypted traffic",
                           "Prefer a WPA2/WPA3 network; here, keep to HTTPS sites "
                           "and mark it public: sudo languard network --public")]
        if "WEP" in sec or sec.strip() == "WPA1":
            return [Result(FAIL, "Wi-Fi security",
                           f"'{ssid}' uses {sec}, which is crackable in minutes",
                           "Switch the router to WPA2-AES or WPA3")]
        if "WPA3" in sec or "SAE" in sec:
            return [Result(PASS, "Wi-Fi security", f"'{ssid}' uses {sec}")]
        return [Result(WARN, "Wi-Fi security",
                       f"'{ssid}' uses {sec}; fine with a strong password",
                       "Prefer WPA3 if your router supports it")]
    return []


def check_gateway_arp(gateway, iface):
    if not gateway:
        return []
    rc, out = _run(["ip", "neigh", "show", gateway])
    if "PERMANENT" in out:
        return [Result(PASS, "Gateway ARP entry", f"{gateway} is pinned (static)")]
    m = re.search(r"lladdr ([0-9a-f:]{17})", out)
    mac = m.group(1) if m else "<router-mac>"
    return [Result(INFO, "Gateway ARP entry",
                   f"{gateway} is learned dynamically (spoofable). Verify "
                   f"{mac} is your router's real MAC before pinning it",
                   f"sudo ip neigh replace {gateway} lladdr {mac} dev "
                   f"{iface or '<iface>'} nud permanent   (lasts until reboot)")]


RESOLVED_DROPIN = "/etc/systemd/resolved.conf.d/languard.conf"


def check_name_poisoning(out=None):
    """LLMNR / mDNS let any LAN device answer name lookups (Responder)."""
    if out is None:
        if not shutil.which("resolvectl"):
            return []
        out = _run(["resolvectl", "status"])[1]
    on = sorted({p for p in ("LLMNR", "mDNS") if f"+{p}" in out})
    if not on:
        return [Result(PASS, "Name poisoning (LLMNR/mDNS)", "Disabled")]
    return [Result(WARN, "Name poisoning (LLMNR/mDNS)",
                   f"{' and '.join(on)} enabled: any device on the LAN can "
                   f"answer your name lookups (Responder attack)",
                   f"sudo languard audit --fix  (writes {RESOLVED_DROPIN})")]


def check_local_dns(info=None):
    """Your own encrypted resolver (dnscrypt-proxy): read-only check that
    every lookup goes through it."""
    from . import localdns
    info = info if info is not None else localdns.inspect()
    if not info.get("resolver"):
        return [Result(INFO, "Encrypted DNS",
                       "No local encrypted resolver (dnscrypt-proxy, stubby...) "
                       "running: DNS goes out in plain text, and LANGuard "
                       "watches it for forged answers")]
    where = ", ".join(info.get("listen") or []) or "?"
    if info.get("leak_risk"):
        return [Result(WARN, "Encrypted DNS",
                       f"{info['label']} runs ({where}), but "
                       f"{'; '.join(info['leak_risk'])}: those are asked in "
                       f"plain text, so a man in the middle can forge answers",
                       "Your call (LANGuard doesn't change DNS settings): "
                       + localdns.advice(info))]
    return [Result(PASS, "Encrypted DNS",
                   f"{info['label']} handles every lookup ({where}); "
                   f"LANGuard leaves its settings alone")]


SMB_CONF = "/etc/samba/smb.conf"
SMB1 = {"core", "coreplus", "lanman1", "lanman2", "nt1"}
# (setting, good values, wanted value, server-only, why)
SMB_SETTINGS = [
    ("client signing", {"required", "mandatory"}, "required", False,
     "unsigned SMB lets a man in the middle relay or alter your sessions"),
    ("ntlm auth", {"ntlmv2-only", "mschapv2-and-ntlmv2-only", "disabled", "no"},
     "ntlmv2-only", False, "NTLMv1 hashes are cracked in minutes"),
    ("client min protocol", None, "SMB2_02", False,
     "SMB1 has no protection against downgrade and relay"),
    ("server signing", {"required", "mandatory"}, "mandatory", True,
     "unsigned SMB lets attackers relay stolen logins to this machine"),
    ("server min protocol", None, "SMB2_02", True, "SMB1 is unsafe"),
]


def _testparm():
    rc, out = _run(["testparm", "-s", "-v"], timeout=15)
    if rc == 127:
        return None
    vals, section = {}, None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line.strip("[]").lower()
        elif section == "global" and "=" in line:
            k, _, v = line.partition("=")
            vals[k.strip().lower()] = v.strip().lower()
    return vals


def _smb_bad(vals, server):
    bad = []
    for key, good, want, server_only, why in SMB_SETTINGS:
        if server_only and not server:
            continue
        have = vals.get(key, "")
        ok = (have not in SMB1 and have != "") if good is None else have in good
        if not ok:
            bad.append((key, have or "default", want, why))
    return bad


def check_smb(vals=None, server=None, mounts=None):
    """SMB signing and NTLM: what NTLM relay attacks (Responder + ntlmrelayx)
    and SMB downgrades need."""
    res = []
    if server is None:
        server = bool(shutil.which("smbd"))
    if vals is None and (shutil.which("testparm") or Path(SMB_CONF).exists()):
        vals = _testparm()
    if vals:
        bad = _smb_bad(vals, server)
        if bad:
            res.append(Result(WARN, "SMB signing / NTLM",
                              "; ".join(f"{k} = {h} (want {w}: {why})"
                                        for k, h, w, why in bad),
                              f"sudo languard audit --fix  (asks first, backs "
                              f"up {SMB_CONF})"))
        else:
            res.append(Result(PASS, "SMB signing / NTLM",
                              "Signing required, NTLMv2 only, no SMB1"))
    if mounts is None:
        try:
            mounts = Path("/proc/mounts").read_text()
        except OSError:
            mounts = ""
    for line in mounts.splitlines():
        p = line.split()
        if len(p) < 4 or p[2] not in ("cifs", "smb3"):
            continue
        opts = p[3].split(",")
        weak = [o for o in opts if o in ("vers=1.0", "sec=ntlm", "sec=lanman")]
        if weak:
            res.append(Result(FAIL, "SMB mount", f"{p[1]} ({p[0]}) uses "
                              f"{', '.join(weak)}: weak and relayable",
                              "remount with vers=3.1.1 (and seal to encrypt)"))
        elif "seal" not in opts:
            res.append(Result(INFO, "SMB mount", f"{p[1]} ({p[0]}) is signed "
                              f"but not encrypted",
                              "add the 'seal' mount option to encrypt it"))
    if not res:
        res.append(Result(PASS, "SMB signing / NTLM", "No Samba or SMB mounts"))
    return res


def fix_smb(assume_yes=False, conf=SMB_CONF, vals=None, server=None,
            validate=None):
    """Add the missing settings to [global] after a backup. Returns the
    backup path, or None if nothing was changed."""
    import time as _time
    if not Path(conf).exists():
        return None
    if server is None:
        server = bool(shutil.which("smbd"))
    vals = _testparm() if vals is None else vals
    bad = _smb_bad(vals or {}, server)
    if not bad:
        print("SMB signing / NTLM: already hardened.")
        return None
    lines = [f"{k} = {w}" for k, _, w, _ in bad]
    print(f"\nHarden Samba against NTLM relay? Adds to [global] in {conf}:\n  "
          + "\n  ".join(lines) + "\nAn old NAS that can't sign or speaks only "
          "SMB1 would stop working; undo by restoring the backup.")
    if not (assume_yes or input("Apply? [y/N] ").strip().lower() == "y"):
        print("Skipped.")
        return None
    text = Path(conf).read_text()
    backup = f"{conf}.languard-{_time.strftime('%Y%m%d-%H%M%S')}.bak"
    Path(backup).write_text(text)
    keys = {k for k, _, _, _ in bad}
    out, done = [], False
    for line in text.splitlines():
        k = line.split("=", 1)[0].strip().lower() if "=" in line else ""
        if k in keys and not line.lstrip().startswith((";", "#")):
            line = f"; {line.strip()}   # replaced by LANGuard"
        out.append(line)
        if not done and line.strip().lower() == "[global]":
            out += [f"   {l}   # LANGuard" for l in lines]
            done = True
    if not done:
        out = ["[global]"] + [f"   {l}   # LANGuard" for l in lines] + out
    Path(conf).write_text("\n".join(out) + "\n")
    check = validate or (lambda: _run(["testparm", "-s", conf])[0] == 0)
    if not check():
        Path(conf).write_text(text)
        print(f"testparm rejected the result; {conf} was put back unchanged.")
        return None
    if server:
        _run(["systemctl", "reload-or-restart", "smbd"], timeout=30)
    print(f"Applied. Backup: {backup}")
    return backup


def check_antimalware():
    res = []
    unit = distro.clamd_unit()
    active = _run(["systemctl", "is-active", unit])[1].strip() if unit else ""
    if active != "active":
        res.append(Result(WARN, "Real-time virus scanning",
                          f"{unit or 'the ClamAV daemon'} not running: new files "
                          "are only checked by heuristics",
                          distro.clamav_enable_hint()))
    else:
        res.append(Result(PASS, "Real-time virus scanning", f"{unit} running"))
    lg = _run(["systemctl", "is-active", "languard"])[1].strip()
    if lg != "active":
        res.append(Result(FAIL, "LANGuard service", f"languard is {lg or 'missing'}",
                          "sudo systemctl enable --now languard languard-guard.timer"))
    return res


def check_updates():
    fam = distro.info()[0]
    if fam == "fedora":
        timers = ("dnf5-automatic.timer", "dnf-automatic.timer",
                  "dnf-automatic-install.timer")
        on = [t for t in timers
              if _run(["systemctl", "is-enabled", t])[1].strip() == "enabled"]
        if on:
            return [Result(PASS, "Automatic security updates", f"{on[0]} enabled")]
        return [Result(WARN, "Automatic security updates", "dnf-automatic not enabled",
                       "sudo dnf install dnf-automatic && sudo systemctl enable "
                       "--now dnf-automatic.timer")]
    if fam == "suse":
        return [Result(INFO, "Automatic security updates",
                       "openSUSE: install updates regularly (sudo zypper patch, "
                       "or 'sudo zypper dup' on Tumbleweed)")]
    if fam == "arch":
        return [Result(INFO, "Automatic security updates",
                       "Arch: rolling release, update regularly (sudo pacman -Syu)")]
    rc, out = _run(["dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"])
    if "install ok installed" not in out:
        return [Result(WARN, "Automatic security updates", "unattended-upgrades missing",
                       "sudo apt install unattended-upgrades && "
                       "sudo dpkg-reconfigure -plow unattended-upgrades")]
    return [Result(PASS, "Automatic security updates", "unattended-upgrades installed")]


# ------------------------------------------------------------------ runner --
def _homes():
    """Home directories to look in: everyone's as root, else your own."""
    if os.geteuid() != 0:
        return [Path.home()]
    out = []
    try:
        import pwd
        for pw in pwd.getpwall():
            if pw.pw_uid >= 1000 and pw.pw_dir.startswith("/home/"):
                out.append(Path(pw.pw_dir))
    except ImportError:
        pass
    return out


def check_browser_https(homes=None):
    """HTTPS-Only mode in Firefox and Chrome/Chromium profiles: closes SSL
    stripping on the first visit to a site, which no network tool can."""
    homes = _homes() if homes is None else homes
    on, off = [], []
    for home in homes:
        for prefs in Path(home, ".mozilla/firefox").glob("*/prefs.js"):
            try:
                text = prefs.read_text(errors="replace")
            except OSError:
                continue
            name = f"Firefox ({prefs.parent.name})"
            (on if re.search(r'user_pref\("dom\.security\.https_only_mode",\s*true\)',
                             text) else off).append(name)
        for base in (".config/google-chrome", ".config/chromium",
                     ".config/BraveSoftware/Brave-Browser"):
            for prefs in Path(home, base).glob("*/Preferences"):
                try:
                    data = json.loads(prefs.read_text(errors="replace"))
                except (OSError, ValueError):
                    continue
                name = f"{base.split('/')[-1]} ({prefs.parent.name})"
                (on if data.get("https_only_mode_enabled") else off).append(name)
    if not on and not off:
        return []
    if off:
        return [Result(WARN, "Browser HTTPS-Only",
                       f"Off in {', '.join(off[:4])}: a site's first visit can "
                       f"still be SSL-stripped",
                       "Firefox: Settings > Privacy & Security > HTTPS-Only Mode "
                       "> all windows. Chrome: Settings > Privacy and security > "
                       "Security > Always use secure connections")]
    return [Result(PASS, "Browser HTTPS-Only", f"On in {', '.join(on[:4])}")]


def run_audit(gateway=None, iface=None):
    results = []
    for fn in (check_firewall, check_listening, check_ssh, check_sysctl,
               check_services, check_name_poisoning, check_local_dns,
               check_smb, check_wifi, check_browser_https, check_antimalware,
               check_updates):
        try:
            results += fn()
        except Exception as e:
            results.append(Result(INFO, fn.__name__, f"check failed: {e}"))
    results += check_gateway_arp(gateway, iface)
    return results


COLORS = {PASS: "\033[32m", WARN: "\033[33m", FAIL: "\033[31m", INFO: "\033[36m"}


def print_report(results):
    tty = os.isatty(1)
    for r in results:
        c, z = (COLORS[r.status], "\033[0m") if tty else ("", "")
        print(f"{c}[{r.status}]{z} {r.check}: {r.detail}")
        if r.fix and r.status != PASS:
            print(f"        fix: {r.fix}")
    counts = {s: sum(r.status == s for r in results) for s in (PASS, WARN, FAIL)}
    score = round(100 * counts[PASS] / max(1, sum(counts.values())))
    print(f"\n{counts[PASS]} passed, {counts[WARN]} warnings, "
          f"{counts[FAIL]} failed  (score {score}/100)")
    return counts


def apply_fixes(assume_yes=False):
    if os.geteuid() != 0:
        print("--fix needs root: sudo languard audit --fix")
        return False
    lines = ["# Written by LANGuard: network hardening for untrusted LANs",
             "# Remove this file and run 'sysctl --system' to undo."]
    lines += [f"{k} = {v}" for k, v, _ in SYSCTLS]
    if check_sysctl()[0].status == PASS:
        print("Kernel network settings: already hardened.")
    else:
        print(f"This will write {SYSCTL_FILE}:\n  " + "\n  ".join(lines[2:]))
        if assume_yes or input("Apply? [y/N] ").strip().lower() == "y":
            Path(SYSCTL_FILE).write_text("\n".join(lines) + "\n")
            rc, _ = _run(["sysctl", "--system"], timeout=30)
            print("Applied." if rc == 0 else
                  "Written; 'sysctl --system' reported errors.")
        else:
            print("Skipped.")

    poison = check_name_poisoning()
    if poison and poison[0].status == WARN:
        print(f"\nAlso disable LLMNR and mDNS name resolution ({RESOLVED_DROPIN})?"
              " Blocks Responder-style credential theft. Your DNS servers and "
              "dnscrypt-proxy are not touched.")
        if assume_yes or input("Apply? [y/N] ").strip().lower() == "y":
            Path(RESOLVED_DROPIN).parent.mkdir(parents=True, exist_ok=True)
            Path(RESOLVED_DROPIN).write_text(
                "# Written by LANGuard. Delete this file to undo.\n"
                "[Resolve]\nLLMNR=no\nMulticastDNS=no\n")
            rc, _ = _run(["systemctl", "restart", "systemd-resolved"], timeout=30)
            print("Applied." if rc == 0 else "Written; restart systemd-resolved manually.")
    try:
        fix_smb(assume_yes)
    except OSError as e:
        print(f"SMB hardening failed: {e}")
    print("Other fixes (firewall, SSH, services) are listed in the report; "
          "they're left to you because they can cut off remote access.")
    return True


def to_json(results):
    return json.dumps([r.as_dict() for r in results], indent=2)
