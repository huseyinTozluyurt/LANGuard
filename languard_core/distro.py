"""
Which Linux this is, and the few names that differ between distributions:
package names for install hints, the ClamAV service and socket names, the
virus-signature folder and where the IEEE vendor list lives.

LANGuard itself is plain Python and the same everywhere; only these names
change. Families: debian (Debian, Ubuntu, Mint, Pop!_OS, Kali, ...),
fedora (Fedora, RHEL, Alma, Rocky, CentOS Stream), suse (openSUSE, SLES),
arch (Arch, Manjaro, EndeavourOS). Anything else falls back to Debian names
in hints and detection by what is actually installed.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

FAMILIES = ("debian", "fedora", "suse", "arch")

# Logical package -> name per family (None: not packaged there / not needed).
PACKAGES = {
    "python3":   {"debian": "python3", "fedora": "python3", "suse": "python3",
                  "arch": "python"},
    "scapy":     {"debian": "python3-scapy", "fedora": "python3-scapy",
                  "suse": "python3-scapy", "arch": "python-scapy"},
    "pyqt5":     {"debian": "python3-pyqt5", "fedora": "python3-qt5",
                  "suse": "python3-qt5", "arch": "python-pyqt5"},
    "iproute":   {"debian": "iproute2", "fedora": "iproute", "suse": "iproute2",
                  "arch": "iproute2"},
    "nftables":  {"debian": "nftables", "fedora": "nftables", "suse": "nftables",
                  "arch": "nftables"},
    "notify":    {"debian": "libnotify-bin", "fedora": "libnotify",
                  "suse": "libnotify-tools", "arch": "libnotify"},
    "oui":       {"debian": "ieee-data", "fedora": "hwdata", "suse": "hwdata",
                  "arch": None},
    "pkexec":    {"debian": "pkexec", "fedora": "polkit", "suse": "polkit",
                  "arch": "polkit"},
    "clamav":    {"debian": "clamav clamav-daemon clamav-freshclam",
                  "fedora": "clamav clamd clamav-update",
                  "suse": "clamav", "arch": "clamav"},
    "firewall":  {"debian": "ufw", "fedora": "firewalld", "suse": "firewalld",
                  "arch": "ufw"},
}
INSTALL_CMD = {"debian": "sudo apt install", "fedora": "sudo dnf install",
               "suse": "sudo zypper install", "arch": "sudo pacman -S"}

# ClamAV: (daemon unit, signature-updater unit) per family. The first unit
# name that systemd knows wins, so a mismatch only costs a lookup.
CLAMD_UNITS = ("clamav-daemon", "clamd@scan", "clamd")
FRESHCLAM_UNITS = ("clamav-freshclam", "freshclam", "clamav-freshclam.timer",
                   "freshclam.timer")
CLAMD_CONFS = ("/etc/clamav/clamd.conf",        # Debian, Ubuntu, Arch
               "/etc/clamd.d/scan.conf",        # Fedora, RHEL
               "/etc/clamd.conf")               # openSUSE
CLAMD_SOCKETS = ("/run/clamav/clamd.ctl", "/var/run/clamav/clamd.ctl",
                 "/run/clamd.scan/clamd.sock", "/run/clamav/clamd-socket",
                 "/var/run/clamav/clamd-socket", "/run/clamav/clamd.sock")
SIGNATURE_DIRS = ("/var/lib/clamav",)
OUI_FILES = ("/usr/share/ieee-data/oui.txt", "/usr/share/hwdata/oui.txt",
             "/usr/share/misc/oui.txt")
MANUF_FILES = ("/usr/share/wireshark/manuf",)

_INFO = None


def os_release(path="/etc/os-release"):
    """/etc/os-release as a dict (empty when missing)."""
    out = {}
    for p in (path, "/usr/lib/os-release"):
        try:
            for line in Path(p).read_text().splitlines():
                k, sep, v = line.partition("=")
                if sep:
                    out[k.strip()] = v.strip().strip('"').strip("'")
            return out
        except OSError:
            continue
    return out


def family(info=None):
    """'debian' | 'fedora' | 'suse' | 'arch' | 'unknown'."""
    info = os_release() if info is None else info
    ids = [info.get("ID", "")] + info.get("ID_LIKE", "").split()
    for i in ids:
        i = i.lower()
        if i in ("debian", "ubuntu", "linuxmint", "pop", "kali", "raspbian",
                 "elementary", "zorin", "neon", "devuan"):
            return "debian"
        if i in ("fedora", "rhel", "centos", "rocky", "almalinux", "ol"):
            return "fedora"
        if i.startswith("opensuse") or i in ("suse", "sles", "sled"):
            return "suse"
        if i in ("arch", "manjaro", "endeavouros", "garuda", "artix"):
            return "arch"
    # No os-release: guess from the package manager.
    for tool, fam in (("apt-get", "debian"), ("dnf", "fedora"), ("yum", "fedora"),
                      ("zypper", "suse"), ("pacman", "arch")):
        if shutil.which(tool):
            return fam
    return "unknown"


def info():
    """(family, pretty name), cached."""
    global _INFO
    if _INFO is None:
        rel = os_release()
        _INFO = (family(rel), rel.get("PRETTY_NAME") or rel.get("NAME") or "Linux")
    return _INFO


def package(key, fam=None):
    fam = fam or info()[0]
    names = PACKAGES.get(key, {})
    return names.get(fam if fam in FAMILIES else "debian")


def install_hint(key, fam=None):
    """'sudo dnf install python3-scapy' for this distribution."""
    fam = fam or info()[0]
    name = package(key, fam)
    if not name:
        return f"install {key} with your package manager"
    return f"{INSTALL_CMD.get(fam, INSTALL_CMD['debian'])} {name}"


# ------------------------------------------------------------- services --
def _unit_known(name):
    if not shutil.which("systemctl"):
        return False
    try:
        return subprocess.run(["systemctl", "cat", name], capture_output=True,
                              timeout=5).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def first_unit(candidates, known=_unit_known):
    for name in candidates:
        if known(name):
            return name
    return None


def clamd_unit(known=_unit_known):
    """systemd unit of the ClamAV daemon here (None if not installed)."""
    return first_unit(CLAMD_UNITS, known)


def freshclam_unit(known=_unit_known):
    return first_unit(FRESHCLAM_UNITS, known)


def clamav_units(known=_unit_known):
    """Installed ClamAV units the guard keeps running."""
    return [u for u in (clamd_unit(known), freshclam_unit(known)) if u]


def clamd_config(paths=CLAMD_CONFS):
    for p in paths:
        if os.path.isfile(p):
            return p
    return None


def clamd_socket(conf=None, sockets=CLAMD_SOCKETS):
    """The clamd socket path: from the config's LocalSocket, else the first
    known path that exists. None when clamd isn't listening locally."""
    conf = conf or clamd_config()
    if conf:
        try:
            m = re.search(r"^\s*LocalSocket\s+(\S+)", Path(conf).read_text(),
                          re.M)
            if m and os.path.exists(m.group(1)):
                return m.group(1)
        except OSError:
            pass
    for p in sockets:
        if os.path.exists(p):
            return p
    return None


def clamdscan_args(conf=None):
    """Extra clamdscan arguments: the config file when it isn't the one
    clamdscan reads by default (Fedora's /etc/clamd.d/scan.conf)."""
    conf = conf or clamd_config()
    if conf and conf not in ("/etc/clamav/clamd.conf", "/etc/clamd.conf"):
        return [f"--config-file={conf}"]
    return []


def clamav_enable_hint(fam=None):
    fam = fam or info()[0]
    units = {"debian": "clamav-freshclam clamav-daemon",
             "fedora": "clamav-freshclam clamd@scan",
             "suse": "freshclam clamd", "arch": "clamav-freshclam clamav-daemon"}
    return (f"{install_hint('clamav', fam)} && sudo systemctl enable --now "
            f"{units.get(fam, units['debian'])}")
