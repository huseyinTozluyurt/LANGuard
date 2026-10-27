#!/usr/bin/env python3
"""Tests for the distribution layer (distro.py): family detection, package
names in hints, ClamAV unit/config/socket lookup, and that the host it runs
on is recognised. Run: python3 tests/test_distro.py   (no root needed)"""

import os
import sys
import tempfile
from pathlib import Path

os.environ["LANGUARD_STATE"] = tempfile.mkdtemp(prefix="languard-test-")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from languard_core import distro  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(("  ok  " if cond else "  FAIL ") + name)
    fails += not cond


print("== Family detection from /etc/os-release")
SAMPLES = {
    "debian": [{"ID": "ubuntu", "ID_LIKE": "debian"}, {"ID": "debian"},
               {"ID": "linuxmint", "ID_LIKE": "ubuntu debian"},
               {"ID": "pop", "ID_LIKE": "ubuntu debian"}, {"ID": "kali", "ID_LIKE": "debian"}],
    "fedora": [{"ID": "fedora"}, {"ID": "almalinux", "ID_LIKE": "rhel centos fedora"},
               {"ID": "rocky", "ID_LIKE": "rhel centos fedora"}, {"ID": "centos"}],
    "suse": [{"ID": "opensuse-tumbleweed", "ID_LIKE": "opensuse suse"},
             {"ID": "opensuse-leap", "ID_LIKE": "suse opensuse"}, {"ID": "sles"}],
    "arch": [{"ID": "arch"}, {"ID": "manjaro", "ID_LIKE": "arch"},
             {"ID": "endeavouros", "ID_LIKE": "arch"}],
}
for fam, rels in SAMPLES.items():
    got = [distro.family(r) for r in rels]
    check(f"{fam}: {', '.join(r['ID'] for r in rels)}", got == [fam] * len(rels))

with tempfile.NamedTemporaryFile("w", delete=False) as f:
    f.write('NAME="Fedora Linux"\nID=fedora\nPRETTY_NAME="Fedora Linux 42"\n# comment\n')
rel = distro.os_release(f.name)
check("os-release parsed (quotes stripped, comments skipped)",
      rel.get("ID") == "fedora" and rel.get("PRETTY_NAME") == "Fedora Linux 42")
os.unlink(f.name)

print("== Install hints use this distribution's names")
check("Ubuntu: apt + python3-scapy",
      distro.install_hint("scapy", "debian") == "sudo apt install python3-scapy")
check("Fedora: dnf + python3-qt5",
      distro.install_hint("pyqt5", "fedora") == "sudo dnf install python3-qt5")
check("openSUSE: zypper + libnotify-tools",
      distro.install_hint("notify", "suse") == "sudo zypper install libnotify-tools")
check("Arch: pacman + python-scapy",
      distro.install_hint("scapy", "arch") == "sudo pacman -S python-scapy")
check("unknown family falls back to Debian names",
      distro.package("iproute", "unknown") == "iproute2")
check("Fedora ClamAV hint enables clamd@scan",
      "clamd@scan" in distro.clamav_enable_hint("fedora"))
check("openSUSE ClamAV hint enables clamd + freshclam",
      distro.clamav_enable_hint("suse").endswith("freshclam clamd"))

print("== ClamAV units, config and socket")
for units, want in ((["clamav-daemon", "clamav-freshclam"], ["clamav-daemon", "clamav-freshclam"]),
                    (["clamd@scan", "clamav-freshclam"], ["clamd@scan", "clamav-freshclam"]),
                    (["clamd", "freshclam"], ["clamd", "freshclam"]),
                    ([], [])):
    got = distro.clamav_units(known=lambda n, u=units: n in u)
    check(f"units {units or 'none'} -> {want}", got == want)

d = tempfile.mkdtemp()
sock = os.path.join(d, "clamd.sock")
open(sock, "w").close()
conf = os.path.join(d, "scan.conf")
Path(conf).write_text(f"#Example\n# LocalSocket /nowhere\nLocalSocket {sock}\n")
check("socket read from the config's LocalSocket", distro.clamd_socket(conf, ()) == sock)
Path(conf).write_text("#LocalSocket /run/clamd.scan/clamd.sock\n")
check("commented socket and no known path -> None", distro.clamd_socket(conf, ()) is None)
check("known socket path used when the config has none",
      distro.clamd_socket(conf, ("/nonexistent", sock)) == sock)
check("Fedora's scan.conf passed to clamdscan",
      distro.clamdscan_args("/etc/clamd.d/scan.conf") == ["--config-file=/etc/clamd.d/scan.conf"])
check("default configs need no flag",
      distro.clamdscan_args("/etc/clamav/clamd.conf") == [] and
      distro.clamdscan_args("/etc/clamd.conf") == [])

print("== This machine")
fam, name = distro.info()
print(f"  ({name}: {fam})")
expected = os.environ.get("LANGUARD_EXPECT_FAMILY")
if expected:
    check(f"detected as {expected}", fam == expected)
else:
    check("detected a known family", fam in distro.FAMILIES)

print(f"\n{'ALL PASSED' if not fails else f'{fails} FAILED'}")
sys.exit(fails)
