#!/usr/bin/env python3
"""Tests for the encrypted-DNS setup guide (dnsguide.py): what it reports
now, the commands per distribution, that it only reads, and the
`languard dnsguide` command. Run: python3 tests/test_dnsguide.py (no root)"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ["LANGUARD_STATE"] = tempfile.mkdtemp(prefix="languard-test-")
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from languard_core import dnsguide, distro  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(("  ok  " if cond else "  FAIL ") + name)
    fails += not cond


print("== systemd-resolved DNS over TLS, read from resolvectl status")
NEW = """Global
           Protocols: -LLMNR -mDNS +DNSOverTLS DNSSEC=no/unsupported
    resolv.conf mode: stub

Link 2 (wlp2s0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS +DNSOverTLS
"""
OPP = NEW.replace("+DNSOverTLS", "DNSOverTLS=opportunistic")
OFF = NEW.replace("+DNSOverTLS", "-DNSOverTLS")
OLD = "Global\n       LLMNR setting: no\nMulticastDNS setting: no\n  DNSOverTLS setting: yes\n"
LINK_ONLY = OFF.replace("Link 2 (wlp2s0)\n    Current Scopes: DNS\n         Protocols: "
                        "+DefaultRoute -LLMNR -mDNS -DNSOverTLS",
                        "Link 2 (wlp2s0)\n         Protocols: +DNSOverTLS")
check("strict (+DNSOverTLS)", dnsguide.resolved_dot(NEW) == "yes")
check("opportunistic", dnsguide.resolved_dot(OPP) == "opportunistic")
check("off (-DNSOverTLS)", dnsguide.resolved_dot(OFF) == "no")
check("systemd 245 format (Ubuntu 20.04)", dnsguide.resolved_dot(OLD) == "yes")
check("only the Global section counts", dnsguide.resolved_dot(LINK_ONLY) == "no")

print("== What it says now")
enc = {"resolver": "dnscrypt-proxy", "label": "dnscrypt-proxy", "leak_risk": []}
leak = dict(enc, leak_risk=["systemd-resolved also uses 192.168.1.1 (from wlp2s0)"],
            via_resolved=True)
c = dnsguide.current(enc, "no", True)
check("dnscrypt-proxy running: nothing to do", c["state"] == "encrypted" and not c["recommend"])
c = dnsguide.current(leak, "no", True)
check("leak: close it first, with the nmcli command",
      c["state"] == "leak" and "ignore-auto-dns" in c["text"])
c = dnsguide.current({}, "yes", True)
check("resolved with strict DoT counts as encrypted",
      c["state"] == "encrypted" and "DNS over TLS" in c["label"])
c = dnsguide.current({}, "opportunistic", True)
check("opportunistic DoT: weak, recommends strict", c["state"] == "weak"
      and c["recommend"] == "resolved-dot")
check("plain DNS with resolved: recommends resolved DoT",
      dnsguide.current({}, "no", True)["recommend"] == "resolved-dot")
check("plain DNS without resolved: recommends dnscrypt-proxy",
      dnsguide.current({}, None, False)["recommend"] == "dnscrypt-proxy")

print("== Commands per distribution")
for fam in distro.FAMILIES:
    for res in (True, False):
        opts = dnsguide.options(fam, res)
        ok = ([o["key"] for o in opts] == list(dnsguide.ORDER)
              and all(o["undo"] and o["steps"] for o in opts))
        check(f"{fam} (resolved={res}): all 5 options, each with steps and undo", ok)


def opt(fam, key, res=True):
    return next(o for o in dnsguide.options(fam, res) if o["key"] == key)


def cmds(o):
    return "\n".join(c for _, c in o["steps"])


check("Ubuntu/Debian: apt install dnscrypt-proxy, listens on 127.0.2.1",
      "sudo apt install dnscrypt-proxy" in cmds(opt("debian", "dnscrypt-proxy"))
      and "DNS=127.0.2.1" in cmds(opt("debian", "dnscrypt-proxy")))
check("Fedora: Stubby is getdns-stubby", "sudo dnf install getdns-stubby" in
      cmds(opt("fedora", "stubby")))
check("openSUSE: zypper; Arch: pacman", "sudo zypper install unbound" in
      cmds(opt("suse", "unbound")) and "sudo pacman -S stubby" in cmds(opt("arch", "stubby")))
check("Unbound uses each family's CA bundle",
      all(dnsguide.CA_BUNDLE[f] in cmds(opt(f, "unbound")) for f in distro.FAMILIES))
check("Arch switches resolved on before DoT",
      "enable --now systemd-resolved" in cmds(opt("arch", "resolved-dot")))
dot = cmds(opt("fedora", "resolved-dot"))
check("strict DoT with certificate names, no plain fallback",
      "DNSOverTLS=yes" in dot and "9.9.9.9#dns.quad9.net" in dot and "FallbackDNS=\n" in dot)
check("without resolved: per-connection nmcli DNS",
      "ipv4.dns 127.0.0.1" in cmds(opt("arch", "stubby", False)))
check("the undo removes what the steps added",
      "rm /etc/systemd/resolved.conf.d/dns-over-tls.conf" in opt("debian", "resolved-dot")["undo"]
      and "ignore-auto-dns no" in opt("debian", "dnscrypt-proxy")["undo"])
check("package list for the CI check",
      dnsguide.packages("fedora") == ["dnscrypt-proxy", "getdns-stubby", "unbound"])
blk = dnsguide.commands_text(opt("debian", "stubby"))
check("copy block: explanations and undo are comments",
      blk.startswith("# Step 1:") and "#   " in blk.split("# Undo:")[1])

print("== Only shows, never runs")
calls = []
real_run = subprocess.run


def spy(cmd, *a, **k):
    calls.append(list(cmd))
    return subprocess.CompletedProcess(cmd, 1, "", "")


subprocess.run = spy
try:
    g = dnsguide.guide(info={})
    txt = dnsguide.text(g)
finally:
    subprocess.run = real_run
check("only `resolvectl status` was run", all(c == ["resolvectl", "status"] for c in calls))
check("says it never runs them", "never runs" in txt and "never changes DNS" in " ".join(g["notes"]))
check("no VPN advice", "vpn" not in txt.lower())
check("a recommendation is marked", "recommended for you" in txt)

print("== languard dnsguide")
r = subprocess.run([sys.executable, str(ROOT / "languard.py"), "dnsguide", "--distro", "arch",
                    "--option", "stubby"], capture_output=True, text=True)
check("--distro arch --option stubby", r.returncode == 0 and "sudo pacman -S stubby" in r.stdout
      and "dnscrypt-proxy  [" not in r.stdout)
r = subprocess.run([sys.executable, str(ROOT / "languard.py"), "dnsguide", "--packages",
                    "--distro", "fedora"], capture_output=True, text=True)
check("--packages", r.stdout.split() == ["dnscrypt-proxy", "getdns-stubby", "unbound"])

print(f"\n{'ALL PASSED' if not fails else f'{fails} FAILED'}")
sys.exit(fails)
