"""
DNS setup guide: how to encrypt this machine's DNS yourself, with the
commands for this distribution.

Options: DNS over TLS in systemd-resolved (nothing to install where it is
already used), dnscrypt-proxy (DNSCrypt and DNS over HTTPS), Stubby (DNS over
TLS), Unbound as a DNS-over-TLS forwarder, and DNS over HTTPS in the browser
only.

LANGuard never runs any of this. It only prints the steps: every command is
for you to read and run in a terminal, and you can undo each one with the
"Undo" commands next to it. Afterwards `languard dnscheck` (or the app's
Encrypted DNS page) shows whether every lookup really goes through the
encrypted resolver, and LANGuard keeps watching it on hostile networks.
"""

import re
import subprocess

from . import distro, localdns

# Public resolvers that offer DNS over TLS / DNSCrypt / DoH. (name, IPv4
# addresses, TLS name). Change them to the provider you trust.
PROVIDERS = (
    ("Quad9", ("9.9.9.9", "149.112.112.112"), "dns.quad9.net"),
    ("Cloudflare", ("1.1.1.1", "1.0.0.1"), "cloudflare-dns.com"),
)

# Logical package -> name per family. Checked against the real repositories
# by scripts/ci-container-test.sh.
PACKAGES = {
    "dnscrypt-proxy": {"debian": "dnscrypt-proxy", "fedora": "dnscrypt-proxy",
                       "suse": "dnscrypt-proxy", "arch": "dnscrypt-proxy"},
    "stubby": {"debian": "stubby", "fedora": "getdns-stubby", "suse": "stubby",
               "arch": "stubby"},
    "unbound": {"debian": "unbound", "fedora": "unbound", "suse": "unbound",
                "arch": "unbound"},
}
CA_BUNDLE = {"debian": "/etc/ssl/certs/ca-certificates.crt",
             "fedora": "/etc/pki/tls/certs/ca-bundle.crt",
             "suse": "/etc/ssl/ca-bundle.pem",
             "arch": "/etc/ssl/certs/ca-certificates.crt"}
# Where Debian's dnscrypt-proxy package listens (systemd socket); upstream
# and the other distributions use 127.0.0.1.
DNSCRYPT_LISTEN = {"debian": "127.0.2.1"}
DROPIN_DIR = "/etc/systemd/resolved.conf.d"

FAMILY_NAMES = {"debian": "Debian, Ubuntu, Mint", "fedora": "Fedora, RHEL, AlmaLinux",
                "suse": "openSUSE", "arch": "Arch, Manjaro"}
ORDER = ("resolved-dot", "dnscrypt-proxy", "stubby", "unbound", "browser-doh")


def _run(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


# ---------------------------------------------------------------- readers --
def resolved_dot(out=None):
    """systemd-resolved's global DNS-over-TLS mode: 'yes', 'opportunistic',
    'no', or None when resolved isn't answering. Read-only."""
    if out is None:
        rc, out = _run(["resolvectl", "status"])
        if rc != 0:
            return None
    head = out.split("\nLink ")[0]                  # the Global section
    if re.search(r"\+DNSOverTLS\b", head):
        return "yes"
    m = re.search(r"DNSOverTLS(?: setting)?[=:]\s*(\w+)", head)
    if m:
        v = m.group(1).lower()
        return "opportunistic" if v.startswith("opp") else \
            ("yes" if v in ("yes", "true", "1") else "no")
    return "no" if "-DNSOverTLS" in head else None


def uses_resolved(resolv="/etc/resolv.conf"):
    """True when system DNS goes through systemd-resolved's stub."""
    return "127.0.0.53" in localdns.resolv_conf(resolv)


def current(info=None, dot=None, resolved=None):
    """What runs now and what to do, from the read-only checks."""
    info = info if info is not None else localdns.inspect()
    dot = dot if dot is not None else resolved_dot()
    resolved = resolved if resolved is not None else uses_resolved()
    if info.get("resolver"):
        if info.get("leak_risk"):
            return {"state": "leak", "label": info.get("label"),
                    "text": f"{info.get('label')} runs, but "
                            f"{'; '.join(info['leak_risk'])}. Close that first: "
                            f"{localdns.advice(info)}.",
                    "recommend": None}
        return {"state": "encrypted", "label": info.get("label"),
                "text": f"{info.get('label')} already handles every lookup. "
                        f"Nothing to do; the options below are for reference.",
                "recommend": None}
    if dot in ("yes", "opportunistic") and resolved:
        weak = dot == "opportunistic"
        return {"state": "weak" if weak else "encrypted",
                "label": "systemd-resolved (DNS over TLS)",
                "text": "systemd-resolved uses DNS over TLS"
                        + (" in opportunistic mode: a man in the middle can "
                           "switch it back to plain DNS. Set DNSOverTLS=yes "
                           "(option 1)." if weak else
                           ". Make sure Wi-Fi connections don't add their own "
                           "plain DNS servers (step 4 of option 1)."),
                "recommend": "resolved-dot" if weak else None}
    return {"state": "plain", "label": None,
            "text": "DNS leaves this computer in plain text, so anyone on the "
                    "network can read and forge it. Pick one option below.",
            "recommend": "resolved-dot" if resolved else "dnscrypt-proxy"}


# ---------------------------------------------------------------- options --
def _install(key, fam):
    name = PACKAGES[key].get(fam) or PACKAGES[key]["debian"]
    return f"{distro.INSTALL_CMD.get(fam, distro.INSTALL_CMD['debian'])} {name}"


def _point_system_dns(addr, resolved, fname):
    """Steps that send system DNS to a local resolver on `addr`."""
    if resolved:
        return [
            ("Send all system DNS to it through systemd-resolved",
             f"sudo mkdir -p {DROPIN_DIR}\n"
             f"printf '[Resolve]\\nDNS={addr}\\nDomains=~.\\n' | "
             f"sudo tee {DROPIN_DIR}/{fname}.conf\n"
             f"sudo systemctl restart systemd-resolved"),
            IGNORE_DHCP_DNS,
        ]
    return [
        ("Send this connection's DNS to it (repeat for each Wi-Fi network)",
         f"nmcli connection modify \"<connection>\" ipv4.dns {addr} "
         f"ipv4.ignore-auto-dns yes ipv6.ignore-auto-dns yes\n"
         f"nmcli connection up \"<connection>\""),
    ]


def _undo_system_dns(resolved, fname):
    if resolved:
        return (f"sudo rm {DROPIN_DIR}/{fname}.conf && "
                f"sudo systemctl restart systemd-resolved\n"
                + IGNORE_DHCP_DNS[1].replace("yes", "no"))
    return ("nmcli connection modify \"<connection>\" ipv4.dns \"\" "
            "ipv4.ignore-auto-dns no ipv6.ignore-auto-dns no")


IGNORE_DHCP_DNS = (
    "Stop Wi-Fi/Ethernet connections from adding the network's own plain DNS "
    "servers (repeat for each connection; `nmcli connection show` lists them)",
    "nmcli connection modify \"<connection>\" ipv4.ignore-auto-dns yes "
    "ipv6.ignore-auto-dns yes\nnmcli connection up \"<connection>\"")
VERIFY = ("Check it with LANGuard", "languard dnscheck")


def options(fam=None, resolved=None):
    """Every option with its steps for this distribution, as dicts."""
    fam = fam or distro.info()[0]
    fam = fam if fam in distro.FAMILIES else "debian"
    resolved = uses_resolved() if resolved is None else resolved
    q9, cf = PROVIDERS
    dot_servers = " ".join(f"{a}#{p[2]}" for p in (q9, cf) for a in p[1])
    out = []

    # 1. systemd-resolved DNS over TLS
    prep = []
    if fam == "arch":
        prep.append(("Turn on systemd-resolved (Arch doesn't by default)",
                     "sudo systemctl enable --now systemd-resolved\n"
                     "sudo ln -sf ../run/systemd/resolve/stub-resolv.conf "
                     "/etc/resolv.conf"))
    elif fam == "suse":
        prep.append(("openSUSE manages DNS with netconfig, not systemd-resolved: "
                     "prefer dnscrypt-proxy or Stubby here. To switch anyway",
                     "sudo zypper install systemd-resolved   # Leap: systemd-network\n"
                     "sudo systemctl enable --now systemd-resolved\n"
                     "sudo ln -sf ../run/systemd/resolve/stub-resolv.conf "
                     "/etc/resolv.conf"))
    elif fam == "debian":
        prep.append(("Only if `resolvectl` is missing (Debian without "
                     "systemd-resolved)",
                     "sudo apt install systemd-resolved"))
    out.append({
        "key": "resolved-dot", "title": "DNS over TLS with systemd-resolved",
        "protocol": "DNS over TLS (port 853)",
        "summary": "Built into systemd: no extra program to install on Ubuntu "
                   "and Fedora. Encrypts every lookup to a public resolver and "
                   "checks its certificate.",
        "pros": "nothing new to run; one small config file; easy to undo",
        "cons": "port 853 is sometimes blocked on hotel and office networks; "
                "openSUSE and Arch need resolved switched on first",
        "steps": prep + [
            ("Create a config file that turns on strict DNS over TLS",
             f"sudo mkdir -p {DROPIN_DIR}\n"
             f"sudo tee {DROPIN_DIR}/dns-over-tls.conf <<'EOF'\n"
             f"[Resolve]\nDNS={dot_servers}\nDNSOverTLS=yes\nDomains=~.\n"
             f"FallbackDNS=\nEOF"),
            ("Apply it", "sudo systemctl restart systemd-resolved"),
            IGNORE_DHCP_DNS,
            ("Check: the Global section should show +DNSOverTLS",
             "resolvectl status | head -n 12"),
            VERIFY],
        "undo": f"sudo rm {DROPIN_DIR}/dns-over-tls.conf && "
                f"sudo systemctl restart systemd-resolved\n" +
                IGNORE_DHCP_DNS[1].replace("yes", "no"),
    })

    # 2. dnscrypt-proxy
    addr = DNSCRYPT_LISTEN.get(fam, "127.0.0.1")
    toml = "/etc/dnscrypt-proxy/dnscrypt-proxy.toml"
    start = ("sudo systemctl restart dnscrypt-proxy.socket dnscrypt-proxy"
             if fam == "debian" else
             "sudo systemctl enable --now dnscrypt-proxy")
    out.append({
        "key": "dnscrypt-proxy", "title": "dnscrypt-proxy",
        "protocol": "DNSCrypt and DNS over HTTPS (port 443)",
        "summary": "A local resolver that encrypts lookups with DNSCrypt or "
                   "DNS over HTTPS, picks the fastest server and can require "
                   "DNSSEC and no-logging servers. LANGuard knows it best: it "
                   "watches it for leaks and blocking.",
        "pros": "uses port 443, which networks rarely block; DNSSEC and "
                "no-log filters; server choice by name",
        "cons": "one more service to keep running",
        "steps": [
            ("Install it", _install("dnscrypt-proxy", fam)),
            ("Choose servers (optional): in the config set for example "
             "server_names = ['quad9-doh-ip4-port443-filter-pri', 'cloudflare'] "
             "and require_dnssec = true",
             f"sudoedit {toml}"),
            ("Start it", start),
            (f"Check where it listens (expected {addr}:53)",
             f"grep -E '^listen_addresses' {toml}; sudo ss -ulpn | "
             f"grep dnscrypt"),
            *_point_system_dns(addr, resolved, "dnscrypt-proxy"), VERIFY],
        "undo": _undo_system_dns(resolved, "dnscrypt-proxy") +
                "\nsudo systemctl disable --now dnscrypt-proxy" +
                (" dnscrypt-proxy.socket" if fam == "debian" else ""),
    })

    # 3. Stubby
    yml = "/etc/stubby/stubby.yml"
    out.append({
        "key": "stubby", "title": "Stubby",
        "protocol": "DNS over TLS (port 853)",
        "summary": "A small local DNS-over-TLS resolver from the getdns "
                   "project, for systems without systemd-resolved (openSUSE, "
                   "Arch) or if you prefer a separate program.",
        "pros": "small; strict TLS authentication by default",
        "cons": "port 853 can be blocked; listens on 127.0.0.1:53, so don't "
                "run it next to dnscrypt-proxy or Unbound",
        "steps": [
            ("Install it", _install("stubby", fam)),
            ("Set the servers: replace the upstream_recursive_servers list in "
             "the config with these (keep tls_authentication: "
             "GETDNS_AUTHENTICATION_REQUIRED)",
             f"sudoedit {yml}\n# upstream_recursive_servers:\n" + "".join(
                 f"#   - address_data: {p[1][0]}\n#     tls_auth_name: \"{p[2]}\"\n"
                 for p in PROVIDERS).rstrip()),
            ("Start it", "sudo systemctl enable --now stubby"),
            *_point_system_dns("127.0.0.1", resolved, "stubby"), VERIFY],
        "undo": _undo_system_dns(resolved, "stubby") +
                "\nsudo systemctl disable --now stubby",
    })

    # 4. Unbound as a DNS-over-TLS forwarder
    conf_d = {"debian": "/etc/unbound/unbound.conf.d/dns-over-tls.conf",
              "fedora": "/etc/unbound/conf.d/dns-over-tls.conf"}.get(fam)
    target = conf_d or "/etc/unbound/unbound.conf"
    tee = f"sudo tee {target}" if conf_d else f"sudo tee -a {target}"
    fwd = "".join(f"    forward-addr: {a}@853#{p[2]}\n"
                  for p in PROVIDERS for a in p[1])
    out.append({
        "key": "unbound", "title": "Unbound (DNS over TLS forwarder)",
        "protocol": "DNS over TLS (port 853)",
        "summary": "A full validating resolver with a cache that forwards "
                   "every lookup over TLS. For people who want DNSSEC "
                   "validation on their own machine.",
        "pros": "DNSSEC validated locally; fast cache; very configurable",
        "cons": "most setup work; port 853 can be blocked",
        "steps": [
            ("Install it", _install("unbound", fam)),
            ("Forward every lookup over TLS" +
             ("" if conf_d else " (appended to the main config)"),
             f"{tee} <<'EOF'\nserver:\n    interface: 127.0.0.1\n"
             f"    tls-cert-bundle: {CA_BUNDLE[fam]}\n"
             f"forward-zone:\n    name: \".\"\n    forward-tls-upstream: yes\n"
             f"{fwd}EOF\nsudo unbound-checkconf"),
            ("Start it", "sudo systemctl enable --now unbound"),
            *_point_system_dns("127.0.0.1", resolved, "unbound"),
            ("Check: TLS connections to port 853 appear after a lookup",
             "getent hosts example.org; sudo ss -tnp | grep ':853'")],
        "undo": _undo_system_dns(resolved, "unbound") +
                "\nsudo systemctl disable --now unbound" +
                (f"\nsudo rm {conf_d}" if conf_d else
                 f"\n# and remove the added lines from {target}"),
    })

    # 5. Browser only
    out.append({
        "key": "browser-doh", "title": "DNS over HTTPS in the browser only",
        "protocol": "DNS over HTTPS (port 443)",
        "summary": "Encrypts the browser's lookups without touching the "
                   "system. Other programs (updates, mail, terminal) still use "
                   "plain DNS.",
        "pros": "no terminal needed; nothing changes system-wide",
        "cons": "covers only that browser",
        "steps": [
            ("Firefox: Settings → Privacy & Security → DNS over HTTPS → "
             "Max Protection, provider Quad9 or Cloudflare", ""),
            ("Chrome / Chromium / Brave: Settings → Privacy and security → "
             "Security → Use secure DNS → choose a provider", ""),
            ("Check in the browser: https://on.quad9.net or "
             "https://1.1.1.1/help", "")],
        "undo": "switch the same setting back off",
    })
    return out


NOTES = (
    "Pick one option. dnscrypt-proxy, Stubby and Unbound each want to answer "
    "on this computer, so running two of them at once breaks DNS.",
    "Hotel and café login pages (captive portals) may not appear while "
    "encrypted DNS is strict. Log in first, or open http://neverssl.com; "
    "don't switch to the network's DNS on a network you don't trust.",
    "<connection> is the name in `nmcli connection show`, for example your "
    "Wi-Fi network's name.",
    "LANGuard never runs these commands and never changes DNS settings. "
    "After you have set one up, `languard dnscheck` and the app's Encrypted "
    "DNS page show whether every lookup goes through it, and LANGuard warns "
    "when it leaks, stops or is blocked.",
)


def guide(fam=None, info=None, dot=None, resolved=None):
    """Everything the CLI and the app show."""
    here, name = distro.info()
    fam = fam or here
    if fam != here:
        name = FAMILY_NAMES.get(fam, fam)
    resolved = uses_resolved() if resolved is None else resolved
    return {"distribution": name, "family": fam,
            "uses_resolved": resolved,
            "current": current(info, dot, resolved),
            "options": options(fam, resolved), "notes": list(NOTES)}


def option_text(o, number=None, recommended=False):
    """One option as terminal text."""
    head = f"{number}. " if number else ""
    lines = [f"{head}{o['title']}  [{o['protocol']}]"
             + ("  <- recommended for you" if recommended else ""),
             f"   {o['summary']}",
             f"   + {o['pros']}", f"   - {o['cons']}", ""]
    for i, (what, cmd) in enumerate(o["steps"], 1):
        lines.append(f"   Step {i}: {what}")
        lines += [f"     {c}" for c in cmd.splitlines()]
    lines += ["", "   Undo:"] + [f"     {c}" for c in o["undo"].splitlines()]
    return "\n".join(lines)


def commands_text(o):
    """One option's steps as a script-like block to copy (the app shows it).
    Explanations are comments; the undo commands are commented out."""
    out = []
    for i, (what, cmd) in enumerate(o["steps"], 1):
        out.append(f"# Step {i}: {what}")
        if cmd:
            out.append(cmd)
        out.append("")
    out.append("# Undo:")
    out += [f"#   {c}" for c in o["undo"].splitlines()]
    return "\n".join(out)


def text(g, only=None):
    """The whole guide as terminal text."""
    cur = g["current"]
    out = [f"Encrypted DNS setup guide for {g['distribution']} "
           f"({g['family']} family)",
           "LANGuard only shows these commands; it never runs them or "
           "changes your DNS.", "",
           f"Now: {cur['text']}", ""]
    for i, o in enumerate(g["options"], 1):
        if only and o["key"] != only:
            continue
        out += [option_text(o, i, o["key"] == cur.get("recommend")), ""]
    out.append("Good to know:")
    out += [f"  * {n}" for n in g["notes"]]
    return "\n".join(out)


def packages(fam):
    """Package names the guide installs on this family (for the CI check)."""
    return sorted({v.get(fam) for v in PACKAGES.values() if v.get(fam)})


def main(args):
    import json
    g = guide(fam=args.distro)
    if args.json:
        print(json.dumps(g, indent=2, ensure_ascii=False))
    elif args.packages:
        print(" ".join(packages(g["family"])))
    else:
        print(text(g, args.option))
