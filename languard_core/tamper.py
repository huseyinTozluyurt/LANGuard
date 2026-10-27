"""
Tamper protection: commands that lower protection ask for your password every
time and are always reported.

Malware running as you can't type your password, but it can ride on a
password you typed a minute ago: polkit's "keep" authorisation. So there are
two entry points:

  * /opt/languard/languard.py (polkit action org.languard.manage): asks once
    per few minutes; for everything that doesn't weaken protection
  * /opt/languard/languard_strict.py (org.languard.weaken): asks every time

Run through pkexec, languard.py refuses the weakening commands below; the app
sends them through languard_strict.py. Every weakening command, however it
was run (pkexec, sudo, root shell), raises a CRITICAL "protection lowered"
alert naming the user and the program that asked.
"""

import os

STRICT_ENV = "LANGUARD_STRICT"


def weakens(argv):
    """What a languard command line lowers, or None. argv without the
    program name, e.g. ['protect', '--set', 'isolate=off']."""
    args = [a for a in argv if a not in ("-v", "--verbose")]
    while args and args[0] in ("-c", "--config", "-i", "--iface", "-g",
                               "--gateway", "--log", "--json-log"):
        args = args[2:]
    if not args:
        return None
    cmd, rest = args[0], args[1:]
    if cmd == "pause":
        return f"protection paused ({' '.join(rest)} min)"
    if cmd == "baseline" and ("--reset" in rest or "--reset-all" in rest):
        return "network baseline forgotten (router re-learned)"
    if cmd == "network" and ("--home" in rest or "--unmark" in rest):
        return "public-network hardening relaxed"
    if cmd == "devices" and ("--trust" in rest or "--forget" in rest):
        return "devices trusted or forgotten"
    if cmd != "protect":
        return None
    out = []
    if "--off" in rest:
        out.append("active protection off")
    if "--undo-all" in rest:
        out.append("every protective action undone")
    if "--unblock" in rest:
        out.append("attackers unblocked")
    if "--unpin" in rest:
        out.append("router pins removed")
    if "--unpin-device" in rest:
        out.append("a device unpinned")
    if "--set" in rest:
        offs = [a.split("=")[0] for a in rest[rest.index("--set") + 1:]
                if a.endswith("=off")]
        if offs:
            out.append("responses switched off: " + ", ".join(offs))
    return "; ".join(out) or None


def caller():
    """(user, program) that asked for this root command."""
    uid = os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID")
    via = "pkexec" if os.environ.get("PKEXEC_UID") else \
        "sudo" if os.environ.get("SUDO_UID") else "root"
    user = uid or str(os.getuid())
    try:
        import pwd
        user = pwd.getpwuid(int(user)).pw_name
    except (KeyError, ValueError, ImportError):
        pass
    prog = "?"
    try:                            # our parent is pkexec/sudo: its parent asked
        pid = os.getppid()
        if via != "root":
            with open(f"/proc/{pid}/stat") as f:
                stat = f.read()
            pid = int(stat[stat.rindex(")") + 2:].split()[1])
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            prog = f.read().replace(b"\0", b" ").decode(errors="replace").strip()[:120] or "?"
    except (OSError, ValueError, IndexError):
        pass
    return user, via, prog


def via_cached_pkexec():
    """True when run through pkexec on the 'keep' entry point."""
    return bool(os.environ.get("PKEXEC_UID")) and not os.environ.get(STRICT_ENV)
