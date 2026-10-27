"""
Live status for the desktop app (languard_gui.py).

The service runs as root and keeps its state in /var/lib/languard, which
normal users can't read. Every few seconds it writes a small summary to
/run/languard/status.json (world-readable, nothing secret: interface, router,
which protections are on, isolated MACs). The app reads that file and the
alert log, and runs privileged commands through `pkexec languard ...`.
"""

import json
import os
import re
import time
from pathlib import Path

from . import __version__
from .core import load_state

RUN_DIR = Path(os.environ.get("LANGUARD_RUN", "/run/languard"))
STATUS_FILE = "status.json"
PAUSE_FILE = "pause.json"


def _write_public(name, data):
    try:
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(RUN_DIR, 0o755)
        p = RUN_DIR / name
        tmp = p.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f, indent=1, sort_keys=True)
        os.chmod(tmp, 0o644)
        os.replace(tmp, p)
    except OSError:
        pass


def _read_public(name):
    try:
        with open(RUN_DIR / name) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def snapshot(ctx, mods, started):
    """Everything the app shows about the running service."""
    p = getattr(ctx, "protect", None)
    pstate = p.state if p is not None else load_state("protect", {})
    base = getattr(ctx, "_baseline", None)
    now = time.time()
    dns = getattr(ctx, "local_dns", None) or {}
    ev = getattr(ctx, "evidence", None)
    try:
        from . import hsts
        hsts_sites = len(hsts.load())
    except OSError:
        hsts_sites = 0
    kind = getattr(p, "kind", None) or (base.kind if base else None)
    return {
        "version": __version__, "pid": os.getpid(),
        "started": started, "updated": now,
        "iface": ctx.iface, "ip": ctx.my_ip, "mac": ctx.my_mac,
        "gateway": ctx.gateway,
        "network": base.key if base else None,
        "router_mac": base.rec.get("gw_mac") if base else None,
        "router_verified": bool(base and base.gw_verified),
        "modules": [m.name for m in mods],
        "network_kind": kind,
        "local_dns": {k: dns.get(k) for k in ("resolver", "label", "listen",
                                              "leak_risk")},
        "hsts_sites": hsts_sites,
        "evidence": len(ev.saved) if ev is not None else 0,
        "router_trust": dict(getattr(ctx, "router_trust", None) or {}),
        "sensor": dict(getattr(getattr(ctx, "sensor", None), "stats", None) or {}),
        "devices": [list(x) for x in (ctx.arp.devices()
                                      if getattr(ctx, "arp", None) else [])],
        "protect": {
            "enabled": bool(p and p.enabled),
            "settings": {k: v for k, v in ctx.cfg.get("protect", {}).items()
                         if k != "enabled"},
            "pin": pstate.get("pin"),
            "blocked": {m: b for m, b in pstate.get("blocked", {}).items()
                        if b.get("until", 0) > now},
            "ipv6_lockdown": pstate.get("accept_ra"),
            "https_guard": pstate.get("guard"),
            "blocked_ips": {i: b for i, b in pstate.get("blocked_ips", {}).items()
                            if b.get("until", 0) > now},
            "llmnr_off": pstate.get("llmnr"),
            "redirects_off": pstate.get("redirects") is not None,
            "pin6": pstate.get("pin6"),
            "pinned_devices": base.pinned() if base else {},
            "l2pins": pstate.get("l2pins"),
            "framed_until": pstate.get("framed_until", 0)
            if pstate.get("framed_until", 0) > now else 0,
        },
    }


def write_status(ctx, mods, started):
    _write_public(STATUS_FILE, snapshot(ctx, mods, started))


def read_status():
    return _read_public(STATUS_FILE)


def write_pause(until):
    _write_public(PAUSE_FILE, {"until": until})


def read_pause():
    """Seconds since epoch the pause ends, or None."""
    d = _read_public(PAUSE_FILE)
    until = (d or {}).get("until")
    return until if until and until > time.time() else None


# ------------------------------------------------------------- alert log --
LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ (\w+)\s+"
                  r"(?:\[([\w-]+)\] )?(.*)$")
LEVELS = ("CRITICAL", "WARNING", "INFO")


def parse_line(line):
    """One line of /var/log/languard.log -> event dict, or None."""
    m = LINE.match(line.rstrip("\n"))
    if not m or m.group(2) not in LEVELS:
        return None
    ts, level, module, msg = m.groups()
    try:
        t = time.mktime(time.strptime(ts, "%Y-%m-%d %H:%M:%S"))
    except ValueError:
        return None
    return {"ts": t, "level": level, "module": module or "languard",
            "msg": msg, "kind": kind_of(module, msg)}


def parse_json(line):
    """One line of the json_log -> event dict, or None."""
    try:
        d = json.loads(line)
        ev = {"ts": float(d["ts"]), "level": d["level"],
              "module": d["module"], "msg": d["msg"]}
    except (ValueError, KeyError, TypeError):
        return None
    ev["kind"] = kind_of(ev["module"], ev["msg"])
    ev["data"] = {k: v for k, v in d.items()
                  if k not in ("ts", "level", "module", "msg")}
    return ev


# Actions LANGuard takes outside the protect module (UFW blocks from `scan`).
ACTION_WORDS = ("Blocked ",)


def kind_of(module, msg):
    """'action' for something LANGuard did, 'threat' for an attack or risk,
    'info' for routine messages."""
    if module == "protect" or any(w in msg for w in ACTION_WORDS):
        return "action"
    if module in (None, "languard", "baseline") or \
            msg.startswith(("Learned", "Remembered", "Baseline", "Gateway ", "LANGuard ",
                            "check failed", "check skipped")):
        return "info"
    return "threat"


class LogTail:
    """Reads new events from a log file; survives truncation and rotation."""

    def __init__(self, path, parser=parse_line, backlog=2_000_000):
        self.path = Path(path)
        self.parser = parser
        self.backlog = backlog          # bytes of history read on first open
        self._pos = None
        self._ino = None

    def read(self):
        try:
            st = self.path.stat()
        except OSError:
            return []
        if self._ino != st.st_ino or (self._pos or 0) > st.st_size:
            self._ino = st.st_ino
            self._pos = max(0, st.st_size - self.backlog) if self._pos is None else 0
        out = []
        try:
            with open(self.path, "rb") as f:
                f.seek(self._pos)
                data = f.read()
        except OSError:
            return []
        end = data.rfind(b"\n") + 1            # keep a partial last line for later
        self._pos += end
        lines = data[:end].decode(errors="replace").splitlines()
        for line in lines:
            ev = self.parser(line)
            if ev:
                out.append(ev)
        return out
