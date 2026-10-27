"""
Real-time behavior monitor for this machine.

  * programs running from /tmp, /var/tmp or /dev/shm
  * programs whose file was deleted after starting (a hiding trick), outside
    normal package upgrades
  * fileless programs running straight from memory (memfd)
  * new services suddenly listening on all interfaces (backdoors, bind shells)
"""

import fnmatch
import os

from .audit import exposed_sockets
from .core import Module, log

TEMP = ("/tmp/", "/var/tmp/", "/dev/shm/")
SYSTEM_PREFIXES = ("/usr/", "/opt/", "/snap/", "/lib/", "/lib64/", "/bin/",
                   "/sbin/", "/var/lib/snapd/", "/app/")


def list_processes():
    out = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip()
        except OSError:
            continue                       # kernel thread or gone
        out.append((int(pid), exe, comm))
    return out


class HostMonitor(Module):
    name = "host"
    threaded = True

    def __init__(self, ctx, procs=list_processes, sockets=exposed_sockets):
        super().__init__(ctx)
        self.interval = self.cfg.get("interval", 15)
        self.procs_fn, self.sockets_fn = procs, sockets
        self.ignore = self.cfg.get("ignore_exes", [])
        self.flagged = set()                # (pid, exe) already reported
        self.listeners = None

    # ---- pure logic ----
    def classify(self, exe):
        """Return (level, reason) for a process executable, or None."""
        if any(fnmatch.fnmatch(exe, p) for p in self.ignore):
            return None
        deleted = exe.endswith(" (deleted)")
        path = exe[:-10] if deleted else exe
        if path.startswith("/memfd:"):
            return ("WARNING", "is running from memory only (fileless, memfd)")
        if path.startswith(TEMP):
            return ("CRITICAL", "is running from a temp folder")
        if deleted and not path.startswith(SYSTEM_PREFIXES):
            return ("CRITICAL", "deleted its own file after starting "
                                "(malware does this to hide)")
        return None

    def check_processes(self, procs):
        hits = []
        live = set()
        for pid, exe, comm in procs:
            live.add((pid, exe))
            res = self.classify(exe)
            if not res or (pid, exe) in self.flagged:
                continue
            self.flagged.add((pid, exe))
            level, why = res
            hits.append(pid)
            self.alert(f"proc:{pid}", level,
                       f"Suspicious process '{comm}' (PID {pid}) {why}: {exe}. "
                       f"Inspect: ls -l /proc/{pid}/exe; sudo ss -tunap | "
                       f"grep pid={pid}", pid=pid, exe=exe, comm=comm)
        self.flagged &= live
        return hits

    def check_listeners(self, sockets):
        cur = set(sockets)
        if self.listeners is None:
            self.listeners = cur
            log.info("[host] %d services listening on the LAN at start",
                     len(cur))
            return []
        new = sorted(cur - self.listeners)
        for proto, port, proc in new:
            self.alert(f"listen:{proto}:{port}", "WARNING",
                       f"New service listening on all interfaces: "
                       f"{proto}/{port} ({proc}). Backdoors open ports like "
                       f"this. If you didn't just start a server, check it",
                       proto=proto, port=port, proc=proc)
        self.listeners = cur
        return new

    def tick(self):
        self.check_processes(self.procs_fn())
        self.check_listeners(self.sockets_fn())
