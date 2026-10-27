"""
Real-time file protection (inotify, no polling).

1. Scans every new or changed file in Downloads, Desktop and temp folders
   with ClamAV (via the clamd daemon, so each scan takes milliseconds) and
   moves infected files to quarantine.
2. Flags disguised files: double extensions (invoice.pdf.sh), right-to-left
   override tricks, .desktop launchers, and executables dropped into /tmp or
   /dev/shm.
3. Watches the places malware uses to survive a reboot (cron, systemd units,
   autostart, shell startup files, SSH authorized_keys, ld.so.preload, sudoers,
   apt sources) and alerts on any change. This catches malware no antivirus
   signature knows yet.
"""

import ctypes
import ctypes.util
import fnmatch
import json
import os
import queue
import re
import select
import shutil
import stat
import struct
import subprocess
import threading
import time

from . import distro
from .core import STATE_DIR, Module, expand_paths, human_homes, log

IN_ATTRIB, IN_CLOSE_WRITE, IN_MOVED_TO = 0x4, 0x8, 0x80
IN_CREATE, IN_DELETE, IN_DELETE_SELF = 0x100, 0x200, 0x400
IN_Q_OVERFLOW, IN_IGNORED, IN_ISDIR = 0x4000, 0x8000, 0x40000000
EVENT = struct.Struct("iIII")

TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
SKIP_SUFFIXES = (".part", ".crdownload", ".download", ".partial", ".tmp",
                 ".swp", ".swx", ".lock", ".lck")
DOC_EXT = r"pdf|docx?|xlsx?|pptx?|odt|ods|jpe?g|png|gif|txt|mp[34]|mkv|zip|rar"
RUN_EXT = r"sh|bash|desktop|py|pl|run|bin|appimage|elf|exe|jar|bat|ps1|deb|js"
DOUBLE_EXT = re.compile(rf"\.({DOC_EXT})\.({RUN_EXT})$", re.I)
RLO_CHARS = ("‮", "‭", "⁦", "⁧")

DEFAULT_IGNORE = ["/tmp/.mount_*", "/tmp/snap-private-tmp/*",
                  "/tmp/systemd-private-*", "/var/tmp/systemd-private-*",
                  "*/.cache/*", "/tmp/.X11-unix/*", "/tmp/.ICE-unix/*"]

SYSTEM_PERSIST = {
    "/etc/cron.d": None, "/etc/cron.hourly": None, "/etc/cron.daily": None,
    "/etc/cron.weekly": None, "/etc/cron.monthly": None,
    "/var/spool/cron/crontabs": None,
    "/etc/systemd/system": None,
    "/etc/systemd/system/multi-user.target.wants": None,
    "/etc/systemd/system/graphical.target.wants": None,
    "/etc/systemd/system/timers.target.wants": None,
    "/etc/xdg/autostart": None, "/etc/profile.d": None,
    "/etc/sudoers.d": None, "/etc/ld.so.conf.d": None,
    "/etc/apt/sources.list.d": None, "/etc/udev/rules.d": None,
    "/etc/yum.repos.d": None, "/etc/zypp/repos.d": None,
    "/etc/pacman.d/hooks": None,
    "/etc": {"ld.so.preload", "passwd", "sudoers", "crontab", "rc.local",
             "environment", "bash.bashrc", "profile", "hosts"},
}
USER_PERSIST = {
    ".config/autostart": None,
    ".config/systemd/user": None,
    ".config/systemd/user/default.target.wants": None,
    ".config/systemd/user/timers.target.wants": None,
    ".ssh": {"authorized_keys", "authorized_keys2", "rc", "environment"},
    "": {".bashrc", ".profile", ".bash_profile", ".bash_login", ".zshrc",
         ".zprofile", ".xprofile", ".xsessionrc", ".pam_environment",
         ".bash_logout"},
}
PKG_PROCS = {"dpkg", "apt", "apt-get", "aptitude", "unattended-upgr",
             "snap", "flatpak", "rpm", "dnf", "dnf5", "yum", "dnf-automatic",
             "packagekitd", "zypper", "pacman", "yay", "paru", "pamac"}


class Inotify:
    """Minimal inotify binding via ctypes (no extra packages needed)."""

    def __init__(self):
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                           use_errno=True)
        self._add = libc.inotify_add_watch
        self._add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self.fd = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self.paths = {}            # wd -> path

    def add(self, path, mask):
        wd = self._add(self.fd, os.fsencode(path), mask)
        if wd >= 0:
            self.paths[wd] = path
        return wd

    def read(self, timeout=1.0):
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return []
        try:
            data = os.read(self.fd, 64 * 1024)
        except BlockingIOError:
            return []
        events, i = [], 0
        while i + EVENT.size <= len(data):
            wd, mask, _cookie, ln = EVENT.unpack_from(data, i)
            name = data[i + EVENT.size:i + EVENT.size + ln].rstrip(b"\0")
            i += EVENT.size + ln
            if mask & IN_IGNORED:
                self.paths.pop(wd, None)
                continue
            events.append((wd, mask, os.fsdecode(name)))
        return events


def pkg_manager_busy():
    """True while a package manager (apt, dnf, zypper, pacman, snap...) is
    installing something (fewer false alarms)."""
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                with open(f"/proc/{pid}/comm") as f:
                    if f.read().strip() in PKG_PROCS:
                        return True
            except OSError:
                pass
    return False


def make_scanner(kind="auto"):
    """Return scan(path) -> ('clean'|'infected'|'error', signature)."""
    sock_ok = distro.clamd_socket() is not None
    if kind == "auto":
        kind = ("clamdscan" if shutil.which("clamdscan") and sock_ok
                else "clamscan" if shutil.which("clamscan") else "none")
    if kind == "none":
        return None, "none"
    cmd = (["clamdscan", *distro.clamdscan_args(), "--fdpass", "--no-summary",
            "--infected"]
           if kind == "clamdscan" else ["clamscan", "--no-summary", "--infected"])

    def scan(path):
        try:
            r = subprocess.run(cmd + [path], capture_output=True, text=True,
                               timeout=300)
        except subprocess.TimeoutExpired:
            return "error", "timeout"
        if r.returncode == 1:
            m = re.search(r":\s*(.+?)\s+FOUND", r.stdout)
            return "infected", m.group(1) if m else "unknown"
        if r.returncode == 0:
            return "clean", None
        return "error", (r.stderr or r.stdout).strip()[:200]
    return scan, kind


def quarantine(path, signature):
    """Move a file into quarantine, unreadable. Returns the new path."""
    qdir = STATE_DIR / "quarantine"
    qdir.mkdir(parents=True, exist_ok=True)
    os.chmod(qdir, 0o700)
    st = os.stat(path)
    qid = time.strftime("%Y%m%d-%H%M%S") + "-" + os.path.basename(path)[:80]
    dest = qdir / qid
    shutil.move(path, dest)
    os.chmod(dest, 0)
    meta = {"original": path, "signature": signature, "time": time.time(),
            "uid": st.st_uid, "gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode)}
    (qdir / (qid + ".json")).write_text(json.dumps(meta, indent=2))
    return str(dest)


def list_quarantine():
    qdir = STATE_DIR / "quarantine"
    items = sorted(qdir.glob("*.json")) if qdir.exists() else []
    if not items:
        print("Quarantine is empty.")
    for m in items:
        meta = json.loads(m.read_text())
        print(f"{m.stem}\n    from: {meta['original']}\n    why:  {meta['signature']}")
    return items


def restore_quarantine(qid):
    qdir = STATE_DIR / "quarantine"
    meta_p, file_p = qdir / (qid + ".json"), qdir / qid
    if not meta_p.exists():
        raise SystemExit(f"No quarantined item '{qid}' (see: languard quarantine)")
    meta = json.loads(meta_p.read_text())
    dest = meta["original"]
    if os.path.exists(dest):
        dest += ".restored"
    shutil.move(str(file_p), dest)
    os.chmod(dest, meta["mode"] & 0o666)          # restored without exec bit
    os.chown(dest, meta["uid"], meta["gid"])
    meta_p.unlink()
    print(f"Restored to {dest} (execute permission removed)")


class FileWatch(Module):
    name = "filewatch"
    threaded = True

    def __init__(self, ctx, scanner=None, homes=None, system_persist=None):
        super().__init__(ctx)
        if scanner is None:
            scanner, kind = make_scanner(self.cfg.get("scanner", "auto"))
            log.info("[filewatch] virus scanner: %s", kind)
        self.scan_fn = scanner
        self.homes = homes if homes is not None else [h for _, _, h in human_homes()]
        self.system_persist = SYSTEM_PERSIST if system_persist is None else system_persist
        self.ignore = DEFAULT_IGNORE + self.cfg.get("ignore", [])
        self.max_bytes = self.cfg.get("max_scan_mb", 100) * 1024 * 1024
        self.queue = queue.Queue()
        self.pending = set()
        self.ino = None
        self.watch_kind = {}         # wd -> ("scan", None) | ("persist", filter)
        self.stats = {"scanned": 0, "infected": 0}

    # ---- setup ----
    def _watch_tree(self, root, depth=3):
        n = 0
        mask = IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE
        for dirpath, dirnames, _ in os.walk(root):
            if self._ignored(dirpath + "/"):
                dirnames[:] = []
                continue
            if dirpath[len(root):].count(os.sep) >= depth:
                dirnames[:] = []
            wd = self.ino.add(dirpath, mask)
            if wd >= 0:
                self.watch_kind[wd] = ("scan", None)
                n += 1
            if len(self.watch_kind) > 4000:
                break
        return n

    def setup(self, scan_dirs=None):
        self.ino = Inotify()
        dirs = scan_dirs if scan_dirs is not None else \
            expand_paths(self.cfg.get("scan_dirs", []))
        n = sum(self._watch_tree(d) for d in dirs)
        persist = dict(self.system_persist)
        for home in self.homes:
            for rel, flt in USER_PERSIST.items():
                persist[os.path.join(home, rel) if rel else home] = flt
        p = 0
        for path, flt in persist.items():
            if os.path.isdir(path):
                wd = self.ino.add(path, IN_CLOSE_WRITE | IN_MOVED_TO |
                                  IN_CREATE | IN_DELETE)
                if wd >= 0:
                    self.watch_kind[wd] = ("persist", flt)
                    p += 1
        log.info("[filewatch] watching %d folders for new files and %d "
                 "persistence locations", n, p)
        return n, p

    def _ignored(self, path):
        return any(fnmatch.fnmatch(path, pat) for pat in self.ignore)

    # ---- pure checks ----
    def heuristics(self, path):
        """Return [(level, message)] for suspicious names / locations."""
        out = []
        name = os.path.basename(path)
        if any(c in name for c in RLO_CHARS):
            out.append(("CRITICAL", f"Filename uses a hidden right-to-left "
                        f"character to fake its extension: {path!r}"))
        if DOUBLE_EXT.search(name):
            out.append(("CRITICAL", f"Disguised file (double extension): "
                        f"{path}. It looks like a document but is a program"))
        elif name.lower().endswith(".desktop") and not path.startswith(TEMP_DIRS):
            out.append(("WARNING", f"Launcher file {path}: .desktop files can "
                        f"run any command when opened. Don't open it unless "
                        f"you know where it came from"))
        if path.startswith(TEMP_DIRS) and _is_executable_binary(path):
            out.append(("WARNING", f"Executable program dropped in a temp "
                        f"folder: {path} (common malware behavior)"))
        return out

    def scan_file(self, path):
        """Heuristics + AV scan + quarantine. Returns a result string."""
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return "gone"
        if not stat.S_ISREG(st.st_mode) or self._ignored(path):
            return "skipped"
        for level, msg in self.heuristics(path):
            self.alert(f"heur:{path}", level, msg, path=path)
        if st.st_size == 0 or st.st_size > self.max_bytes \
                or path.endswith(SKIP_SUFFIXES) or self.scan_fn is None:
            return "skipped"
        status, sig = self.scan_fn(path)
        self.stats["scanned"] += 1
        if status == "infected":
            self.stats["infected"] += 1
            where = "left in place"
            if self.cfg.get("quarantine", True):
                try:
                    where = "moved to quarantine: " + quarantine(path, sig)
                except OSError as e:
                    where = f"quarantine failed ({e}); delete it manually"
            self.alert(f"virus:{path}", "CRITICAL",
                       f"MALWARE FOUND: {path} is {sig}. File {where}",
                       path=path, signature=sig)
        elif status == "error":
            log.debug("[filewatch] scan error %s: %s", path, sig)
        return status

    def persistence_change(self, path, mask, busy=None):
        """A watched autostart/persistence location changed."""
        name = os.path.basename(path)
        d = os.path.dirname(path)
        if d.rstrip("/").endswith(("/systemd/system", "/systemd/user")) and \
                name.startswith(("snap-", "snap.", "languard")):
            return None
        if name.endswith((".dpkg-new", ".dpkg-tmp", ".dpkg-old", ".rpmnew",
                          ".rpmsave", ".rpmorig", ".pacnew", ".pacsave", "~",
                          ".swp")) \
                or name.startswith(".#"):
            return None
        busy = pkg_manager_busy() if busy is None else busy
        what = ("deleted" if mask & IN_DELETE else
                "created" if mask & IN_CREATE else "modified")
        if mask & IN_DELETE or busy:
            level = "INFO"
            why = " during a package install/update" if busy else ""
        else:
            level = "WARNING"
            why = (". Malware uses this location to restart itself. If you "
                   "didn't just change this, inspect it")
        self.alert(f"persist:{path}", level,
                   f"Startup/persistence location {what}: {path}{why}",
                   path=path, change=what)
        return level

    # ---- threads ----
    def _scanner_loop(self):
        while True:
            path = self.queue.get()
            time.sleep(0.5)                 # let writers finish
            self.pending.discard(path)
            try:
                self.scan_file(path)
            except Exception as e:
                log.debug("[filewatch] %s: %s", path, e)

    def enqueue(self, path):
        if path not in self.pending:
            self.pending.add(path)
            self.queue.put(path)

    def process(self, events):
        for wd, mask, name in events:
            if mask & IN_Q_OVERFLOW:
                log.warning("[filewatch] event queue overflowed; some files "
                            "were not scanned")
                continue
            base = self.ino.paths.get(wd)
            kind = self.watch_kind.get(wd)
            if not base or not kind or not name:
                continue
            path = os.path.join(base, name)
            if kind[0] == "persist":
                flt = kind[1]
                if (flt is None or name in flt) and \
                        mask & (IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE):
                    if mask & IN_CREATE and not mask & IN_ISDIR \
                            and not os.path.islink(path):
                        continue            # CLOSE_WRITE will follow
                    self.persistence_change(path, mask)
            elif mask & IN_ISDIR:
                if mask & (IN_CREATE | IN_MOVED_TO):
                    self._watch_tree(path, depth=2)
            elif mask & (IN_CLOSE_WRITE | IN_MOVED_TO):
                self.enqueue(path)

    def start(self):
        if self.ino is None:
            self.setup()
        threading.Thread(target=self._scanner_loop, name="av-scanner",
                         daemon=True).start()

    def run(self):
        while True:
            try:
                self.process(self.ino.read(timeout=2.0))
            except Exception as e:
                log.warning("[filewatch] %s", e)
                time.sleep(1)

    # ---- full scan ----
    def full_scan(self, paths=None):
        """Scan whole home folders (weekly timer). Uses clamdscan multiscan,
        or clamscan (slower, same signatures) when the daemon isn't up."""
        paths = paths or self.homes
        if shutil.which("clamdscan") and distro.clamd_socket():
            cmd = ["clamdscan", *distro.clamdscan_args(), "--multiscan", "--fdpass"]
        elif shutil.which("clamscan"):
            log.warning("[filewatch] ClamAV daemon not running: full scan with "
                        "clamscan (slower)")
            cmd = ["clamscan", "-r"]
        else:
            print(f"ClamAV not installed: {distro.clamav_enable_hint()}")
            return []
        found, errors = [], []
        for p in paths:
            r = subprocess.run(cmd + ["--infected", "--no-summary", p],
                               capture_output=True, text=True)
            for line in r.stdout.splitlines():
                m = re.match(r"(.+?):\s*(.+?)\s+FOUND$", line)
                if m:
                    found.append(m.groups())
            if r.returncode not in (0, 1):          # 2: scanner error
                errors.append(f"{p}: {(r.stderr or r.stdout).strip()[:200]}")
        for e in errors:
            self.alert(f"avscan-error:{e[:60]}", "WARNING",
                       f"Full virus scan incomplete: {e}")
        for path, sig in found:
            where = "left in place"
            if self.cfg.get("quarantine", True):
                try:
                    where = "moved to quarantine: " + quarantine(path, sig)
                except OSError as e:
                    where = f"quarantine failed ({e})"
            self.alert(f"virus:{path}", "CRITICAL",
                       f"MALWARE FOUND (full scan): {path} is {sig}. {where}",
                       path=path, signature=sig)
        log.info("[filewatch] full scan of %s: %d infected",
                 ", ".join(paths), len(found))
        return found


def _is_executable_binary(path):
    try:
        if not os.access(path, os.X_OK):
            return False
        with open(path, "rb") as f:
            head = f.read(4)
        return head == b"\x7fELF" or head[:2] == b"#!"
    except OSError:
        return False
