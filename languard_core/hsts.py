"""
The full HSTS preload list (the ~125,000 sites browsers only ever reach over
HTTPS), so SSL-stripping detection and the HTTPS guard know every one of them,
not only the sites this machine has already visited over HTTPS.

The list is Mozilla's (nsSTSPreloadList.inc, the one Firefox ships). It is
downloaded over HTTPS with certificate checks, at install and then weekly by
`languard guard`, and kept in /var/lib/languard/hsts_preload.txt. Update now:
    sudo languard hsts --update
Without it LANGuard falls back to its short built-in list (strip.PRELOADED).
"""

import os
import ssl
import threading
import time
import urllib.request

from . import core
from .core import log

SOURCES = (
    "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/manager/ssl/"
    "nsSTSPreloadList.inc",
    "https://raw.githubusercontent.com/mozilla-firefox/firefox/main/security/"
    "manager/ssl/nsSTSPreloadList.inc",
)
FILE = "hsts_preload.txt"
MAX_BYTES = 30 * 1024 * 1024
MIN_ENTRIES = 10000                 # less than this is not the real list
MAX_AGE = 7 * 86400

_table = None
_loaded_mtime = None
_lock = threading.Lock()


def path():
    return core.STATE_DIR / FILE


def parse(text):
    """{domain: include_subdomains} from nsSTSPreloadList.inc."""
    out, inside = {}, False
    for line in text.splitlines():
        if line.startswith("%%"):
            if inside:
                break
            inside = True
            continue
        if not inside:
            continue
        name, _, flag = line.partition(",")
        name = name.strip().lower().rstrip(".")
        if name and all(c.isalnum() or c in ".-_" for c in name):
            out[name] = flag.strip() == "1"
    return out


def update(fetch=None):
    """Download, check and store the list. Returns the number of entries."""
    errors = []
    for url in SOURCES:
        try:
            text = fetch(url) if fetch else _get(url)
        except Exception as e:
            errors.append(f"{url.split('/')[2]}: {e}")
            continue
        table = parse(text)
        if len(table) < MIN_ENTRIES:
            errors.append(f"{url.split('/')[2]}: only {len(table)} entries")
            continue
        core.STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = path().with_suffix(".tmp")
        with open(tmp, "w") as f:
            f.write(f"# HSTS preload list from {url}, {time.strftime('%Y-%m-%d')}\n")
            for name in sorted(table):
                f.write(f"{name} {int(table[name])}\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path())
        global _table
        with _lock:
            _table = table
        return len(table)
    raise OSError("; ".join(errors))


def _get(url):
    ctx = ssl.create_default_context()          # verifies the certificate
    req = urllib.request.Request(url, headers={"User-Agent": "LANGuard"})
    with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise OSError("file too large")
    return data.decode("utf-8", "replace")


def load():
    """The stored list ({} if there is none); reloaded when the file changes."""
    global _table, _loaded_mtime
    try:
        mtime = path().stat().st_mtime
    except OSError:
        return _table or {}
    with _lock:
        if _table is not None and mtime == _loaded_mtime:
            return _table
        table = {}
        try:
            with open(path()) as f:
                for line in f:
                    if line.startswith("#"):
                        continue
                    p = line.split()
                    if len(p) == 2:
                        table[p[0]] = p[1] == "1"
        except OSError as e:
            log.debug("[hsts] can't read %s: %s", path(), e)
        _table, _loaded_mtime = table, mtime
        return table


def preloaded(host, table=None):
    """True if browsers must use HTTPS for host (exact entry, or a parent
    entry that includes subdomains)."""
    table = load() if table is None else table
    if not table or not host:
        return False
    host = host.lower().rstrip(".")
    if host in table:
        return True
    parts = host.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if table.get(parent):
            return True
    return False


def age_days():
    try:
        return (time.time() - path().stat().st_mtime) / 86400
    except OSError:
        return None


def refresh_if_old(alert=None):
    """For `languard guard` (every 5 min): update once a week; on failure
    retry at most every 6 hours."""
    age = age_days()
    if age is not None and age * 86400 < MAX_AGE:
        return False
    stamp = core.STATE_DIR / "hsts_attempt"
    try:
        if time.time() - stamp.stat().st_mtime < 6 * 3600:
            return False
    except OSError:
        pass
    try:
        core.STATE_DIR.mkdir(parents=True, exist_ok=True)
        stamp.touch()
        n = update()
        log.info("[hsts] HSTS preload list updated: %d sites", n)
        return True
    except OSError as e:
        log.warning("[hsts] HSTS preload list update failed: %s", e)
        return False


def status():
    n, age = len(load()), age_days()
    if not n:
        return "HSTS preload list: not downloaded (sudo languard hsts --update)"
    return f"HSTS preload list: {n} sites, updated {age:.0f} day(s) ago"
