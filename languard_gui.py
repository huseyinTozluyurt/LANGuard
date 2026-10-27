#!/usr/bin/env python3
"""
LANGuard desktop app (PyQt5).

An intrusion prevention console for LANGuard: protection status, the threats
it detects and the actions it takes, every response switch, active blocks
with undo, network trust (home / public) and pinned devices, your encrypted
DNS resolver (shown, never changed) with a guide to set one up yourself,
and tools: self-test, security audit, evidence captures and the HSTS
preload list.

Run it as your normal user: it reads the service's live status
(/run/languard/status.json) and alert log, and asks for your password through
polkit (pkexec) only for the buttons that change something.

    languard-gui            (or: python3 languard_gui.py)
"""

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Python packages the installer fetched with pip (see requirements-gui.txt);
# the distribution's own PyQt5 wins when both exist.
_VENDOR = Path(__file__).resolve().parent / "vendor"
if _VENDOR.is_dir():
    sys.path.append(str(_VENDOR))

from PyQt5.QtCore import (QPointF, QProcess, QRectF, QSize, Qt,  # noqa: E402
                          QTimer, pyqtSignal)
from PyQt5.QtGui import (QBrush, QColor, QFont, QIcon, QPainter,  # noqa: E402
                         QPainterPath, QPen, QPixmap, QRadialGradient)
from PyQt5.QtWidgets import (QAbstractItemView, QApplication,  # noqa: E402
                             QButtonGroup, QCheckBox, QComboBox, QFrame,
                             QGridLayout, QHBoxLayout, QHeaderView, QLabel,
                             QLineEdit, QMainWindow, QMenu, QMessageBox,
                             QPlainTextEdit, QPushButton, QScrollArea,
                             QSplitter, QStackedWidget, QSystemTrayIcon,
                             QTableWidget, QTableWidgetItem, QToolButton,
                             QVBoxLayout, QWidget)

from languard_core import __version__, status, tamper  # noqa: E402
from languard_core.core import load_config      # noqa: E402

LANGUARD = os.environ.get("LANGUARD_BIN", "/opt/languard/languard.py")
# Commands that lower protection go through this entry point: polkit asks for
# your password every time, so malware can't reuse one you typed earlier.
LANGUARD_STRICT = str(Path(LANGUARD).with_name("languard_strict.py"))
MAX_EVENTS = 20000
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")

COLORS = {
    "bg": "#0e1116", "side": "#0a0c10", "panel": "#151a21", "panel2": "#1c232c",
    "border": "#262e39", "text": "#e7ebf1", "muted": "#8a94a6",
    "CRITICAL": "#f2545b", "WARNING": "#f5a524", "INFO": "#4f9cf9",
    "action": "#2fd38a", "ok": "#2fd38a", "off": "#5b6473", "paused": "#f5a524",
    "accent": "#2fd38a", "select": "#22344d",
}

CATEGORIES = {
    "arp": "ARP spoofing", "path": "Routing MITM", "dhcp": "DHCP attacks",
    "dns": "DNS spoofing", "devices": "Rogue devices / MAC flood",
    "ipv6": "IPv6 MITM", "mitm": "Redirects / name poisoning",
    "tls": "HTTPS interception", "strip": "SSL stripping", "scan": "Scans / brute force",
    "wifi": "Wi-Fi attacks", "filewatch": "Malware (files)",
    "host": "Malware (processes)", "guard": "Protection tampering",
    "protect": "Protection action", "localdns": "Encrypted DNS",
    "evidence": "Evidence capture", "netid": "Network identity (evil twin)",
    "sensor": "Sensor health", "tamper": "Protection tampering",
}

try:                                    # the responses the service knows
    from languard_core.protect import OPTIONS  # noqa: E402
except Exception:                       # pragma: no cover
    OPTIONS = {"pin_gateway": True, "isolate": True, "block_ips": True,
               "cut_connections": True, "flush_dns": True, "repair_dhcp": True,
               "ipv6_lockdown": True, "llmnr_off": True, "block_redirects": True,
               "https_guard": True, "block_wpad": True, "pin_devices": True,
               "pin_router6": True, "public_hardening": True, "kill_switch": False,
               "pin_dhcp": True, "pin_ra": True, "https_only": False}

# (group, [(key, title, what it does)]) for the Protection page.
RESPONSES = [
    ("Router and devices", [
        ("pin_gateway", "Pin the router",
         "Static ARP entry for your verified router, so ARP spoofing can't "
         "put an attacker between you and the internet."),
        ("pin_router6", "Pin the IPv6 router",
         "The same for the verified IPv6 router (stops NDP spoofing)."),
        ("pin_devices", "Pin your devices",
         "Keep devices you pinned on the Network page (NAS, printer) at "
         "their real MAC."),
        ("pin_dhcp", "Only the real DHCP server",
         "Drop DHCP answers from any MAC but the verified router's, so a "
         "rogue DHCP server can't win the race for your lease."),
        ("pin_ra", "Only the real IPv6 router",
         "Drop IPv6 router advertisements from any MAC but the verified "
         "router's (stops mitm6 and SLAAC attacks before they start)."),
        ("isolate", "Isolate attackers",
         "Drop every frame from a device caught attacking, for a limited "
         "time. Your router and pinned devices are never isolated, and "
         "isolation pauses if known devices are being framed."),
        ("block_ips", "Block attacker addresses",
         "Reject traffic to and from the attacker's IP addresses."),
        ("cut_connections", "Cut hijacked connections",
         "End live connections that went through the attacker."),
    ]),
    ("Web and traffic", [
        ("https_guard", "HTTPS guard",
         "Upgrades plain HTTP to sites you use over HTTPS and to HSTS-preloaded "
         "sites: stops SSL stripping."),
        ("https_only", "HTTPS for every site",
         "Upgrade every public site to HTTPS, not only ones known to support "
         "it. Closes first-visit SSL stripping, but sites without HTTPS stop "
         "loading. Off by default; turning on HTTPS-Only in your browser does "
         "the same with a click-through."),
        ("block_redirects", "Ignore ICMP redirects",
         "After a redirect attack, stop the kernel from following redirects."),
        ("ipv6_lockdown", "IPv6 lockdown",
         "After a rogue IPv6 router, ignore router advertisements."),
        ("repair_dhcp", "Repair after rogue DHCP",
         "Renew the lease from the real DHCP server. Your DNS settings are "
         "never touched."),
    ]),
    ("Name services", [
        ("llmnr_off", "Turn off LLMNR after poisoning",
         "Stops Responder-style name poisoning from stealing credentials."),
        ("block_wpad", "Block WPAD proxy hijacks",
         "Isolate a LAN host that pushes a rogue proxy configuration."),
        ("flush_dns", "Flush forged DNS answers",
         "Empty the systemd-resolved cache after spoofing. It doesn't change "
         "your resolver or its settings."),
    ]),
    ("Networks", [
        ("public_hardening", "Harden public networks",
         "On networks marked public or open Wi-Fi: LLMNR off, ICMP "
         "redirects and rogue IPv6 routers ignored from the start."),
        ("kill_switch", "Kill switch",
         "Disconnect the network on a confirmed router MITM (two different "
         "signs of it within two minutes). Off by default: it takes you "
         "offline."),
    ]),
]
TITLES = {k: t for _, rows in RESPONSES for k, t, _ in rows}


def category(module):
    return CATEGORIES.get(module, module)


# ------------------------------------------------------------------ icons --
def _shield_path(x, y, s):
    path = QPainterPath()
    path.moveTo(x + s * .5, y + s * .04)
    path.lineTo(x + s * .9, y + s * .19)
    path.cubicTo(x + s * .9, y + s * .58, x + s * .73, y + s * .83, x + s * .5, y + s * .97)
    path.cubicTo(x + s * .27, y + s * .83, x + s * .1, y + s * .58, x + s * .1, y + s * .19)
    path.closeSubpath()
    return path


def _glyph(p, mode, x, y, s, color="white"):
    """The mark inside the shield: check, pause, eye or cross."""
    p.setPen(QPen(QColor(color), s * .08, cap=Qt.RoundCap, join=Qt.RoundJoin))
    p.setBrush(Qt.NoBrush)
    if mode == "protected":
        p.drawPolyline(QPointF(x + s * .33, y + s * .5), QPointF(x + s * .46, y + s * .63),
                       QPointF(x + s * .68, y + s * .38))
    elif mode == "paused":
        p.drawLine(QPointF(x + s * .42, y + s * .36), QPointF(x + s * .42, y + s * .64))
        p.drawLine(QPointF(x + s * .58, y + s * .36), QPointF(x + s * .58, y + s * .64))
    elif mode == "monitoring":
        p.drawEllipse(QPointF(x + s * .5, y + s * .5), s * .08, s * .08)
        eye = QPainterPath()
        eye.moveTo(x + s * .27, y + s * .5)
        eye.quadTo(x + s * .5, y + s * .28, x + s * .73, y + s * .5)
        eye.quadTo(x + s * .5, y + s * .72, x + s * .27, y + s * .5)
        p.setPen(QPen(QColor(color), s * .055))
        p.drawPath(eye)
    else:
        p.drawLine(QPointF(x + s * .37, y + s * .37), QPointF(x + s * .63, y + s * .63))
        p.drawLine(QPointF(x + s * .63, y + s * .37), QPointF(x + s * .37, y + s * .63))


def shield_icon(color, size=64, mode="protected"):
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.fillPath(_shield_path(0, 0, size), QColor(color))
    _glyph(p, mode, 0, 0, size)
    p.end()
    return QIcon(pm)


def nav_icon(kind, color, size=40):
    """Line icons for the sidebar."""
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    s = size
    pen = QPen(QColor(color), s * .075, cap=Qt.RoundCap, join=Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    if kind == "dashboard":
        for dx, dy in ((0, 0), (.42, 0), (0, .42), (.42, .42)):
            p.drawRoundedRect(QRectF(s * (.14 + dx), s * (.14 + dy), s * .3, s * .3), s * .05, s * .05)
    elif kind == "threats":
        path = QPainterPath()
        path.moveTo(s * .5, s * .14)
        path.lineTo(s * .88, s * .84)
        path.lineTo(s * .12, s * .84)
        path.closeSubpath()
        p.drawPath(path)
        p.drawLine(QPointF(s * .5, s * .4), QPointF(s * .5, s * .6))
        p.drawPoint(QPointF(s * .5, s * .72))
    elif kind == "protection":
        p.drawPath(_shield_path(s * .1, s * .08, s * .8))
        p.drawPolyline(QPointF(s * .37, s * .5), QPointF(s * .47, s * .6), QPointF(s * .64, s * .4))
    elif kind == "blocks":
        p.drawEllipse(QRectF(s * .16, s * .16, s * .68, s * .68))
        p.drawLine(QPointF(s * .28, s * .72), QPointF(s * .72, s * .28))
    elif kind == "network":
        pts = [QPointF(s * .5, s * .2), QPointF(s * .2, s * .78), QPointF(s * .8, s * .78)]
        for a in pts[1:]:
            p.drawLine(pts[0], a)
        p.drawLine(pts[1], pts[2])
        p.setBrush(QColor(color))
        for a in pts:
            p.drawEllipse(a, s * .08, s * .08)
    elif kind == "dns":
        p.drawEllipse(QRectF(s * .14, s * .14, s * .72, s * .72))
        p.drawEllipse(QRectF(s * .34, s * .14, s * .32, s * .72))
        p.drawLine(QPointF(s * .14, s * .5), QPointF(s * .86, s * .5))
    elif kind == "tools":
        p.drawRoundedRect(QRectF(s * .12, s * .2, s * .76, s * .6), s * .08, s * .08)
        p.drawPolyline(QPointF(s * .26, s * .4), QPointF(s * .38, s * .5), QPointF(s * .26, s * .6))
        p.drawLine(QPointF(s * .46, s * .62), QPointF(s * .64, s * .62))
    p.end()
    return QIcon(pm)


def duration(seconds):
    m = int(seconds // 60)
    d, h, m = m // 1440, m // 60 % 24, m % 60
    return f"{d} d {h} h" if d else f"{h} h {m} min" if h else f"{m} min"


def ago(t):
    d = max(0, time.time() - t)
    if d < 60:
        return f"{int(d)} s ago"
    if d < 3600:
        return f"{int(d / 60)} min ago"
    if d < 86400:
        return f"{int(d / 3600)} h ago"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t))


def label(text="", obj=None, wrap=False, muted=False, select=False):
    w = QLabel(text)
    if obj:
        w.setObjectName(obj)
    if muted:
        w.setObjectName("muted")
    w.setWordWrap(wrap)
    if select:
        w.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return w


def panel(obj="panel"):
    f = QFrame()
    f.setObjectName(obj)
    return f


def table(cols, stretch=None):
    t = QTableWidget(0, len(cols))
    t.setHorizontalHeaderLabels(cols)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setAlternatingRowColors(True)
    t.setShowGrid(False)
    h = t.horizontalHeader()
    for i in range(len(cols)):
        h.setSectionResizeMode(i, QHeaderView.Stretch if stretch in (None, i)
                               else QHeaderView.ResizeToContents)
    return t


# ---------------------------------------------------------------- backend --
class Backend:
    """Reads service state and events; runs commands."""

    def __init__(self):
        self.cfg = load_config()
        jl = self.cfg.get("json_log")
        if jl and Path(jl).exists():
            self.tail = status.LogTail(jl, status.parse_json)
            self.log_path = jl
        else:
            self.log_path = self.cfg.get("log_file") or "/var/log/languard.log"
            self.tail = status.LogTail(self.log_path)
        self.events = deque(maxlen=MAX_EVENTS)

    def service_state(self):
        try:
            return subprocess.run(["systemctl", "is-active", "languard"],
                                  capture_output=True, text=True,
                                  timeout=3).stdout.strip() or "unknown"
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"

    def poll_events(self):
        new = self.tail.read()
        self.events.extend(new)
        return new

    def log_readable(self):
        return os.access(self.log_path, os.R_OK)

    def config(self):
        try:
            return load_config()
        except (OSError, SystemExit, ValueError):
            return self.cfg

    def local_dns(self):
        """Your local encrypted resolver (read-only, never changed)."""
        try:
            from languard_core import localdns
            info = localdns.inspect()
            info["advice"] = localdns.advice(info) if info.get("leak_risk") else ""
            return info
        except Exception as e:
            return {"resolver": None, "error": str(e), "listen": [], "leak_risk": []}

    def privileged(self, *args):
        """argv to run `languard args` as root (pkexec unless we are root).
        Commands that lower protection use the strict entry point."""
        prog = LANGUARD_STRICT if tamper.weakens(list(args)) else LANGUARD
        if os.geteuid() == 0:
            return [sys.executable, prog, *args]
        if shutil.which("pkexec"):
            return ["pkexec", prog, *args]
        return None

    def plain(self, *args):
        """argv to run `languard args` as you (read-only commands)."""
        script = LANGUARD if Path(LANGUARD).exists() else \
            str(Path(__file__).resolve().parent / "languard.py")
        return [sys.executable, script, *args]


# ---------------------------------------------------------------- widgets --
class StatusShield(QWidget):
    """The big shield in the dashboard hero, with a soft glow."""

    def __init__(self, size=112):
        super().__init__()
        self.mode, self.color = "protected", COLORS["ok"]
        self.setFixedSize(size, size)

    def set_mode(self, mode, color):
        self.mode, self.color = mode, color
        self.update()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        s = self.width()
        c = QColor(self.color)
        g = QRadialGradient(QPointF(s / 2, s / 2), s / 2)
        c.setAlpha(70)
        g.setColorAt(0, c)
        c.setAlpha(0)
        g.setColorAt(1, c)
        p.setBrush(g)
        p.setPen(Qt.NoPen)
        p.drawEllipse(QRectF(0, 0, s, s))
        inner = s * .62
        x = y = (s - inner) / 2
        p.fillPath(_shield_path(x, y, inner), QColor(self.color))
        _glyph(p, self.mode, x, y, inner, COLORS["bg"])
        p.end()


class Card(QFrame):
    """A number with a caption and a colored accent."""

    def __init__(self, title, color):
        super().__init__()
        self.setObjectName("card")
        self.setStyleSheet(f"QFrame#card {{ border-left: 3px solid {color}; }}")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(2)
        self.value = QLabel("0")
        self.value.setStyleSheet(f"font-size: 26px; font-weight: 700; color: {color};")
        lay.addWidget(self.value)
        lay.addWidget(label(title, muted=True))

    def set(self, v):
        self.value.setText(str(v))


STATE_COLORS = {"Active": "ok", "Ready": "INFO", "Off": "off", "Attention": "WARNING",
                "Alert": "CRITICAL"}


class LayerTile(QFrame):
    """One protection layer on the dashboard: name, state chip, one line."""

    def __init__(self, icon, title):
        super().__init__()
        self.setObjectName("tile")
        lay = QGridLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setHorizontalSpacing(10)
        ic = QLabel()
        ic.setPixmap(nav_icon(icon, COLORS["muted"]).pixmap(22, 22))
        lay.addWidget(ic, 0, 0, Qt.AlignTop)
        t = QLabel(title)
        t.setStyleSheet("font-weight: 600;")
        lay.addWidget(t, 0, 1)
        self.chip = QLabel()
        lay.addWidget(self.chip, 0, 2, Qt.AlignRight)
        self.detail = label("", wrap=True, muted=True)
        lay.addWidget(self.detail, 1, 1, 1, 2)
        lay.setColumnStretch(1, 1)
        self.state = None

    def set(self, state, detail):
        self.state = state
        c = COLORS[STATE_COLORS[state]]
        self.chip.setText(state.upper())
        self.chip.setStyleSheet(
            f"color: {c}; border: 1px solid {c}; border-radius: 9px; padding: 1px 8px;"
            f" font-size: 10px; font-weight: 700;")
        self.detail.setText(detail)


class Timeline(QWidget):
    """Stacked bars of threats per time bucket, with action ticks."""

    RANGES = {"Last hour": (3600, 60), "Last 6 hours": (6 * 3600, 600),
              "Last 24 hours": (86400, 1800), "Last 7 days": (7 * 86400, 6 * 3600)}

    def __init__(self):
        super().__init__()
        self.events = []
        self.span, self.bucket = self.RANGES["Last 24 hours"]
        self.setMinimumHeight(190)
        self.setMouseTracking(True)
        self._hover = None

    def set_range(self, name):
        self.span, self.bucket = self.RANGES[name]
        self.update()

    def set_events(self, events):
        self.events = events
        self.update()

    def _buckets(self):
        now = time.time()
        n = int(self.span / self.bucket)
        start = now - n * self.bucket
        crit, warn, act = [0] * n, [0] * n, [0] * n
        for e in self.events:
            i = int((e["ts"] - start) // self.bucket)
            if not 0 <= i < n:
                continue
            if e["kind"] == "action":
                act[i] += 1
            elif e["kind"] == "threat":
                if e["level"] == "CRITICAL":
                    crit[i] += 1
                elif e["level"] == "WARNING":
                    warn[i] += 1
        return start, n, crit, warn, act

    def mouseMoveEvent(self, ev):
        self._hover = ev.pos().x()
        self.update()

    def leaveEvent(self, ev):
        self._hover = None
        self.update()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = self.rect().adjusted(40, 10, -12, -28)
        start, n, crit, warn, act = self._buckets()
        top = max([c + w for c, w in zip(crit, warn)] + [4])
        f = p.font()
        if f.pointSizeF() > 0:
            f.setPointSizeF(f.pointSizeF() * .85)
        else:
            f.setPixelSize(max(9, int(f.pixelSize() * .85)))
        p.setFont(f)
        for k in range(5):                       # grid + y labels
            y = r.bottom() - r.height() * k / 4
            p.setPen(QPen(QColor(COLORS["border"]), 1, Qt.DotLine))
            p.drawLine(r.left(), int(y), r.right(), int(y))
            p.setPen(QColor(COLORS["muted"]))
            p.drawText(QRectF(0, y - 8, 34, 16), Qt.AlignRight | Qt.AlignVCenter,
                       str(round(top * k / 4)))
        bw = r.width() / n
        hover_i = None
        if self._hover is not None and r.left() <= self._hover <= r.right():
            hover_i = int((self._hover - r.left()) // bw)
        p.setPen(Qt.NoPen)
        for i in range(n):
            x = r.left() + i * bw
            w = max(1.0, bw - 2)
            hw = r.height() * warn[i] / top
            hc = r.height() * crit[i] / top
            if i == hover_i:
                p.fillRect(QRectF(x, r.top(), bw, r.height()), QColor(255, 255, 255, 14))
            p.setBrush(QColor(COLORS["WARNING"]))
            if hw:
                p.drawRoundedRect(QRectF(x + 1, r.bottom() - hw, w, hw), 1.5, 1.5)
            p.setBrush(QColor(COLORS["CRITICAL"]))
            if hc:
                p.drawRoundedRect(QRectF(x + 1, r.bottom() - hw - hc, w, hc), 1.5, 1.5)
            if act[i]:
                p.setBrush(QColor(COLORS["action"]))
                p.drawEllipse(QRectF(x + bw / 2 - 3, r.bottom() + 5, 6, 6))
        p.setPen(QColor(COLORS["muted"]))           # x labels
        fmt = "%H:%M" if self.span <= 86400 else "%a %H:%M"
        for k in range(5):
            t = start + self.span * k / 4
            x = r.left() + r.width() * k / 4
            align = Qt.AlignLeft if k == 0 else Qt.AlignRight if k == 4 else Qt.AlignHCenter
            rect = QRectF(x - (0 if k == 0 else 120 if k == 4 else 60), r.bottom() + 12, 120, 16)
            p.drawText(rect, align, time.strftime(fmt, time.localtime(t)))
        if hover_i is not None:                       # tooltip
            t0 = start + hover_i * self.bucket
            txt = (f"{time.strftime('%H:%M', time.localtime(t0))}  "
                   f"critical {crit[hover_i]}  warning {warn[hover_i]}  "
                   f"actions {act[hover_i]}")
            fm = p.fontMetrics()
            tw = fm.horizontalAdvance(txt) + 16
            tx = min(max(self._hover - tw / 2, r.left()), r.right() - tw)
            box = QRectF(tx, r.top(), tw, 22)
            p.setBrush(QColor(COLORS["panel2"]))
            p.setPen(QColor(COLORS["border"]))
            p.drawRoundedRect(box, 4, 4)
            p.setPen(QColor(COLORS["text"]))
            p.drawText(box, Qt.AlignCenter, txt)
        p.end()


class TypeBars(QWidget):
    """Horizontal bars: threats per attack type."""

    def __init__(self):
        super().__init__()
        self.counts = []
        self.setMinimumHeight(150)

    def set_counts(self, counts):
        self.counts = counts[:8]
        self.setMinimumHeight(max(150, 26 * len(self.counts) + 10))
        self.update()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        if not self.counts:
            p.setPen(QColor(COLORS["muted"]))
            p.drawText(self.rect(), Qt.AlignCenter, "No threats in this period")
            return
        top = max(c for _, c, _ in self.counts)
        label_w = 180
        y = 6
        p.setPen(Qt.NoPen)
        for name, count, crit in self.counts:
            p.setPen(QColor(COLORS["text"]))
            p.drawText(QRectF(0, y, label_w - 10, 20), Qt.AlignRight | Qt.AlignVCenter, name)
            p.setPen(Qt.NoPen)
            full = max(4, (self.width() - label_w - 50) * count / top)
            cw = full * crit / count if count else 0
            p.setBrush(QColor(COLORS["panel2"]))
            p.drawRoundedRect(QRectF(label_w, y + 3, self.width() - label_w - 50, 14), 7, 7)
            p.setBrush(QColor(COLORS["WARNING"]))
            p.drawRoundedRect(QRectF(label_w, y + 3, full, 14), 7, 7)
            if cw:
                p.setBrush(QColor(COLORS["CRITICAL"]))
                p.drawRoundedRect(QRectF(label_w, y + 3, cw, 14), 7, 7)
            p.setPen(QColor(COLORS["muted"]))
            p.drawText(QRectF(self.width() - 44, y, 44, 20), Qt.AlignVCenter, str(count))
            y += 26
        p.end()


class Switch(QCheckBox):
    """A toggle switch."""

    def sizeHint(self):
        return QSize(46, 26)

    def hitButton(self, pos):
        return self.rect().contains(pos)

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        on = self.isChecked()
        track = QColor(COLORS["ok"] if on else COLORS["off"])
        if not self.isEnabled():
            track.setAlpha(110)
        p.setBrush(track)
        p.setPen(Qt.NoPen)
        p.drawRoundedRect(QRectF(0, 2, 46, 22), 11, 11)
        p.setBrush(QColor("white"))
        p.drawEllipse(QRectF(26 if on else 4, 5, 16, 16))
        p.end()


class EventTable(QTableWidget):
    COLS = ("Time", "Severity", "Type", "What happened")

    def __init__(self):
        super().__init__(0, len(self.COLS))
        self.setHorizontalHeaderLabels(self.COLS)
        self.verticalHeader().setVisible(False)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setShowGrid(False)
        self.setWordWrap(False)
        h = self.horizontalHeader()
        for i in range(3):
            h.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(3, QHeaderView.Stretch)
        self.rows = []

    def set_events(self, events):
        self.rows = events
        self.setUpdatesEnabled(False)
        self.setRowCount(len(events))
        for i, e in enumerate(events):
            t = QTableWidgetItem(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["ts"])))
            text = "ACTION" if e["kind"] == "action" else e["level"]
            sev = QTableWidgetItem(f"●  {text}")
            sev.setForeground(QBrush(QColor(COLORS["action" if e["kind"] == "action" else e["level"]])))
            f = sev.font()
            f.setBold(True)
            sev.setFont(f)
            self.setItem(i, 0, t)
            self.setItem(i, 1, sev)
            self.setItem(i, 2, QTableWidgetItem(category(e["module"])))
            msg = QTableWidgetItem(e["msg"])
            msg.setToolTip(e["msg"])
            self.setItem(i, 3, msg)
        self.setUpdatesEnabled(True)


class ResponseRow(QFrame):
    """A response on the Protection page: title, explanation, switch."""

    def __init__(self, key, title, text):
        super().__init__()
        self.key = key
        self.setObjectName("row")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        col = QVBoxLayout()
        col.setSpacing(2)
        self.title = QLabel(title)
        self.title.setStyleSheet("font-weight: 600;")
        col.addWidget(self.title)
        col.addWidget(label(text, wrap=True, muted=True))
        lay.addLayout(col, 1)
        self.switch = Switch()
        self.switch.setToolTip(f"protect.{key}")
        lay.addWidget(self.switch, 0, Qt.AlignVCenter)


# ------------------------------------------------------------ main window --
PAGES = (("dashboard", "Dashboard"), ("threats", "Threats"),
         ("protection", "Protection"), ("blocks", "Blocks and pins"),
         ("network", "Network"), ("dns", "Encrypted DNS"), ("tools", "Tools"))


class MainWindow(QMainWindow):
    refreshed = pyqtSignal()
    probed = pyqtSignal(str)

    def __init__(self, backend):
        super().__init__()
        self.b = backend
        self.status = None
        self.state = "unknown"
        self.proc = None
        self.pending = {}
        self.dns_info = None
        self._dns_at = 0
        self._primed = False
        self.setWindowTitle("LANGuard")
        self.resize(1280, 820)
        self.icons = {k: shield_icon(COLORS[c], mode=k) for k, c in
                      (("protected", "ok"), ("monitoring", "INFO"),
                       ("paused", "paused"), ("stopped", "CRITICAL"))}
        self.setWindowIcon(self.icons["protected"])

        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._sidebar())
        self.pages = QStackedWidget()
        self.pages.setObjectName("content")
        builders = {"dashboard": self._dashboard_page, "threats": self._threats_page,
                    "protection": self._protection_page, "blocks": self._blocks_page,
                    "network": self._network_page, "dns": self._dns_page,
                    "tools": self._tools_page}
        for key, title in PAGES:
            self.pages.addWidget(self._page(title, builders[key]()))
        root.addWidget(self.pages, 1)
        self.setCentralWidget(central)
        self.statusBar().showMessage("Starting…")
        self._tray()
        self.probed.connect(self._probe_done)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(2000)
        QTimer.singleShot(0, self.refresh)

    # ---- frame ----
    def _sidebar(self):
        side = QFrame()
        side.setObjectName("sidebar")
        side.setFixedWidth(220)
        lay = QVBoxLayout(side)
        lay.setContentsMargins(14, 18, 14, 14)
        lay.setSpacing(4)
        brand = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(shield_icon(COLORS["accent"]).pixmap(30, 30))
        brand.addWidget(logo)
        name = QVBoxLayout()
        name.setSpacing(0)
        t = QLabel("LANGuard")
        t.setStyleSheet("font-size: 17px; font-weight: 700;")
        name.addWidget(t)
        name.addWidget(label("Intrusion prevention", muted=True))
        brand.addLayout(name, 1)
        lay.addLayout(brand)
        lay.addSpacing(18)
        self.nav = QButtonGroup(self)
        self.nav_buttons = {}
        for i, (key, title) in enumerate(PAGES):
            b = QPushButton(f"  {title}")
            b.setObjectName("nav")
            b.setCheckable(True)
            b.setIcon(nav_icon(key, COLORS["muted"]))
            b.setIconSize(QSize(18, 18))
            b.clicked.connect(lambda _=False, n=i: self.go(n))
            self.nav.addButton(b, i)
            self.nav_buttons[key] = b
            lay.addWidget(b)
        self.nav_buttons["dashboard"].setChecked(True)
        lay.addStretch()
        box = panel("sidestate")
        bl = QVBoxLayout(box)
        bl.setContentsMargins(12, 10, 12, 10)
        self.side_state = QLabel("…")
        self.side_state.setStyleSheet("font-weight: 600;")
        bl.addWidget(self.side_state)
        self.side_detail = label("", wrap=True, muted=True)
        bl.addWidget(self.side_detail)
        lay.addWidget(box)
        lay.addWidget(label(f"Version {__version__}", muted=True))
        return side

    def _page(self, title, body):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(26, 20, 26, 14)
        lay.setSpacing(14)
        h = QLabel(title)
        h.setObjectName("pagetitle")
        lay.addWidget(h)
        lay.addWidget(body, 1)
        return w

    def go(self, index):
        self.pages.setCurrentIndex(index)
        self.nav.button(index).setChecked(True)
        if PAGES[index][0] == "dns":
            self._update_dns(force=True)

    def _scroll(self, inner):
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        sa.setFrameShape(QFrame.NoFrame)
        sa.setWidget(inner)
        return sa

    def _section(self, text):
        return label(text, "section")

    # ---- dashboard ----
    def _dashboard_page(self):
        inner = QWidget()
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(14)
        lay.addWidget(self._hero())
        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.c_threats = Card("Threats, last 24 h", COLORS["WARNING"])
        self.c_crit = Card("Critical, last 24 h", COLORS["CRITICAL"])
        self.c_actions = Card("Attacks blocked, last 24 h", COLORS["action"])
        self.c_isolated = Card("Devices isolated now", COLORS["INFO"])
        for c in (self.c_threats, self.c_crit, self.c_actions, self.c_isolated):
            cards.addWidget(c)
        lay.addLayout(cards)

        lay.addWidget(self._section("Protection layers"))
        grid = QGridLayout()
        grid.setSpacing(10)
        self.layers = {}
        for i, (key, icon, title) in enumerate((
                ("router", "network", "Router and ARP"),
                ("isolation", "blocks", "Attacker isolation"),
                ("https", "protection", "HTTPS guard"),
                ("ipv6", "network", "IPv6 router guard"),
                ("names", "threats", "Name poisoning shield"),
                ("dns", "dns", "Encrypted DNS"),
                ("trust", "dashboard", "Network trust"),
                ("evidence", "tools", "Evidence capture"),
                ("identity", "network", "Router identity"),
                ("l2pins", "protection", "Rogue DHCP / RA shield"),
                ("sensor", "threats", "Sensor health"),
                ("tamper", "protection", "Tamper protection"))):
            t = LayerTile(icon, title)
            self.layers[key] = t
            grid.addWidget(t, i // 4, i % 4)
        for c in range(4):
            grid.setColumnStretch(c, 1)
        lay.addLayout(grid)

        chart = panel()
        cl = QVBoxLayout(chart)
        cl.setContentsMargins(16, 12, 16, 12)
        head = QHBoxLayout()
        head.addWidget(self._section("Threat activity"))
        legend = QLabel(f"<span style='color:{COLORS['CRITICAL']}'>■</span> critical  "
                        f"<span style='color:{COLORS['WARNING']}'>■</span> warning  "
                        f"<span style='color:{COLORS['action']}'>●</span> blocked")
        legend.setObjectName("muted")
        head.addWidget(legend)
        head.addStretch()
        self.range_box = QComboBox()
        self.range_box.addItems(list(Timeline.RANGES))
        self.range_box.setCurrentText("Last 24 hours")
        self.range_box.currentTextChanged.connect(self._range_changed)
        head.addWidget(self.range_box)
        cl.addLayout(head)
        self.timeline = Timeline()
        cl.addWidget(self.timeline)
        lay.addWidget(chart)

        row = QHBoxLayout()
        row.setSpacing(12)
        p1 = panel()
        l1 = QVBoxLayout(p1)
        l1.setContentsMargins(16, 12, 16, 12)
        l1.addWidget(self._section("Threats by type"))
        self.typebars = TypeBars()
        l1.addWidget(self.typebars, 1)
        p2 = panel()
        l2 = QVBoxLayout(p2)
        l2.setContentsMargins(16, 12, 16, 12)
        l2.addWidget(self._section("Latest critical alerts"))
        self.latest = EventTable()
        self.latest.hideColumn(2)
        self.latest.setMinimumHeight(200)
        l2.addWidget(self.latest, 1)
        row.addWidget(p1, 1)
        row.addWidget(p2, 1)
        lay.addLayout(row)
        return self._scroll(inner)

    def _hero(self):
        box = panel("hero")
        lay = QHBoxLayout(box)
        lay.setContentsMargins(18, 14, 22, 14)
        lay.setSpacing(16)
        self.shield = StatusShield()
        lay.addWidget(self.shield)
        col = QVBoxLayout()
        col.setSpacing(4)
        col.addStretch()
        self.headline = QLabel("…")
        self.headline.setObjectName("headline")
        self.subline = label("", wrap=True, muted=True, select=True)
        self.hero_note = label("", wrap=True)
        col.addWidget(self.headline)
        col.addWidget(self.subline)
        col.addWidget(self.hero_note)
        col.addStretch()
        lay.addLayout(col, 1)

        right = QVBoxLayout()
        right.setSpacing(8)
        row = QHBoxLayout()
        row.addStretch()
        lbl = QLabel("Active protection")
        lbl.setStyleSheet("font-weight: 600;")
        row.addWidget(lbl)
        self.protect_switch = Switch()
        self.protect_switch.setToolTip("Block attacks, not only report them: pin the "
                                       "router, isolate attackers, HTTPS guard, …")
        self.protect_switch.clicked.connect(self.toggle_protect)
        row.addWidget(self.protect_switch)
        right.addLayout(row)
        self.protect_hint = label("", muted=True)
        right.addWidget(self.protect_hint, 0, Qt.AlignRight)
        btns = QHBoxLayout()
        btns.addStretch()
        self.selftest_btn = QPushButton("Run self-test")
        self.selftest_btn.clicked.connect(self.run_selftest)
        btns.addWidget(self.selftest_btn)
        self.run_btn = QPushButton("Resume")
        self.run_btn.setObjectName("primary")
        self.run_btn.clicked.connect(lambda: self.run_priv(["resume"], "Resuming protection"))
        self.pause_btn = QToolButton()
        self.pause_btn.setText("Pause")
        self.pause_btn.setPopupMode(QToolButton.InstantPopup)
        menu = QMenu(self)
        for text, minutes in (("15 minutes", 15), ("1 hour", 60),
                              ("8 hours", 480), ("Until I resume", 525600)):
            a = menu.addAction(text)
            a.triggered.connect(lambda _=False, m=minutes, t=text:
                                self.run_priv(["pause", str(m)], f"Pausing protection ({t.lower()})"))
        self.pause_btn.setMenu(menu)
        btns.addWidget(self.run_btn)
        btns.addWidget(self.pause_btn)
        right.addLayout(btns)
        lay.addLayout(right)
        return box

    # ---- threats ----
    def _threats_page(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        bar = QHBoxLayout()
        self.f_level = QComboBox()
        self.f_level.addItems(["All severities", "Critical", "Warning", "Info"])
        self.f_kind = QComboBox()
        self.f_kind.addItems(["Threats and actions", "Threats only", "Actions only", "Everything"])
        self.f_type = QComboBox()
        self.f_type.addItem("All types")
        self.f_search = QLineEdit()
        self.f_search.setPlaceholderText("Search (IP, MAC, text)…")
        self.f_search.setClearButtonEnabled(True)
        for wd in (self.f_level, self.f_kind, self.f_type):
            wd.currentIndexChanged.connect(self._fill_table)
            bar.addWidget(wd)
        self.f_search.textChanged.connect(self._fill_table)
        bar.addWidget(self.f_search, 1)
        lay.addLayout(bar)
        split = QSplitter(Qt.Vertical)
        self.table = EventTable()
        self.table.itemSelectionChanged.connect(self._show_detail)
        split.addWidget(self.table)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("Select an alert to see the full message.")
        split.addWidget(self.detail)
        split.setSizes([520, 140])
        lay.addWidget(split, 1)
        return w

    # ---- protection ----
    def _protection_page(self):
        inner = QWidget()
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(10)
        self.protect_banner = label("", "banner", wrap=True)
        lay.addWidget(self.protect_banner)
        bar = QHBoxLayout()
        bar.addWidget(label("Choose how LANGuard answers each attack. Every action can "
                            "be undone on the Blocks and pins page. LANGuard never "
                            "changes your DNS settings.", wrap=True, muted=True), 1)
        self.pending_lbl = label("", muted=True)
        bar.addWidget(self.pending_lbl)
        self.revert_btn = QPushButton("Revert")
        self.revert_btn.clicked.connect(self.revert_responses)
        self.apply_btn = QPushButton("Apply changes")
        self.apply_btn.setObjectName("primary")
        self.apply_btn.clicked.connect(self.apply_responses)
        bar.addWidget(self.revert_btn)
        bar.addWidget(self.apply_btn)
        lay.addLayout(bar)
        self.resp = {}
        for group, rows in RESPONSES:
            lay.addWidget(self._section(group))
            box = panel()
            bl = QVBoxLayout(box)
            bl.setContentsMargins(0, 0, 0, 0)
            bl.setSpacing(0)
            for key, title, text in rows:
                r = ResponseRow(key, title, text)
                r.switch.clicked.connect(lambda on, k=key: self._response_clicked(k, on))
                self.resp[key] = r
                bl.addWidget(r)
            lay.addWidget(box)
        lay.addStretch()
        return self._scroll(inner)

    # ---- blocks ----
    def _blocks_page(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)
        self.inforce_box = panel()
        self.inforce = QGridLayout(self.inforce_box)
        self.inforce.setContentsMargins(16, 12, 16, 12)
        self.inforce.setHorizontalSpacing(24)
        lay.addWidget(self._section("In force now"))
        lay.addWidget(self.inforce_box)

        row = QHBoxLayout()
        row.addWidget(self._section("Blocked devices and addresses"))
        row.addStretch()
        self.unblock_btn = QPushButton("Unblock selected")
        self.unblock_btn.clicked.connect(self.unblock_selected)
        self.unpin_btn = QPushButton("Remove router pins")
        self.unpin_btn.clicked.connect(lambda: self.run_priv(["protect", "--unpin"],
                                                             "Removing router pins"))
        self.undo_btn = QPushButton("Undo all actions")
        self.undo_btn.setObjectName("danger")
        self.undo_btn.clicked.connect(self.undo_all)
        for b_ in (self.unblock_btn, self.unpin_btn, self.undo_btn):
            row.addWidget(b_)
        lay.addLayout(row)
        self.blocked = table(("Address", "Kind", "Why", "Blocked", "Expires"), stretch=2)
        self.blocked.setMinimumHeight(140)
        self.blocked.setMaximumHeight(220)
        lay.addWidget(self.blocked)
        lay.addWidget(self._section("Action history"))
        self.history = EventTable()
        lay.addWidget(self.history, 1)
        return w

    # ---- network ----
    def _network_page(self):
        inner = QWidget()
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(10)
        top = QHBoxLayout()
        top.setSpacing(12)
        info = panel()
        g = QGridLayout(info)
        g.setContentsMargins(16, 12, 16, 12)
        g.addWidget(self._section("This connection"), 0, 0, 1, 2)
        self.net_fields = {}
        for i, (k, t) in enumerate((("iface", "Interface"), ("ip", "Your address"),
                                    ("mac", "Your MAC"), ("gateway", "Router"),
                                    ("router_mac", "Router MAC"),
                                    ("verified", "Router verified"),
                                    ("network", "Network ID"), ("pin6", "IPv6 router"),
                                    ("identity", "Router identity"),
                                    ("wifi", "Wi-Fi access point"))):
            g.addWidget(label(t, muted=True), i + 1, 0)
            v = label("-", select=True)
            g.addWidget(v, i + 1, 1)
            self.net_fields[k] = v
        g.setColumnStretch(1, 1)
        top.addWidget(info, 1)

        trust = panel()
        tl = QVBoxLayout(trust)
        tl.setContentsMargins(16, 12, 16, 12)
        tl.addWidget(self._section("Network trust"))
        self.net_kind = label("", wrap=True)
        tl.addWidget(self.net_kind)
        tl.addWidget(label("Public: LLMNR off, ICMP redirects and rogue IPv6 routers ignored from the "
                           "start, before any attack. Home: put back when you "
                           "return. DNS servers are never changed.", wrap=True, muted=True))
        br = QHBoxLayout()
        self.net_home = QPushButton("Home")
        self.net_public = QPushButton("Public")
        self.net_unmark = QPushButton("Not marked")
        for b_, flag, text in ((self.net_home, "--home", "home"),
                               (self.net_public, "--public", "public"),
                               (self.net_unmark, "--unmark", "not marked")):
            b_.setObjectName("segment")
            b_.setCheckable(True)
            b_.clicked.connect(lambda _=False, f=flag, t=text:
                               self.run_priv(["network", f], f"Marking this network {t}"))
            br.addWidget(b_)
        br.addStretch()
        tl.addLayout(br)
        tl.addStretch()
        top.addWidget(trust, 1)
        lay.addLayout(top)

        lay.addWidget(self._section("Pinned devices"))
        lay.addWidget(label("Pin a device you depend on (NAS, printer, server) to its real "
                            "MAC: LANGuard keeps a static entry and treats a different "
                            "MAC for it as spoofing. Leave the MAC empty to use the one "
                            "it has now, then check it against the device's label.",
                            wrap=True, muted=True))
        add = QHBoxLayout()
        self.pin_ip = QLineEdit()
        self.pin_ip.setPlaceholderText("IP address, e.g. 192.168.1.20")
        self.pin_mac = QLineEdit()
        self.pin_mac.setPlaceholderText("MAC (optional)")
        self.pin_add_btn = QPushButton("Pin device")
        self.pin_add_btn.setObjectName("primary")
        self.pin_add_btn.clicked.connect(self.pin_device)
        self.pin_remove_btn = QPushButton("Unpin selected")
        self.pin_remove_btn.clicked.connect(self.unpin_device)
        add.addWidget(self.pin_ip, 2)
        add.addWidget(self.pin_mac, 2)
        add.addWidget(self.pin_add_btn)
        add.addWidget(self.pin_remove_btn)
        lay.addLayout(add)
        self.pinned = table(("IP address", "Pinned MAC"))
        self.pinned.setSelectionMode(QAbstractItemView.SingleSelection)
        self.pinned.setMinimumHeight(160)
        lay.addWidget(self.pinned, 1)

        row = QHBoxLayout()
        row.addWidget(self._section("Devices seen on this network"))
        row.addStretch()
        self.pin_seen_btn = QPushButton("Pin selected")
        self.pin_seen_btn.clicked.connect(self.pin_seen)
        row.addWidget(self.pin_seen_btn)
        lay.addLayout(row)
        lay.addWidget(label("Pinning a device you rely on stops slow spoofing: a "
                            "different MAC for it is treated as an attack at once, "
                            "and it is never isolated if its MAC is forged.",
                            wrap=True, muted=True))
        self.seen = table(("IP address", "MAC", "Status"), stretch=1)
        self.seen.setSelectionMode(QAbstractItemView.SingleSelection)
        self.seen.setMinimumHeight(160)
        lay.addWidget(self.seen, 1)
        return self._scroll(inner)

    # ---- dns ----
    def _dns_page(self):
        inner = QWidget()
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(10)
        note = label("LANGuard never changes your DNS settings or your resolver's "
                     "configuration, and never restarts it. It only shows what it sees "
                     "and watches the answers for spoofing.", "banner_ok", wrap=True)
        lay.addWidget(note)
        card = panel("hero")
        cl = QHBoxLayout(card)
        cl.setContentsMargins(18, 14, 18, 14)
        self.dns_icon = QLabel()
        cl.addWidget(self.dns_icon)
        col = QVBoxLayout()
        self.dns_title = QLabel("…")
        self.dns_title.setObjectName("headline")
        self.dns_sub = label("", wrap=True, muted=True, select=True)
        col.addWidget(self.dns_title)
        col.addWidget(self.dns_sub)
        cl.addLayout(col, 1)
        bc = QVBoxLayout()
        self.dns_test_btn = QPushButton("Test the resolver")
        self.dns_test_btn.clicked.connect(self.probe_dns)
        self.dns_check_btn = QPushButton("Full DNS check")
        self.dns_check_btn.clicked.connect(
            lambda: self.run_tool(["dnscheck"], "DNS check", root=False))
        bc.addWidget(self.dns_test_btn)
        bc.addWidget(self.dns_check_btn)
        cl.addLayout(bc)
        lay.addWidget(card)

        det = panel()
        g = QGridLayout(det)
        g.setContentsMargins(16, 12, 16, 12)
        self.dns_fields = {}
        for i, (k, t) in enumerate((("listen", "Listening on"), ("chain", "System DNS goes to"),
                                    ("bootstrap", "Bootstrap resolvers"),
                                    ("config", "Configuration"), ("probe", "Last test"))):
            g.addWidget(label(t, muted=True), i, 0, Qt.AlignTop)
            v = label("-", wrap=True, select=True)
            g.addWidget(v, i, 1)
            self.dns_fields[k] = v
        g.setColumnStretch(1, 1)
        lay.addWidget(det)
        lay.addWidget(self._section("Leak check"))
        self.dns_leak = label("", wrap=True, select=True)
        lay.addWidget(self.dns_leak)
        self.dns_advice = label("", "code", wrap=True, select=True)
        lay.addWidget(self.dns_advice)

        lay.addWidget(self._section("Set up encrypted DNS yourself"))
        lay.addWidget(label("Recommendations with the terminal commands for this "
                            "distribution. LANGuard only shows them: you run them, and "
                            "every option lists how to undo it.", wrap=True, muted=True))
        self.guide_now = label("", wrap=True, select=True)
        lay.addWidget(self.guide_now)
        row = QHBoxLayout()
        self.guide_pick = QComboBox()
        self.guide_pick.currentIndexChanged.connect(self._show_guide_option)
        row.addWidget(self.guide_pick, 1)
        self.guide_copy = QPushButton("Copy commands")
        self.guide_copy.clicked.connect(self._copy_guide)
        row.addWidget(self.guide_copy)
        lay.addLayout(row)
        self.guide_about = label("", wrap=True, select=True)
        lay.addWidget(self.guide_about)
        self.guide_cmds = QPlainTextEdit()
        self.guide_cmds.setObjectName("console")
        self.guide_cmds.setReadOnly(True)
        self.guide_cmds.setMinimumHeight(300)
        lay.addWidget(self.guide_cmds)
        self.guide_notes = label("", wrap=True, muted=True)
        lay.addWidget(self.guide_notes)
        self.guide = None
        lay.addStretch()
        return self._scroll(inner)

    def _update_guide(self, info):
        try:
            from languard_core import dnsguide
            g = dnsguide.guide(info=info)
        except Exception as e:
            self.guide_now.setText(f"DNS guide unavailable: {e}")
            return None
        self.guide = g
        cur = g["current"]
        color = {"encrypted": COLORS["ok"], "plain": COLORS["WARNING"]}.get(
            cur["state"], COLORS["WARNING"])
        self.guide_now.setText(f"<b style='color:{color}'>Now:</b> {cur['text']}")
        keep = self.guide_pick.currentData()
        self.guide_pick.blockSignals(True)
        self.guide_pick.clear()
        for o in g["options"]:
            rec = o["key"] == cur.get("recommend")
            self.guide_pick.addItem(f"{o['title']}  ({o['protocol']})"
                                    + ("  - recommended" if rec else "")
                                    + ("" if o.get("available", True) else
                                       "  - not packaged here"), o["key"])
        keys = [o["key"] for o in g["options"]]
        want = keep if keep in keys else (cur.get("recommend") or keys[0])
        self.guide_pick.setCurrentIndex(keys.index(want))
        self.guide_pick.blockSignals(False)
        self._show_guide_option()
        self.guide_notes.setText("".join(f"<p>• {n}</p>" for n in g["notes"]))
        return cur

    def _show_guide_option(self, *_):
        if not self.guide:
            return
        from languard_core import dnsguide
        key = self.guide_pick.currentData()
        o = next((o for o in self.guide["options"] if o["key"] == key), None)
        if not o:
            return
        self.guide_about.setText(
            f"{o['summary']}<br><span style='color:{COLORS['ok']}'>+</span> {o['pros']}"
            f"<br><span style='color:{COLORS['WARNING']}'>−</span> {o['cons']}"
            f"<br><span style='color:{COLORS['muted']}'>Commands for "
            f"{self.guide['distribution']}</span>")
        self.guide_cmds.setPlainText(dnsguide.commands_text(o))

    def _copy_guide(self):
        QApplication.clipboard().setText(self.guide_cmds.toPlainText())
        self.statusBar().showMessage("Commands copied. LANGuard didn't run them.", 5000)

    # ---- tools ----
    def _tools_page(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)
        grid = QGridLayout()
        grid.setSpacing(10)
        self.tool_btns = {}
        for i, (key, title, text, button) in enumerate((
                ("selftest", "Self-test",
                 "Simulates ARP, DHCP, DNS, IPv6, LLMNR and SSL-stripping attacks against "
                 "a sandboxed copy and checks that each one is detected and blocked.",
                 "Run self-test"),
                ("audit", "Security audit",
                 "Firewall, exposed services, kernel network settings, SMB/NTLM and your "
                 "DNS chain. Read-only: fixes run only with your consent, in a terminal "
                 "(sudo languard audit --fix).", "Run audit"),
                ("evidence", "Evidence captures",
                 "Packets around each critical alert, saved as pcap files you can open in "
                 "Wireshark. Readable by root only.", "List captures"),
                ("hsts", "HSTS preload list",
                 "Sites browsers only reach over HTTPS. The HTTPS guard and the SSL "
                 "stripping detector use it.", "Update now"))):
            box = panel("tile")
            bl = QVBoxLayout(box)
            bl.setContentsMargins(14, 12, 14, 12)
            t = QLabel(title)
            t.setStyleSheet("font-weight: 600; font-size: 14px;")
            bl.addWidget(t)
            bl.addWidget(label(text, wrap=True, muted=True), 1)
            b_ = QPushButton(button)
            b_.clicked.connect(lambda _=False, k=key: self.run_named_tool(k))
            bl.addWidget(b_, 0, Qt.AlignLeft)
            self.tool_btns[key] = b_
            grid.addWidget(box, 0, i)
            grid.setColumnStretch(i, 1)
        lay.addLayout(grid)
        split = QSplitter(Qt.Vertical)
        self.audit = table(("Result", "Check", "Detail", "How to fix"), stretch=2)
        self.audit.setWordWrap(True)
        self.audit.hide()
        split.addWidget(self.audit)
        out = QWidget()
        ol = QVBoxLayout(out)
        ol.setContentsMargins(0, 0, 0, 0)
        hl = QHBoxLayout()
        hl.addWidget(self._section("Output"))
        hl.addStretch()
        self.tool_status = label("", muted=True)
        hl.addWidget(self.tool_status)
        ol.addLayout(hl)
        self.console = QPlainTextEdit()
        self.console.setObjectName("console")
        self.console.setReadOnly(True)
        self.console.setPlaceholderText("Results of the tools appear here.")
        ol.addWidget(self.console, 1)
        split.addWidget(out)
        lay.addWidget(split, 1)
        return w

    # ---- tray ----
    def _tray(self):
        self.tray = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(self.icons["protected"], self)
        m = QMenu()
        m.addAction("Open LANGuard", self.show_normal)
        m.addSeparator()
        m.addAction("Pause 15 minutes", lambda: self.run_priv(["pause", "15"], "Pausing protection"))
        m.addAction("Resume", lambda: self.run_priv(["resume"], "Resuming protection"))
        m.addSeparator()
        m.addAction("Quit", QApplication.instance().quit)
        self.tray.setContextMenu(m)
        self.tray.activated.connect(lambda r: self.show_normal()
                                    if r == QSystemTrayIcon.Trigger else None)
        self.tray.messageClicked.connect(self._open_threats)
        self.tray.show()

    def _open_threats(self):
        self.show_normal()
        self.go(1)

    def show_normal(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, ev):
        if self.tray and self.tray.isVisible():
            self.hide()
            ev.ignore()
        else:
            ev.accept()

    # ---- refresh ----
    def refresh(self):
        new = self.b.poll_events()
        self.state = self.b.service_state()
        st = status.read_status()
        fresh = bool(st and time.time() - st.get("updated", 0) < 30)
        self.status = st if fresh and self.state == "active" else None
        self._notify(new)
        self._update_header()
        self._update_cards()
        self._update_layers()
        self._update_overview()
        self._fill_table()
        self._update_protection()
        self._update_actions()
        self._update_network()
        self._update_dns()
        log = self.b.log_path if self.b.log_readable() else f"{self.b.log_path} (not readable)"
        self.statusBar().showMessage(
            f"LANGuard {__version__} · service {self.state} · alerts from {log} · "
            f"updated {time.strftime('%H:%M:%S')}")
        self.refreshed.emit()

    def _notify(self, new):
        """Desktop notification for new critical threats (not history)."""
        if self._primed and self.tray:
            crit = [e for e in new if e["level"] == "CRITICAL" and e["kind"] == "threat"]
            if crit:
                e = crit[-1]
                more = f" (+{len(crit) - 1} more)" if len(crit) > 1 else ""
                self.tray.showMessage(f"LANGuard: {category(e['module'])}{more}",
                                      e["msg"][:240], QSystemTrayIcon.Critical, 10000)
        self._primed = True

    def _mode(self):
        if self.state == "active" and self.status:
            return "protected" if self.status["protect"]["enabled"] else "monitoring"
        if status.read_pause():
            return "paused"
        return "stopped"

    def _protect_enabled(self):
        if self.status:
            return bool(self.status["protect"]["enabled"])
        return bool(self.b.config().get("protect", {}).get("enabled"))

    def _update_header(self):
        mode = self._mode()
        s = self.status
        text = {"protected": "Protected", "monitoring": "Monitoring (alerts only)",
                "paused": "Paused", "stopped": "Not running"}[mode]
        color = {"protected": COLORS["ok"], "monitoring": COLORS["INFO"],
                 "paused": COLORS["paused"], "stopped": COLORS["CRITICAL"]}[mode]
        self.headline.setText(text)
        self.headline.setStyleSheet(f"color: {color};")
        self.shield.set_mode(mode, color)
        self.setWindowIcon(self.icons[mode])
        self.side_state.setText(f"<span style='color:{color}'>●</span>  {text}")
        if self.tray:
            self.tray.setIcon(self.icons[mode])
            self.tray.setToolTip(f"LANGuard: {text}")
        note = ""
        if s:
            router = s.get("router_mac") or "unknown"
            mark = "verified" if s.get("router_verified") else "not verified yet"
            up = duration(time.time() - s["started"])
            self.subline.setText(
                f"{s['iface']} · {s.get('ip') or '-'} · router {s['gateway']} at {router} "
                f"({mark}) · running {up} · {len(s['modules'])} detectors")
            self.side_detail.setText(f"{s['iface']} · {s.get('network_kind') or 'unmarked'} "
                                     f"network\nup {up}")
            recent = [e for e in self._since(3600)
                      if e["kind"] == "threat" and e["level"] == "CRITICAL"]
            if recent:
                note = (f"<span style='color:{COLORS['CRITICAL']}'>{len(recent)} critical "
                        f"threat(s) in the last hour</span> · latest: {category(recent[-1]['module'])}")
            elif mode == "monitoring":
                note = "Attacks are reported but not blocked. Turn on active protection."
            else:
                note = f"<span style='color:{COLORS['ok']}'>No critical threats in the last hour</span>"
        elif mode == "paused":
            until = status.read_pause()
            when = "until you resume" if until - time.time() > 30 * 86400 else \
                "until " + time.strftime("%H:%M", time.localtime(until))
            self.subline.setText(f"Protection is paused {when}.")
            self.side_detail.setText(f"Paused {when}")
            note = "Your network isn't watched while paused."
        elif self.state == "active":
            self.subline.setText("Service running; waiting for its first status update…")
            self.side_detail.setText("Starting")
        else:
            self.subline.setText(f"The languard service is {self.state}. Press Resume to start it.")
            self.side_detail.setText(f"Service {self.state}")
            note = "Your network isn't protected."
        self.hero_note.setText(note)
        running = self.state == "active"
        self.run_btn.setText("Restart" if running else "Resume")
        self.run_btn.setVisible(not running)
        self.pause_btn.setEnabled(running)
        enabled = self._protect_enabled()
        self.protect_switch.blockSignals(True)
        self.protect_switch.setChecked(enabled)
        self.protect_switch.setEnabled(self.proc is None)
        self.protect_switch.blockSignals(False)
        if not running:
            self.protect_hint.setText("Takes effect when LANGuard runs")
        elif s and not s.get("router_verified") and enabled:
            self.protect_hint.setText("Waiting to verify your router before acting")
        else:
            self.protect_hint.setText("Off: attacks are only reported" if not enabled
                                      else "On: attacks are blocked")
        busy = self.proc is not None
        self.selftest_btn.setEnabled(not busy)

    def _since(self, seconds):
        cut = time.time() - seconds
        return [e for e in self.b.events if e["ts"] >= cut]

    def _update_cards(self):
        day = self._since(86400)
        threats = [e for e in day if e["kind"] == "threat" and e["level"] != "INFO"]
        self.c_threats.set(len(threats))
        self.c_crit.set(sum(1 for e in threats if e["level"] == "CRITICAL"))
        self.c_actions.set(sum(1 for e in day if e["kind"] == "action"))
        self.c_isolated.set(len(self.status["protect"]["blocked"]) if self.status else 0)

    def _settings(self):
        """Current response settings: the service's, else the config's."""
        if self.status:
            got = self.status["protect"].get("settings") or {}
        else:
            got = self.b.config().get("protect", {})
        return {k: bool(got.get(k, d)) for k, d in OPTIONS.items()}

    def _update_layers(self):
        s = self.status
        L = self.layers
        if not s:
            for t in L.values():
                t.set("Off", "LANGuard isn't running")
            return
        p = s["protect"]
        on = p["enabled"]
        opt = self._settings()

        def ready(key, active, detail_active, detail_ready):
            if not on or not opt.get(key, True):
                return ("Off", "Response switched off" if on else "Detection only")
            return ("Active", detail_active) if active else ("Ready", detail_ready)

        pin = p.get("pin")
        L["router"].set(*ready("pin_gateway", pin,
                               f"Router {pin['ip']} pinned to {pin['mac']}" if pin else "",
                               "Pins the router once it is verified"
                               if not s.get("router_verified") else "Router verified"))
        n = len(p.get("blocked") or {}) + len(p.get("blocked_ips") or {})
        L["isolation"].set(*ready("isolate", n, f"{n} blocked now",
                                  "Blocks a device the moment it attacks"))
        L["https"].set(*ready("https_guard", p.get("https_guard"),
                              "Upgrading plain HTTP" + (f" · HSTS list {s['hsts_sites']} sites"
                                                        if s.get("hsts_sites") else ""),
                              "Starts with the service"))
        v6 = p.get("pin6") or p.get("ipv6_lockdown")
        L["ipv6"].set(*ready("pin_router6", v6,
                             f"IPv6 router {p['pin6']['ip']} pinned" if p.get("pin6")
                             else "Router advertisements ignored",
                             "Watches router advertisements"))
        ll = p.get("llmnr_off")
        L["names"].set(*ready("llmnr_off", ll or p.get("redirects_off"),
                              "LLMNR off" + (" (public network)" if ll and ll.get("preventive") else "")
                              if ll else "ICMP redirects ignored",
                              "LLMNR, NBNS and WPAD watched"))
        dns = s.get("local_dns") or {}
        if dns.get("resolver"):
            risk = dns.get("leak_risk") or []
            L["dns"].set("Attention" if risk else "Active",
                         f"{dns.get('label')}: {risk[0]}" if risk else
                         f"{dns.get('label')} on {', '.join(dns.get('listen') or []) or 'loopback'}")
        else:
            L["dns"].set("Attention", "No local encrypted resolver; plain DNS is watched "
                                      "for spoofing")
        kind = s.get("network_kind")
        L["trust"].set("Active" if kind == "public" and on else "Ready" if kind else "Attention",
                       {"public": "Public network: hardened from the start",
                        "home": "Home network"}.get(kind, "Not marked: tell LANGuard on "
                                                          "the Network page"))
        L["evidence"].set("Active" if s.get("evidence") else "Ready",
                          f"{s['evidence']} capture(s) this session" if s.get("evidence")
                          else "Saves packets around critical alerts")
        rt = s.get("router_trust") or {}
        level = rt.get("level") or "unverified"
        L["identity"].set({"verified+key": "Active", "verified": "Active",
                           "doubtful": "Attention", "first contact": "Attention"
                           }.get(level, "Ready"),
                          {"verified+key": "MAC and HTTPS key match",
                           "verified": "MAC verified (no router key to check)",
                           "doubtful": "Possible evil twin: see Threats",
                           "first contact": "First visit: can't be verified yet"
                           }.get(level, "Verifying the router"))
        l2 = p.get("l2pins") or {}
        L["l2pins"].set(*ready("pin_dhcp", l2.get("dhcp") or l2.get("ra"),
                               "Only the verified router may answer DHCP"
                               + (" and IPv6 RA" if l2.get("ra") else ""),
                               "Pins DHCP and IPv6 router once verified"))
        sen = s.get("sensor") or {}
        st = sen.get("state") or "ok"
        L["sensor"].set("Active" if st == "ok" else "Attention",
                        f"{sen.get('pps', 0)} packets/s, no drops" if st == "ok" and sen
                        else "Watching for floods and drops" if st == "ok" else
                        {"overloaded": f"Kernel dropped {sen.get('drops', 0)} packets",
                         "flooded": f"Flood from {', '.join(sen.get('flooders') or ['?'])}",
                         "errors": f"{sen.get('errors', 0)} detector errors"}.get(st, st))
        lowered = [e for e in self.b.events if e.get("module") == "tamper"
                   and e["ts"] > time.time() - 86400]
        L["tamper"].set("Attention" if lowered else "Active",
                        f"Protection lowered {len(lowered)}x in 24 h" if lowered
                        else "Lowering protection asks for your password every time")

    def _range_changed(self, name):
        self.timeline.set_range(name)
        self._update_overview()

    def _update_overview(self):
        events = self._since(self.timeline.span)
        self.timeline.set_events(events)
        tally, crit = Counter(), Counter()
        for e in events:
            if e["kind"] == "threat" and e["level"] != "INFO":
                tally[category(e["module"])] += 1
                crit[category(e["module"])] += e["level"] == "CRITICAL"
        self.typebars.set_counts([(k, v, crit[k]) for k, v in tally.most_common()])
        latest = [e for e in reversed(self.b.events)
                  if e["level"] == "CRITICAL" and e["kind"] != "info"][:50]
        if [e["ts"] for e in latest] != [e["ts"] for e in self.latest.rows]:
            self.latest.set_events(latest)

    def _fill_table(self):
        types = sorted({category(e["module"]) for e in self.b.events})
        if types != [self.f_type.itemText(i) for i in range(1, self.f_type.count())]:
            cur = self.f_type.currentText()
            self.f_type.blockSignals(True)
            self.f_type.clear()
            self.f_type.addItems(["All types"] + types)
            self.f_type.setCurrentText(cur)
            self.f_type.blockSignals(False)
        lvl = self.f_level.currentText().upper()
        kind = self.f_kind.currentIndex()
        typ = self.f_type.currentText()
        q = self.f_search.text().strip().lower()
        rows = []
        for e in reversed(self.b.events):
            if lvl != "ALL SEVERITIES" and e["level"] != lvl:
                continue
            if kind == 0 and e["kind"] == "info":
                continue
            if kind == 1 and e["kind"] != "threat":
                continue
            if kind == 2 and e["kind"] != "action":
                continue
            if typ != "All types" and category(e["module"]) != typ:
                continue
            if q and q not in e["msg"].lower():
                continue
            rows.append(e)
            if len(rows) >= 2000:
                break
        key = [(e["ts"], e["msg"]) for e in rows[:3]] + [len(rows)]
        if key != getattr(self, "_table_key", None):
            self._table_key = key
            self.table.set_events(rows)

    def _show_detail(self):
        r = self.table.currentRow()
        if 0 <= r < len(self.table.rows):
            e = self.table.rows[r]
            extra = "".join(f"\n{k}: {v}" for k, v in (e.get("data") or {}).items())
            self.detail.setPlainText(
                f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e['ts']))}  "
                f"{e['level']}  {category(e['module'])} ({e['module']})\n\n{e['msg']}{extra}")

    # ---- protection page ----
    def _update_protection(self):
        cur = self._settings()
        for k in list(self.pending):
            if self.pending[k] == cur.get(k):
                del self.pending[k]
        for k, r in self.resp.items():
            want = self.pending.get(k, cur.get(k, False))
            r.switch.blockSignals(True)
            r.switch.setChecked(want)
            r.switch.setEnabled(self.proc is None)
            r.switch.blockSignals(False)
            r.title.setText(TITLES[k] + ("  •" if k in self.pending else ""))
        n = len(self.pending)
        self.pending_lbl.setText(f"{n} unsaved change(s)" if n else "")
        self.apply_btn.setEnabled(bool(n) and self.proc is None)
        self.revert_btn.setEnabled(bool(n))
        if not self._protect_enabled():
            self.protect_banner.setText("Active protection is off: LANGuard only reports "
                                        "attacks. These responses act once you turn it on "
                                        "(switch on the Dashboard).")
            self.protect_banner.show()
        else:
            self.protect_banner.hide()

    def _response_clicked(self, key, on):
        if key == "kill_switch" and on and QMessageBox.question(
                self, "Kill switch", "Disconnect this computer from the network when "
                "your router is confirmed to be impersonated?\n\nYou stay offline until "
                "you reconnect yourself.") != QMessageBox.Yes:
            self.resp[key].switch.setChecked(False)
            return
        self.pending[key] = on
        self._update_protection()

    def revert_responses(self):
        self.pending.clear()
        self._update_protection()

    def apply_responses(self):
        if not self.pending:
            return
        args = [f"{k}={'on' if v else 'off'}" for k, v in sorted(self.pending.items())]
        self.run_priv(["protect", "--set", *args], "Saving response settings",
                      done=self._applied)

    def _applied(self, code, out):
        if code == 0:
            self.pending.clear()
        self._default_done(code, out, "Saving response settings")

    # ---- blocks page ----
    def _update_actions(self):
        s = self.status
        items = []
        if not s:
            items.append(("Service", "not running, nothing is in force", "off"))
        else:
            p = s["protect"]
            if not p["enabled"]:
                items.append(("Active protection", "off: alerts only", "INFO"))
            pin = p.get("pin")
            items.append(("Router pin", f"{pin['ip']} → {pin['mac']}" if pin else "none",
                          "ok" if pin else "off"))
            pin6 = p.get("pin6")
            items.append(("IPv6 router pin", f"{pin6['ip']} → {pin6['mac']}" if pin6
                          else "none", "ok" if pin6 else "off"))
            lock = p.get("ipv6_lockdown")
            items.append(("IPv6 lockdown", f"RAs ignored on {lock['iface']}" if lock else "off",
                          "WARNING" if lock else "off"))
            items.append(("HTTPS guard", "upgrading plain HTTP" if p.get("https_guard")
                          else "off", "ok" if p.get("https_guard") else "off"))
            ll = p.get("llmnr_off")
            items.append(("LLMNR", ("off (public network)" if ll.get("preventive")
                                    else "off (after name poisoning)") if ll else "unchanged",
                          "ok" if ll else "off"))
            items.append(("ICMP redirects", "ignored" if p.get("redirects_off") else "unchanged",
                          "ok" if p.get("redirects_off") else "off"))
            pd = p.get("pinned_devices") or {}
            items.append(("Pinned devices", f"{len(pd)}" if pd else "none",
                          "ok" if pd else "off"))
            l2 = p.get("l2pins") or {}
            items.append(("DHCP / IPv6 router pins",
                          f"DHCP from {', '.join(l2.get('dhcp') or ['any'])}, RA from "
                          f"{', '.join(l2.get('ra') or ['any'])}" if l2 else "none",
                          "ok" if l2 and (l2.get("dhcp") or l2.get("ra")) else "off"))
            fu = p.get("framed_until") or 0
            if fu:
                items.append(("Isolation paused",
                              f"known devices were being framed; until "
                              f"{time.strftime('%H:%M', time.localtime(fu))}",
                              "WARNING"))
        while self.inforce.count():
            w = self.inforce.takeAt(0).widget()
            if w:
                w.deleteLater()
        for i, (k, v, c) in enumerate(items):
            r, col = divmod(i, 2)
            self.inforce.addWidget(QLabel(f"<span style='color:{COLORS[c]}'>●</span>  "
                                          f"<b>{k}</b>"), r, col * 2)
            self.inforce.addWidget(label(v, muted=True, select=True), r, col * 2 + 1)
        self.inforce.setColumnStretch(1, 1)
        self.inforce.setColumnStretch(3, 1)

        pr = (s or {}).get("protect", {})
        blocked = [(a, "Device (MAC)", b) for a, b in sorted(pr.get("blocked", {}).items())] + \
            [(a, "Address (IP)", b) for a, b in sorted(pr.get("blocked_ips", {}).items())]
        self.blocked.setRowCount(len(blocked))
        for i, (addr, kind, b) in enumerate(blocked):
            left = max(0, int((b["until"] - time.time()) / 60))
            for j, v in enumerate((addr, kind, b.get("reason", "?").replace("_", " "),
                                   ago(b.get("since", b["until"])), f"in {left} min")):
                it = QTableWidgetItem(v)
                if j == 0:
                    it.setForeground(QBrush(QColor(COLORS["CRITICAL"])))
                self.blocked.setItem(i, j, it)
        busy = self.proc is not None
        self.unblock_btn.setEnabled(bool(blocked) and not busy)
        self.unpin_btn.setEnabled(bool(s and (pr.get("pin") or pr.get("pin6"))) and not busy)
        self.undo_btn.setEnabled(bool(s) and not busy)
        acts = [e for e in reversed(self.b.events) if e["kind"] == "action"][:1000]
        if [e["ts"] for e in acts[:3]] + [len(acts)] != getattr(self, "_act_key", None):
            self._act_key = [e["ts"] for e in acts[:3]] + [len(acts)]
            self.history.set_events(acts)

    # ---- network page ----
    def _update_network(self):
        s = self.status or {}
        p = s.get("protect", {})
        f = self.net_fields
        for k in ("iface", "ip", "mac", "gateway", "router_mac", "network"):
            f[k].setText(str(s.get(k) or "-"))
        f["verified"].setText(("yes" if s.get("router_verified") else "not yet") if s else "-")
        pin6 = p.get("pin6")
        f["pin6"].setText(f"{pin6['ip']} at {pin6['mac']} (pinned)" if pin6 else "-")
        rt = s.get("router_trust") or {}
        f["identity"].setText(f"{rt.get('level', '-')}: {rt.get('detail', '')}" if rt else "-")
        w = rt.get("wifi") or {}
        f["wifi"].setText(f"{w.get('ssid')} via {w.get('bssid')} "
                          f"({w.get('security') or 'open, no encryption'})" if w else
                          "not on Wi-Fi" if s else "-")
        kind = s.get("network_kind") if s else None
        self.net_kind.setText(
            {"home": "This network is marked <b>home</b>.",
             "public": "This network is treated as <b>public</b>: hardened from the start."
             }.get(kind, "This network isn't marked yet." if s else
                   "Start LANGuard to mark this network."))
        busy = self.proc is not None
        for b_, k in ((self.net_home, "home"), (self.net_public, "public"),
                      (self.net_unmark, None)):
            b_.setChecked(bool(s) and kind == k)
            b_.setEnabled(bool(s) and not busy)
        pd = sorted((p.get("pinned_devices") or {}).items())
        if pd != getattr(self, "_pinned_key", None):
            self._pinned_key = pd
            self.pinned.setRowCount(len(pd))
            for i, (ip, mac) in enumerate(pd):
                self.pinned.setItem(i, 0, QTableWidgetItem(ip))
                self.pinned.setItem(i, 1, QTableWidgetItem(mac))
        self.pin_add_btn.setEnabled(bool(s) and not busy)
        self.pin_remove_btn.setEnabled(bool(pd) and not busy)
        pinned = dict(pd)
        gw = (s.get("gateway"), s.get("router_mac"))
        seen = [tuple(x) for x in s.get("devices") or []]
        if seen != getattr(self, "_seen_key", None):
            self._seen_key = seen
            self.seen.setRowCount(len(seen))
            for i, (ip, mac) in enumerate(seen):
                st = ("router" if (ip, mac) == gw else
                      "pinned" if pinned.get(ip) == mac else
                      "pinned to another MAC!" if ip in pinned else "")
                for j, v in enumerate((ip, mac, st)):
                    it = QTableWidgetItem(v)
                    if st.endswith("!"):
                        it.setForeground(QBrush(QColor(COLORS["CRITICAL"])))
                    self.seen.setItem(i, j, it)
        self.pin_seen_btn.setEnabled(bool(seen) and not busy)

    def pin_seen(self):
        r = self.seen.currentRow()
        if r < 0:
            QMessageBox.information(self, "Pin device", "Select a device in the list first.")
            return
        ip, mac = self.seen.item(r, 0).text(), self.seen.item(r, 1).text()
        self.run_priv(["protect", "--pin-device", ip, mac], f"Pinning {ip}")

    def pin_device(self):
        ip = self.pin_ip.text().strip()
        mac = self.pin_mac.text().strip().lower().replace("-", ":")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            QMessageBox.warning(self, "Pin device", f"'{ip}' isn't an IP address.")
            return
        if mac and not MAC_RE.match(mac):
            QMessageBox.warning(self, "Pin device", f"'{mac}' isn't a MAC address "
                                "(like aa:bb:cc:dd:ee:ff).")
            return
        self.run_priv(["protect", "--pin-device", ip] + ([mac] if mac else []),
                      f"Pinning {ip}", done=self._pinned_done)

    def _pinned_done(self, code, out):
        if code == 0:
            self.pin_ip.clear()
            self.pin_mac.clear()
        self._default_done(code, out, "Pinning the device")

    def unpin_device(self):
        r = self.pinned.currentRow()
        if r < 0:
            QMessageBox.information(self, "Unpin", "Select a device in the list first.")
            return
        ip = self.pinned.item(r, 0).text()
        self.run_priv(["protect", "--unpin-device", ip], f"Unpinning {ip}")

    # ---- dns page ----
    def _update_dns(self, force=False):
        if not force and time.time() - self._dns_at < 30:
            return
        self._dns_at = time.time()
        info = self.b.local_dns()
        svc = (self.status or {}).get("local_dns") or {}
        if not info.get("resolver") and svc.get("resolver"):
            info.update({k: v for k, v in svc.items() if v})
            if info.get("leak_risk") and not info.get("advice"):
                from languard_core import localdns
                info["advice"] = localdns.advice(info)
        self.dns_info = info
        risk = info.get("leak_risk") or []
        if info.get("resolver"):
            self._update_guide(info)
            color = COLORS["WARNING"] if risk else COLORS["ok"]
            self.dns_title.setText(f"{info.get('label') or info['resolver']} is running")
            self.dns_sub.setText("Your DNS lookups are encrypted before they leave this "
                                 "computer." if not risk else
                                 "Encrypted resolver found, but some lookups may bypass it.")
        else:
            cur = self._update_guide(info) or {}
            if cur.get("label"):
                color = COLORS["ok"] if cur["state"] == "encrypted" else COLORS["WARNING"]
                self.dns_title.setText(f"{cur['label']} is on")
                self.dns_sub.setText("Your DNS lookups are encrypted by systemd-resolved."
                                     if cur["state"] == "encrypted" else cur["text"])
            else:
                color = COLORS["INFO"]
                self.dns_title.setText("No local encrypted resolver")
                self.dns_sub.setText("DNS goes out in plain text; LANGuard watches the "
                                     "answers for spoofing. See \"Set up encrypted DNS "
                                     "yourself\" below.")
        self.dns_title.setStyleSheet(f"color: {color};")
        self.dns_icon.setPixmap(nav_icon("dns", color, 64).pixmap(48, 48))
        f = self.dns_fields
        f["listen"].setText(", ".join(info.get("listen") or []) or "-")
        if info.get("via_resolved"):
            chain = "systemd-resolved (127.0.0.53) → " + "; ".join(
                f"{k}: {', '.join(v)}" for k, v in (info.get("resolved") or {}).items()) or \
                "systemd-resolved (127.0.0.53)"
        else:
            chain = ", ".join(info.get("resolv_conf") or []) or "-"
        f["chain"].setText(chain)
        f["bootstrap"].setText(", ".join(info.get("bootstrap") or []) or "-")
        f["config"].setText(str(info.get("config") or "-"))
        self.dns_test_btn.setEnabled(bool(info.get("listen")))
        if risk:
            self.dns_leak.setText("".join(f"<p><span style='color:{COLORS['WARNING']}'>▲</span>"
                                          f"  {r}</p>" for r in risk))
            self.dns_advice.setText("If you want to close it (LANGuard won't): "
                                    + (info.get("advice") or ""))
            self.dns_advice.show()
        else:
            self.dns_leak.setText(f"<span style='color:{COLORS['ok']}'>✔</span>  No leak seen: "
                                  "system DNS only goes to your local resolver."
                                  if info.get("resolver") else "Nothing to check without a "
                                  "local resolver.")
            self.dns_advice.hide()

    def probe_dns(self):
        addrs = list((self.dns_info or {}).get("listen") or [])
        if not addrs:
            return
        self.dns_test_btn.setEnabled(False)
        self.dns_fields["probe"].setText("testing…")

        def work():
            from languard_core import localdns
            res = []
            for a in addrs:
                try:
                    ok = localdns.probe(a, timeout=3)
                except Exception:
                    ok = False
                res.append(f"{a} {'answers' if ok else 'NO ANSWER'}")
            self.probed.emit(f"{time.strftime('%H:%M:%S')}: " + "; ".join(res))
        threading.Thread(target=work, daemon=True).start()

    def _probe_done(self, text):
        self.dns_fields["probe"].setText(text)
        self.dns_test_btn.setEnabled(True)

    # ---- tools page ----
    def run_selftest(self):
        self.go([k for k, _ in PAGES].index("tools"))
        self.run_named_tool("selftest")

    def run_named_tool(self, key):
        if key == "selftest":
            self.run_tool(["selftest"], "Self-test")
        elif key == "audit":
            self.run_tool(["audit", "--json"], "Security audit", root=False,
                          parse=self._show_audit)
        elif key == "evidence":
            self.run_tool(["evidence"], "Evidence captures")
        elif key == "hsts":
            self.run_tool(["hsts", "--update"], "HSTS preload list update")

    def run_tool(self, args, what, root=True, parse=None):
        self.audit.setVisible(parse is not None)
        self.console.setPlainText(f"$ {'sudo ' if root else ''}languard {' '.join(args)}\n")
        self.tool_status.setText(f"{what}: running…")

        def done(code, out):
            if code in (126, 127) and not out:
                self.tool_status.setText(f"{what}: cancelled")
                return
            if parse:
                out = parse(out) or out
            self.console.appendPlainText(out)
            self.tool_status.setText(f"{what}: {'done' if code == 0 else f'exit {code}'}"
                                     f" at {time.strftime('%H:%M:%S')}")
        self.run_priv(args, what, done=done, root=root)

    def _show_audit(self, out):
        try:
            rows = json.loads(out[out.index("["):])
        except ValueError:
            return None
        colors = {"PASS": "ok", "WARN": "WARNING", "FAIL": "CRITICAL", "INFO": "INFO"}
        self.audit.setRowCount(len(rows))
        for i, r in enumerate(rows):
            st = QTableWidgetItem(f"●  {r.get('status')}")
            st.setForeground(QBrush(QColor(COLORS[colors.get(r.get("status"), "INFO")])))
            self.audit.setItem(i, 0, st)
            self.audit.setItem(i, 1, QTableWidgetItem(r.get("check") or ""))
            d = " ".join((r.get("detail") or "").split())
            it = QTableWidgetItem(d)
            it.setToolTip(r.get("detail") or "")
            self.audit.setItem(i, 2, it)
            self.audit.setItem(i, 3, QTableWidgetItem(r.get("fix") or ""))
        self.audit.resizeRowsToContents()
        n = Counter(r.get("status") for r in rows)
        return (f"{n['PASS']} passed, {n['WARN']} warnings, {n['FAIL']} failed. "
                f"Fixes are only applied with your consent, in a terminal: "
                f"sudo languard audit --fix")

    # ---- commands ----
    def toggle_protect(self, checked):
        if checked:
            msg = ("Turn on active protection?\n\nLANGuard will pin your router, isolate "
                   "devices caught attacking, guard HTTPS against SSL stripping and use "
                   "the responses chosen on the Protection page. Your DNS settings are "
                   "never changed. You can undo every action.")
        else:
            msg = ("Turn off active protection?\n\nLANGuard keeps detecting and "
                   "alerting, and undoes the router pin, blocks and IPv6 lockdown.")
        if QMessageBox.question(self, "Active protection", msg) != QMessageBox.Yes:
            self.protect_switch.setChecked(not checked)
            return
        self.run_priv(["protect", "--on" if checked else "--off"],
                      f"Turning active protection {'on' if checked else 'off'}")

    def unblock_selected(self):
        rows = {i.row() for i in self.blocked.selectedItems()}
        addrs = [self.blocked.item(r, 0).text() for r in sorted(rows)]
        if not addrs:
            QMessageBox.information(self, "Unblock", "Select a device in the list first.")
            return
        self.run_priv(["protect", "--unblock", *addrs], f"Unblocking {', '.join(addrs)}")

    def undo_all(self):
        if QMessageBox.question(self, "Undo all actions",
                                "Remove the router pins, every block, the IPv6 lockdown, "
                                "and put LLMNR, ICMP redirects and the HTTPS guard back? "
                                "Active protection stays on and acts again on new "
                                "attacks.") == QMessageBox.Yes:
            self.run_priv(["protect", "--undo-all"], "Undoing all protective actions")

    def run_priv(self, args, what, done=None, root=True):
        """Run `languard args` (as root through polkit unless root=False);
        done(code, output) replaces the default message on completion."""
        if self.proc is not None:
            return
        argv = self.b.privileged(*args) if root else self.b.plain(*args)
        if not argv:
            QMessageBox.warning(self, "LANGuard",
                                f"pkexec (polkit) isn't installed. Run this in a terminal:\n\n"
                                f"sudo languard {' '.join(args)}")
            return
        self.statusBar().showMessage(f"{what}…" + (" (you may be asked for your password)"
                                                   if root else ""))
        self.proc = QProcess(self)
        self.proc.setProcessChannelMode(QProcess.MergedChannels)
        self.proc.finished.connect(lambda code, _s, w=what, d=done: self._done(code, w, d))
        self.proc.start(argv[0], argv[1:])
        self.protect_switch.setEnabled(False)

    def _done(self, code, what, done=None):
        out = bytes(self.proc.readAll()).decode(errors="replace").strip()
        self.proc = None
        if done:
            done(code, out)
            if not (code in (126, 127) and not out):
                self.statusBar().showMessage(f"{what}: {'done' if code == 0 else 'failed'}")
        else:
            self._default_done(code, out, what)
        self._dns_at = 0
        QTimer.singleShot(1500, self.refresh)
        self.refresh()

    def _default_done(self, code, out, what):
        if code in (126, 127) and not out:
            self.statusBar().showMessage(f"{what}: cancelled")
        elif code != 0:
            QMessageBox.warning(self, "LANGuard", f"{what} failed (exit {code}).\n\n{out}")
        else:
            self.statusBar().showMessage(f"{what}: done")


STYLE = f"""
QWidget {{ background: {COLORS['bg']}; color: {COLORS['text']}; font-size: 13px; }}
QLabel {{ background: transparent; }}
QLabel#muted {{ color: {COLORS['muted']}; }}
QLabel#pagetitle {{ font-size: 22px; font-weight: 700; }}
QLabel#section {{ font-size: 14px; font-weight: 600; padding: 4px 0 0 0; }}
QLabel#headline {{ font-size: 24px; font-weight: 700; }}
QLabel#banner {{ background: #2a2212; color: {COLORS['WARNING']}; border: 1px solid #4a3a16;
    border-radius: 8px; padding: 10px 12px; }}
QLabel#banner_ok {{ background: #0f2a1f; color: {COLORS['ok']}; border: 1px solid #1d4a35;
    border-radius: 8px; padding: 10px 12px; }}
QLabel#code {{ font-family: monospace; background: {COLORS['panel']};
    border: 1px solid {COLORS['border']}; border-radius: 6px; padding: 8px; }}
QFrame#sidebar {{ background: {COLORS['side']}; border-right: 1px solid {COLORS['border']}; }}
QFrame#sidebar QWidget {{ background: transparent; }}
QFrame#sidestate {{ background: {COLORS['panel']}; border: 1px solid {COLORS['border']};
    border-radius: 8px; }}
QPushButton#nav {{ text-align: left; background: transparent; border: none; border-radius: 8px;
    padding: 9px 10px; color: {COLORS['muted']}; font-size: 13px; }}
QPushButton#nav:hover {{ background: {COLORS['panel']}; color: {COLORS['text']}; }}
QPushButton#nav:checked {{ background: {COLORS['panel2']}; color: {COLORS['text']};
    font-weight: 600; border-left: 3px solid {COLORS['accent']}; }}
QFrame#hero {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #17212a,
    stop:1 {COLORS['panel']}); border: 1px solid {COLORS['border']}; border-radius: 12px; }}
QFrame#hero QWidget {{ background: transparent; }}
QFrame#panel, QFrame#card, QFrame#tile {{ background: {COLORS['panel']};
    border: 1px solid {COLORS['border']}; border-radius: 10px; }}
QFrame#panel QWidget, QFrame#card QWidget, QFrame#tile QWidget {{ background: transparent; }}
QFrame#panel QTableWidget {{ background: {COLORS['bg']}; }}
QFrame#row {{ background: transparent; border: none; border-bottom: 1px solid {COLORS['border']}; }}
QScrollArea, QScrollArea > QWidget > QWidget {{ background: {COLORS['bg']}; }}
QPushButton, QToolButton, QComboBox, QLineEdit {{ background: {COLORS['panel2']};
    border: 1px solid {COLORS['border']}; border-radius: 6px; padding: 6px 12px; }}
QPushButton:hover, QToolButton:hover, QComboBox:hover {{ border-color: {COLORS['muted']}; }}
QPushButton:disabled, QToolButton:disabled {{ color: {COLORS['off']}; }}
QPushButton#primary {{ background: {COLORS['accent']}; color: #06150e; font-weight: 600; border: none; }}
QPushButton#primary:disabled {{ background: #1f3b2f; color: #557a68; }}
QPushButton#danger {{ color: {COLORS['CRITICAL']}; border-color: #4a2427; }}
QPushButton#segment:checked {{ background: #133326; border-color: {COLORS['accent']};
    color: {COLORS['accent']}; font-weight: 600; }}
QTableWidget, QPlainTextEdit {{ background: {COLORS['bg']}; alternate-background-color: #12161c;
    border: 1px solid {COLORS['border']}; border-radius: 8px; }}
QPlainTextEdit#console {{ font-family: monospace; background: #080a0d; }}
QHeaderView::section {{ background: {COLORS['panel2']}; color: {COLORS['muted']}; border: none;
    padding: 6px; font-weight: 600; }}
QTableWidget::item {{ padding: 3px 6px; }}
QTableWidget::item:selected {{ background: {COLORS['select']}; }}
QSplitter::handle {{ background: transparent; height: 8px; }}
QScrollBar:vertical {{ background: transparent; width: 10px; }}
QScrollBar::handle:vertical {{ background: {COLORS['border']}; border-radius: 5px; min-height: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QStatusBar {{ color: {COLORS['muted']}; background: {COLORS['side']};
    border-top: 1px solid {COLORS['border']}; }}
QMenu {{ background: {COLORS['panel2']}; border: 1px solid {COLORS['border']}; }}
QMenu::item {{ padding: 6px 18px; }}
QMenu::item:selected {{ background: {COLORS['select']}; }}
QToolTip {{ background: {COLORS['panel2']}; color: {COLORS['text']}; border: 1px solid {COLORS['border']}; }}
"""


def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    app = QApplication(sys.argv)
    app.setApplicationName("LANGuard")
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    f = QFont()
    f.setFamilies(["Inter", "Cantarell", "Noto Sans", "DejaVu Sans"]) \
        if hasattr(f, "setFamilies") else None
    app.setFont(f)
    app.setQuitOnLastWindowClosed(False)
    w = MainWindow(Backend())
    w.show()
    if not w.tray:
        app.setQuitOnLastWindowClosed(True)
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
