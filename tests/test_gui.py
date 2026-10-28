#!/usr/bin/env python3
"""Tests for the desktop app's data layer (status file, alert log parsing,
protection on/off switch) and a smoke test of the PyQt5 window.
Run: python3 tests/test_gui.py   (no root; the window test needs python3-pyqt5)"""

import ipaddress
import json
import os
import sys
import tempfile
import time
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="languard-test-")
os.environ["LANGUARD_STATE"] = TMP + "/state"
os.environ["LANGUARD_RUN"] = TMP + "/run"
os.environ["LANGUARD_CONFIG"] = TMP + "/config.json"
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from languard_core import core, status               # noqa: E402
from languard_core.core import Alerter, load_config  # noqa: E402

core.setup_logging(None)
fails = 0


def check(name, cond):
    global fails
    print(("  ok  " if cond else "  FAIL ") + name)
    fails += not cond


print("== Alert log parsing")
e = status.parse_line("2026-10-26 20:50:14,123 CRITICAL [arp] GATEWAY SPOOFING: 192.168.1.1 moved a -> b")
check("critical ARP line parsed", e and e["level"] == "CRITICAL" and e["module"] == "arp"
      and e["kind"] == "threat" and e["msg"].startswith("GATEWAY"))
e = status.parse_line("2026-10-26 20:50:15,001 WARNING  [protect] Isolated 66:66:66:66:66:66 for 60 min")
check("protect line is an action", e and e["kind"] == "action")
e = status.parse_line("2026-10-26 20:50:15,001 INFO     LANGuard 1.2.0 protecting eth0")
check("line without a module is info", e and e["module"] == "languard" and e["kind"] == "info")
check("debug and garbage ignored", status.parse_line("2026-10-26 20:50:15,001 DEBUG    [arp] x") is None
      and status.parse_line("Traceback (most recent call last):") is None)
check("offline check errors are not threats",
      status.kind_of("path", "check failed: [Errno 100] Network is down") == "info")
check("UFW block counts as an action", status.kind_of("scan", "Blocked 192.168.1.66 with UFW") == "action")
j = status.parse_json(json.dumps({"ts": 1.5, "module": "dhcp", "level": "CRITICAL",
                                  "msg": "ROGUE DHCP SERVER", "server_mac": "66"}))
check("JSON log line keeps extra data", j and j["data"] == {"server_mac": "66"} and j["kind"] == "threat")

print("== Log tail")
log = Path(TMP) / "languard.log"
log.write_text("2026-10-26 20:00:00,1 WARNING  [dns] one\n")
tail = status.LogTail(log)
check("first read returns history", [x["msg"] for x in tail.read()] == ["one"])
with open(log, "a") as f:
    f.write("2026-10-26 20:00:01,1 CRITICAL [arp] two\n2026-10-26 20:00:02,1 WARNING  [dns] thr")
check("only new complete lines", [x["msg"] for x in tail.read()] == ["two"])
with open(log, "a") as f:
    f.write("ee\n")
check("partial line finished later", [x["msg"] for x in tail.read()] == ["three"])
log.write_text("2026-10-26 21:00:00,1 WARNING  [scan] after rotate\n")
check("truncated/rotated file reread", [x["msg"] for x in tail.read()] == ["after rotate"])
check("missing file is harmless", status.LogTail(Path(TMP) / "nope.log").read() == [])

print("== Status file")


class Ctx:
    pass


c = Ctx()
c.cfg = load_config("/nonexistent"); c.cfg["protect"]["enabled"] = True
c.alert = Alerter(0)
c.iface, c.gateway, c.my_ip, c.my_mac = "eth0", "192.168.1.1", "192.168.1.5", "02:00:00:00:00:05"
c.network = ipaddress.ip_network("192.168.1.0/24"); c.net_label = "home"


class P:
    enabled = True
    state = {"pin": {"ip": "192.168.1.1", "mac": "aa", "iface": "eth0"},
             "blocked": {"66:66:66:66:66:66": {"until": time.time() + 600, "reason": "gateway_spoof"},
                         "77:77:77:77:77:77": {"until": time.time() - 5, "reason": "old"}}}


c.protect = P()


class M:
    name = "arp"


status.write_status(c, [M()], time.time() - 60)
st = status.read_status()
check("status written and read back", st and st["iface"] == "eth0" and st["modules"] == ["arp"])
check("status lists only live isolations", list(st["protect"]["blocked"]) == ["66:66:66:66:66:66"])
check("status file is world-readable", oct((Path(TMP) / "run/status.json").stat().st_mode)[-3:] == "644")
status.write_pause(time.time() + 900)
check("pause visible to the app", status.read_pause() is not None)
status.write_pause(None)
check("resume clears it", status.read_pause() is None)

print("== Protection on/off in the config")
sys.argv = ["languard"]
import importlib.util                                   # noqa: E402
spec = importlib.util.spec_from_file_location("lgcli", ROOT / "languard.py")
cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
cfgp = Path(TMP) / "config.json"
cfgp.write_text(json.dumps({"notify": True, "arp": {"flood_threshold": 40}}))
cli.set_protect(str(cfgp), True)
d = json.loads(cfgp.read_text())
check("--on sets protect.enabled and keeps other settings",
      d["protect"]["enabled"] is True and d["notify"] is True and d["arp"]["flood_threshold"] == 40)
cli.set_protect(str(cfgp), False)
check("--off clears it", json.loads(cfgp.read_text())["protect"]["enabled"] is False)
cli.set_protect(str(cfgp), options={"https_guard": False, "kill_switch": True})
d = json.loads(cfgp.read_text())["protect"]
check("--set switches single responses and keeps enabled",
      d == {"enabled": False, "https_guard": False, "kill_switch": True})

print("== Launcher")
entry = dict(line.split("=", 1) for line in
             (ROOT / "desktop/languard.desktop").read_text().splitlines() if "=" in line)
check("launcher uses the shipped icon", entry["Icon"] == "languard"
      and (ROOT / "desktop/languard.svg").is_file())
# Matches the app's WM_CLASS (X11) and desktop file name (Wayland app_id), so
# windows group under the launcher instead of appearing as extra apps.
check("launcher matches the app's windows", entry["StartupWMClass"] == "LANGuard"
      and "app.setDesktopFileName(DESKTOP_ID)" in (ROOT / "languard_gui.py").read_text()
      and 'DESKTOP_ID = "languard"' in (ROOT / "languard_gui.py").read_text())

print("== Desktop window (offscreen)")
try:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt5.QtWidgets import QApplication, QScrollArea
except ImportError:
    print("  (python3-pyqt5 not installed: skipped)")
else:
    log.write_text("".join(
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 300 + i)) + f",1 {lvl} [{mod}] {msg}\n"
        for i, (lvl, mod, msg) in enumerate([
            ("CRITICAL", "arp", "GATEWAY SPOOFING: 192.168.1.1 moved aa -> 66:66:66:66:66:66"),
            ("WARNING ", "protect", "Isolated 66:66:66:66:66:66 for 60 min (gateway_spoof)"),
            ("WARNING ", "dns", "bank.com resolved to private address 192.168.1.66")])))
    cfgp.write_text(json.dumps({"log_file": str(log)}))
    status.write_status(c, [M()], time.time() - 60)
    import languard_gui as g
    app = QApplication.instance() or QApplication([])
    # The app's own look (as in main()), so screenshots match what users see.
    app.setStyle("Fusion")
    app.setStyleSheet(g.STYLE)
    g.Backend.service_state = lambda self: "active"
    w = g.MainWindow(g.Backend())
    w.refresh()
    check("header says protected", w.headline.text() == "Protected")
    check("cards count threats, criticals and actions",
          (w.c_threats.value.text(), w.c_crit.value.text(), w.c_actions.value.text(),
           w.c_isolated.value.text()) == ("2", "1", "1", "1"))
    check("threat table lists threats and actions", w.table.rowCount() == 3)
    w.f_kind.setCurrentIndex(1)
    check("filter: threats only", w.table.rowCount() == 2)
    w.f_search.setText("bank.com")
    check("search filter", w.table.rowCount() == 1)
    check("isolated device listed with unblock enabled",
          w.blocked.rowCount() == 1 and w.unblock_btn.isEnabled())
    check("protection switch reflects the service", w.protect_switch.isChecked())
    g.Backend.service_state = lambda self: "inactive"
    w.refresh()
    check("stopped service shows Not running and a Resume button",
          w.headline.text() == "Not running" and not w.run_btn.isHidden())
    w.b.privileged = lambda *a: [sys.executable, "-c", "import sys; sys.exit(0)"]
    w.run_priv(["resume"], "Resuming")
    w.proc.waitForFinished(5000)
    app.processEvents()
    check("privileged command runs and finishes", w.proc is None)

    print("== One app per user")
    # A separate socket name, so a LANGuard app you have open isn't touched.
    g.instance_name = lambda: f"languard-gui-test-{os.getpid()}"
    check("first launch finds nothing running", not g.raise_running())
    w.hide()
    w.server = g.listen_for_launches(w)
    check("second launch reaches the running app", g.raise_running())
    for _ in range(50):
        app.processEvents()
        if w.isVisible():
            break
        time.sleep(0.02)
    check("running app shows its window", w.isVisible())
    w.server.close()
    check("nothing listening after close", not g.raise_running())

    print("== New pages")

    class B:
        key, rec, gw_verified, kind = "net-1", {"gw_mac": "aa:aa:aa:aa:aa:aa"}, True, "public"

        def pinned(self):
            return {"192.168.1.20": "02:00:00:00:00:20"}

    c._baseline = B()
    P.state["pin6"] = {"ip": "fe80::1", "mac": "aa:aa:aa:aa:aa:aa", "iface": "eth0"}
    P.state["guard"] = {"port": 8443}
    c.local_dns = {"resolver": "dnscrypt-proxy", "label": "dnscrypt-proxy",
                   "listen": ["127.0.0.1:53"], "leak_risk": ["/etc/resolv.conf also lists 8.8.8.8"]}
    status.write_status(c, [M()], time.time() - 60)
    g.Backend.service_state = lambda self: "active"
    ran = []

    def fake_priv(*a):
        ran.append(list(a))
        return [sys.executable, "-c", "print('ok')"]
    w.b.privileged = fake_priv
    w.b.plain = fake_priv
    w.refresh()

    def finish():
        if w.proc:
            w.proc.waitForFinished(5000)
        app.processEvents()

    check("layers: router pinned, HTTPS guard active, DNS leak needs attention",
          w.layers["router"].state == "Active" and w.layers["https"].state == "Active"
          and w.layers["dns"].state == "Attention" and w.layers["trust"].state == "Active")
    check("network page: public network, pinned device listed",
          w.net_public.isChecked() and not w.net_home.isChecked()
          and w.pinned.rowCount() == 1 and w.pinned.item(0, 0).text() == "192.168.1.20")
    check("response switches follow the settings",
          w.resp["https_guard"].switch.isChecked() and not w.resp["kill_switch"].switch.isChecked())
    w.resp["https_guard"].switch.click()
    check("a changed switch is pending until applied",
          w.pending == {"https_guard": False} and w.apply_btn.isEnabled())
    w.apply_responses()
    finish()
    check("apply runs protect --set and clears pending",
          ran[-1] == ["protect", "--set", "https_guard=off"] and not w.pending)
    w.revert_responses()
    w.net_home.click()
    finish()
    check("mark network home", ran[-1] == ["network", "--home"])
    w.pin_ip.setText("192.168.1.30")
    w.pin_mac.setText("02-00-00-00-00-30")
    w.pin_device()
    finish()
    check("pin a device with its MAC",
          ran[-1] == ["protect", "--pin-device", "192.168.1.30", "02:00:00:00:00:30"]
          and w.pin_ip.text() == "")
    g.QMessageBox.warning = staticmethod(lambda *a, **k: None)
    n = len(ran)
    w.pin_ip.setText("not-an-ip")
    w.pin_device()
    check("an invalid IP isn't sent", len(ran) == n and w.proc is None)
    w.pinned.selectRow(0)
    w.unpin_device()
    finish()
    check("unpin the selected device", ran[-1] == ["protect", "--unpin-device", "192.168.1.20"])
    w.b.local_dns = lambda: {"resolver": "dnscrypt-proxy", "label": "dnscrypt-proxy",
                             "listen": ["127.0.0.1:53"], "resolv_conf": ["127.0.0.1"],
                             "leak_risk": [], "bootstrap": ["9.9.9.9"], "config": "/etc/x.toml"}
    w.go(5)
    check("DNS page shows the resolver read-only",
          "dnscrypt-proxy" in w.dns_title.text() and w.dns_advice.isHidden()
          and "127.0.0.1:53" in w.dns_fields["listen"].text())
    check("DNS guide: 5 options with commands, read-only",
          w.guide_pick.count() == 5 and "# Step 1:" in w.guide_cmds.toPlainText()
          and "already handles every lookup" in w.guide_now.text())
    w.guide_pick.setCurrentIndex(2)
    check("picking an option shows its commands",
          "stubby" in w.guide_cmds.toPlainText().lower() and "Undo" in w.guide_cmds.toPlainText())
    w._copy_guide()
    check("copy puts the commands on the clipboard",
          QApplication.clipboard().text() == w.guide_cmds.toPlainText())
    n = len(ran)
    with_resolver = w.b.local_dns
    w.b.local_dns = lambda: {"resolver": None, "listen": [], "leak_risk": []}
    saved, w.status = w.status, dict(w.status or {}, local_dns={})
    w._update_dns(force=True)
    w.status = saved
    check("no resolver: points to the guide, marks a recommendation, keeps your "
          "pick, runs nothing",
          "No local encrypted resolver" in w.dns_title.text()
          and any("recommended" in w.guide_pick.itemText(i) for i in range(5))
          and w.guide_pick.currentData() == "stubby" and len(ran) == n)
    w.b.local_dns = with_resolver
    audit = json.dumps([{"status": "FAIL", "check": "Firewall", "detail": "off", "fix": "ufw"},
                        {"status": "PASS", "check": "SMB", "detail": "ok", "fix": None}])
    w.b.plain = lambda *a: ran.append(list(a)) or [sys.executable, "-c", f"print({audit!r})"]
    w.run_named_tool("audit")
    finish()
    check("audit runs as you and fills the table",
          ran[-1] == ["audit", "--json"] and w.audit.rowCount() == 2
          and "1 passed" in w.console.toPlainText())
    w.run_named_tool("selftest")
    finish()
    check("self-test runs through polkit and shows output",
          ran[-1] == ["selftest"] and "ok" in w.console.toPlainText())

    print("== 1.7: router identity, sensor, DHCP/RA pins, devices, tamper")

    class Arp:
        def devices(self, limit=64):
            return [("192.168.1.1", "aa:aa:aa:aa:aa:aa"), ("192.168.1.20", "02:00:00:00:00:20"),
                    ("192.168.1.40", "02:00:00:00:00:40")]

    class Sen:
        stats = {"pps": 120, "drops": 0, "skipped": 0, "errors": 0, "flooders": [],
                 "state": "ok"}

    c.arp, c.sensor = Arp(), Sen()
    c.router_trust = {"level": "verified+key", "detail": "MAC and key match",
                      "wifi": {"ssid": "Home", "bssid": "aa:bb:cc:dd:ee:01",
                               "security": "WPA2 WPA3"}}
    B.rec = {"gw_mac": "aa:aa:aa:aa:aa:aa"}
    P.state["l2pins"] = {"dhcp": ["aa:aa:aa:aa:aa:aa"], "ra": ["aa:aa:aa:aa:aa:aa"]}
    P.state["framed_until"] = time.time() + 600
    status.write_status(c, [M()], time.time() - 60)
    w.refresh()
    check("12 protection tiles", len(w.layers) == 12)
    check("router identity, DHCP/RA shield, sensor and tamper tiles active",
          all(w.layers[k].state == "Active" for k in ("identity", "l2pins", "sensor", "tamper")))
    check("network page: router identity and Wi-Fi access point",
          "verified+key" in w.net_fields["identity"].text()
          and "aa:bb:cc:dd:ee:01" in w.net_fields["wifi"].text())
    check("devices seen listed with router and pinned marks",
          w.seen.rowCount() == 3 and w.seen.item(0, 2).text() == "router"
          and w.seen.item(1, 2).text() == "pinned")
    w.seen.selectRow(2)
    w.pin_seen()
    finish()
    check("pin a seen device", ran[-1] == ["protect", "--pin-device", "192.168.1.40",
                                           "02:00:00:00:00:40"])
    texts = [w.inforce.itemAt(i).widget().text() for i in range(w.inforce.count())]
    check("blocks page shows the DHCP/RA pins and the framing pause",
          any("DHCP / IPv6 router pins" in t for t in texts)
          and any("Isolation paused" in t for t in texts))
    check("new switches on the Protection page",
          all(k in w.resp for k in ("pin_dhcp", "pin_ra", "https_only"))
          and not w.resp["https_only"].switch.isChecked())
    c.router_trust = {"level": "doubtful", "detail": "evil twin?"}
    c.sensor.stats = {"state": "flooded", "flooders": ["66:66:66:66:66:66"]}
    status.write_status(c, [M()], time.time() - 60)
    w.refresh()
    check("doubtful router and a flood need attention",
          w.layers["identity"].state == "Attention" and w.layers["sensor"].state == "Attention"
          and "66:66" in w.layers["sensor"].detail.text())
    b = g.Backend()
    old_which, old_euid = g.shutil.which, g.os.geteuid
    g.shutil.which = lambda x: "/usr/bin/pkexec"
    g.os.geteuid = lambda: 1000
    try:
        check("lowering protection goes through the strict entry point",
              b.privileged("protect", "--set", "isolate=off")[1].endswith("languard_strict.py")
              and b.privileged("pause", "30")[1].endswith("languard_strict.py"))
        check("everything else through the normal one",
              b.privileged("protect", "--set", "isolate=on")[1] == g.LANGUARD
              and b.privileged("selftest")[1] == g.LANGUARD)
    finally:
        g.shutil.which, g.os.geteuid = old_which, old_euid

    if os.environ.get("LANGUARD_SHOTS"):
        out = Path(os.environ["LANGUARD_SHOTS"])
        out.mkdir(parents=True, exist_ok=True)
        w.resize(1360, 900)
        for i, (key, _) in enumerate(g.PAGES):
            w.go(i)
            app.processEvents()
            w.grab().save(str(out / f"{i + 1}-{key}.png"))
        w.b.local_dns = lambda: {"resolver": None, "listen": [], "leak_risk": [],
                                 "resolv_conf": ["127.0.0.53"]}
        w.status = dict(w.status or {}, local_dns={})
        w.go(5)
        w.guide_pick.setCurrentIndex(1)
        app.processEvents()
        sa = w.pages.currentWidget().findChild(QScrollArea)
        sa.ensureWidgetVisible(w.guide_cmds)
        app.processEvents()
        w.grab().save(str(out / "8-dns-guide.png"))

print(f"\n{'ALL PASSED' if not fails else f'{fails} FAILED'}")
sys.exit(fails)
