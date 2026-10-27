#!/usr/bin/env bash
# End-to-end check of LANGuard on one distribution, run as root inside a
# throwaway container or VM (GitHub Actions runs it for every distro in
# .github/workflows/tests.yml):
#   install.sh --dry-run, a real install, the CLI (status, audit, selftest),
#   the full test suite with the interpreter the installer chose, and a
#   clean uninstall.
# Usage: sudo scripts/ci-container-test.sh [install.sh options]
#   default options: --no-av (ClamAV's first signature download is ~300 MB)
# Never run this on a machine you care about: it installs and removes
# LANGuard system-wide.
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root (in a container)"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
OPTS=("$@"); [ ${#OPTS[@]} -gt 0 ] || OPTS=(--no-av)
FAILED=""
step() { echo; echo "======== $*"; }
check() {              # check NAME CMD... : run, record failure, keep going
  local name="$1"; shift
  if "$@"; then echo "-------- PASS: $name"; else echo "-------- FAIL: $name"; FAILED="$FAILED|$name"; fi
}

# shellcheck disable=SC1091
. /etc/os-release
step "Distribution: ${PRETTY_NAME:-unknown}"

# A copy, so a read-only checkout works and nothing is written into it.
WORK="$(mktemp -d)"
cp -r "$SRC/." "$WORK/"
cd "$WORK" || exit 1

step "install.sh --dry-run"
check "dry run" ./install.sh --dry-run "${OPTS[@]}"

step "install.sh ${OPTS[*]}"
check "install" ./install.sh "${OPTS[@]}"
check "files in /opt/languard" test -x /opt/languard/languard.py
check "languard on PATH" test -L /usr/local/bin/languard
check "polkit policy installed" test -f /usr/share/polkit-1/actions/org.languard.policy

PY="$(head -1 /opt/languard/languard.py | sed 's/^#!//; s|^/usr/bin/env ||')"
step "CLI (interpreter: $PY)"
check "languard --version" /usr/local/bin/languard --version
check "languard config" sh -c '/usr/local/bin/languard config >/dev/null'
check "languard status" /usr/local/bin/languard status
# The audit reports findings about the container (no firewall...), that's fine;
# it only has to run.
check "languard audit runs" sh -c '/usr/local/bin/languard audit; [ $? -lt 100 ]'
check "languard selftest" /usr/local/bin/languard selftest
check "languard dnsguide" sh -c '/usr/local/bin/languard dnsguide >/dev/null'
check "scapy importable by LANGuard" "$PY" -c \
  'import sys; sys.path[:0]=["/opt/languard", "/opt/languard/vendor"]; import scapy.all'
# The desktop app, when PyQt5 is there: start it offscreen and make sure it
# is still running after a few seconds (timeout's 124 = it didn't crash).
if "$PY" -c 'import sys; sys.path.append("/opt/languard/vendor"); import PyQt5.QtWidgets' 2>/dev/null; then
  check "desktop app starts (offscreen)" sh -c \
    'QT_QPA_PLATFORM=offscreen timeout 8 /usr/local/bin/languard-gui >/tmp/gui.log 2>&1; [ $? -eq 124 ] || { cat /tmp/gui.log; false; }'
else
  echo "-------- SKIP: desktop app (PyQt5 not available)"
fi

# The DNS guide tells people to install these: they must exist here.
pkg_exists() {
  if command -v apt-cache >/dev/null; then apt-cache show "$1" >/dev/null 2>&1
  elif command -v dnf >/dev/null; then dnf -q info "$1" >/dev/null 2>&1
  elif command -v zypper >/dev/null; then zypper -n -q search -x "$1" >/dev/null 2>&1
  elif command -v pacman >/dev/null; then pacman -Si "$1" >/dev/null 2>&1
  else return 1; fi
}
step "DNS guide packages"
if pkg_exists bash; then
  for p in $(/usr/local/bin/languard dnsguide --packages); do
    check "package $p exists" pkg_exists "$p"
  done
  if command -v zypper >/dev/null; then
    for p in systemd-resolved systemd-network; do
      pkg_exists "$p" && echo "INFO: $p available" || echo "INFO: no $p"
    done
  fi
else
  echo "-------- SKIP: DNS guide packages (no package index, offline)"
fi

step "Test suite"
FAM="$("$PY" -c 'import sys; sys.path.insert(0, "."); from languard_core import distro; print(distro.info()[0])')"
# PYTHONPATH: scapy/PyQt5 the installer put in /opt/languard/vendor (--pip).
check "test suite" env LANGUARD_EXPECT_FAMILY="$FAM" PYTHONPATH=/opt/languard/vendor \
  tests/run_all.sh "$PY"

step "uninstall.sh --purge"
check "uninstall" ./uninstall.sh --purge
check "nothing left in /opt" test ! -e /opt/languard
check "no command left" test ! -e /usr/local/bin/languard

echo
if [ -z "$FAILED" ]; then
  echo "RESULT ${ID:-?} ${VERSION_ID:-}: ALL PASSED"
else
  echo "RESULT ${ID:-?} ${VERSION_ID:-}: FAILED ${FAILED#|}"
  exit 1
fi
