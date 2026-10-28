#!/usr/bin/env bash
# Install or update LANGuard on Linux: Ubuntu, Debian, Linux Mint, Pop!_OS,
# Fedora, RHEL/Alma/Rocky, openSUSE and Arch (plus their relatives).
# Usage: sudo ./install.sh [--enable] [--no-av] [--no-gui] [--pip] [--no-deps] [--dry-run]
#   --enable   start protection now and at every boot
#   --no-av    skip ClamAV (saves ~1 GB RAM; heuristics still run)
#   --no-gui   skip the desktop app (PyQt5)
#   --pip      Python libraries (requirements*.txt) from PyPI into
#              /opt/languard/vendor instead of distribution packages
#   --no-deps  don't use the package manager (you installed the dependencies
#              yourself: python3 3.8+, scapy, nftables, iproute2...)
#   --dry-run  show what would be installed and changed, change nothing
#              (works without root)
#
# LANGuard never installs, removes or reconfigures DNS software: your DNS
# servers, systemd-resolved settings and dnscrypt-proxy stay as they are.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/languard
ENABLE=0; AV=1; GUI=1; DRY=0; DEPS=1; PIP=0
for a in "$@"; do
  case "$a" in
    --enable) ENABLE=1 ;; --no-av) AV=0 ;; --no-gui) GUI=0 ;; --dry-run) DRY=1 ;; --no-deps) DEPS=0 ;; --pip) PIP=1 ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $a (see --help)"; exit 2 ;;
  esac
done
[ "$DRY" -eq 1 ] || [ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo ./install.sh"; exit 1; }
run() { if [ "$DRY" -eq 1 ]; then echo "    would run: $*"; else "$@"; fi; }
# Application menus and icon themes cache what's installed; not every
# distribution ships these tools, and menus also notice changes on their own.
refresh_menus() {
  if command -v update-desktop-database >/dev/null; then
    run update-desktop-database -q /usr/share/applications || true
  fi
  if command -v gtk-update-icon-cache >/dev/null && [ -f /usr/share/icons/hicolor/index.theme ]; then
    run gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
  fi
}

# ------------------------------------------------------------ distribution --
ID=""; ID_LIKE=""; PRETTY_NAME="Linux"
# shellcheck disable=SC1091
[ -r /etc/os-release ] && . /etc/os-release
FAMILY=unknown
for i in ${ID:-} ${ID_LIKE:-}; do
  case "$i" in
    debian|ubuntu|linuxmint|pop|kali|raspbian|elementary|zorin|neon|devuan) FAMILY=debian ;;
    fedora|rhel|centos|rocky|almalinux|ol) FAMILY=fedora ;;
    opensuse*|suse|sles|sled) FAMILY=suse ;;
    arch|manjaro|endeavouros|garuda|artix) FAMILY=arch ;;
    *) continue ;;
  esac
  break
done
if [ "$FAMILY" = unknown ]; then
  if command -v apt-get >/dev/null; then FAMILY=debian
  elif command -v dnf >/dev/null || command -v yum >/dev/null; then FAMILY=fedora
  elif command -v zypper >/dev/null; then FAMILY=suse
  elif command -v pacman >/dev/null; then FAMILY=arch
  else
    echo "Unsupported distribution ($PRETTY_NAME): no apt, dnf, zypper or pacman."
    echo "Install python3 (3.8+), scapy, nftables and iproute2 yourself, then run"
    echo "this script again with the same options."
    FAMILY=none
  fi
fi
echo "==> $PRETTY_NAME (${FAMILY} family)"

# Logical name -> package name for this family (empty: not needed here).
pkgname() {
  case "$FAMILY:$1" in
    arch:python3) echo python ;;            *:python3) echo python3 ;;
    arch:scapy) echo python-scapy ;;        *:scapy) echo python3-scapy ;;
    debian:pyqt5) echo python3-pyqt5 ;;     arch:pyqt5) echo python-pyqt5 ;;
    *:pyqt5) echo python3-qt5 ;;
    fedora:iproute) echo iproute ;;         *:iproute) echo iproute2 ;;
    *:nftables) echo nftables ;;
    debian:notify) echo libnotify-bin ;;    suse:notify) echo libnotify-tools ;;
    *:notify) echo libnotify ;;
    debian:oui) echo ieee-data ;;           fedora:oui|suse:oui) echo hwdata ;;
    *:oui) echo "" ;;
    debian:pkexec)                          # Ubuntu 22.04+/Debian 12+ split it out
      if apt-cache show pkexec >/dev/null 2>&1; then echo pkexec; else echo policykit-1; fi ;;
    *:pkexec) echo polkit ;;
    debian:clamav) echo "clamav clamav-daemon clamav-freshclam" ;;
    fedora:clamav) echo "clamav clamd clamav-update" ;;
    *:clamav) echo clamav ;;
    *:pip) case "$FAMILY" in arch) echo python-pip ;; *) echo python3-pip ;; esac ;;
    # System libraries a PyQt5 wheel from PyPI needs (it bundles Qt itself).
    debian:qtlibs) echo "libgl1 libegl1 libxkbcommon-x11-0 libfontconfig1 libdbus-1-3" ;;
    fedora:qtlibs) echo "mesa-libGL mesa-libEGL libxkbcommon-x11 fontconfig dbus-libs" ;;
    suse:qtlibs) echo "Mesa-libGL1 Mesa-libEGL1 libxkbcommon-x11-0 fontconfig libdbus-1-3" ;;
    arch:qtlibs) echo "mesa libxkbcommon-x11 fontconfig dbus" ;;
  esac
}

installed() {
  case "$FAMILY" in
    debian) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed" ;;
    fedora|suse) rpm -q --whatprovides "$1" >/dev/null 2>&1 ;;
    arch) pacman -Qq "$1" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

available() {
  case "$FAMILY" in
    debian) [ -n "$(apt-cache policy "$1" 2>/dev/null | sed -n 's/^ *Candidate: //p' | grep -v '(none)')" ] ;;
    fedora) dnf -q list --available "$1" >/dev/null 2>&1 || dnf -q list --installed "$1" >/dev/null 2>&1 ;;
    suse) zypper -q -n search --provides --match-exact "$1" >/dev/null 2>&1 ;;
    arch) pacman -Si "$1" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

REFRESHED=0
refresh() {
  [ "$REFRESHED" -eq 0 ] || return 0
  REFRESHED=1
  case "$FAMILY" in
    debian) run apt-get -o DPkg::Lock::Timeout=300 update -qq ;;
    suse) run zypper -q -n refresh ;;
  esac      # Arch: no -Sy here (partial upgrades); keep up to date with -Syu
}

pkg_install() {
  [ $# -gt 0 ] || return 0
  case "$FAMILY" in
    debian) run env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -qq "$@" >/dev/null ;;
    fedora) run "$(command -v dnf || command -v yum)" install -y -q "$@" ;;
    suse) run zypper -q -n install --no-recommends "$@" ;;
    arch) run pacman -S --noconfirm --needed "$@" ;;
  esac
}

# ------------------------------------------------------------ dependencies --
echo "==> Checking dependencies"
# An existing enabled install counts as --enable (updates keep everything on).
systemctl is-enabled --quiet languard.service 2>/dev/null && ENABLE=1
# Python libraries from the distribution unless --pip (see requirements.txt).
WANT="python3 iproute nftables notify oui"
[ "$PIP" -eq 1 ] && WANT="$WANT pip" || WANT="$WANT scapy"
[ "$AV" -eq 1 ] && WANT="$WANT clamav"
if [ "$GUI" -eq 1 ]; then
  if [ "$PIP" -eq 1 ]; then WANT="$WANT qtlibs"; else WANT="$WANT pyqt5"; fi
  command -v pkexec >/dev/null || WANT="$WANT pkexec"
fi
MISSING=""; UNAVAILABLE=""
if [ "$DEPS" -eq 0 ]; then
  echo "    --no-deps: package manager not used"
elif [ "$FAMILY" != none ]; then
  refresh
  for key in $WANT; do
    for p in $(pkgname "$key"); do
      installed "$p" && continue
      if available "$p"; then
        MISSING="$MISSING $p"
      else
        UNAVAILABLE="$UNAVAILABLE $key:$p"
      fi
    done
  done
fi
if [ -n "$MISSING" ]; then
  echo "    installing:$MISSING"
  # shellcheck disable=SC2086
  pkg_install $MISSING
elif [ "$DEPS" -eq 1 ]; then
  echo "    all distribution packages present"
fi
[ -z "$UNAVAILABLE" ] || echo "    not in your enabled repositories:$UNAVAILABLE"

# Python 3.8+ (openSUSE Leap 15 and RHEL 8 default to 3.6: use a newer one).
find_py() {
  PY=""
  for c in /usr/bin/python3 python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8; do
    p="$(command -v "$c" 2>/dev/null)" || continue
    if "$p" -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null; then PY="$p"; return; fi
  done
}
find_py
NEWPY=""
case "$FAMILY" in suse) NEWPY="python311 python311-pip" ;; fedora) NEWPY="python3.11 python3.11-pip" ;; esac
if [ -z "$PY" ] && [ "$DEPS" -eq 1 ] && [ -n "$NEWPY" ]; then
  echo "    system python3 is older than 3.8: installing$(printf ' %s' $NEWPY)"
  # shellcheck disable=SC2086
  pkg_install $NEWPY || true
  find_py
fi
if [ -z "$PY" ]; then
  [ "$DRY" -eq 1 ] && PY=/usr/bin/python3 && echo "    (dry run) Python 3.8+ not found yet"
  [ -n "$PY" ] || { echo "LANGuard needs Python 3.8 or newer; install it (e.g. python311) and re-run."; exit 1; }
fi
echo "    python: $PY ($("$PY" -c 'import platform; print(platform.python_version())' 2>/dev/null || echo '?'))"

# Python libraries from PyPI into $DEST/vendor when the distribution doesn't
# ship them for this Python (RHEL-likes without EPEL, a newer Python than the
# packaged one) or with --pip. Never into the system's site-packages.
NEED_VENDOR=0; NEED_QT_VENDOR=0
"$PY" -c 'import scapy' 2>/dev/null || NEED_VENDOR=1
HAVE_QT=1
"$PY" -c 'import PyQt5.QtWidgets' 2>/dev/null || HAVE_QT=0
[ "$PIP" -eq 1 ] && NEED_VENDOR=1
[ "$GUI" -eq 1 ] && { [ "$HAVE_QT" -eq 0 ] || [ "$PIP" -eq 1 ]; } && NEED_QT_VENDOR=1

# ------------------------------------------------------------------ files --
echo "==> Copying files to $DEST"
run mkdir -p "$DEST" /etc/languard /var/lib/languard
run rm -rf "$DEST/languard_core"
run cp -r "$SRC/languard.py" "$SRC/languard_strict.py" "$SRC/languard_gui.py" \
  "$SRC/languard_core" "$DEST/"
if [ "$PY" != /usr/bin/python3 ]; then
  echo "    using $PY for LANGuard (shebangs rewritten)"
  for f in languard.py languard_strict.py languard_gui.py; do
    run sed -i "1s|^#!.*|#!$PY|" "$DEST/$f"
  done
fi
# Old distribution pips (Ubuntu 20.04: 20.0) can't read today's wheel tags and
# would try to compile PyQt5, so run a current pip from a temporary folder;
# the system's pip is left as it is.
PIPCMD=("$PY" -m pip)
pip_bootstrap() {
  [ -z "${PIPBOOT:-}" ] || return 0
  PIPBOOT="$(mktemp -d)"
  if "$PY" -m pip install -q --disable-pip-version-check --target "$PIPBOOT" pip >/dev/null 2>&1 \
     || "$PY" -m pip install -q --disable-pip-version-check --break-system-packages \
          --target "$PIPBOOT" pip >/dev/null 2>&1; then
    PIPCMD=(env PYTHONPATH="$PIPBOOT" "$PY" -m pip)
  fi
}
vendor_install() {     # vendor_install REQUIREMENTS-FILE
  pip_bootstrap
  local opts=(-q --disable-pip-version-check --target "$DEST/vendor" --upgrade
              "--only-binary=PyQt5,PyQt5-sip,PyQt5-Qt5" -r "$1")
  "${PIPCMD[@]}" install "${opts[@]}" 2>/dev/null \
    || "${PIPCMD[@]}" install --break-system-packages "${opts[@]}"
}
if [ "$NEED_VENDOR" -eq 1 ] || [ "$NEED_QT_VENDOR" -eq 1 ]; then
  if [ "$DRY" -eq 1 ]; then
    [ "$NEED_VENDOR" -eq 1 ] && echo "    would install requirements.txt (scapy) from PyPI into $DEST/vendor"
    [ "$NEED_QT_VENDOR" -eq 1 ] && echo "    would install requirements-gui.txt (PyQt5) from PyPI into $DEST/vendor"
  else
    if [ "$PY" = /usr/bin/python3 ]; then PIPPKG="$(pkgname pip)"; else
      V="$("$PY" -c 'import sys; print("%d%d" % sys.version_info[:2])')"
      case "$FAMILY" in suse) PIPPKG="python$V-pip" ;; fedora) PIPPKG="python${V:0:1}.${V:1}-pip" ;; *) PIPPKG="$(pkgname pip)" ;; esac
    fi
    "$PY" -m pip --version >/dev/null 2>&1 || [ "$DEPS" -eq 0 ] || pkg_install "$PIPPKG" || true
    if [ "$NEED_VENDOR" -eq 1 ]; then
      echo "    installing requirements.txt (scapy) from PyPI into $DEST/vendor"
      vendor_install "$SRC/requirements.txt" \
        || echo "    WARNING: could not install scapy; network modules stay off until it is installed"
    fi
    if [ "$NEED_QT_VENDOR" -eq 1 ]; then
      echo "    installing requirements-gui.txt (PyQt5) from PyPI into $DEST/vendor"
      # shellcheck disable=SC2046
      [ "$DEPS" -eq 0 ] || pkg_install $(pkgname qtlibs) >/dev/null 2>&1 || true
      vendor_install "$SRC/requirements-gui.txt" || echo "    WARNING: could not install PyQt5 from PyPI"
    fi
  fi
fi
[ -z "${PIPBOOT:-}" ] || rm -rf "$PIPBOOT"
# What LANGuard will actually import (distribution first, then vendor/).
if [ "$DRY" -eq 0 ]; then
  CHECK="import sys; sys.path.append('$DEST/vendor')"
  "$PY" -c "$CHECK; import PyQt5.QtWidgets" 2>/dev/null && HAVE_QT=1
fi
run chmod 755 "$DEST/languard.py" "$DEST/languard_strict.py" "$DEST/languard_gui.py"
# Readable by everyone (the desktop app runs as you), writable only by root,
# whatever umask root has or the modes the source files came with.
run chmod -R u=rwX,go=rX "$DEST"
run ln -sf "$DEST/languard.py" /usr/local/bin/languard
# sudo on RHEL-likes (secure_path) doesn't search /usr/local/bin.
SECURE_PATH="$(grep -hs '^ *Defaults.*secure_path' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | tail -1 || true)"
if [ -n "$SECURE_PATH" ] && ! echo "$SECURE_PATH" | grep -q /usr/local/bin; then
  if [ ! -e /usr/bin/languard ] || [ "$(readlink /usr/bin/languard)" = "$DEST/languard.py" ]; then
    echo "    sudo doesn't search /usr/local/bin here: linking /usr/bin/languard too"
    run ln -sf "$DEST/languard.py" /usr/bin/languard
  fi
fi
# The HSTS preload list (~125,000 HTTPS-only sites) for the SSL-stripping
# guard; refreshed weekly by languard-guard.timer.
if [ "$DRY" -eq 0 ]; then
  /usr/local/bin/languard hsts --update 2>/dev/null | sed 's/^/    /' \
    || echo "    HSTS preload list: download failed, retried weekly"
fi
# Password prompts: cached a few minutes for normal commands, asked every
# time for anything that lowers protection (tamper protection).
run mkdir -p /usr/share/polkit-1/actions
run install -m 644 "$SRC/desktop/org.languard.policy" /usr/share/polkit-1/actions/
if [ "$GUI" -eq 1 ]; then
  run ln -sf "$DEST/languard_gui.py" /usr/local/bin/languard-gui
  # One launcher, under one fixed desktop file ID: drop copies left by older
  # installs or made by hand, which show up as extra LANGuard entries.
  WHO_HOME=""
  [ -n "${SUDO_USER:-}" ] && WHO_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  for f in /usr/share/applications/*.desktop /usr/local/share/applications/*.desktop \
           ${WHO_HOME:+"$WHO_HOME"/.local/share/applications/*.desktop}; do
    [ -f "$f" ] && [ "$f" != /usr/share/applications/languard.desktop ] || continue
    if grep -Eq '^Exec=.*(languard-gui|languard_gui\.py)' "$f"; then
      echo "    removing old launcher $f"
      run rm -f "$f"
    fi
  done
  run mkdir -p /usr/share/applications /usr/share/icons/hicolor/scalable/apps
  run install -m 644 "$SRC/desktop/languard.desktop" /usr/share/applications/
  run install -m 644 "$SRC/desktop/languard.svg" /usr/share/icons/hicolor/scalable/apps/
  refresh_menus
  if [ "$HAVE_QT" -eq 1 ] || [ "$DRY" -eq 1 ]; then
    echo "    desktop app: 'LANGuard' in your applications menu (or run languard-gui)"
  else
    echo "    WARNING: PyQt5 isn't available for $PY, so the desktop app won't start;"
    echo "    the command line and the service work without it."
  fi
fi
run chmod 700 /var/lib/languard

# The desktop app reads the alert log as you: let your admin group read it
# (adm on Debian/Ubuntu, wheel on Fedora/openSUSE/Arch).
WHO="${SUDO_USER:-}"
[ -z "$WHO" ] && [ -n "${PKEXEC_UID:-}" ] && WHO="$(id -nu "$PKEXEC_UID" 2>/dev/null || true)"
LOG_GROUP=""
for g in adm wheel sudo; do
  getent group "$g" >/dev/null || continue
  if [ -z "$WHO" ] || id -nG "$WHO" 2>/dev/null | tr ' ' '\n' | grep -qx "$g"; then
    LOG_GROUP="$g"; break
  fi
done
run touch /var/log/languard.log
if [ -n "$LOG_GROUP" ]; then
  run chown "root:$LOG_GROUP" /var/log/languard.log
  echo "    alert log readable by group $LOG_GROUP"
fi
run chmod 640 /var/log/languard.log
if [ ! -f /etc/languard/config.json ]; then
  run cp "$SRC/config.example.json" /etc/languard/config.json
  echo "    wrote /etc/languard/config.json (edit to taste)"
fi
run chmod 644 /etc/languard/config.json   # no secrets; lets "languard status" run without sudo

# ---------------------------------------------------------------- systemd --
if ! command -v systemctl >/dev/null || [ ! -d /run/systemd/system ]; then
  echo "==> systemd isn't running here: skipped the services."
  echo "    Run 'sudo languard monitor' from your init system to protect this machine."
  SYSTEMD=0
else
  SYSTEMD=1
fi

if [ "$SYSTEMD" -eq 1 ]; then
  echo "==> Installing systemd units"
  NFT="$(command -v nft || echo /usr/sbin/nft)"
  for u in "$SRC"/systemd/*.service "$SRC"/systemd/*.timer; do
    if [ "$DRY" -eq 1 ]; then echo "    would install $(basename "$u")"; continue; fi
    sed "s|/usr/sbin/nft|$NFT|g" "$u" > "/etc/systemd/system/$(basename "$u")"
    chmod 644 "/etc/systemd/system/$(basename "$u")"
  done
  run systemctl daemon-reload
fi

# ----------------------------------------------------------------- ClamAV --
# Unit, config and socket names differ: clamav-daemon (Debian, Ubuntu, Arch),
# clamd@scan (Fedora, RHEL), clamd (openSUSE). LANGuard finds them itself.
first_unit() { for u in "$@"; do systemctl cat "$u" >/dev/null 2>&1 && { echo "$u"; return; }; done; }
if [ "$AV" -eq 1 ] && [ "$SYSTEMD" -eq 1 ]; then
  CLAMD="$(first_unit clamav-daemon clamd@scan clamd)"
  FRESH="$(first_unit clamav-freshclam freshclam clamav-freshclam.timer freshclam.timer)"
  # Fedora ships clamd's config with the local socket commented out, and
  # some builds still carry the "Example" line that stops clamd/freshclam.
  for conf in /etc/clamd.d/scan.conf /etc/freshclam.conf /etc/clamav/freshclam.conf \
              /etc/clamav/clamd.conf /etc/clamd.conf; do
    [ -f "$conf" ] || continue
    if grep -q '^Example' "$conf"; then
      echo "    enabling $conf (commenting out its 'Example' line)"
      run sed -i 's/^Example/#Example/' "$conf"
    fi
  done
  if [ -f /etc/clamd.d/scan.conf ] && ! grep -q '^LocalSocket ' /etc/clamd.d/scan.conf; then
    echo "    turning on clamd's local socket in /etc/clamd.d/scan.conf"
    run sed -i 's|^#LocalSocket /run/clamd.scan/clamd.sock|LocalSocket /run/clamd.scan/clamd.sock|' \
      /etc/clamd.d/scan.conf
  fi
  # SELinux (Fedora, RHEL): let clamd read the files it is asked to scan.
  if command -v getenforce >/dev/null && [ "$(getenforce 2>/dev/null)" = Enforcing ] \
     && command -v setsebool >/dev/null; then
    run setsebool -P antivirus_can_scan_system 1 || true
  fi
  if [ "$ENABLE" -eq 1 ]; then
    echo "==> Starting ClamAV (first signature download can take a few minutes)"
    if [ -n "$FRESH" ]; then
      run systemctl enable --now "$FRESH" >/dev/null 2>&1 || true
    elif command -v freshclam >/dev/null; then
      run freshclam --quiet || true
    fi
    if [ -n "$CLAMD" ]; then
      run systemctl enable --now "$CLAMD" >/dev/null 2>&1 \
        || echo "    $CLAMD will start once signatures are downloaded"
    fi
  fi
fi

if [ "$ENABLE" -eq 1 ] && [ "$SYSTEMD" -eq 1 ]; then
  run systemctl enable languard.service languard-guard.timer languard-avscan.timer \
    languard-audit.timer
  run systemctl restart languard.service
  run systemctl start languard-guard.timer languard-avscan.timer languard-audit.timer
  echo "    protection is running and will start at every boot"
fi

if [ "$DRY" -eq 1 ]; then
  echo
  echo "Dry run: nothing was changed."
  exit 0
fi

cat <<'EOF'

Done.
  languard status                     # health + latest alerts
  sudo languard audit                 # hardening check
  sudo languard tls --once            # HTTPS interception check right now
  journalctl -u languard -f           # live alerts
  sudo languard pause 30              # stop protection for 30 min
  sudo languard selftest              # simulated attacks: is it all working?
  sudo languard network --home        # on your own network (--public in cafés)
  languard dnscheck                   # is all DNS going through dnscrypt-proxy?
EOF
[ "$ENABLE" -eq 1 ] || echo "  sudo ./install.sh --enable        # turn on always-on protection"
