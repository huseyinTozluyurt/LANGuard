#!/usr/bin/env bash
# Remove LANGuard.  Usage: sudo ./uninstall.sh [--purge]
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }

# Guard timer first, so it doesn't restart the service mid-uninstall.
for u in languard-guard.timer languard-avscan.timer languard-audit.timer languard.service; do
  systemctl disable --now "$u" 2>/dev/null || true
done
# Undo active protection (router pin, isolated devices, IPv6 lockdown).
[ -x /usr/local/bin/languard ] && /usr/local/bin/languard protect --undo-all >/dev/null 2>&1 || true
nft delete table netdev languard 2>/dev/null || true
nft delete table inet languard_guard 2>/dev/null || true
nft delete table inet languard_ip 2>/dev/null || true
rm -f /etc/systemd/system/languard*.service /etc/systemd/system/languard*.timer
systemctl daemon-reload 2>/dev/null || true
rm -f /usr/local/bin/languard /usr/local/bin/languard-gui
# Extra link the installer made where sudo doesn't search /usr/local/bin.
if [ "$(readlink /usr/bin/languard 2>/dev/null || true)" = /opt/languard/languard.py ]; then
  rm -f /usr/bin/languard
fi
rm -f /usr/share/polkit-1/actions/org.languard.policy /usr/share/applications/languard.desktop \
  /usr/share/icons/hicolor/scalable/apps/languard.svg
command -v update-desktop-database >/dev/null && { update-desktop-database -q /usr/share/applications || true; }
if command -v gtk-update-icon-cache >/dev/null && [ -f /usr/share/icons/hicolor/index.theme ]; then
  gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
fi
rm -rf /run/languard
rm -rf /opt/languard

if [ "${1:-}" = "--purge" ]; then
  if ls /var/lib/languard/quarantine/*.json >/dev/null 2>&1; then
    echo "Quarantine is not empty; kept /var/lib/languard/quarantine"
    find /var/lib/languard -mindepth 1 -maxdepth 1 ! -name quarantine -exec rm -rf {} +
  else
    rm -rf /var/lib/languard
  fi
  rm -rf /etc/languard
  rm -f /var/log/languard.log /var/log/languard-audit.json
  rm -f /etc/systemd/resolved.conf.d/languard.conf
  if [ -f /etc/sysctl.d/99-languard.conf ]; then
    rm -f /etc/sysctl.d/99-languard.conf && { sysctl --system >/dev/null 2>&1 || true; }
  fi
  systemctl try-restart systemd-resolved 2>/dev/null || true
fi
if command -v apt-get >/dev/null; then RM="sudo apt remove clamav clamav-daemon"
elif command -v dnf >/dev/null; then RM="sudo dnf remove clamav clamd clamav-update"
elif command -v zypper >/dev/null; then RM="sudo zypper remove clamav"
elif command -v pacman >/dev/null; then RM="sudo pacman -Rs clamav"
else RM="your package manager"; fi
echo "LANGuard removed. (ClamAV was left installed: $RM)"
