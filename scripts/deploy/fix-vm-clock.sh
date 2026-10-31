#!/usr/bin/env bash
# Keeps a VirtualBox VM's clock right after the VM (or the Mac under it) was paused, slept or restored.
#   sudo scripts/deploy/fix-vm-clock.sh --install    chrony drop-in "makestep 1 -1" + a timer that steps the clock when it is off by more than 1 second
#   sudo scripts/deploy/fix-vm-clock.sh --remove     undo both
#        scripts/deploy/fix-vm-clock.sh --check      what the timer runs: step the clock if |offset| > ASIX_CLOCK_MAX_OFFSET seconds (default 1)
# Why: chrony steps the clock only for its first few updates ("makestep 1 3"), then only slews, so a jump of minutes or hours after a pause is never corrected.
# "makestep 1 -1" lets it step at any time; the timer is a second line of defence. Run on every VM that has the problem (the ASIX k3s VM and each broker VM).
set -euo pipefail
ROOT="${ASIX_ROOT:-}"                                   # tests point this at a scratch folder
CONF="$ROOT/etc/chrony/conf.d/asix-makestep.conf"
UNIT_DIR="$ROOT/etc/systemd/system"
SELF="$ROOT/usr/local/sbin/asix-fix-vm-clock"
MAX="${ASIX_CLOCK_MAX_OFFSET:-1}"
[[ "$MAX" =~ ^[0-9]+$ ]] || { echo "ASIX_CLOCK_MAX_OFFSET must be whole seconds" >&2; exit 2; }

check() {
  command -v chronyc >/dev/null 2>&1 || { echo "chronyc not found (install chrony)" >&2; exit 1; }
  local out off
  out="$(chronyc tracking 2>/dev/null)" || { echo "chronyd is not answering" >&2; exit 1; }
  off="$(printf '%s\n' "$out" | awk -F: '/^System time/ { split($2, a, " "); print a[1] }')"
  [[ "$off" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "no offset in chronyc tracking, nothing done"; exit 0; }
  if awk -v o="$off" -v m="$MAX" 'BEGIN { exit !(o > m) }'; then
    echo "clock is $off s off, stepping"
    chronyc burst 4/4 >/dev/null 2>&1 || true
    sleep "${ASIX_CLOCK_WAIT:-5}"
    chronyc makestep
  fi
}

install_() {
  [[ -z "$ROOT" && $EUID -ne 0 ]] && { echo "run as root" >&2; exit 2; }
  mkdir -p "$(dirname "$CONF")" "$UNIT_DIR" "$(dirname "$SELF")"
  printf '# ASIX: step the clock whenever it is more than 1 second off (default: only the first 3 updates)\nmakestep 1 -1\n' > "$CONF"
  install -m 0755 "${BASH_SOURCE[0]}" "$SELF"
  cat > "$UNIT_DIR/asix-fix-vm-clock.service" <<UNIT
[Unit]
Description=ASIX: step the VM clock if it drifted
After=chrony.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/asix-fix-vm-clock --check
UNIT
  cat > "$UNIT_DIR/asix-fix-vm-clock.timer" <<UNIT
[Unit]
Description=ASIX: check the VM clock every minute
[Timer]
OnBootSec=60
OnUnitActiveSec=60
[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl restart chrony 2>/dev/null || systemctl restart chronyd 2>/dev/null || true
  systemctl enable --now asix-fix-vm-clock.timer
  echo "installed: $CONF and asix-fix-vm-clock.timer"
}

remove_() {
  systemctl disable --now asix-fix-vm-clock.timer 2>/dev/null || true
  rm -f "$CONF" "$UNIT_DIR/asix-fix-vm-clock.service" "$UNIT_DIR/asix-fix-vm-clock.timer" "$SELF"
  systemctl daemon-reload
  systemctl restart chrony 2>/dev/null || systemctl restart chronyd 2>/dev/null || true
  echo "removed"
}

case "${1:-}" in
  --install) install_ ;;
  --remove) remove_ ;;
  --check) check ;;
  *) sed -n 2,6p "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
