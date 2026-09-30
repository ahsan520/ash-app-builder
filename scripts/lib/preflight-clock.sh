#!/usr/bin/env bash
#
# Preflight: refuse to continue if the system clock is wrong.
#
# Why: apt rejects Release files whose timestamps are "in the future" relative
# to the local clock ("Release file ... is not valid yet"), which otherwise
# surfaces as a confusing failure halfway through apt-get update. TLS
# certificate validation and Keycloak/JWT tokens are time-sensitive too.
#
# Typical cause on a VM (e.g. VirtualBox on a laptop): the host sleeps, the VM
# clock stops, and after wake-up it is hours behind. chrony only steps a large
# offset in its first few updates unless "makestep 1 -1" is configured, and
# the kernel's "synchronized" flag stays "no" until chrony's next update.
#
# So this check passes if EITHER
#   - timedatectl reports NTPSynchronized=yes, OR
#   - chrony reports "Leap status: Normal" and a system-time offset under 1s.
# If neither holds it tries to fix things (enable NTP, restart the client,
# `chronyc makestep`) and re-checks for up to 30s before failing.
#
# Source this file (don't execute it):  source "$SCRIPT_DIR/scripts/lib/preflight-clock.sh"
# Set SKIP_CLOCK_CHECK=1 to bypass (e.g. containers where the host owns the clock).

_ntp_synced() {
  [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" == "yes" ]]
}

# chrony has a live NTP source, and the clock is within 1s of it
_chrony_ok() {
  command -v chronyc &>/dev/null || return 1
  local t off
  t="$(chronyc tracking 2>/dev/null)" || return 1
  grep -q '^Leap status *: Normal' <<<"$t" || return 1
  off="$(awk -F: '/^System time/ {split($2, a, " "); print a[1]}' <<<"$t")"
  [[ -n "$off" ]] || return 1
  awk -v o="$off" 'BEGIN { exit !(o + 0 < 1.0 && o + 0 > -1.0) }'
}

_clock_ok() { _ntp_synced || _chrony_ok; }

preflight_clock() {
  echo "== Preflight: system clock =="

  if [[ "${SKIP_CLOCK_CHECK:-0}" == "1" ]]; then
    echo "SKIP_CLOCK_CHECK=1 — skipping clock check (current: $(date -u))."
    return 0
  fi

  if ! command -v timedatectl &>/dev/null || ! timedatectl show &>/dev/null; then
    echo "WARN: timedatectl unavailable (container or no systemd?). Cannot verify NTP sync." >&2
    echo "      The clock comes from the host — verify it there. Current UTC: $(date -u)" >&2
    return 0
  fi

  if ! _clock_ok; then
    echo "WARN: clock not synchronized (UTC now: $(date -u)). Trying to fix..."
    timedatectl set-ntp true || true
    systemctl restart systemd-timesyncd 2>/dev/null || systemctl restart chrony 2>/dev/null || true
    # Step the clock now instead of waiting for chrony to slew a huge offset.
    command -v chronyc &>/dev/null && chronyc makestep 2>/dev/null || true
    for _ in $(seq 1 15); do
      _clock_ok && break
      sleep 2
    done
  fi

  if _ntp_synced; then
    echo "Clock OK: synchronized, UTC now $(date -u)."
  elif _chrony_ok; then
    echo "Clock OK: chrony reports offset < 1s (kernel 'synchronized' flag not set yet), UTC now $(date -u)."
  else
    echo "ERROR: clock is still not synchronized (UTC now: $(date -u))." >&2
    echo "  Fix time before deploying, otherwise apt will reject Release files as 'not valid yet'." >&2
    echo "  - Check: timedatectl status; chronyc tracking   (offset should be < 1s)" >&2
    echo "  - Allow outbound UDP 123 (NTP) through the firewall" >&2
    echo "  - Set 'makestep 1 -1' in /etc/chrony/chrony.conf so chrony can step after a VM pause/host sleep" >&2
    echo "  - VM: keep the host awake / enable guest time sync; then: hwclock --systohc" >&2
    echo "  Bypass (only after checking the time yourself): SKIP_CLOCK_CHECK=1 ./sync-and-deploy.sh" >&2
    return 1
  fi
}
