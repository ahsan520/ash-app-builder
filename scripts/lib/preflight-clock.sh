#!/usr/bin/env bash
#
# Preflight: refuse to continue if the system clock isn't NTP-synchronized.
#
# Why: apt rejects Release files whose timestamps are "in the future" relative
# to the local clock ("Release file ... is not valid yet"), which otherwise
# surfaces as a confusing failure halfway through apt-get update. TLS
# certificate validation and k3s/Keycloak tokens are time-sensitive too.
#
# Source this file (don't execute it):  source "$SCRIPT_DIR/scripts/lib/preflight-clock.sh"
# Set SKIP_CLOCK_CHECK=1 to bypass (e.g. containers where the host owns the clock).

_ntp_synced() {
  [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" == "yes" ]]
}

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

  if ! _ntp_synced; then
    echo "WARN: clock not NTP-synchronized (UTC now: $(date -u)). Trying to enable NTP..."
    timedatectl set-ntp true || true
    systemctl restart systemd-timesyncd 2>/dev/null || systemctl restart chrony 2>/dev/null || true
    for _ in $(seq 1 15); do
      _ntp_synced && break
      sleep 2
    done
  fi

  if ! _ntp_synced; then
    echo "ERROR: clock is still not synchronized (UTC now: $(date -u))." >&2
    echo "  Fix time before deploying, otherwise apt will reject Release files as 'not valid yet'." >&2
    echo "  - Check: timedatectl status   (System clock synchronized / NTP service)" >&2
    echo "  - Allow outbound UDP 123 (NTP) through the firewall" >&2
    echo "  - VM: enable host time sync / correct the RTC on the hypervisor" >&2
    echo "  - Then: hwclock --systohc" >&2
    echo "  Bypass (not recommended): SKIP_CLOCK_CHECK=1 ./sync-and-deploy.sh" >&2
    return 1
  fi

  echo "Clock OK: synchronized, UTC now $(date -u)."
}
