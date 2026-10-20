#!/bin/bash
# Upgrades Vector on THIS broker VM (set up by bootstrap-broker.sh). Debian/Ubuntu, as root.
#
# Usage:
#   sudo ./scripts/deploy/upgrade-broker.sh [--version 0.60.0] [--dry-run]
#
# --version X.Y.Z  Install exactly this version from the Vector package repository. Without it, upgrade to the newest
#                  version the repository offers. A version older than the one installed is refused.
# --dry-run        Say what would happen and change nothing.
#
# What it does, in this order, and stops at the first failure:
#   1. reads the installed version (nothing to do if it is already the one asked for)
#   2. installs the package (the running Vector keeps running on its old binary until the restart)
#   3. checks THIS broker's config against the NEW binary with `vector validate`, BEFORE restarting. A release can stop
#      accepting an old config (0.59 stopped substituting ${VAR} unless told to), so a config that fails is left alone:
#      Vector is not restarted and keeps forwarding on the old binary until the next restart
#   4. restarts Vector and waits for its health check
#   5. sends one heartbeat so the Brokers page shows the new version straight away
# It does not touch /etc/asix-broker/broker.env, the keys, the certificates or the buffer on disk.

set -uo pipefail

VERSION=""; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2;;
    --dry-run) DRY=1; shift;;
    *) echo "Unknown option: $1" >&2; exit 2;;
  esac
done
if [ -n "$VERSION" ] && ! [[ "$VERSION" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then echo "--version must look like 0.60.0" >&2; exit 2; fi
[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }

ENV_FILE="${ASIX_BROKER_ENV:-/etc/asix-broker/broker.env}"
VECTOR_DIR="${ASIX_VECTOR_DIR:-/etc/vector}"
WAIT_S="${ASIX_UPGRADE_WAIT_S:-30}"
[ -r "$ENV_FILE" ] || { echo "$ENV_FILE not found: this machine was not set up with bootstrap-broker.sh." >&2; exit 1; }
command -v vector >/dev/null 2>&1 || { echo "Vector is not installed here; run bootstrap-broker.sh first." >&2; exit 1; }
[[ "$WAIT_S" =~ ^[0-9]{1,3}$ ]] || { echo "ASIX_UPGRADE_WAIT_S must be a number of seconds." >&2; exit 2; }

vver() { vector --version 2>/dev/null | awk 'NR==1{print $2}'; }
# 0 equal, 1 first is newer, 2 first is older (plain x.y.z only)
cmp() { local IFS=.; local -a a=($1) b=($2); local i; for i in 0 1 2; do [ "${a[$i]:-0}" -gt "${b[$i]:-0}" ] && return 1; [ "${a[$i]:-0}" -lt "${b[$i]:-0}" ] && return 2; done; return 0; }

CUR="$(vver)"
echo "== ASIX broker upgrade =="
echo "-- Installed Vector: ${CUR:-unknown} --"
OLD_PKG="$(dpkg-query -W -f='${Version}' vector 2>/dev/null || true)"

PKG_SPEC="vector"
if [ -n "$VERSION" ]; then
  if [[ "$CUR" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    cmp "$CUR" "$VERSION"; rc=$?
    [ "$rc" -eq 0 ] && { echo "Already on Vector $VERSION. Nothing to do."; exit 0; }
    [ "$rc" -eq 1 ] && { echo "Vector $CUR is newer than $VERSION. Downgrades are not done by this script." >&2; exit 1; }
  fi
  command -v apt-cache >/dev/null 2>&1 || { echo "apt-cache not found; this script needs Debian or Ubuntu." >&2; exit 1; }
  [ "$DRY" -eq 1 ] || apt-get update -qq || { echo "apt-get update failed; nothing changed." >&2; exit 1; }
  PKG_VER="$(apt-cache madison vector 2>/dev/null | awk '{print $3}' | grep -E "^${VERSION//./\\.}(-|\$)" | head -1)"
  [ -n "$PKG_VER" ] || { echo "The package repository has no Vector $VERSION (apt-cache madison vector lists what it has). Nothing changed." >&2; exit 1; }
  PKG_SPEC="vector=$PKG_VER"
fi

if [ "$DRY" -eq 1 ]; then
  echo "Dry run: would install $PKG_SPEC, validate the config against it, restart Vector and send a heartbeat."; exit 0
fi

echo "-- 1. Installing $PKG_SPEC --"
if [ -n "$VERSION" ]; then
  apt-get install -y "$PKG_SPEC" || { echo "The package install failed. Vector was not restarted." >&2; exit 1; }
else
  apt-get update -qq || { echo "apt-get update failed; nothing changed." >&2; exit 1; }
  apt-get install -y --only-upgrade vector || { echo "The package install failed. Vector was not restarted." >&2; exit 1; }
fi
NEW="$(vver)"
echo "-- Vector on disk is now: ${NEW:-unknown} --"
if [ -n "$CUR" ] && [ "$CUR" = "$NEW" ]; then echo "Already on the newest version the repository offers ($NEW). Nothing was restarted."; exit 0; fi

ROLLBACK="To go back: apt-get install -y --allow-downgrades vector=${OLD_PKG:-<previous version>}"

echo "-- 2. Checking this broker's config against Vector ${NEW:-?} --"
TLS=""; [ -r "$VECTOR_DIR/vector-tls.yaml" ] && TLS="$VECTOR_DIR/vector-tls.yaml"
EXTRA=(); for f in vector-file.yaml vector-http.yaml; do [ -r "$VECTOR_DIR/$f" ] && EXTRA+=("$VECTOR_DIR/$f"); done   # the optional file and HTTP inputs, when installed
if ! ( set -a; . "$ENV_FILE"; set +a; vector validate --no-environment ${TLS:+"$TLS"} ${EXTRA[@]+"${EXTRA[@]}"} "$VECTOR_DIR/vector.yaml" ); then
  echo "The config does not pass 'vector validate' on Vector ${NEW:-?}. Vector was NOT restarted: the running process keeps forwarding on the old binary." >&2
  echo "$ROLLBACK" >&2
  exit 1
fi

echo "-- 3. Restarting Vector --"
systemctl restart vector || { echo "systemctl restart vector failed. $ROLLBACK" >&2; exit 1; }
HEALTH="${ASIX_VECTOR_HEALTH_URL:-http://127.0.0.1:8686/health}"
HEALTH="$( set -a; . "$ENV_FILE"; set +a; echo "${ASIX_VECTOR_HEALTH_URL:-$HEALTH}" )"
ok=0
for _ in $(seq 1 "$WAIT_S"); do
  if curl -fsS -m 3 "$HEALTH" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
[ "$ok" -eq 1 ] || { echo "Vector did not become healthy within ${WAIT_S}s after the restart (journalctl -u vector). $ROLLBACK" >&2; exit 1; }

echo "-- 4. Heartbeat --"
systemctl start asix-broker-heartbeat.service >/dev/null 2>&1 || echo "(the heartbeat will report the new version within a minute)"
echo "Done: Vector ${CUR:-?} -> ${NEW:-?}, healthy."
