#!/bin/bash
# Installs the disk and health reporter on the central findings indexer VM (docs/wazuh-indexer.md, "Watching the indexer's disk"; docs/endpoints.md, task E6i).
# Every few minutes a systemd timer runs deploy/indexer/asix-indexer-health.sh, which sends ONE small event to ASIX (disk used, free space, the indexer's own
# health, how many indices it has made read-only). ASIX's built-in rules "Endpoint findings store ..." raise the alerts; nothing else is needed on the ASIX side.
#
# Usage (as root, on the indexer machine):
#   ./scripts/deploy/install-indexer-health.sh --url https://ASIX-ADDRESS[:PORT] --key-file FILE [--collector NAME] [--ca-file FILE] [--data-path PATH] [--interval-min N]
#   ./scripts/deploy/install-indexer-health.sh --check  [same options]     # look only: measures and prints what would be sent, changes and sends nothing
#   ./scripts/deploy/install-indexer-health.sh --remove                     # stops the timer and removes everything this installed
#
#   --url U            ASIX's API address as the indexer machine reaches it (https, no path), for example https://192.168.68.57:30443
#   --key-file F       a file holding an ingestion key (asix_ik_...): in ASIX, Settings, Installers, make a key named for this machine (for example indexer-vm). The key is
#                      copied to /etc/asix-indexer/health.key (root only); read it from a file, never from the command line.
#   --collector N      the name this machine shows under in ASIX (default indexer-<host name>); it is also the name to give "Alert if silent" on the Collectors page.
#   --ca-file F        a certificate to trust for ASIX's address (a self-signed install): the CA, or the server certificate itself. Default: the system store.
#   --data-path P      the folder that holds the indexer's data (default /var/lib/wazuh-indexer); the disk that holds it is the one measured.
#   --interval-min N   minutes between reports, 1 to 60 (default 5). The built-in rules count two reports in 15 minutes for the "unhealthy" alert, so keep it at 7 or less.
# Safe to run again (the settings are rewritten, the key is replaced by the one given). The first report is sent at the end so a wrong address or key is found now.
set -euo pipefail

URL=""; KEY_FILE=""; COLLECTOR=""; CA_FILE=""; DATA_PATH="/var/lib/wazuh-indexer"; INTERVAL="5"; CHECK=0; REMOVE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="$2"; shift 2;;
    --key-file) KEY_FILE="$2"; shift 2;;
    --collector) COLLECTOR="$2"; shift 2;;
    --ca-file) CA_FILE="$2"; shift 2;;
    --data-path) DATA_PATH="$2"; shift 2;;
    --interval-min) INTERVAL="$2"; shift 2;;
    --check) CHECK=1; shift;;
    --remove) REMOVE=1; shift;;
    *) echo "Unknown option: $1" >&2; exit 2;;
  esac
done

# Where things are. The environment variables exist for the tests; on the indexer VM the defaults are right.
ETC="${ASIX_HEALTH_ETC:-/etc/asix-indexer}"; LIB="${ASIX_HEALTH_LIB:-/usr/local/lib/asix-indexer}"; UNITS="${ASIX_SYSTEMD_DIR:-/etc/systemd/system}"
HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="${ASIX_HEALTH_SRC:-$HERE/../../deploy/indexer}"

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
if [ "$REMOVE" -eq 1 ]; then
  if command -v systemctl >/dev/null 2>&1; then systemctl disable --now asix-indexer-health.timer >/dev/null 2>&1 || true; fi
  rm -f "$UNITS/asix-indexer-health.service" "$UNITS/asix-indexer-health.timer" "$LIB/asix-indexer-health.sh" "$ETC/health.env" "$ETC/health.key"
  rmdir "$LIB" "$ETC" 2>/dev/null || true
  if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi
  echo "Removed the timer, the script and the settings. The alerts and the collector row stay in ASIX (delete the collector there if you want it gone)."
  exit 0
fi

[ -n "$URL" ] || { echo "--url is required (ASIX's API address, for example https://192.168.68.57:30443)." >&2; exit 2; }
[[ "$URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || { echo "--url must look like https://host or https://host:port (https, no path)." >&2; exit 2; }
[ -n "$KEY_FILE" ] || { echo "--key-file is required (a file holding an ingestion key, asix_ik_...)." >&2; exit 2; }
[ -n "$COLLECTOR" ] || COLLECTOR="indexer-$(hostname 2>/dev/null | cut -d. -f1)"
[[ "$COLLECTOR" =~ ^[A-Za-z0-9._:-]{1,100}$ ]] || { echo "--collector must be 1 to 100 letters, digits or . _ : -" >&2; exit 2; }
[[ "$DATA_PATH" =~ ^/[A-Za-z0-9._/-]{0,200}$ ]] || { echo "--data-path must be an absolute path of plain characters." >&2; exit 2; }
[[ "$INTERVAL" =~ ^[0-9]{1,2}$ ]] && [ "$INTERVAL" -ge 1 ] && [ "$INTERVAL" -le 60 ] || { echo "--interval-min must be a number from 1 to 60." >&2; exit 2; }
[ -s "$KEY_FILE" ] || { echo "No key in $KEY_FILE." >&2; exit 2; }
KEY="$(tr -d ' \t\r\n' < "$KEY_FILE")"
[[ "$KEY" =~ ^asix_ik_[A-Za-z0-9_-]{20,128}$ ]] || { echo "$KEY_FILE does not hold an ingestion key (it starts with asix_ik_)." >&2; exit 2; }
[ -z "$CA_FILE" ] || [ -s "$CA_FILE" ] || { echo "--ca-file $CA_FILE is not a file." >&2; exit 2; }
for f in asix-indexer-health.sh asix-indexer-health.service asix-indexer-health.timer; do [ -f "$SRC/$f" ] || { echo "Missing $SRC/$f (run this from a checkout of the repository)." >&2; exit 1; }; done
for c in curl python3 awk df; do command -v "$c" >/dev/null 2>&1 || { echo "Missing '$c': apt-get install -y curl python3 gawk coreutils" >&2; exit 1; }; done
if [ "$INTERVAL" -gt 7 ]; then echo "   warning: with a report every $INTERVAL minutes the built-in \"unhealthy\" alert (two reports in 15 minutes) can never fire." >&2; fi
[ -d "$DATA_PATH" ] || echo "   warning: $DATA_PATH does not exist on this machine: the report will say the disk was not measured. Is this the indexer VM? (--data-path)" >&2

echo "== 1. What would be sent =="
if [ "$CHECK" -eq 1 ]; then
  ASIX_HEALTH_ENV=/nonexistent ASIX_HEALTH_DATA_PATH="$DATA_PATH" ASIX_HEALTH_COLLECTOR="$COLLECTOR" bash "$SRC/asix-indexer-health.sh" --print
  echo "Checks passed. Nothing was installed and nothing was sent."
  exit 0
fi
ASIX_HEALTH_ENV=/nonexistent ASIX_HEALTH_DATA_PATH="$DATA_PATH" ASIX_HEALTH_COLLECTOR="$COLLECTOR" bash "$SRC/asix-indexer-health.sh" --print

command -v systemctl >/dev/null 2>&1 || { echo "This installer needs systemd." >&2; exit 1; }
echo "== 2. Files =="
install -d -m 755 "$LIB"; install -d -m 750 "$ETC"
install -m 755 "$SRC/asix-indexer-health.sh" "$LIB/asix-indexer-health.sh"
( umask 077; printf '%s\n' "$KEY" > "$ETC/health.key.new" ); chmod 600 "$ETC/health.key.new"; mv -f "$ETC/health.key.new" "$ETC/health.key"
{
  printf 'ASIX_HEALTH_URL=%s\nASIX_HEALTH_COLLECTOR=%s\nASIX_HEALTH_DATA_PATH=%s\nASIX_HEALTH_KEY_FILE=%s\n' "$URL" "$COLLECTOR" "$DATA_PATH" "$ETC/health.key"
  if [ -n "$CA_FILE" ]; then
    install -m 644 "$CA_FILE" "$ETC/asix-ca.pem"; printf 'ASIX_HEALTH_CA=%s\n' "$ETC/asix-ca.pem"
  else
    rm -f "$ETC/asix-ca.pem"
  fi
} > "$ETC/health.env.new"
chmod 640 "$ETC/health.env.new"; mv -f "$ETC/health.env.new" "$ETC/health.env"
install -m 644 "$SRC/asix-indexer-health.service" "$UNITS/asix-indexer-health.service"
sed "s/^OnUnitActiveSec=.*/OnUnitActiveSec=${INTERVAL}min/" "$SRC/asix-indexer-health.timer" > "$UNITS/asix-indexer-health.timer.new"; chmod 644 "$UNITS/asix-indexer-health.timer.new"; mv -f "$UNITS/asix-indexer-health.timer.new" "$UNITS/asix-indexer-health.timer"
echo "   $LIB/asix-indexer-health.sh, $ETC/health.env, $ETC/health.key (root only), the service and the timer (every ${INTERVAL} minutes)"

echo "== 3. Timer and a first report =="
systemctl daemon-reload
systemctl enable --now asix-indexer-health.timer >/dev/null 2>&1 || systemctl enable --now asix-indexer-health.timer
if ! "$LIB/asix-indexer-health.sh" --env "$ETC/health.env"; then
  echo "The timer is installed, but the first report did not reach ASIX (the reason is above). Fix the address, the key or --ca-file and run this again." >&2
  exit 1
fi
echo
echo "Done. $COLLECTOR now reports every ${INTERVAL} minutes. In ASIX:"
echo "  - Collectors page: $COLLECTOR appears after the first report; press \"Alert if silent\" on it (for example 20 minutes) to be told when the reports stop."
echo "  - Detections page: four built-in rules \"Endpoint findings store ...\" (disk 80% and 90%, writes refused, indexer unhealthy) are on by default and use the notification channels you already have."
echo "  - Search: dataset = indexer-health shows each report."
