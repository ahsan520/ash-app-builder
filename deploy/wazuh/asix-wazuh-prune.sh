#!/bin/bash
# Keeps a Wazuh manager's log folders from filling the broker VM's disk (docs/endpoints.md, task E4b). Run daily by asix-wazuh-prune.timer.
# The manager rotates archives.json and alerts.json every day into logs/archives/YEAR/Mon/ossec-archive-DD.json.gz (and logs/alerts/...) and never deletes
# anything. ASIX already has the events (the broker sent them), so this keeps only the last ASIX_WAZUH_KEEP_DAYS days of rotated files (default 3, set in
# /etc/asix-broker/wazuh.env). It never touches the live archives.json and alerts.json files, which the broker is reading.
# DISK GUARD: when the disk holding the logs is ASIX_WAZUH_DISK_PCT percent full (default 90) or more, rotated files older than one day go too, and it says so.
# Everything it removes is printed (journalctl -u asix-wazuh-prune).
set -u
DIR="${ASIX_WAZUH_DIR:-/var/ossec}"
KEEP="${ASIX_WAZUH_KEEP_DAYS:-3}"; [[ "$KEEP" =~ ^[0-9]{1,3}$ ]] && [ "$KEEP" -ge 1 ] || KEEP=3
LIMIT="${ASIX_WAZUH_DISK_PCT:-90}"; [[ "$LIMIT" =~ ^[0-9]{1,3}$ ]] || LIMIT=90
LOGS="$DIR/logs"
[ -d "$LOGS" ] || { echo "No $LOGS: nothing to prune."; exit 0; }

prune() {  # $1 = delete rotated files modified more than this many days ago
  local days="$1" n=0 f
  for d in "$LOGS/archives" "$LOGS/alerts"; do
    [ -d "$d" ] || continue
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      rm -f -- "$f" && { echo "removed $f"; n=$((n + 1)); }
    done < <(find "$d" -mindepth 2 -type f -name 'ossec-*' -mtime +"$((days - 1))" 2>/dev/null)
    find "$d" -mindepth 1 -type d -empty -delete 2>/dev/null
  done
  echo "Removed $n rotated file(s) older than $days day(s)."
}

prune "$KEEP"
PCT="$(df --output=pcent "$LOGS" 2>/dev/null | tail -n 1 | tr -dc '0-9')"
if [ -n "$PCT" ] && [ "$PCT" -ge "$LIMIT" ]; then
  echo "WARNING: the disk holding $LOGS is $PCT% full (limit $LIMIT%): keeping only one day of rotated files." >&2
  prune 1
  PCT="$(df --output=pcent "$LOGS" 2>/dev/null | tail -n 1 | tr -dc '0-9')"
  [ -z "$PCT" ] || [ "$PCT" -lt "$LIMIT" ] || echo "WARNING: still $PCT% full. The live files are too big: check that the broker is reading $LOGS/archives/archives.json (journalctl -u vector) and consider a bigger disk." >&2
fi
exit 0
