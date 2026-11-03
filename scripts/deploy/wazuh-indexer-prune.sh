#!/bin/bash
# Removes the vulnerability indices of managers that no longer exist, from the central findings indexer (docs/wazuh-indexer.md, "Removing the indices of removed managers"; docs/endpoints.md, task E6j).
# Each manager writes its own index, wazuh-states-vulnerabilities-<manager name>. Removing a manager (or renaming it) leaves that index on the indexer's disk for ever. ASIX cannot clean it up:
# its indexer users are read-only on one index each, by design. This script runs on the INDEXER machine, as root, with the admin password in /etc/wazuh-indexer/asix-admin.pass.
#
# Which indices are still wanted comes from ASIX, never from a guess: the indices registered for the tenants (wazuh-indexer-cli.js, command `indices`) are the KEEP LIST.
#   on the ASIX machine:  kubectl -n asix-platform exec deploy/asix-api -- node src/endpoints/wazuh-indexer-cli.js indices > keep.txt      (copy keep.txt to the indexer machine)
#   on the indexer:       sudo ./scripts/deploy/wazuh-indexer-prune.sh --keep-file keep.txt                  # preview: changes nothing
#                         sudo ./scripts/deploy/wazuh-indexer-prune.sh --keep-file keep.txt --delete         # removes what the preview listed
#
# Options:
#   --keep-file F       the registered index names, one per line (blank lines and # comments are allowed). Required. A line that is not an exact index name is refused, nothing is guessed.
#   --delete            really delete. Without it this only shows what it would do.
#   --min-age-days N    never touch an index created less than N days ago (default 7): a manager that was installed lately and is not registered in ASIX yet keeps its index.
#   --max-delete N      refuse to delete more than N indices in one run (default 5); raise it on purpose.
#   --url U             the indexer's address as it listens (default: ASIX_HEALTH_INDEXER_URL from /etc/asix-indexer/health.env if present, else https://127.0.0.1:9200)
#   --ca F              the indexer's root CA (default /etc/wazuh-indexer/certs/root-ca.pem)
# Safety, in the order they are checked:
#   - only names that match wazuh-states-vulnerabilities-<name> are ever looked at, and each delete names ONE exact index (no wildcard in a delete, ever);
#   - an empty keep file is refused, and so is a keep file none of whose names exists on this indexer (the wrong file, or the wrong indexer): the script will not decide that everything is orphaned;
#   - an index in the keep file is never touched; an index younger than --min-age-days is never touched;
#   - more than --max-delete candidates is refused.
# A deleted index is gone: the manager that owns it, if it still runs, writes a new one on its next scan, but its findings are not recovered from anywhere else. The preview shows each index's documents and size.
# Exit: 0 done (or nothing to do, or a preview), 1 refused or failed (the reason on stderr), 2 a wrong option or file.
set -uo pipefail

KEEP_FILE=""; DELETE=0; MIN_AGE=7; MAX_DEL=5; URL=""; CA="${ASIX_PRUNE_CA:-/etc/wazuh-indexer/certs/root-ca.pem}"; PW="${ASIX_PRUNE_ADMIN_PW:-/etc/wazuh-indexer/asix-admin.pass}"
HEALTH_ENV="${ASIX_PRUNE_HEALTH_ENV:-/etc/asix-indexer/health.env}"
while [ $# -gt 0 ]; do
  case "$1" in
    --keep-file) KEEP_FILE="${2:-}"; shift 2;;
    --delete) DELETE=1; shift;;
    --min-age-days) MIN_AGE="${2:-}"; shift 2;;
    --max-delete) MAX_DEL="${2:-}"; shift 2;;
    --url) URL="${2:-}"; shift 2;;
    --ca) CA="${2:-}"; shift 2;;
    *) echo "Unknown option: $1" >&2; exit 2;;
  esac
done
bad() { echo "$*" >&2; exit 2; }
refuse() { echo "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || refuse "Run as root."
for c in curl python3; do command -v "$c" >/dev/null 2>&1 || refuse "Missing '$c'."; done
[ -n "$KEEP_FILE" ] || bad "--keep-file is required (the registered index names from: wazuh-indexer-cli.js indices)."
[ -r "$KEEP_FILE" ] || bad "Cannot read $KEEP_FILE."
[[ "$MIN_AGE" =~ ^[0-9]{1,4}$ ]] || bad "--min-age-days must be a whole number."
[[ "$MAX_DEL" =~ ^[0-9]{1,4}$ ]] || bad "--max-delete must be a whole number."
if [ -z "$URL" ] && [ -r "$HEALTH_ENV" ]; then URL="$(sed -n 's/^ASIX_HEALTH_INDEXER_URL=//p' "$HEALTH_ENV" | tail -n 1)"; fi
URL="${URL:-https://127.0.0.1:9200}"
[[ "$URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || bad "--url must look like https://host:9200 (https, no path)."
[ -s "$CA" ] || refuse "No CA file at $CA (--ca)."
[ -s "$PW" ] || refuse "No admin password file at $PW."

NAME_RE='^wazuh-states-vulnerabilities-[a-z0-9][a-z0-9._-]{0,100}$'
declare -A KEEP=(); NKEEP=0
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%%#*}"; line="${line//$'\r'/}"; line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"   # trim both ends only: a space INSIDE a name stays and fails the check below
  [ -n "$line" ] || continue
  [[ "$line" =~ $NAME_RE ]] || bad "$KEEP_FILE: '$line' is not an index name of the form wazuh-states-vulnerabilities-<manager>. Nothing was changed."
  KEEP["$line"]=1; NKEEP=$((NKEEP + 1))
done < "$KEEP_FILE"
[ "$NKEEP" -gt 0 ] || refuse "$KEEP_FILE holds no index names. Refusing: an empty keep list would make every index look orphaned."

call() {   # call METHOD PATH -> body on stdout; non-zero when curl fails or the answer is not 2xx. The admin password goes to curl on a file descriptor.
  local cfg out code
  cfg="$(printf 'silent\nshow-error\nmax-time = 30\nrequest = "%s"\nurl = "%s%s"\nuser = "admin:%s"\n' "$1" "$URL" "$2" "$(cat "$PW")")"
  out="$(curl -K <(printf '%s\n' "$cfg") --cacert "$CA" -w $'\n%{http_code}' 2>/dev/null)" || return 1
  code="${out##*$'\n'}"; [[ "$code" =~ ^2[0-9][0-9]$ ]] || { echo "the indexer answered HTTP $code" >&2; return 1; }
  printf '%s' "${out%$'\n'*}"
}
LIST="$(call GET '/_cat/indices/wazuh-states-vulnerabilities-*?format=json&bytes=b&h=index,docs.count,store.size,creation.date')" || refuse "Could not list the indices at $URL (wrong address, CA or admin password?)."

# one line per index: name <TAB> docs <TAB> bytes <TAB> age in days (whole)
ROWS="$(printf '%s' "$LIST" | python3 -c '
import sys, json, time
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(3)
now = time.time() * 1000
for r in sorted(d, key=lambda r: r.get("index", "")):
    try:
        age = int((now - float(r.get("creation.date") or 0)) / 86400000)
    except Exception:
        age = 0
    print("%s\t%s\t%s\t%d" % (r.get("index", ""), r.get("docs.count") or 0, r.get("store.size") or 0, max(age, 0)))
')" || refuse "The indexer's answer was not a list of indices."

human() { python3 -c 'import sys; n=float(sys.argv[1]); u=["B","KB","MB","GB","TB"]; i=0
while n>=1024 and i<4: n/=1024; i+=1
print("%.1f %s" % (n,u[i]))' "$1"; }

CANDIDATES=(); CAND_BYTES=0; KEPT_FOUND=0; TOTAL=0
echo "Indices on $URL (keep list: $NKEEP name(s) from $KEEP_FILE):"
while IFS=$'\t' read -r name docs bytes age; do
  [ -n "$name" ] || continue
  [[ "$name" =~ $NAME_RE ]] || { echo "  ?  $name  (not an index name this script handles: left alone)"; continue; }
  TOTAL=$((TOTAL + 1))
  if [ -n "${KEEP[$name]:-}" ]; then KEPT_FOUND=$((KEPT_FOUND + 1)); printf '  keep    %s  %s docs, %s, %s day(s) old  (registered in ASIX)\n' "$name" "$docs" "$(human "$bytes")" "$age"
  elif [ "$age" -lt "$MIN_AGE" ]; then printf '  skip    %s  %s docs, %s, %s day(s) old  (younger than --min-age-days %s)\n' "$name" "$docs" "$(human "$bytes")" "$age" "$MIN_AGE"
  else CANDIDATES+=("$name"); CAND_BYTES=$((CAND_BYTES + bytes)); printf '  ORPHAN  %s  %s docs, %s, %s day(s) old  (not registered in ASIX)\n' "$name" "$docs" "$(human "$bytes")" "$age"
  fi
done <<< "$ROWS"

[ "${#CANDIDATES[@]}" -gt 0 ] || { echo "Nothing to remove."; exit 0; }
if [ "$KEPT_FOUND" -eq 0 ]; then refuse "None of the $NKEEP registered index name(s) exists on this indexer. Refusing to treat all $TOTAL as orphaned: is the keep file from the right ASIX, and is this the right indexer?"; fi
if [ "${#CANDIDATES[@]}" -gt "$MAX_DEL" ]; then refuse "${#CANDIDATES[@]} indices would be removed, more than --max-delete $MAX_DEL. Check the list above; if it is right, run again with --max-delete ${#CANDIDATES[@]}."; fi
echo "${#CANDIDATES[@]} orphaned index(es), $(human "$CAND_BYTES") to reclaim."
if [ "$DELETE" -ne 1 ]; then echo "Preview only. Nothing was removed. Add --delete to remove them."; exit 0; fi

FAILED=0
for name in "${CANDIDATES[@]}"; do
  [[ "$name" =~ $NAME_RE ]] || continue   # again, at the moment of deleting: an exact name, no wildcard
  if R="$(call DELETE "/$name")" && printf '%s' "$R" | python3 -c 'import sys,json; sys.exit(0 if json.load(sys.stdin).get("acknowledged") is True else 1)' 2>/dev/null; then echo "  removed $name"
  else echo "  FAILED  $name" >&2; FAILED=$((FAILED + 1)); fi
done
[ "$FAILED" -eq 0 ] || refuse "$FAILED index(es) could not be removed (see above)."
echo "Done: removed ${#CANDIDATES[@]} index(es), about $(human "$CAND_BYTES")."
