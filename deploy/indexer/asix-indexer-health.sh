#!/bin/bash
# Reports the disk and the health of the central findings indexer VM to ASIX (docs/wazuh-indexer.md, "Watching the indexer's disk"; docs/endpoints.md, task E6i).
# Runs as root on the indexer machine from a systemd timer (asix-indexer-health.timer, every 5 minutes by default), installed by scripts/deploy/install-indexer-health.sh.
#
# It sends ONE event per run to ASIX's HTTP ingest lane (POST /v1/ingest/http, an ingestion key, source type `indexer-health`). ASIX's built-in rules
# ("Endpoint findings store ...", src/detection/rule-runner.js) read the fields. Nothing else is sent: no index names, no findings, no passwords.
#
#   disk_used_pct, disk_free_gb, disk_total_gb   the filesystem that holds ASIX_HEALTH_DATA_PATH (used = total minus what a normal process may still write, the way OpenSearch counts)
#   cluster_status                                green | yellow | red (the indexer's own answer), unreachable (it did not answer, or answered with a server error), unknown (no admin password file here, the password was refused, or an answer that is not JSON)
#   write_blocked_indices                         how many indices the indexer has switched to read-only because the disk passed its flood-stage limit (95%); left out when unknown
#   disk_path                                     the path measured
#
# Usage:   asix-indexer-health.sh [--print] [--env FILE]
#   --print    print the body that would be sent and send nothing (no ASIX address or key needed)
#   --env F    read the settings from F instead of /etc/asix-indexer/health.env (systemd passes the same file as EnvironmentFile)
# Exit: 0 sent and accepted (HTTP 2xx), 1 measured but could not send (the reason on stderr), 2 a setting is missing or wrong.
#
# Settings (environment, normally from health.env):
#   ASIX_HEALTH_URL            https://host[:port] of ASIX's API (required unless --print)
#   ASIX_HEALTH_KEY_FILE       a file holding an ingestion key (asix_ik_...), default /etc/asix-indexer/health.key
#   ASIX_HEALTH_COLLECTOR      the sender's name in ASIX (default indexer-<host name>)
#   ASIX_HEALTH_CA             a CA or certificate file to trust for ASIX's address (default: the system store)
#   ASIX_HEALTH_DATA_PATH      default /var/lib/wazuh-indexer
#   ASIX_HEALTH_INDEXER_URL    default https://127.0.0.1:9200
#   ASIX_HEALTH_INDEXER_CA     default /etc/wazuh-indexer/certs/root-ca.pem
#   ASIX_HEALTH_ADMIN_PW       the file install-wazuh-indexer.sh keeps the admin password in, default /etc/wazuh-indexer/asix-admin.pass
# Secrets (the key, the admin password) go to curl through a config on a file descriptor, never on a command line, and are never printed.
set -uo pipefail

PRINT=0; ENVFILE="${ASIX_HEALTH_ENV:-/etc/asix-indexer/health.env}"
while [ $# -gt 0 ]; do
  case "$1" in
    --print) PRINT=1; shift;;
    --env) ENVFILE="$2"; shift 2;;
    *) echo "Unknown option: $1" >&2; exit 2;;
  esac
done
# A settings file given with --env is read here; under systemd the same lines are already in the environment. Only plain NAME=value lines for our own names are taken.
if [ -r "$ENVFILE" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ASIX_HEALTH_[A-Z_]*=*) k="${line%%=*}"; v="${line#*=}"; v="${v#\"}"; v="${v%\"}"; [ -n "${!k:-}" ] || export "$k=$v";;
    esac
  done < "$ENVFILE"
fi

URL="${ASIX_HEALTH_URL:-}"; KEY_FILE="${ASIX_HEALTH_KEY_FILE:-/etc/asix-indexer/health.key}"; CA="${ASIX_HEALTH_CA:-}"
DATA_PATH="${ASIX_HEALTH_DATA_PATH:-/var/lib/wazuh-indexer}"; IDX_URL="${ASIX_HEALTH_INDEXER_URL:-https://127.0.0.1:9200}"
IDX_CA="${ASIX_HEALTH_INDEXER_CA:-/etc/wazuh-indexer/certs/root-ca.pem}"; ADMIN_PW="${ASIX_HEALTH_ADMIN_PW:-/etc/wazuh-indexer/asix-admin.pass}"
HOST="$(hostname 2>/dev/null || echo unknown-host)"; HOST="${HOST%%.*}"
COLLECTOR="${ASIX_HEALTH_COLLECTOR:-indexer-$HOST}"

bad() { echo "asix-indexer-health: $*" >&2; exit 2; }
for c in curl python3 awk df; do command -v "$c" >/dev/null 2>&1 || bad "'$c' is missing."; done
[[ "$COLLECTOR" =~ ^[A-Za-z0-9._:-]{1,100}$ ]] || bad "ASIX_HEALTH_COLLECTOR must be 1 to 100 letters, digits or . _ : -"
[[ "$DATA_PATH" =~ ^/[A-Za-z0-9._/-]{0,200}$ ]] || bad "ASIX_HEALTH_DATA_PATH must be an absolute path of plain characters."
if [ "$PRINT" -eq 0 ]; then
  [[ "$URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || bad "ASIX_HEALTH_URL must look like https://asix.example:30443 (https, no path)."
  [ -s "$KEY_FILE" ] || bad "no ingestion key in $KEY_FILE."
  KEY="$(tr -d ' \t\r\n' < "$KEY_FILE")"
  [[ "$KEY" =~ ^asix_ik_[A-Za-z0-9_-]{20,128}$ ]] || bad "$KEY_FILE does not hold an ingestion key (asix_ik_...)."
  [ -z "$CA" ] || [ -s "$CA" ] || bad "ASIX_HEALTH_CA $CA is not a file."
fi

# --- 1. the disk. df -P: Filesystem 1024-blocks Used Available Capacity Mounted. Used% here is (total - available) / total, which counts the reserved blocks as used, as OpenSearch does.
DISK=""
if [ -e "$DATA_PATH" ]; then
  DISK="$(df -Pk -- "$DATA_PATH" 2>/dev/null | awk 'NR == 2 && $2 > 0 { printf "%.1f %.1f %.1f", 100 * ($2 - $4) / $2, $4 / 1048576, $2 / 1048576 }')"
fi

# --- 2. the indexer, as admin. Only two read calls; a problem here never stops the report (the disk is the part that matters most).
STATUS="unknown"; BLOCKED=""
call() {   # call PATH -> the body on stdout. Returns 0 on a 2xx answer, 3 when the indexer refused the admin password (401/403: says nothing about its health), 1 for anything else (no answer, TLS failure, 5xx).
  local cfg out code
  cfg="$(printf 'silent\nshow-error\nmax-time = 10\nurl = "%s%s"\nuser = "admin:%s"\n' "$IDX_URL" "$1" "$(cat "$ADMIN_PW")")"
  out="$(curl -K <(printf '%s\n' "$cfg") --cacert "$IDX_CA" -w $'\n%{http_code}' 2>/dev/null)" || return 1
  code="${out##*$'\n'}"
  case "$code" in 2[0-9][0-9]) printf '%s' "${out%$'\n'*}"; return 0;; 401|403) return 3;; *) return 1;; esac
}
if [ -s "$ADMIN_PW" ] && [ -s "$IDX_CA" ]; then
  H=""; rc=0; H="$(call /_cluster/health)" || rc=$?
  if [ "$rc" -eq 0 ]; then
    STATUS="$(printf '%s' "$H" | python3 -c 'import sys,json
try:
    s = json.load(sys.stdin).get("status", "")
except Exception:
    s = ""
print(s if s in ("green", "yellow", "red") else "unknown")' 2>/dev/null)"; STATUS="${STATUS:-unknown}"
    # Indices the indexer made read-only (index.blocks.read_only_allow_delete = true) when the disk passed the flood stage: writes to them are refused until space is freed.
    S=""; rc=0; S="$(call '/_all/_settings/index.blocks.*?flat_settings=true')" || rc=$?
    if [ "$rc" -eq 0 ]; then
      BLOCKED="$(printf '%s' "$S" | python3 -c 'import sys,json
try:
    d = json.load(sys.stdin)
    n = 0
    for v in d.values():
        st = (v or {}).get("settings") or {}
        if str(st.get("index.blocks.read_only_allow_delete", "false")).lower() == "true" or str(st.get("index.blocks.read_only", "false")).lower() == "true":
            n += 1
    print(n)
except Exception:
    print("")' 2>/dev/null)"
    fi
  elif [ "$rc" -eq 1 ]; then
    STATUS="unreachable"
  fi   # rc 3: the indexer is there but refused the admin password: health stays "unknown" (the disk is still reported)
fi

# --- 3. the body: a JSON array with one event. Built by python3 so no value can break the JSON.
BODY="$(DISK="$DISK" STATUS="$STATUS" BLOCKED="$BLOCKED" HOST="$HOST" DATA_PATH="$DATA_PATH" python3 -c '
import os, json
disk = os.environ["DISK"].split()
status = os.environ["STATUS"]
blocked = os.environ["BLOCKED"]
f = {"disk_path": os.environ["DATA_PATH"], "cluster_status": status}
parts = []
if len(disk) == 3:
    f["disk_used_pct"], f["disk_free_gb"], f["disk_total_gb"] = float(disk[0]), float(disk[1]), float(disk[2])
    parts.append("disk %.1f%% used (%.1f GB free of %.1f GB)" % (f["disk_used_pct"], f["disk_free_gb"], f["disk_total_gb"]))
else:
    parts.append("disk not measured")
parts.append("indexer " + status)
if blocked.isdigit():
    f["write_blocked_indices"] = int(blocked)
    parts.append("%d index(es) refusing writes" % int(blocked))
print(json.dumps([{"message": "Findings indexer %s: %s" % (os.environ["HOST"], ", ".join(parts)), "host": os.environ["HOST"], "fields": f}]))
')" || { echo "asix-indexer-health: could not build the report." >&2; exit 1; }

if [ "$PRINT" -eq 1 ]; then printf '%s\n' "$BODY"; exit 0; fi

# --- 4. send it. The key is in a curl config on a file descriptor; the body comes from standard input.
CFG="$(printf 'silent\nshow-error\nmax-time = 30\nrequest = "POST"\nurl = "%s/v1/ingest/http"\nheader = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\nheader = "X-ASIX-Collector: %s"\nheader = "X-ASIX-Platform: linux"\nheader = "X-ASIX-Source-Type: indexer-health"\nheader = "X-ASIX-Version: asix-indexer-health-1"\n' "$URL" "$KEY" "$COLLECTOR")"
CA_ARGS=(); [ -z "$CA" ] || CA_ARGS=(--cacert "$CA")
OUT="$(printf '%s' "$BODY" | curl -K <(printf '%s\n' "$CFG") "${CA_ARGS[@]}" --data-binary @- -o /dev/null -w '%{http_code}' 2>&1)"; RC=$?
CODE="${OUT##*$'\n'}"
if [ "$RC" -ne 0 ] || ! [[ "$CODE" =~ ^2[0-9][0-9]$ ]]; then
  case "$CODE" in
    401|429) echo "asix-indexer-health: ASIX refused the report (HTTP $CODE): is the ingestion key active, and not over its rate limit?" >&2;;
    000|"") echo "asix-indexer-health: could not reach $URL (curl exit $RC). Is the address right, and does ASIX_HEALTH_CA hold its certificate?" >&2;;
    *) echo "asix-indexer-health: ASIX answered HTTP $CODE." >&2;;
  esac
  exit 1
fi
echo "reported to ASIX as $COLLECTOR (HTTP $CODE): $(printf '%s' "$BODY" | python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["message"])' 2>/dev/null)"
