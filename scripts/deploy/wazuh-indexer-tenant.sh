#!/bin/bash
# Makes ONE tenant's read-only access to the central Wazuh indexer (docs/wazuh-indexer.md, task E6h; step 3 and the registration file of step 6). Run as root ON THE INDEXER
# MACHINE after install-wazuh-indexer.sh. For one manager it creates, through the indexer's security API as `admin`:
#   role     asix_vuln_read_<slug>   read on the ONE index  wazuh-states-vulnerabilities-<manager name>  (index permission `read` and nothing else, no cluster permission)
#   user     asix-vuln-<slug>        with a random password
#   mapping  that user to that role
# then READS BACK what it made (the user must exist, and the role must name exactly that one index pattern) and writes the file the operator tool wants:
#   kubectl -n asix-platform exec -i deploy/asix-api -- node src/endpoints/wazuh-indexer-cli.js register --tenant "TENANT NAME" < asix-indexer-registration-<slug>.json
#
# Usage:
#   ./scripts/deploy/wazuh-indexer-tenant.sh --tenant-name "Acme Corp" --manager-name acme-mgr --address indexer.internal [--port 9200] [--label TEXT] [--rotate] [--ca-file P] [--out-dir DIR]
#   ./scripts/deploy/wazuh-indexer-tenant.sh --check --manager-name acme-mgr      # look only: can admin sign in, is there a role and user already? changes and writes nothing
#
#   --tenant-name N   the tenant's name as ASIX knows it; used only for the label and the next-step text, and to make the slug (names of the role and user).
#   --manager-name M  the Wazuh manager's NAME (lower case letters, digits, dots, dashes, underscores): the index is wazuh-states-vulnerabilities-M. Read it off the indexer:
#                     GET /_cat/indices/wazuh-states-vulnerabilities-*?v. The index need not exist yet (the manager creates it after its first scan).
#   --address A       the address ASIX will use to reach the indexer (written into the registration file only; not a loopback address).
#   --slug S          the name part for the role and user (default: the manager name). 1 to 40 letters, digits, dashes.
#   --rotate          give an existing user a NEW password (the registration file then holds the new one; register again).
#   --ca-file P       the indexer's root CA (default /etc/wazuh-indexer/certs/root-ca.pem), written into the registration file as ca_pem. Exactly one certificate.
#   --out-dir DIR     where the registration file goes (default /root).
#
# WRITER MODE (task E6g): --writer makes the WRITE side instead, for the Wazuh MANAGER that fills the index (install-wazuh-manager.sh --indexer-file reads what it writes):
#   role     asix_vuln_write_<slug>  crud + create_index + manage on the ONE index (no other index; no cluster permission unless --templates)
#   user     asix-mgr-<slug>         with its own random password (kept in /etc/wazuh-indexer/asix-mgr-<slug>.pass)
#   file     asix-manager-indexer-<slug>.json (mode 600: url, user, password, root CA, index): copy it to the manager's machine. On the SAME machine as the indexer (lab)
#            give --address 127.0.0.1 (the certificate names it); a loopback address is refused only for the read side, which ASIX uses.
#   --templates      also give the writer the cluster permissions to read and put index templates (add it only if the manager's ossec.log says the template was refused:
#                    a template is shared by every index of its family, so this right reaches beyond the manager's own index).
#   Only the actions of the real Wazuh manager are a guess (not tried): the role is read back and stored as exactly this list or the script stops.
# Passwords never appear on a command line or in output (curl gets them through a config file on a file descriptor). Safe to run again: the same role, user and mapping are written
# again and the file is rewritten with the SAME password unless --rotate. Tested against a stand-in for the security API, NOT a real indexer: the paths are the OpenSearch security
# plugin's as I know them; a different answer from a real indexer stops the script with its message.
set -euo pipefail

TENANT=""; MANAGER=""; ADDRESS=""; PORT="9200"; LABEL=""; SLUG=""; ROTATE=0; CHECK=0; CA_FILE=""; OUT_DIR=""; MODE="read"; TEMPLATES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --tenant-name) TENANT="$2"; shift 2;;
    --manager-name) MANAGER="$2"; shift 2;;
    --address) ADDRESS="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --label) LABEL="$2"; shift 2;;
    --slug) SLUG="$2"; shift 2;;
    --rotate) ROTATE=1; shift;;
    --check) CHECK=1; shift;;
    --ca-file) CA_FILE="$2"; shift 2;;
    --out-dir) OUT_DIR="$2"; shift 2;;
    --writer) MODE="write"; shift;;
    --templates) TEMPLATES=1; shift;;
    *) echo "Unknown option: $1" >&2; exit 2;;
  esac
done
[[ "$MANAGER" =~ ^[a-z0-9][a-z0-9._-]{0,60}$ ]] || { echo "--manager-name is required: lower case letters, digits, dots, dashes or underscores (it ends the index name, and ASIX accepts nothing else)." >&2; exit 2; }
[ -n "$SLUG" ] || SLUG="$(printf '%s' "$MANAGER" | tr -c 'a-z0-9\n-' '-' | sed 's/^-*//; s/-*$//' | cut -c1-40)"
[[ "$SLUG" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,39}$ ]] || { echo "--slug must be 1 to 40 letters, digits or dashes." >&2; exit 2; }
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || { echo "--port must be a number from 1 to 65535." >&2; exit 2; }
if [ "$CHECK" -eq 0 ]; then
  [ -n "$ADDRESS" ] || { echo "--address is required (the address ASIX will use to reach the indexer)." >&2; exit 2; }
  [[ "$ADDRESS" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$ ]] || { echo "--address must be a host name or an IP address." >&2; exit 2; }
  if [ "$MODE" = "read" ]; then
    case "$ADDRESS" in 127.*|localhost|::1) echo "--address must be an address ASIX can reach, not this machine's loopback address." >&2; exit 2;; esac
  fi
fi
[ "$TEMPLATES" -eq 0 ] || [ "$MODE" = "write" ] || { echo "--templates only makes sense with --writer." >&2; exit 2; }

CONF_DIR="${ASIX_INDEXER_CONF_DIR:-/etc/wazuh-indexer}"; BASE="${ASIX_INDEXER_BASE:-https://127.0.0.1:$PORT}"
[ -n "$CA_FILE" ] || CA_FILE="$CONF_DIR/certs/root-ca.pem"; [ -n "$OUT_DIR" ] || OUT_DIR="/root"
ADMIN_PW="$CONF_DIR/asix-admin.pass"; INDEX="wazuh-states-vulnerabilities-$MANAGER"
if [ "$MODE" = "write" ]; then
  ROLE="asix_vuln_write_$(printf '%s' "$SLUG" | tr '-' '_')"; USER_NAME="asix-mgr-$SLUG"; USER_PW="$CONF_DIR/asix-mgr-$SLUG.pass"
  ACTIONS_JSON='["crud","create_index","manage"]'; PURPOSE="Wazuh manager, writes its own vulnerability index"
  if [ "$TEMPLATES" -eq 1 ]; then CLUSTER_JSON='["indices:admin/index_template/get","indices:admin/index_template/put","indices:admin/template/get","indices:admin/template/put"]'; else CLUSTER_JSON='[]'; fi
else
  ROLE="asix_vuln_read_$(printf '%s' "$SLUG" | tr '-' '_')"; USER_NAME="asix-vuln-$SLUG"; USER_PW="$CONF_DIR/asix-vuln-$SLUG.pass"
  ACTIONS_JSON='["read"]'; PURPOSE="ASIX vulnerability tab, read only"; CLUSTER_JSON='[]'
fi
export ACTIONS_JSON CLUSTER_JSON PURPOSE
[ -n "$LABEL" ] || LABEL="${TENANT:-$MANAGER}"

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
for c in curl openssl python3; do command -v "$c" >/dev/null 2>&1 || { echo "Missing '$c': apt-get install -y curl openssl python3" >&2; exit 1; }; done
[ -s "$ADMIN_PW" ] || { echo "No $ADMIN_PW: run install-wazuh-indexer.sh first (it keeps the admin password there)." >&2; exit 1; }
[ -s "$CA_FILE" ] || { echo "No $CA_FILE (the indexer's root CA). Use --ca-file." >&2; exit 1; }
[ "$(grep -c 'BEGIN CERTIFICATE' "$CA_FILE")" -eq 1 ] || { echo "$CA_FILE must hold exactly one certificate (the root CA)." >&2; exit 1; }
openssl x509 -in "$CA_FILE" -noout >/dev/null 2>&1 || { echo "$CA_FILE is not a readable certificate." >&2; exit 1; }
umask 077
die() { echo "ERROR: $*" >&2; exit 1; }

# api METHOD PATH [JSON-BODY] -> sets HTTP and BODY. The admin password goes in through a curl config on a file descriptor, never in the arguments.
HTTP=""; BODY=""
api() {
  local method="$1" path="$2" data="${3:-}" cfg out
  cfg="$(printf 'silent\nshow-error\nmax-time = 30\nrequest = "%s"\nurl = "%s%s"\nuser = "admin:%s"\n' "$method" "$BASE" "$path" "$(cat "$ADMIN_PW")")"
  if [ -n "$data" ]; then
    out="$(printf '%s' "$data" | curl -K <(printf '%s\n' "$cfg") --cacert "$CA_FILE" -H 'Content-Type: application/json' --data-binary @- -w $'\n%{http_code}' 2>/dev/null)" || out=$'\n000'
  else
    out="$(curl -K <(printf '%s\n' "$cfg") --cacert "$CA_FILE" -w $'\n%{http_code}' 2>/dev/null)" || out=$'\n000'
  fi
  HTTP="${out##*$'\n'}"; BODY="${out%$'\n'*}"
}
jpy() { python3 -c "$1" 2>/dev/null; }

echo "== 1. Sign in as admin =="
api GET "/_plugins/_security/api/roles/$ROLE"
case "$HTTP" in
  200) HAVE_ROLE=1;;
  404) HAVE_ROLE=0;;
  401|403) die "the indexer refused admin (HTTP $HTTP): is $ADMIN_PW the password the installer set? Is the security configuration loaded?";;
  000) die "could not reach $BASE with the CA $CA_FILE. Is the indexer running (systemctl status wazuh-indexer)?";;
  *) die "unexpected answer HTTP $HTTP for the role: $(printf '%s' "$BODY" | head -c 200)";;
esac
api GET "/_plugins/_security/api/internalusers/$USER_NAME"
case "$HTTP" in 200) HAVE_USER=1;; 404) HAVE_USER=0;; *) die "unexpected answer HTTP $HTTP for the user: $(printf '%s' "$BODY" | head -c 200)";; esac
echo "   role $ROLE: $([ "$HAVE_ROLE" -eq 1 ] && echo exists || echo "not there yet"); user $USER_NAME: $([ "$HAVE_USER" -eq 1 ] && echo exists || echo "not there yet")"
if [ "$CHECK" -eq 1 ]; then echo "Checks passed. Nothing was changed and nothing was written."; exit 0; fi

echo "== 2. The password =="
NEW_PW=0
if [ ! -s "$USER_PW" ] || [ "$ROTATE" -eq 1 ]; then
  R="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-28)"; printf '%sAa1!\n' "$R" > "$USER_PW.new"; mv -f "$USER_PW.new" "$USER_PW"; NEW_PW=1
fi
chmod 600 "$USER_PW"
echo "   $([ "$NEW_PW" -eq 1 ] && echo "a new password was made" || echo "the password already kept in $USER_PW is reused"); it is in $USER_PW (root only)"

echo "== 3. Role, user and mapping =="
api PUT "/_plugins/_security/api/roles/$ROLE" "$(INDEX="$INDEX" python3 -c 'import json,os; print(json.dumps({"cluster_permissions": json.loads(os.environ["CLUSTER_JSON"]), "index_permissions": [{"index_patterns": [os.environ["INDEX"]], "allowed_actions": json.loads(os.environ["ACTIONS_JSON"])}]}))')"
case "$HTTP" in 200|201) :;; *) die "the role was not made (HTTP $HTTP): $(printf '%s' "$BODY" | head -c 300)";; esac
api PUT "/_plugins/_security/api/internalusers/$USER_NAME" "$(PW="$(cat "$USER_PW")" python3 -c 'import json,os; print(json.dumps({"password": os.environ["PW"], "backend_roles": [], "attributes": {"purpose": os.environ["PURPOSE"]}}))')"
case "$HTTP" in 200|201) :;; *) die "the user was not made (HTTP $HTTP): $(printf '%s' "$BODY" | head -c 300)";; esac
api PUT "/_plugins/_security/api/rolesmapping/$ROLE" "$(U="$USER_NAME" python3 -c 'import json,os; print(json.dumps({"users": [os.environ["U"]]}))')"
case "$HTTP" in 200|201) :;; *) die "the role mapping was not made (HTTP $HTTP): $(printf '%s' "$BODY" | head -c 300)";; esac

echo "== 4. Reading it back =="
api GET "/_plugins/_security/api/roles/$ROLE"
[ "$HTTP" = "200" ] || die "cannot read the role back (HTTP $HTTP)."
printf '%s' "$BODY" | ROLE="$ROLE" INDEX="$INDEX" jpy '
import sys, json, os
r = json.load(sys.stdin)[os.environ["ROLE"]]
ip = r.get("index_permissions") or []
ok = len(ip) == 1 and ip[0].get("index_patterns") == [os.environ["INDEX"]] and sorted(ip[0].get("allowed_actions") or []) == sorted(json.loads(os.environ["ACTIONS_JSON"])) and sorted(r.get("cluster_permissions") or []) == sorted(json.loads(os.environ["CLUSTER_JSON"])) and not (r.get("tenant_permissions") or [])
sys.exit(0 if ok else 1)' || die "the role as the indexer stored it is NOT '$([ "$MODE" = write ] && echo "write on" || echo read on) $INDEX and nothing else'. Nothing was written$([ "$MODE" = write ] || echo " for ASIX"). Look at GET /_plugins/_security/api/roles/$ROLE as admin."
api GET "/_plugins/_security/api/rolesmapping/$ROLE"
[ "$HTTP" = "200" ] && printf '%s' "$BODY" | ROLE="$ROLE" U="$USER_NAME" jpy 'import sys,json,os; m=json.load(sys.stdin)[os.environ["ROLE"]]; sys.exit(0 if m.get("users")==[os.environ["U"]] else 1)' || die "the role is not mapped to exactly the user $USER_NAME. Nothing was written for ASIX."
api GET "/_plugins/_security/api/internalusers/$USER_NAME"
[ "$HTTP" = "200" ] || die "the user $USER_NAME cannot be read back (HTTP $HTTP)."
echo "   the role $([ "$MODE" = write ] && echo "writes" || echo "reads") only $INDEX, and only $USER_NAME has it"

if [ "$MODE" = "write" ]; then
echo "== 5. The file for the manager =="
install -d -m 700 "$OUT_DIR"
OUT="$OUT_DIR/asix-manager-indexer-$SLUG.json"
URL="https://$ADDRESS:$PORT"
PW="$(cat "$USER_PW")" CA="$(cat "$CA_FILE")" URL="$URL" USER_NAME="$USER_NAME" INDEX="$INDEX" python3 -c '
import json, os
print(json.dumps({"url": os.environ["URL"], "user": os.environ["USER_NAME"], "password": os.environ["PW"], "ca_pem": os.environ["CA"].strip() + "\n", "index": os.environ["INDEX"]}, indent=2))' > "$OUT.new"
chmod 600 "$OUT.new"; mv -f "$OUT.new" "$OUT"
echo "   wrote $OUT (root only)"
echo
echo "Done. Next, on the machine that runs the Wazuh manager (copy the file there, root only, delete it from here afterwards):"
echo "  sudo ./scripts/deploy/install-wazuh-manager.sh --indexer-file $(basename "$OUT")"
echo "(the manager then writes $INDEX; register the READ side for ASIX with this script without --writer.)"
exit 0
fi

echo "== 5. The registration file =="
install -d -m 700 "$OUT_DIR"
OUT="$OUT_DIR/asix-indexer-registration-$SLUG.json"
URL="https://$ADDRESS:$PORT"
PW="$(cat "$USER_PW")" CA="$(cat "$CA_FILE")" URL="$URL" USER_NAME="$USER_NAME" INDEX="$INDEX" LABEL="$LABEL" python3 -c '
import json, os
print(json.dumps({"url": os.environ["URL"], "user": os.environ["USER_NAME"], "password": os.environ["PW"], "ca_pem": os.environ["CA"].strip() + "\n", "index": os.environ["INDEX"], "label": os.environ["LABEL"]}, indent=2))' > "$OUT.new"
chmod 600 "$OUT.new"; mv -f "$OUT.new" "$OUT"
echo "   wrote $OUT (root only)"
echo
echo "Done. Next, on the machine that runs kubectl (copy the file there, then delete it from here):"
echo "  kubectl -n asix-platform exec -i deploy/asix-api -- node src/endpoints/wazuh-indexer-cli.js register --tenant \"${TENANT:-TENANT NAME}\" --no-check < $(basename "$OUT")"
echo "(--no-check until the manager has sent its first findings and the index exists; then run the same command with the word  check  instead of  register  to test the read.)"
