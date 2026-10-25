#!/bin/bash
# Prepares the API of a Wazuh MANAGER for ASIX (docs/endpoints.md, task E4c). Run it as root ON THE MANAGER MACHINE after install-wazuh-manager.sh (a broker VM with
# --wazuh-manager, or a dedicated central manager VM). It talks to the manager's own API on this machine (https://127.0.0.1:55000) and does three things:
#
#   1. CHANGES THE DEFAULT API PASSWORDS. A new Wazuh manager's API has the users `wazuh` and `wazuh-wui` with well-known default passwords and full rights. The installer
#      (E4b) does not open port 55000 in a firewall, but anything that can reach it could sign in until this is done. The new passwords are random and are kept, readable
#      by root only, in /var/ossec/etc/asix-api-admin.pass and asix-api-wui.pass (nothing needs them day to day; they are there so you can sign in as an administrator).
#   2. CREATES A READ-ONLY API USER for ASIX (default name asix-readonly, role `readonly`, random password in /var/ossec/etc/asix-api-readonly.pass). ASIX only ever reads:
#      the proxy (src/endpoints/wazuh-api.js) sends GET requests, and this user could not do more even if it tried.
#   3. WRITES THE REGISTRATION FILE ASIX NEEDS: the address ASIX will use, that user and password, and the API's own certificate (ASIX trusts only that certificate when it
#      connects). Register it with the operator tool, on the machine that runs kubectl:
#        kubectl -n asix-platform exec -i deploy/asix-api -- node src/endpoints/wazuh-manager-cli.js register --tenant "TENANT NAME" < asix-wazuh-registration.json
#
# Usage:
#   ./scripts/deploy/wazuh-api-setup.sh --check                          # look only: what state is the API in? changes nothing, writes nothing
#   ./scripts/deploy/wazuh-api-setup.sh --address HOST [--port 55000] [--label TEXT] [--user NAME] [--rotate] [--cert-file PATH] [--out-dir DIR]
#
#   --address HOST   the address or name ASIX will use to reach this manager's API (a private address; NOT 127.0.0.1). Written into the registration file only.
#   --port N         the API port (default 55000).
#   --label TEXT     a label shown in ASIX (default: the machine's host name).
#   --user NAME      the name of the read-only user (default asix-readonly).
#   --rotate         also replace the read-only user's password (the registration file then holds the new one; register again).
#   --cert-file P    the API's certificate (default /var/ossec/api/configuration/security/server.crt; if that file does not exist the certificate is read from the running API).
#   --out-dir DIR    where the registration file goes (default /root).
#
# The script is safe to run again: with nothing left to do it changes nothing and rewrites the registration file with the same password. Passwords are never printed and never put
# on a command line (a command line is visible to other users of the machine); the API is reached with the certificate pinned (curl --pinnedpubkey), so a loopback
# impostor cannot collect the password either. It does NOT open the firewall: let ONLY the ASIX API node reach this machine's API port, for example
#   ufw allow from <ASIX node address> to any port 55000 proto tcp
# Built and tested against a stand-in for the Wazuh API (tests/wazuh-api-setup-script.test.js), NOT a real manager: see docs/endpoints.md, "E4c as built".
set -euo pipefail

ADDRESS=""; PORT="55000"; LABEL=""; RO_USER="asix-readonly"; ROTATE=0; CHECK=0; CERT_FILE=""; OUT_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --address) ADDRESS="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --label) LABEL="$2"; shift 2;;
    --user) RO_USER="$2"; shift 2;;
    --rotate) ROTATE=1; shift;;
    --check) CHECK=1; shift;;
    --cert-file) CERT_FILE="$2"; shift 2;;
    --out-dir) OUT_DIR="$2"; shift 2;;
    *) echo "Unknown option: $1" >&2; exit 2;;
  esac
done
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || { echo "--port must be a number from 1 to 65535." >&2; exit 2; }
[[ "$RO_USER" =~ ^[A-Za-z0-9._-]{3,64}$ ]] || { echo "--user must be 3 to 64 letters, digits, dots, dashes or underscores." >&2; exit 2; }
if [ "$CHECK" -eq 0 ]; then
  [ -n "$ADDRESS" ] || { echo "--address is required (the address ASIX will use to reach this manager's API)." >&2; exit 2; }
  [[ "$ADDRESS" =~ ^[A-Za-z0-9._:-]{1,253}$ ]] || { echo "--address must be a host name or an IP address." >&2; exit 2; }
  case "$ADDRESS" in 127.*|localhost|::1) echo "--address must be an address ASIX can reach, not this machine's loopback address." >&2; exit 2;; esac
fi

# Where things are. The environment variables exist for the tests; on a manager the defaults are right.
OSSEC="${ASIX_WAZUH_DIR:-/var/ossec}"; BASE="${ASIX_WAZUH_API_BASE:-https://127.0.0.1:$PORT}"
ETC="$OSSEC/etc"; ADMIN_PW="$ETC/asix-api-admin.pass"; WUI_PW="$ETC/asix-api-wui.pass"; RO_PW="$ETC/asix-api-readonly.pass"
[ -n "$CERT_FILE" ] || CERT_FILE="$OSSEC/api/configuration/security/server.crt"
[ -n "$OUT_DIR" ] || OUT_DIR="/root"
[ -n "$LABEL" ] || LABEL="$(hostname 2>/dev/null || echo wazuh-manager)"

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
for c in curl openssl python3; do command -v "$c" >/dev/null 2>&1 || { echo "Missing '$c': apt-get install -y curl openssl python3" >&2; exit 1; }; done
umask 077
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

PROBLEMS=0
say() { echo "   $*"; }
problem() { echo "   PROBLEM: $*" >&2; PROBLEMS=$((PROBLEMS + 1)); }
die() { echo "ERROR: $*" >&2; exit 1; }

echo "== 1. The API's certificate =="
if [ -s "$CERT_FILE" ]; then
  openssl x509 -in "$CERT_FILE" -noout >/dev/null 2>&1 || die "$CERT_FILE is not a readable certificate."
  openssl x509 -in "$CERT_FILE" > "$WORK/server.crt"; say "read $CERT_FILE"
else
  say "no $CERT_FILE: reading the certificate from the running API on $BASE"
  HP="${BASE#https://}"
  echo | openssl s_client -connect "$HP" 2>/dev/null | openssl x509 > "$WORK/server.crt" 2>/dev/null || true
  [ -s "$WORK/server.crt" ] || die "could not read a certificate from $BASE. Is the manager running? (systemctl status wazuh-manager; ss -ltn | grep $PORT)"
fi
PIN="$(openssl x509 -in "$WORK/server.crt" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64)"
FPR="$(openssl x509 -in "$WORK/server.crt" -noout -fingerprint -sha256 | sed 's/.*=//')"
say "certificate sha256 $FPR"
openssl x509 -in "$WORK/server.crt" -noout -checkend 0 >/dev/null 2>&1 || problem "the API certificate has expired ($(openssl x509 -in "$WORK/server.crt" -noout -enddate)): ASIX will refuse it."
openssl x509 -in "$WORK/server.crt" -noout -checkend $((30 * 86400)) >/dev/null 2>&1 || say "note: the certificate expires within 30 days ($(openssl x509 -in "$WORK/server.crt" -noout -enddate)); register the manager again when it is replaced."

# --- talking to the API ---------------------------------------------------------------------------------------------------------------------
# api METHOD PATH [JSON-BODY] [USER:PASS | TOKEN]  -> sets HTTP (status) and BODY (text). Secrets go in through a curl config on a file descriptor, never in the arguments.
HTTP=""; BODY=""
api() {
  local method="$1" path="$2" data="${3:-}" cred="${4:-}" out; local cfg
  cfg="$(printf 'silent\nshow-error\nmax-time = 20\nrequest = "%s"\nurl = "%s%s"\n' "$method" "$BASE" "$path")"
  case "$cred" in
    token:*) cfg+=$'\n'"$(printf 'header = "Authorization: Bearer %s"' "${cred#token:}")";;
    basic:*) cfg+=$'\n'"$(printf 'user = "%s"' "${cred#basic:}")";;
  esac
  if [ -n "$data" ]; then cfg+=$'\nheader = "Content-Type: application/json"'; fi
  if [ -n "$data" ]; then
    out="$(printf '%s' "$data" | curl -K <(printf '%s\n' "$cfg") --insecure --pinnedpubkey "sha256//$PIN" --data-binary @- -w $'\n%{http_code}' 2>/dev/null)" || out=$'\n000'
  else
    out="$(curl -K <(printf '%s\n' "$cfg") --insecure --pinnedpubkey "sha256//$PIN" -w $'\n%{http_code}' 2>/dev/null)" || out=$'\n000'
  fi
  HTTP="${out##*$'\n'}"; BODY="${out%$'\n'*}"
}
# jq-less JSON reading
jpy() { python3 -c "$1" 2>/dev/null; }
sign_in() {   # sign_in USER PASS -> token on stdout, or nothing
  api POST "/security/user/authenticate?raw=true" "" "basic:$1:$2"
  [ "$HTTP" = "200" ] && [[ "$BODY" =~ ^[A-Za-z0-9._-]{20,4096}$ ]] && printf '%s' "$BODY" || true
}
user_id() {   # user_id TOKEN NAME -> numeric id, or nothing
  api GET "/security/users?limit=500" "" "token:$1"
  [ "$HTTP" = "200" ] || return 0
  printf '%s' "$BODY" | NAME="$2" jpy 'import sys,json,os; d=json.load(sys.stdin); n=os.environ["NAME"]; print(next((str(u["id"]) for u in d["data"]["affected_items"] if u.get("username")==n),""), end="")'
}
role_id() {   # role_id TOKEN NAME -> numeric id, or nothing
  api GET "/security/roles?limit=500" "" "token:$1"
  [ "$HTTP" = "200" ] || return 0
  printf '%s' "$BODY" | NAME="$2" jpy 'import sys,json,os; d=json.load(sys.stdin); n=os.environ["NAME"]; print(next((str(r["id"]) for r in d["data"]["affected_items"] if r.get("name")==n),""), end="")'
}
user_has_role() {   # user_has_role TOKEN USERNAME ROLE_ID -> exit 0 when yes
  api GET "/security/users?limit=500" "" "token:$1"
  [ "$HTTP" = "200" ] || return 1
  printf '%s' "$BODY" | NAME="$2" RID="$3" jpy 'import sys,json,os; d=json.load(sys.stdin); u=next((u for u in d["data"]["affected_items"] if u.get("username")==os.environ["NAME"]),{}); sys.exit(0 if int(os.environ["RID"]) in [int(x) for x in u.get("roles",[])] else 1)'
}
# A password the Wazuh API accepts (8 to 64 characters with an upper case letter, a lower case letter, a digit and a symbol), random.
new_password() { printf 'Aa1!%s' "$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 24)"; }
read_pw() { [ -s "$1" ] && head -n 1 "$1" | tr -d '\r\n' || true; }
save_pw() {   # save_pw FILE PASSWORD  (root only, written before it is used so a crash cannot lose a password the API now holds)
  ( umask 077; printf '%s\n' "$2" > "$1.new" ); chmod 600 "$1.new"; mv "$1.new" "$1"
}
set_password() {   # set_password TOKEN USER_ID NEWPW -> exit 0 when the API took it
  api PUT "/security/users/$2" "$(NEW="$3" jpy 'import json,os; print(json.dumps({"password": os.environ["NEW"]}), end="")')" "token:$1"
  [ "$HTTP" = "200" ]
}

echo "== 2. The API =="
api POST "/security/user/authenticate?raw=true" "" "basic:nobody:nobody-at-all"
[ "$HTTP" = "000" ] && die "no answer from $BASE (or the certificate is not the one the API presents). Is the manager running? Is the API listening on port $PORT?"
say "the API answers on $BASE"

# Which administrator can we use? The one a previous run saved, else the default.
ADMIN_USER="wazuh"; ADMIN_TOKEN=""; ADMIN_STATE=""
SAVED="$(read_pw "$ADMIN_PW")"
if [ -n "$SAVED" ]; then ADMIN_TOKEN="$(sign_in "$ADMIN_USER" "$SAVED")"; [ -n "$ADMIN_TOKEN" ] && ADMIN_STATE="saved"; fi
if [ -z "$ADMIN_TOKEN" ]; then ADMIN_TOKEN="$(sign_in "$ADMIN_USER" "wazuh")"; [ -n "$ADMIN_TOKEN" ] && ADMIN_STATE="default"; fi
WUI_DEFAULT=0; [ -n "$(sign_in wazuh-wui wazuh-wui)" ] && WUI_DEFAULT=1
[ "$ADMIN_STATE" = "default" ] && problem "the API user 'wazuh' still has its DEFAULT password."
[ "$WUI_DEFAULT" -eq 1 ] && problem "the API user 'wazuh-wui' still has its DEFAULT password."
if [ "$CHECK" -eq 1 ]; then
  if [ -z "$ADMIN_TOKEN" ]; then say "cannot sign in as 'wazuh' (not the default password, and $ADMIN_PW is missing or does not work): the read-only user cannot be checked."
  else
    RO_TOKEN=""; SAVED_RO="$(read_pw "$RO_PW")"; [ -n "$SAVED_RO" ] && RO_TOKEN="$(sign_in "$RO_USER" "$SAVED_RO")"
    if [ -n "$RO_TOKEN" ]; then say "the read-only user '$RO_USER' exists and its saved password works"; else problem "no working read-only user '$RO_USER' yet: run this script without --check."; fi
  fi
  echo; if [ "$PROBLEMS" -eq 0 ]; then echo "Nothing to do."; else echo "$PROBLEMS problem(s). Run without --check to fix them."; exit 1; fi
  exit 0
fi
[ "$PROBLEMS" -eq 0 ] || [ -n "$ADMIN_TOKEN" ] || die "cannot sign in to the API as 'wazuh' (not the default password, and $ADMIN_PW is missing or wrong). Reset it as the Wazuh documentation describes (Securing the Wazuh API), then run this again."
[ -n "$ADMIN_TOKEN" ] || die "cannot sign in to the API as 'wazuh' (not the default password, and $ADMIN_PW is missing or wrong). Reset it as the Wazuh documentation describes (Securing the Wazuh API), then run this again."

echo "== 3. The default API passwords =="
if [ "$ADMIN_STATE" = "default" ]; then
  PW="$(new_password)"; save_pw "$ADMIN_PW" "$PW"                                   # saved first: the API takes the new password the moment the call succeeds
  UID_W="$(user_id "$ADMIN_TOKEN" wazuh)"; [ -n "$UID_W" ] || die "the API does not list a user 'wazuh'."
  if set_password "$ADMIN_TOKEN" "$UID_W" "$PW"; then say "changed the password of 'wazuh' (saved in $ADMIN_PW)"
  else rm -f "$ADMIN_PW"; die "the API refused the new password of 'wazuh' (HTTP $HTTP). Nothing was changed."; fi
  ADMIN_TOKEN="$(sign_in wazuh "$PW")"; [ -n "$ADMIN_TOKEN" ] || die "signed out after changing the password of 'wazuh'; the new password is in $ADMIN_PW. Run this again."
else say "'wazuh' is already off its default password"; fi
if [ "$WUI_DEFAULT" -eq 1 ]; then
  PW="$(new_password)"; save_pw "$WUI_PW" "$PW"
  UID_U="$(user_id "$ADMIN_TOKEN" wazuh-wui)"; [ -n "$UID_U" ] || die "the API does not list a user 'wazuh-wui'."
  if set_password "$ADMIN_TOKEN" "$UID_U" "$PW"; then say "changed the password of 'wazuh-wui' (saved in $WUI_PW)"
  else rm -f "$WUI_PW"; die "the API refused the new password of 'wazuh-wui' (HTTP $HTTP)."; fi
else say "'wazuh-wui' is already off its default password (or does not exist)"; fi

echo "== 4. The read-only user for ASIX =="
RID="$(role_id "$ADMIN_TOKEN" readonly)"; [ -n "$RID" ] || die "the API has no role called 'readonly'. Not creating a user that could do more than read."
RO_ID="$(user_id "$ADMIN_TOKEN" "$RO_USER")"; RO_PASS="$(read_pw "$RO_PW")"
if [ -z "$RO_ID" ]; then
  RO_PASS="$(new_password)"; save_pw "$RO_PW" "$RO_PASS"
  api POST "/security/users" "$(U="$RO_USER" P="$RO_PASS" jpy 'import json,os; print(json.dumps({"username": os.environ["U"], "password": os.environ["P"]}), end="")')" "token:$ADMIN_TOKEN"
  [ "$HTTP" = "200" ] || { rm -f "$RO_PW"; die "the API refused to create the user '$RO_USER' (HTTP $HTTP)."; }
  RO_ID="$(user_id "$ADMIN_TOKEN" "$RO_USER")"; [ -n "$RO_ID" ] || die "the user '$RO_USER' was created but is not listed."
  say "created '$RO_USER' (password in $RO_PW)"
elif [ "$ROTATE" -eq 1 ] || [ -z "$RO_PASS" ] || [ -z "$(sign_in "$RO_USER" "$RO_PASS")" ]; then
  RO_PASS="$(new_password)"; save_pw "$RO_PW" "$RO_PASS"
  set_password "$ADMIN_TOKEN" "$RO_ID" "$RO_PASS" || die "the API refused the new password of '$RO_USER' (HTTP $HTTP)."
  say "set a new password for '$RO_USER' (saved in $RO_PW)"
else say "'$RO_USER' exists and its saved password works"; fi
if user_has_role "$ADMIN_TOKEN" "$RO_USER" "$RID"; then say "'$RO_USER' has the role 'readonly'"
else
  api POST "/security/users/$RO_ID/roles?role_ids=$RID" "" "token:$ADMIN_TOKEN"
  [ "$HTTP" = "200" ] || die "the API refused to give '$RO_USER' the role 'readonly' (HTTP $HTTP)."
  say "gave '$RO_USER' the role 'readonly'"
fi

echo "== 5. What ASIX will do, tried as that user =="
RO_TOKEN="$(sign_in "$RO_USER" "$RO_PASS")"; [ -n "$RO_TOKEN" ] || die "cannot sign in as '$RO_USER' with the saved password."
api GET "/manager/info" "" "token:$RO_TOKEN"; [ "$HTTP" = "200" ] || die "'$RO_USER' cannot read the manager's information (HTTP $HTTP): its role does not allow it."
VER="$(printf '%s' "$BODY" | jpy 'import sys,json; print(json.load(sys.stdin)["data"]["affected_items"][0]["version"], end="")')"; say "read the manager information: Wazuh ${VER:-?}"
api GET "/agents?limit=1" "" "token:$RO_TOKEN"; [ "$HTTP" = "200" ] || die "'$RO_USER' cannot list agents (HTTP $HTTP): its role does not allow it."
say "listed agents"

echo "== 6. The registration file for ASIX =="
mkdir -p "$OUT_DIR"; REG="$OUT_DIR/asix-wazuh-registration.json"
( umask 077; U="$RO_USER" P="$RO_PASS" A="$ADDRESS" PT="$PORT" L="$LABEL" CRT="$WORK/server.crt" python3 - > "$REG.new" <<'PY'
import json, os
print(json.dumps({"url": "https://%s:%s" % (os.environ["A"] if ":" not in os.environ["A"] else "[%s]" % os.environ["A"], os.environ["PT"]), "user": os.environ["U"], "password": os.environ["P"],
                  "ca_pem": open(os.environ["CRT"]).read(), "label": os.environ["L"]}, indent=2))
PY
); chmod 600 "$REG.new"; mv "$REG.new" "$REG"
say "wrote $REG (root only; it holds the read-only password and the certificate)"
echo
echo "Done. Next:"
echo "  1. Let ONLY the ASIX API node reach this machine's port $PORT/tcp (do not expose it more widely)."
echo "  2. Copy $REG to the machine that runs kubectl for ASIX and register it for the tenant:"
echo "       kubectl -n asix-platform exec -i deploy/asix-api -- node src/endpoints/wazuh-manager-cli.js register --tenant \"TENANT NAME\" < asix-wazuh-registration.json"
echo "     (it signs in first and saves only if that works), then delete the copy."
echo "  3. In ASIX:  GET /v1/endpoints/manager  shows the manager and its version;  GET /v1/endpoints/agents  lists its agents."
echo "  The API certificate sha256 is $FPR. If the manager's certificate is ever replaced, run this again and register again."
