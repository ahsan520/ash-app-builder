#!/bin/bash
# Broker config pull: asks ASIX what this broker should be configured with and applies it, SAFELY. Run as root every 5 minutes by
# asix-broker-config.timer, which scripts/deploy/bootstrap-broker.sh installs ONLY when given --accept-config (ASIX_ACCEPT_CONFIG=true
# in broker.env). A broker set up without that flag never runs this and ASIX cannot change it.
#
# Two settings: the syslog port (one value for the tenant, or a port set for this broker alone) and the syslog-over-TLS port (one value for the tenant;
# acted on only by a broker that already HAS a TLS listener, see below). Each is applied on its own, the syslog port first. What it does, in this order, and stops at the first failure:
#   1. fetches GET <ingest URL>/../broker-config?collector=<this broker's name> with this broker's own ingestion key (nothing is sent but the key and the name)
#   2. null or the port already in use: does nothing
#   3. checks the port itself, whatever ASIX sent: 1-65535, not SSH (22), HTTPS (443), Vector's health API (8686) or ASIX's HTTPS (30443),
#      not the syslog-over-TLS port of this broker
#   4. edits ASIX_SYSLOG_PORT in broker.env (a copy kept as broker.env.before-config), runs `vector validate` on the result, restarts Vector,
#      waits for its health check
#   5. any failure from step 4 puts the old broker.env back and restarts Vector on it, and remembers the rejected port in
#      /var/lib/asix-broker/config-rejected so it is not retried every 5 minutes until ASIX asks for a different port
# After EVERY run that got as far as asking, it tells ASIX which syslog port it is listening on now and which one it rejected (POST to
# <ingest URL>/../broker-config/report, an EXIT trap, best effort: a failed report changes nothing and never the exit status). That only feeds the
# Applied / Pending / Rejected column on ASIX's Brokers page; it is information, not a setting.
# SIGNED CONFIG (optional): when ASIX_CONFIG_PUBKEY_FILE is set (bootstrap-broker.sh --config-pubkey), the broker acts ONLY on the signed copy of the
# answer. It checks, with openssl, the ECDSA P-256 / SHA-256 signature against the public key(s) in that file (several keys: any one will do, so a
# key can be replaced without a gap), that the signed text was made for THIS broker's name, and that it was issued within ASIX_CONFIG_MAX_SKEW_S
# (default 600) seconds of this machine's clock. An unsigned answer, a bad signature, another broker's answer or an old one changes nothing (exit 1,
# the reason in the journal). The unsigned `config` part of the answer is ignored in this mode.
# The report also says which syslog-over-TLS port this broker listens on (null = it has no TLS listener) and which TLS port it rejected (tls_port, rejected_tls_port).
# The report also says whether this broker checks signatures (`signature`): off (no public key), unchecked (it has one but got no answer to check), ok (the
# last answer passed) or the reason the last answer was refused (unsigned, bad_signature, wrong_broker, clock_skew, bad_format, no_key_file, no_openssl).
# The TLS port is moved only on a broker that has a TLS listener (ASIX_SYSLOG_TLS_PORT in broker.env and vector-tls.yaml present); otherwise it is ignored with a note.
# OPTIONAL INPUTS (pause / resume): the answer may also say `paused_inputs` ("file,journald"; "" = run them all): the optional inputs this broker should NOT run. Only file, http,
# journald and wazuh can be paused (never syslog or syslog over TLS). The broker takes those inputs' config files out of VECTOR_CONFIG (and puts back the ones it paused earlier and ASIX no longer
# lists), writes ASIX_INPUTS_PAUSED, runs `vector validate` on the new list, restarts Vector, waits for health, and puts broker.env back on any failure (remembering the rejected list in
# config-paused-rejected). The config files stay installed, so resuming needs nothing from ASIX but an empty list. A re-run of bootstrap-broker.sh writes the full list again; the next pull pauses again.
# The report also says which inputs this broker has paused (paused_inputs) and the list it rejected (rejected_paused_inputs).
# WINDOWS EVENT FILTER: the answer may also say `win_filter` (64 hex): the SHA-256 of the Vector program that holds this tenant's Windows event filter policy (Settings > Windows event filter in ASIX). The broker
# downloads the program from <ingest URL>/../broker-config/win-filter with its own key, refuses it unless it hashes to exactly the announced value (in signed mode the hash is inside the signature, so a program
# changed on the way is refused), checks the file itself (size, no control characters), runs `vector validate` on a one-transform config that loads it, and only then puts it in $VECTOR_DIR/win-filter.vrl
# (the old file kept as win-filter.vrl.before-config). If a Vector config in VECTOR_CONFIG reads win-filter.vrl, the whole config is validated again, Vector restarted and its health checked, and any failure puts
# the old file back (restarting Vector on it) and remembers the rejected hash in win-filter-rejected so it is not retried every 5 minutes until ASIX announces a different program. Nothing reads the file until a
# Windows events input exists (task E4), so today the program is placed and checked and Vector is not restarted. When ASIX's policy is removed it announces the keep-everything program and this broker takes the filter away
# the same way. The report also says the hash of the program file this broker has (win_filter, '' = none) and the hash it rejected (rejected_win_filter); a broker that never had a file and rejected nothing sends neither.
# It does not open the firewall: the new port must be opened on this VM by hand. Results go to the journal (journalctl -u asix-broker-config).
set -uo pipefail

ENV_FILE="${ASIX_BROKER_ENV:-/etc/asix-broker/broker.env}"
VECTOR_DIR="${ASIX_VECTOR_DIR:-/etc/vector}"
STATE_DIR="${ASIX_CONFIG_STATE_DIR:-/var/lib/asix-broker}"
WAIT_S="${ASIX_CONFIG_WAIT_S:-30}"

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
[ -r "$ENV_FILE" ] || { echo "$ENV_FILE not found: this machine was not set up with bootstrap-broker.sh." >&2; exit 1; }
[[ "$WAIT_S" =~ ^[0-9]{1,3}$ ]] || { echo "ASIX_CONFIG_WAIT_S must be a number of seconds." >&2; exit 2; }
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

[ "${ASIX_ACCEPT_CONFIG:-}" = "true" ] || { echo "This broker was not set up to accept config from ASIX (bootstrap-broker.sh --accept-config). Nothing to do."; exit 0; }
: "${ASIX_INGEST_KEY:?ASIX_INGEST_KEY is not set}"
URL="${ASIX_CONFIG_URL:-}"
if [ -z "$URL" ]; then : "${ASIX_INGEST_URL:?ASIX_INGEST_URL is not set}"; URL="${ASIX_INGEST_URL%/v1/ingest/http}/v1/ingest/broker-config"; fi

MAX_SKEW="${ASIX_CONFIG_MAX_SKEW_S:-600}"
[[ "$MAX_SKEW" =~ ^[0-9]{1,5}$ ]] || { echo "ASIX_CONFIG_MAX_SKEW_S must be a number of seconds." >&2; exit 2; }
W=""   # scratch folder for the signature check, removed on exit
# What this broker reports about checking ASIX's signature (see the report below): off = no public key, so nothing is checked; with one,
# unchecked until an answer has been checked, then ok or the reason it was refused.
SIG="off"; [ -z "${ASIX_CONFIG_PUBKEY_FILE:-}" ] || SIG="unchecked"

ARGS=(-fsS -m 10 -H "Authorization: Bearer ${ASIX_INGEST_KEY}")
[ -n "${ASIX_CA_FILE:-}" ] && ARGS+=(--cacert "$ASIX_CA_FILE")

report() {  # EXIT trap: what this broker listens on now (read from broker.env AFTER any change or put-back) and the port it rejected, if any
  local cur rej name body tls trej
  name="$(printf '%s' "${ASIX_BROKER_NAME:-}" | tr -d '"\\' | cut -c1-100)"; [ -n "$name" ] || return 0
  cur="$( . "$ENV_FILE" >/dev/null 2>&1; printf '%s' "${ASIX_SYSLOG_PORT:-514}" )"
  [[ "$cur" =~ ^[1-9][0-9]{0,4}$ ]] || return 0
  rej=""; [ -r "$STATE_DIR/config-rejected" ] && rej="$(tr -cd '0-9' < "$STATE_DIR/config-rejected" 2>/dev/null | cut -c1-5)"
  [[ "$rej" =~ ^[1-9][0-9]{0,4}$ ]] || rej="null"
  # The syslog-over-TLS listener: the port it uses now (read AFTER any change or put-back), or null when this broker has none (no ASIX_SYSLOG_TLS_PORT or no vector-tls.yaml),
  # and the TLS port it rejected. Same rule as step 2 below for "has a TLS listener".
  tls="$( . "$ENV_FILE" >/dev/null 2>&1; printf '%s' "${ASIX_SYSLOG_TLS_PORT:-}" )"
  if [[ "$tls" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$tls" -le 65535 ] && [ -r "$VECTOR_DIR/vector-tls.yaml" ]; then :; else tls="null"; fi
  trej=""; [ -r "$STATE_DIR/config-tls-rejected" ] && trej="$(tr -cd '0-9' < "$STATE_DIR/config-tls-rejected" 2>/dev/null | cut -c1-5)"
  [[ "$trej" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$trej" -le 65535 ] || trej="null"
  # The optional inputs this broker has paused now (read AFTER any change or put-back; '' = none) and the list it rejected, when it is a valid list. Only sent by a broker that has ever
  # been asked to pause something (its broker.env has an ASIX_INPUTS_PAUSED line, empty after a resume) or has a rejected list; every other broker's report is what it always was.
  pz=""; pzr=""; extra=""
  [ -r "$STATE_DIR/config-paused-rejected" ] && pzr="$(tr -cd 'a-z,' < "$STATE_DIR/config-paused-rejected" 2>/dev/null | cut -c1-40)"
  case "$pzr" in none) pzr="";; esac
  if grep -q '^ASIX_INPUTS_PAUSED=' "$ENV_FILE" 2>/dev/null || [ -n "$pzr" ]; then
    pz="$( . "$ENV_FILE" >/dev/null 2>&1; printf '%s' "${ASIX_INPUTS_PAUSED:-}" | tr -cd 'a-z,' | cut -c1-40 )"
    extra="$(printf ',"paused_inputs":"%s","rejected_paused_inputs":"%s"' "$pz" "$pzr")"
  fi
  # The Windows event filter program this broker has (the hash of the file, '' = no file) and the hash it rejected. Only sent by a broker that has such a file or a rejected hash.
  wfr=""; [ -r "$STATE_DIR/win-filter-rejected" ] && wfr="$(tr -cd '0-9a-f' < "$STATE_DIR/win-filter-rejected" 2>/dev/null | cut -c1-64)"
  [[ "$wfr" =~ ^[0-9a-f]{64}$ ]] || wfr=""
  if [ -r "$VECTOR_DIR/win-filter.vrl" ] || [ -n "$wfr" ]; then
    wfh=""; [ -r "$VECTOR_DIR/win-filter.vrl" ] && wfh="$(sha256sum < "$VECTOR_DIR/win-filter.vrl" 2>/dev/null | cut -d' ' -f1)"
    [[ "$wfh" =~ ^[0-9a-f]{64}$ ]] || wfh=""
    extra="$extra$(printf ',"win_filter":"%s","rejected_win_filter":"%s"' "$wfh" "$wfr")"
  fi
  body="$(printf '{"collector":"%s","syslog_port":%s,"rejected_port":%s,"signature":"%s","tls_port":%s,"rejected_tls_port":%s%s}' "$name" "$cur" "$rej" "$SIG" "$tls" "$trej" "$extra")"
  curl "${ARGS[@]}" -X POST -H "Content-Type: application/json" --data "$body" "$URL/report" >/dev/null 2>&1 || true
}
trap 'report; [ -z "${W:-}" ] || rm -rf "$W"' EXIT
# Say which broker this is, so ASIX can answer with THIS broker's own port if one was set on the Brokers page (otherwise the tenant-wide port).
# Only a plain name goes in the URL; anything else is left out and ASIX answers with the tenant-wide port.
FETCH_URL="$URL"; [[ "${ASIX_BROKER_NAME:-}" =~ ^[A-Za-z0-9._:-]{1,100}$ ]] && FETCH_URL="$URL?collector=${ASIX_BROKER_NAME}"
BODY="$(curl "${ARGS[@]}" "$FETCH_URL")" || { echo "Could not fetch the config from ASIX; nothing changed." >&2; exit 1; }
FLAT="$(printf '%s' "$BODY" | tr -d ' \t\r\n')"
if [ -n "${ASIX_CONFIG_PUBKEY_FILE:-}" ]; then
  # Signed mode: from here on only the verified payload is read; `config` in the answer is never looked at.
  [ -r "$ASIX_CONFIG_PUBKEY_FILE" ] || { SIG=no_key_file; echo "Cannot read the config public key $ASIX_CONFIG_PUBKEY_FILE; nothing changed." >&2; exit 1; }
  command -v openssl >/dev/null 2>&1 || { SIG=no_openssl; echo "openssl is needed to check ASIX's signature; nothing changed." >&2; exit 1; }
  W="$(mktemp -d)" || { echo "Cannot make a scratch folder; nothing changed." >&2; exit 1; }
  PB="$(printf '%s' "$FLAT" | sed -n 's/.*"payload":"\([A-Za-z0-9+\/=]*\)".*/\1/p')"
  SB="$(printf '%s' "$FLAT" | sed -n 's/.*"signature":"\([A-Za-z0-9+\/=]*\)".*/\1/p')"
  [ -n "$PB" ] && [ -n "$SB" ] || { SIG=unsigned; echo "ASIX did not sign this answer, and this broker accepts only signed config (ASIX_CONFIG_PUBKEY_FILE). Is the signing key set on ASIX? Nothing changed." >&2; exit 1; }
  [ "${#PB}" -le 2000 ] && [ "${#SB}" -le 2000 ] || { SIG=bad_format; echo "The signed part of ASIX's answer is too long to be valid; nothing changed." >&2; exit 1; }
  printf '%s' "$PB" | base64 -d > "$W/payload" 2>/dev/null && printf '%s' "$SB" | base64 -d > "$W/sig" 2>/dev/null && [ -s "$W/payload" ] && [ -s "$W/sig" ] \
    || { SIG=bad_format; echo "The signed part of ASIX's answer is not valid base64; nothing changed." >&2; exit 1; }
  awk -v d="$W" '/-----BEGIN PUBLIC KEY-----/{n++} n{print > (d "/key" n ".pem")}' "$ASIX_CONFIG_PUBKEY_FILE"
  ok=0; shopt -s nullglob
  for k in "$W"/key*.pem; do
    if openssl dgst -sha256 -verify "$k" -signature "$W/sig" "$W/payload" >/dev/null 2>&1; then ok=1; break; fi
  done
  shopt -u nullglob
  [ "$ok" -eq 1 ] || { SIG=bad_signature; echo "The signature on ASIX's answer does not match the public key in $ASIX_CONFIG_PUBKEY_FILE (wrong key, or the answer was changed); nothing changed." >&2; exit 1; }
  PAY="$(tr -d ' \t\r\n' < "$W/payload")"
  [[ "$PAY" == '{"v":1,'* ]] || { SIG=bad_format; echo "The signed answer has an unknown format; nothing changed." >&2; exit 1; }
  WHO="null"; [[ "${ASIX_BROKER_NAME:-}" =~ ^[A-Za-z0-9._:-]{1,100}$ ]] && WHO="\"${ASIX_BROKER_NAME}\""
  case "$PAY" in *'"collector":'"$WHO"',"issued_at":'*) ;; *) SIG=wrong_broker; echo "The signed answer was made for another broker; nothing changed." >&2; exit 1;; esac
  ISSUED="$(printf '%s' "$PAY" | sed -n 's/.*"issued_at":\([0-9]\{1,12\}\),.*/\1/p')"
  NOW="$(date +%s)"; DIFF=$(( NOW - ${ISSUED:-0} )); [ "$DIFF" -ge 0 ] || DIFF=$(( -DIFF ))
  [ -n "$ISSUED" ] && [ "$DIFF" -le "$MAX_SKEW" ] || { SIG=clock_skew; echo "The signed answer is ${DIFF}s away from this machine's clock (limit ${MAX_SKEW}s): replayed, or one of the clocks is wrong; nothing changed." >&2; exit 1; }
  SIG=ok   # signature, broker name and age all passed
  FLAT="$PAY"
fi
PORT=""
if ! printf '%s' "$FLAT" | grep -q '"syslog_port":null'; then
  PORT="$(printf '%s' "$FLAT" | sed -n 's/.*"syslog_port":\([0-9]\{1,5\}\)[,}].*/\1/p')"
  [ -n "$PORT" ] || { echo "Unexpected answer from ASIX (no syslog_port); nothing changed." >&2; exit 1; }

  # The broker's own rules, independent of what ASIX sent.
  [[ "$PORT" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$PORT" -le 65535 ] || { echo "ASIX asked for syslog port $PORT, which is not a valid port; ignored." >&2; exit 1; }
  case "$PORT" in 22|443|8686|30443) echo "ASIX asked for syslog port $PORT, which this broker never uses for syslog; ignored." >&2; exit 1;; esac
  [ "$PORT" != "${ASIX_SYSLOG_TLS_PORT:-}" ] || { echo "ASIX asked for syslog port $PORT, which is this broker's syslog-over-TLS port; ignored." >&2; exit 1; }
fi
# The syslog-over-TLS port: absent or null (an ASIX or a signed answer from before it existed, or none set) means no opinion.
TPORT="$(printf '%s' "$FLAT" | sed -n 's/.*"tls_port":\([0-9]\{1,5\}\)[,}].*/\1/p')"
if [ -z "$TPORT" ] && printf '%s' "$FLAT" | grep -q '"tls_port":[^n]'; then echo "Unexpected syslog-over-TLS port in the answer from ASIX (neither a port nor null); nothing changed." >&2; exit 1; fi
# The optional inputs to pause: absent means no opinion (an ASIX from before this, a broker with nothing paused and nothing asked); "" means run them all again.
PI_SET=0; PI=""
if printf '%s' "$FLAT" | grep -q '"paused_inputs":'; then
  printf '%s' "$FLAT" | grep -q '"paused_inputs":"[a-z,]\{0,40\}"' || { echo "Unexpected paused_inputs in the answer from ASIX (not a short comma list); nothing changed." >&2; exit 1; }
  PI_SET=1; PI="$(printf '%s' "$FLAT" | sed -n 's/.*"paused_inputs":"\([a-z,]\{0,40\}\)".*/\1/p')"
  PI_SEEN=","
  for t in ${PI//,/ }; do
    case "$t" in file|http|journald|wazuh) ;; *) echo "ASIX asked to pause '$t', which cannot be paused (only file, http, journald, wazuh); ignored." >&2; exit 1;; esac
    case "$PI_SEEN" in *",$t,"*) echo "ASIX listed '$t' twice in paused_inputs; ignored." >&2; exit 1;; esac
    PI_SEEN="$PI_SEEN$t,"
  done
  # always the same order, whatever ASIX sent
  PI_ORD=""; for t in file http journald wazuh; do case ",$PI," in *",$t,"*) PI_ORD="${PI_ORD:+$PI_ORD,}$t";; esac; done; PI="$PI_ORD"
fi

# The Windows event filter: absent means no opinion (an ASIX from before this, or nothing to say); a 64-character hash names the program ASIX wants in win-filter.vrl.
WF_SET=0; WF=""
if printf '%s' "$FLAT" | grep -q '"win_filter":'; then
  printf '%s' "$FLAT" | grep -q '"win_filter":"[0-9a-f]\{64\}"' || { echo "Unexpected win_filter in the answer from ASIX (not a 64-character hash); nothing changed." >&2; exit 1; }
  WF_SET=1; WF="$(printf '%s' "$FLAT" | sed -n 's/.*"win_filter":"\([0-9a-f]\{64\}\)".*/\1/p')"
fi

BACKUP="$ENV_FILE.before-config"

# apply_env VAR VALUE REJECTED_FILE LABEL DONE_HINT: puts VAR=VALUE in broker.env, validates the result, restarts Vector, waits for health. Any failure puts the
# old broker.env back (restarting Vector on it if it had already been restarted), remembers VALUE in REJECTED_FILE so it is not retried every 5 minutes, returns 1.
apply_env() {
  local VAR="$1" VAL="$2" REJ="$STATE_DIR/$3" LABEL="$4" HINT="$5" TMP CURV TLS ok HEALTH
  CURV="$( . "$ENV_FILE" >/dev/null 2>&1; eval "printf '%s' \"\${$VAR:-}\"" )"
  echo "ASIX asks for $LABEL $VAL (now ${CURV:-not set}). Applying."
  TMP="$(mktemp "$ENV_FILE.XXXXXX")" || { echo "Cannot write next to $ENV_FILE; nothing changed." >&2; return 1; }
  cp -p "$ENV_FILE" "$BACKUP" && cp -p "$ENV_FILE" "$TMP" || { rm -f "$TMP"; echo "Cannot make a backup of $ENV_FILE; nothing changed." >&2; return 1; }
  if grep -q "^$VAR=" "$TMP"; then sed -i "s/^$VAR=.*/$VAR=$VAL/" "$TMP"; else echo "$VAR=$VAL" >> "$TMP"; fi
  mv "$TMP" "$ENV_FILE"

  reject() {  # $1 = why, $2 = restart if Vector was already restarted
    echo "$1 Putting the old settings back." >&2
    cp -p "$BACKUP" "$ENV_FILE"
    mkdir -p "$STATE_DIR" && echo "$VAL" > "$REJ"
    if [ "${2:-}" = restart ]; then systemctl restart vector || echo "Restarting Vector on the old settings failed: journalctl -u vector -n 50" >&2; fi
    return 1
  }

  TLS=""; [ -r "$VECTOR_DIR/vector-tls.yaml" ] && TLS="$VECTOR_DIR/vector-tls.yaml"
  EXTRA=(); for f in vector-file.yaml vector-http.yaml vector-journald.yaml vector-wazuh.yaml; do [ -r "$VECTOR_DIR/$f" ] && EXTRA+=("$VECTOR_DIR/$f"); done   # the optional file, HTTP, journal and Wazuh inputs, when installed
  ( set -a; . "$ENV_FILE"; set +a; vector validate --no-environment ${TLS:+"$TLS"} ${EXTRA[@]+"${EXTRA[@]}"} "$VECTOR_DIR/vector.yaml" ) >/dev/null 2>&1 \
    || { reject "The config does not pass 'vector validate' with $LABEL $VAL."; return 1; }
  systemctl restart vector || { reject "systemctl restart vector failed with $LABEL $VAL." restart; return 1; }
  HEALTH="${ASIX_VECTOR_HEALTH_URL:-http://127.0.0.1:8686/health}"
  ok=0
  for _ in $(seq 1 "$WAIT_S"); do
    if curl -fsS -m 3 "$HEALTH" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  [ "$ok" -eq 1 ] || { reject "Vector did not become healthy within ${WAIT_S}s on $LABEL $VAL (is something else using it?)." restart; return 1; }

  rm -f "$REJ"
  echo "Done: $LABEL ${CURV:-not set} -> $VAL, Vector healthy. $HINT"
  return 0
}

RC=0
# ---- 1. The syslog port ----
if [ -n "$PORT" ]; then
  CUR="${ASIX_SYSLOG_PORT:-514}"
  if [ "$PORT" = "$CUR" ]; then :
  elif [ -r "$STATE_DIR/config-rejected" ] && [ "$(cat "$STATE_DIR/config-rejected" 2>/dev/null)" = "$PORT" ]; then
    echo "Syslog port $PORT was tried before and failed on this broker; not trying again until ASIX asks for a different port."
  else
    apply_env ASIX_SYSLOG_PORT "$PORT" config-rejected "syslog port" "Open $PORT/udp and $PORT/tcp on this VM's firewall; senders must use the new port." || exit 1
  fi
fi

# ---- 2. The syslog-over-TLS port ----
# Only moves the port of a TLS listener this broker ALREADY has (bootstrap-broker.sh --tls-cert/--tls-key). ASIX cannot turn TLS on or off: that needs
# certificates here. The broker's own rules apply whatever ASIX sent: a valid port, not a reserved one, not the syslog port it now uses.
if [ -n "$TPORT" ]; then
  [[ "$TPORT" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$TPORT" -le 65535 ] || { echo "ASIX asked for syslog-over-TLS port $TPORT, which is not a valid port; ignored." >&2; exit 1; }
  case "$TPORT" in 22|443|8686|30443) echo "ASIX asked for syslog-over-TLS port $TPORT, which this broker never uses for syslog; ignored." >&2; exit 1;; esac
  CURT="$( . "$ENV_FILE" >/dev/null 2>&1; printf '%s' "${ASIX_SYSLOG_TLS_PORT:-}" )"   # read again: step 1 may just have changed the file
  NOWP="$( . "$ENV_FILE" >/dev/null 2>&1; printf '%s' "${ASIX_SYSLOG_PORT:-514}" )"
  if [ -z "$CURT" ] || [ ! -r "$VECTOR_DIR/vector-tls.yaml" ]; then
    echo "ASIX asks for syslog-over-TLS port $TPORT, but this broker has no TLS listener (bootstrap-broker.sh --tls-cert and --tls-key); ignored."
  elif [ "$TPORT" = "$NOWP" ]; then
    echo "ASIX asked for syslog-over-TLS port $TPORT, which is the syslog port this broker uses; ignored." >&2; exit 1
  elif [ "$TPORT" = "$CURT" ]; then :
  elif [ -r "$STATE_DIR/config-tls-rejected" ] && [ "$(cat "$STATE_DIR/config-tls-rejected" 2>/dev/null)" = "$TPORT" ]; then
    echo "Syslog-over-TLS port $TPORT was tried before and failed on this broker; not trying again until ASIX asks for a different port."
  else
    apply_env ASIX_SYSLOG_TLS_PORT "$TPORT" config-tls-rejected "syslog-over-TLS port" "Open $TPORT/tcp on this VM's firewall; senders must use the new port." || RC=1
  fi
fi

# ---- 3. Paused inputs ----
# apply_paused LIST: takes the config files of the listed inputs out of VECTOR_CONFIG, and puts back those paused before and not listed now. Vector is restarted only when the list of
# files actually changes (a pause of an input this broker does not have just records the setting). Same safety as the ports: validate on the new list BEFORE the restart, health check
# after, any failure puts the old broker.env back (and restarts Vector on it if it had been restarted) and remembers the list so it is not retried every 5 minutes.
apply_paused() {
  local NEW="$1" OLD CURVC e t base skip has LIST TMP ok HEALTH REJ="$STATE_DIR/config-paused-rejected" RESTART=1 ENT=() OUT=()
  OLD="$( . "$ENV_FILE" >/dev/null 2>&1; printf '%s' "${ASIX_INPUTS_PAUSED:-}" | tr -cd 'a-z,' )"
  [ "$NEW" != "$OLD" ] || return 0
  if [ -r "$REJ" ] && [ "$(cat "$REJ" 2>/dev/null)" = "${NEW:-none}" ]; then
    echo "Paused inputs '${NEW:-none}' was tried before and failed on this broker; not trying again until ASIX asks for a different list."; return 0
  fi
  CURVC="$( . "$ENV_FILE" >/dev/null 2>&1; printf '%s' "${VECTOR_CONFIG:-$VECTOR_DIR/vector.yaml}" )"
  [[ "$CURVC" =~ ^[A-Za-z0-9._/+,-]+$ ]] || { echo "VECTOR_CONFIG in $ENV_FILE has characters this script does not edit safely; nothing changed." >&2; return 1; }
  IFS=, read -ra ENT <<< "$CURVC"
  for e in "${ENT[@]}"; do
    base="${e##*/}"; skip=0
    for t in ${NEW//,/ }; do [ "$base" = "vector-$t.yaml" ] && skip=1; done
    [ "$skip" -eq 1 ] || OUT+=("$e")
  done
  for t in ${OLD//,/ }; do   # paused before, not listed now: put back, if its file is installed and not already listed
    case ",$NEW," in *",$t,"*) continue;; esac
    [ -r "$VECTOR_DIR/vector-$t.yaml" ] || continue
    has=0; for e in ${OUT[@]+"${OUT[@]}"}; do [ "${e##*/}" = "vector-$t.yaml" ] && has=1; done
    [ "$has" -eq 1 ] || OUT+=("$VECTOR_DIR/vector-$t.yaml")
  done
  LIST="$(IFS=,; printf '%s' "${OUT[*]}")"
  [ -n "$LIST" ] || { echo "The new VECTOR_CONFIG would be empty; nothing changed." >&2; return 1; }
  [ "$LIST" != "$CURVC" ] || RESTART=0
  echo "ASIX asks for paused inputs '${NEW:-none}' (now '${OLD:-none}'). Applying."
  TMP="$(mktemp "$ENV_FILE.XXXXXX")" || { echo "Cannot write next to $ENV_FILE; nothing changed." >&2; return 1; }
  cp -p "$ENV_FILE" "$BACKUP" && cp -p "$ENV_FILE" "$TMP" || { rm -f "$TMP"; echo "Cannot make a backup of $ENV_FILE; nothing changed." >&2; return 1; }
  if grep -q '^ASIX_INPUTS_PAUSED=' "$TMP"; then sed -i "s|^ASIX_INPUTS_PAUSED=.*|ASIX_INPUTS_PAUSED=$NEW|" "$TMP"; else echo "ASIX_INPUTS_PAUSED=$NEW" >> "$TMP"; fi
  if [ "$RESTART" -eq 1 ]; then
    if grep -q '^VECTOR_CONFIG=' "$TMP"; then sed -i "s|^VECTOR_CONFIG=.*|VECTOR_CONFIG=$LIST|" "$TMP"; else echo "VECTOR_CONFIG=$LIST" >> "$TMP"; fi
  fi
  mv "$TMP" "$ENV_FILE"
  if [ "$RESTART" -eq 0 ]; then rm -f "$REJ"; echo "Done: paused inputs '${OLD:-none}' -> '${NEW:-none}'. No Vector config file changed, so Vector was not restarted."; return 0; fi

  reject_paused() {  # $1 = why, $2 = restart if Vector was already restarted
    echo "$1 Putting the old settings back." >&2
    cp -p "$BACKUP" "$ENV_FILE"
    mkdir -p "$STATE_DIR" && echo "${NEW:-none}" > "$REJ"
    if [ "${2:-}" = restart ]; then systemctl restart vector || echo "Restarting Vector on the old settings failed: journalctl -u vector -n 50" >&2; fi
    return 1
  }
  ( set -a; . "$ENV_FILE"; set +a; vector validate --no-environment "${OUT[@]}" ) >/dev/null 2>&1 \
    || { reject_paused "The config does not pass 'vector validate' with paused inputs '${NEW:-none}'."; return 1; }
  systemctl restart vector || { reject_paused "systemctl restart vector failed with paused inputs '${NEW:-none}'." restart; return 1; }
  HEALTH="${ASIX_VECTOR_HEALTH_URL:-http://127.0.0.1:8686/health}"
  ok=0
  for _ in $(seq 1 "$WAIT_S"); do
    if curl -fsS -m 3 "$HEALTH" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  [ "$ok" -eq 1 ] || { reject_paused "Vector did not become healthy within ${WAIT_S}s with paused inputs '${NEW:-none}'." restart; return 1; }
  rm -f "$REJ"
  echo "Done: paused inputs '${OLD:-none}' -> '${NEW:-none}', Vector healthy. Senders to a paused input will get connection errors until it is resumed."
  return 0
}
if [ "$PI_SET" -eq 1 ]; then apply_paused "$PI" || RC=1; fi

# ---- 4. The Windows event filter ----
# apply_winfilter HASH: makes $VECTOR_DIR/win-filter.vrl the program ASIX announced. Order, stopping at the first failure: skip when the file already has that hash; skip a hash tried and rejected before;
# download; the hash must match what ASIX announced (a mismatch changes nothing and is NOT remembered: the policy may just have been saved again, the next pull asks again); the file's own sanity checks;
# `vector validate` on a one-transform config that loads the candidate; then replace the file (the old one kept). Vector is restarted only when a Vector config in VECTOR_CONFIG reads win-filter.vrl.
apply_winfilter() {
  local WANT="$1" F="$VECTOR_DIR/win-filter.vrl" REJ="$STATE_DIR/win-filter-rejected" BAK="$VECTOR_DIR/win-filter.vrl.before-config" HAVE="" HS GOT CURVC e CONS=0 ent ok HEALTH HAD=0
  [ -r "$F" ] && HAVE="$(sha256sum < "$F" 2>/dev/null | cut -d' ' -f1)"
  if [ "$WANT" = "$HAVE" ]; then rm -f "$REJ"; return 0; fi
  HS="${HAVE:0:12}"; [ -n "$HS" ] || HS=none   # what the file is now, short, for the messages
  if [ -r "$REJ" ] && [ "$(cat "$REJ" 2>/dev/null)" = "$WANT" ]; then
    echo "Windows filter ${WANT:0:12} was tried before and failed on this broker; not trying again until ASIX announces a different one."; return 0
  fi
  command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is needed to check the Windows filter; nothing changed." >&2; return 1; }
  [ -n "$W" ] || W="$(mktemp -d)" || { echo "Cannot make a scratch folder; nothing changed." >&2; return 1; }
  echo "ASIX announces Windows filter ${WANT:0:12} (now $HS). Downloading."
  curl "${ARGS[@]}" --max-filesize 1048576 -o "$W/win-filter.vrl" "$URL/win-filter" \
    || { echo "Could not download the Windows filter from ASIX; nothing changed." >&2; return 1; }
  GOT="$(sha256sum < "$W/win-filter.vrl" | cut -d' ' -f1)"
  [ "$GOT" = "$WANT" ] || { echo "The Windows filter ASIX served (${GOT:0:12}) is not the one it announced (${WANT:0:12}): the policy was saved again meanwhile, or the download was changed. Nothing changed; asking again at the next pull." >&2; return 1; }
  [ -s "$W/win-filter.vrl" ] && [ "$(wc -c < "$W/win-filter.vrl")" -le 1048576 ] || { echo "The Windows filter is empty or too large; nothing changed." >&2; return 1; }
  # Tab, newline and carriage return are allowed; every other control character, NUL included, is not (grep would not see a NUL, so the file is compared with a copy that has them removed).
  tr -d '\000-\010\013\014\016-\037\177' < "$W/win-filter.vrl" | cmp -s - "$W/win-filter.vrl" || { echo "The Windows filter has control characters; nothing changed." >&2; return 1; }
  mkdir -p "$W/wf-data"
  printf '%s\n' "data_dir: $W/wf-data" "sources:" "  t: { type: demo_logs, format: json, count: 1 }" "transforms:" \
    "  f: { type: remap, inputs: [t], file: $W/win-filter.vrl, drop_on_abort: true }" "sinks:" "  s: { type: blackhole, inputs: [f] }" > "$W/wf-check.yaml"
  vector validate --no-environment "$W/wf-check.yaml" >/dev/null 2>&1 \
    || { mkdir -p "$STATE_DIR" && echo "$WANT" > "$REJ"; echo "The Windows filter ${WANT:0:12} does not pass 'vector validate'. Nothing changed." >&2; return 1; }

  restore() {  # puts the old file back (or removes the new one when there was none)
    if [ "$HAD" -eq 1 ]; then cp -p "$BAK" "$F"; else rm -f "$F"; fi
  }
  if [ -e "$F" ]; then cp -p "$F" "$BAK" && HAD=1 || { echo "Cannot keep a copy of $F; nothing changed." >&2; return 1; }; else rm -f "$BAK"; fi
  install -m 0644 "$W/win-filter.vrl" "$F.new" && mv "$F.new" "$F" || { rm -f "$F.new"; echo "Cannot write $F; nothing changed." >&2; return 1; }

  CURVC="$( . "$ENV_FILE" >/dev/null 2>&1; printf '%s' "${VECTOR_CONFIG:-$VECTOR_DIR/vector.yaml}" )"
  IFS=, read -ra ent <<< "$CURVC"
  for e in "${ent[@]}"; do [ -r "$e" ] && grep -q 'win-filter\.vrl' "$e" 2>/dev/null && CONS=1; done
  if [ "$CONS" -eq 0 ]; then
    rm -f "$REJ"; echo "Done: Windows filter $HS -> ${WANT:0:12}. No Vector config reads $F yet, so Vector was not restarted."; return 0
  fi
  reject_wf() {  # $1 = why, $2 = restart if Vector was already restarted
    echo "$1 Putting the old Windows filter back." >&2
    restore
    mkdir -p "$STATE_DIR" && echo "$WANT" > "$REJ"
    if [ "${2:-}" = restart ]; then systemctl restart vector || echo "Restarting Vector on the old Windows filter failed: journalctl -u vector -n 50" >&2; fi
    return 1
  }
  ( set -a; . "$ENV_FILE"; set +a; vector validate --no-environment "${ent[@]}" ) >/dev/null 2>&1 \
    || { reject_wf "The config does not pass 'vector validate' with Windows filter ${WANT:0:12}."; return 1; }
  systemctl restart vector || { reject_wf "systemctl restart vector failed with Windows filter ${WANT:0:12}." restart; return 1; }
  HEALTH="${ASIX_VECTOR_HEALTH_URL:-http://127.0.0.1:8686/health}"
  ok=0
  for _ in $(seq 1 "$WAIT_S"); do
    if curl -fsS -m 3 "$HEALTH" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  [ "$ok" -eq 1 ] || { reject_wf "Vector did not become healthy within ${WAIT_S}s with Windows filter ${WANT:0:12}." restart; return 1; }
  rm -f "$REJ"
  echo "Done: Windows filter $HS -> ${WANT:0:12}, Vector healthy."
  return 0
}
if [ "$WF_SET" -eq 1 ]; then apply_winfilter "$WF" || RC=1; fi
exit $RC
