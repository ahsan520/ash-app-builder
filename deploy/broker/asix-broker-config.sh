#!/bin/bash
# Broker config pull: asks ASIX what this broker should be configured with and applies it, SAFELY. Run as root every 5 minutes by
# asix-broker-config.timer, which scripts/deploy/bootstrap-broker.sh installs ONLY when given --accept-config (ASIX_ACCEPT_CONFIG=true
# in broker.env). A broker set up without that flag never runs this and ASIX cannot change it.
#
# One setting so far: the syslog port (one value for the tenant, or a port set for this broker alone). What it does, in this order, and stops at the first failure:
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

ARGS=(-fsS -m 10 -H "Authorization: Bearer ${ASIX_INGEST_KEY}")
[ -n "${ASIX_CA_FILE:-}" ] && ARGS+=(--cacert "$ASIX_CA_FILE")

report() {  # EXIT trap: what this broker listens on now (read from broker.env AFTER any change or put-back) and the port it rejected, if any
  local cur rej name body
  name="$(printf '%s' "${ASIX_BROKER_NAME:-}" | tr -d '"\\' | cut -c1-100)"; [ -n "$name" ] || return 0
  cur="$( . "$ENV_FILE" >/dev/null 2>&1; printf '%s' "${ASIX_SYSLOG_PORT:-514}" )"
  [[ "$cur" =~ ^[1-9][0-9]{0,4}$ ]] || return 0
  rej=""; [ -r "$STATE_DIR/config-rejected" ] && rej="$(tr -cd '0-9' < "$STATE_DIR/config-rejected" 2>/dev/null | cut -c1-5)"
  [[ "$rej" =~ ^[1-9][0-9]{0,4}$ ]] || rej="null"
  body="$(printf '{"collector":"%s","syslog_port":%s,"rejected_port":%s}' "$name" "$cur" "$rej")"
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
  [ -r "$ASIX_CONFIG_PUBKEY_FILE" ] || { echo "Cannot read the config public key $ASIX_CONFIG_PUBKEY_FILE; nothing changed." >&2; exit 1; }
  command -v openssl >/dev/null 2>&1 || { echo "openssl is needed to check ASIX's signature; nothing changed." >&2; exit 1; }
  W="$(mktemp -d)" || { echo "Cannot make a scratch folder; nothing changed." >&2; exit 1; }
  PB="$(printf '%s' "$FLAT" | sed -n 's/.*"payload":"\([A-Za-z0-9+\/=]*\)".*/\1/p')"
  SB="$(printf '%s' "$FLAT" | sed -n 's/.*"signature":"\([A-Za-z0-9+\/=]*\)".*/\1/p')"
  [ -n "$PB" ] && [ -n "$SB" ] && [ "${#PB}" -le 2000 ] && [ "${#SB}" -le 2000 ] || { echo "ASIX did not sign this answer, and this broker accepts only signed config (ASIX_CONFIG_PUBKEY_FILE). Is the signing key set on ASIX? Nothing changed." >&2; exit 1; }
  printf '%s' "$PB" | base64 -d > "$W/payload" 2>/dev/null && printf '%s' "$SB" | base64 -d > "$W/sig" 2>/dev/null && [ -s "$W/payload" ] && [ -s "$W/sig" ] \
    || { echo "The signed part of ASIX's answer is not valid base64; nothing changed." >&2; exit 1; }
  awk -v d="$W" '/-----BEGIN PUBLIC KEY-----/{n++} n{print > (d "/key" n ".pem")}' "$ASIX_CONFIG_PUBKEY_FILE"
  ok=0; shopt -s nullglob
  for k in "$W"/key*.pem; do
    if openssl dgst -sha256 -verify "$k" -signature "$W/sig" "$W/payload" >/dev/null 2>&1; then ok=1; break; fi
  done
  shopt -u nullglob
  [ "$ok" -eq 1 ] || { echo "The signature on ASIX's answer does not match the public key in $ASIX_CONFIG_PUBKEY_FILE (wrong key, or the answer was changed); nothing changed." >&2; exit 1; }
  PAY="$(tr -d ' \t\r\n' < "$W/payload")"
  [[ "$PAY" == '{"v":1,'* ]] || { echo "The signed answer has an unknown format; nothing changed." >&2; exit 1; }
  WHO="null"; [[ "${ASIX_BROKER_NAME:-}" =~ ^[A-Za-z0-9._:-]{1,100}$ ]] && WHO="\"${ASIX_BROKER_NAME}\""
  case "$PAY" in *'"collector":'"$WHO"',"issued_at":'*) ;; *) echo "The signed answer was made for another broker; nothing changed." >&2; exit 1;; esac
  ISSUED="$(printf '%s' "$PAY" | sed -n 's/.*"issued_at":\([0-9]\{1,12\}\),.*/\1/p')"
  NOW="$(date +%s)"; DIFF=$(( NOW - ${ISSUED:-0} )); [ "$DIFF" -ge 0 ] || DIFF=$(( -DIFF ))
  [ -n "$ISSUED" ] && [ "$DIFF" -le "$MAX_SKEW" ] || { echo "The signed answer is ${DIFF}s away from this machine's clock (limit ${MAX_SKEW}s): replayed, or one of the clocks is wrong; nothing changed." >&2; exit 1; }
  FLAT="$PAY"
fi
if printf '%s' "$FLAT" | grep -q '"syslog_port":null'; then exit 0; fi
PORT="$(printf '%s' "$FLAT" | sed -n 's/.*"syslog_port":\([0-9]\{1,5\}\)[,}].*/\1/p')"
[ -n "$PORT" ] || { echo "Unexpected answer from ASIX (no syslog_port); nothing changed." >&2; exit 1; }

# The broker's own rules, independent of what ASIX sent.
[[ "$PORT" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$PORT" -le 65535 ] || { echo "ASIX asked for syslog port $PORT, which is not a valid port; ignored." >&2; exit 1; }
case "$PORT" in 22|443|8686|30443) echo "ASIX asked for syslog port $PORT, which this broker never uses for syslog; ignored." >&2; exit 1;; esac
[ "$PORT" != "${ASIX_SYSLOG_TLS_PORT:-}" ] || { echo "ASIX asked for syslog port $PORT, which is this broker's syslog-over-TLS port; ignored." >&2; exit 1; }

CUR="${ASIX_SYSLOG_PORT:-514}"
[ "$PORT" != "$CUR" ] || exit 0
if [ -r "$STATE_DIR/config-rejected" ] && [ "$(cat "$STATE_DIR/config-rejected" 2>/dev/null)" = "$PORT" ]; then
  echo "Syslog port $PORT was tried before and failed on this broker; not trying again until ASIX asks for a different port."; exit 0
fi

echo "ASIX asks for syslog port $PORT (now $CUR). Applying."
BACKUP="$ENV_FILE.before-config"
TMP="$(mktemp "$ENV_FILE.XXXXXX")" || { echo "Cannot write next to $ENV_FILE; nothing changed." >&2; exit 1; }
cp -p "$ENV_FILE" "$BACKUP" && cp -p "$ENV_FILE" "$TMP" || { rm -f "$TMP"; echo "Cannot make a backup of $ENV_FILE; nothing changed." >&2; exit 1; }
if grep -q '^ASIX_SYSLOG_PORT=' "$TMP"; then sed -i "s/^ASIX_SYSLOG_PORT=.*/ASIX_SYSLOG_PORT=$PORT/" "$TMP"; else echo "ASIX_SYSLOG_PORT=$PORT" >> "$TMP"; fi
mv "$TMP" "$ENV_FILE"

reject() {  # $1 = why. Puts the old env back, restarts Vector on it if it was already restarted, remembers the port.
  echo "$1 Putting the old settings back." >&2
  cp -p "$BACKUP" "$ENV_FILE"
  mkdir -p "$STATE_DIR" && echo "$PORT" > "$STATE_DIR/config-rejected"
  if [ "${2:-}" = restart ]; then systemctl restart vector || echo "Restarting Vector on the old settings failed: journalctl -u vector -n 50" >&2; fi
  exit 1
}

TLS=""; [ -r "$VECTOR_DIR/vector-tls.yaml" ] && TLS="$VECTOR_DIR/vector-tls.yaml"
( set -a; . "$ENV_FILE"; set +a; vector validate --no-environment ${TLS:+"$TLS"} "$VECTOR_DIR/vector.yaml" ) >/dev/null 2>&1 \
  || reject "The config does not pass 'vector validate' with syslog port $PORT."
systemctl restart vector || reject "systemctl restart vector failed with syslog port $PORT." restart
HEALTH="${ASIX_VECTOR_HEALTH_URL:-http://127.0.0.1:8686/health}"
ok=0
for _ in $(seq 1 "$WAIT_S"); do
  if curl -fsS -m 3 "$HEALTH" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
[ "$ok" -eq 1 ] || reject "Vector did not become healthy within ${WAIT_S}s on syslog port $PORT (is something else using it?)." restart

rm -f "$STATE_DIR/config-rejected"
echo "Done: syslog port $CUR -> $PORT, Vector healthy. Open $PORT/udp and $PORT/tcp on this VM's firewall; senders must use the new port."
