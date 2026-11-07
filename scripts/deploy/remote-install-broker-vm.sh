#!/bin/bash
# Installs and sets up a NEW broker VM (Vector + the Wazuh manager) from THIS machine over ssh (docs/remote-install.md, task E12). Run it on asix1 (or any machine with the repo).
# It asks for the VM's address, the ssh user and the password (also used for sudo), signs in, becomes root with sudo, copies scripts/ and deploy/ over, and runs there as root:
#   scripts/deploy/bootstrap-broker.sh --wazuh-manager [--wazuh-alerts] ...your options...      (docs/broker-vm.md; this is the usual install command)
#   then, only with --indexer-file:  scripts/deploy/install-wazuh-manager.sh --indexer-file ...  (points the manager at the central indexer, docs/wazuh-indexer.md)
#
# Usage:
#   ./scripts/deploy/remote-install-broker-vm.sh --check [--host H --user U]            # look only: signs in, runs the installers' own --check, changes nothing
#   ./scripts/deploy/remote-install-broker-vm.sh [--host H] [--user U] [--ssh-port 22] [--password-file F] --url URL --name NAME
#         [--key-file F] [--timezone America/Toronto] [--port 514] [--ca F] [--tls-cert F --tls-key F [--tls-port N] [--tls-client-ca F]] [--accept-config [--config-pubkey F]]
#         [--no-alerts] [--journald] [--wazuh-keep-days N] [--no-install] [--indexer-file F [--indexer-url U]] [--out-dir DIR] [-- more options for bootstrap-broker.sh]
#
#   Anything not given is asked for on the terminal (host, user, password, the ingest key). The ingest key is NOT an option here: give --key-file (one line), or ASIX_INGEST_KEY, or type it.
#   The password: --password-file (mode 600), ASIX_SSH_PASSWORD, or typed. Never an argument, so `ps` here does not show it.
#   --no-alerts      leave out --wazuh-alerts (the default sends the manager's alerts to ASIX too).
#   --indexer-file   a file made on the indexer VM by wazuh-indexer-tenant.sh --writer (see remote-install-indexer-vm.sh, which fetches it for you): the manager's vulnerability
#                    detection is switched on and pointed at that indexer. --indexer-url overrides its address.
#   A re-run of bootstrap-broker.sh forgets any option not given again: give EVERY option again when you run this on a VM that is already set up (add --no-install).
#   Files you name (--ca, --tls-*, --config-pubkey, --key-file, --indexer-file) are copied to the VM in a private folder that is deleted at the end.
# It does not open the firewall: 1514/tcp and 1515/tcp for the agents, the syslog port for the senders (docs/broker-vm.md).
# Every run writes an AUDIT LOG (remote-install-out/<host>-<time>/audit-broker-vm.log here, /var/log/asix-remote-install-<time>.log on the VM). Read those when it stops.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
# shellcheck source=../lib/remote-ssh.sh
. "$REPO/scripts/lib/remote-ssh.sh"

CHECK=0; URL=""; NAME=""; KEY_FILE=""; TZ_=""; PORT=""; CA=""; TLS_CERT=""; TLS_KEY=""; TLS_PORT=""; TLS_CA=""; ACCEPT=0; PUBKEY=""; ALERTS=1; JOURNALD=0; KEEP=""; NOINST=0; IDX_FILE=""; IDX_URL=""; EXTRA=()
RS_HOST=""; RS_USER=""; RS_PORT=""; RS_PWFILE_IN=""; RS_OUT_DIR=""
need() { [ $# -ge 2 ] || rs_die "the option $1 needs a value"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK=1; shift;;
    --host) need "$@"; RS_HOST="$2"; shift 2;;
    --user) need "$@"; RS_USER="$2"; shift 2;;
    --ssh-port) need "$@"; RS_PORT="$2"; shift 2;;
    --password-file) need "$@"; RS_PWFILE_IN="$2"; shift 2;;
    --out-dir) need "$@"; RS_OUT_DIR="$2"; shift 2;;
    --url) need "$@"; URL="$2"; shift 2;;
    --name) need "$@"; NAME="$2"; shift 2;;
    --key-file) need "$@"; KEY_FILE="$2"; shift 2;;
    --timezone) need "$@"; TZ_="$2"; shift 2;;
    --port) need "$@"; PORT="$2"; shift 2;;
    --ca) need "$@"; CA="$2"; shift 2;;
    --tls-cert) need "$@"; TLS_CERT="$2"; shift 2;;
    --tls-key) need "$@"; TLS_KEY="$2"; shift 2;;
    --tls-port) need "$@"; TLS_PORT="$2"; shift 2;;
    --tls-client-ca) need "$@"; TLS_CA="$2"; shift 2;;
    --accept-config) ACCEPT=1; shift;;
    --config-pubkey) need "$@"; PUBKEY="$2"; shift 2;;
    --no-alerts) ALERTS=0; shift;;
    --journald) JOURNALD=1; shift;;
    --wazuh-keep-days) need "$@"; KEEP="$2"; shift 2;;
    --no-install) NOINST=1; shift;;
    --indexer-file) need "$@"; IDX_FILE="$2"; shift 2;;
    --indexer-url) need "$@"; IDX_URL="$2"; shift 2;;
    --) shift; EXTRA=("$@"); break;;
    -h|--help) sed -n 2,30p "$0"; exit 0;;
    *) rs_die "unknown option $1 (see --help)";;
  esac
done

# --- checks that need no connection ------------------------------------------------------------------------------------------------------------------------------------
if [ "$CHECK" -eq 0 ]; then
  [[ "$URL" =~ ^https?://[A-Za-z0-9.:/_-]+$ ]] || rs_die "--url is required: the ASIX ingest address, for example https://asix1:30443/v1/ingest/http"
  [[ "$NAME" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || rs_die "--name is required: the broker's name (letters, digits, . _ -, up to 64)"
fi
[[ -z "$TZ_" || "$TZ_" =~ ^[A-Za-z0-9_+/-]{1,64}$ ]] || rs_die "--timezone is not a valid time zone name"
for p in "$PORT" "$TLS_PORT"; do [ -z "$p" ] || rs_valid_port "$p" || rs_die "'$p' is not a valid port"; done
[[ -z "$KEEP" || "$KEEP" =~ ^[0-9]{1,2}$ ]] || rs_die "--wazuh-keep-days must be a number"
[[ -z "$IDX_URL" || "$IDX_URL" =~ ^https://[A-Za-z0-9.:_-]+$ ]] || rs_die "--indexer-url must look like https://host:9200"
[ -z "$IDX_URL" ] || [ -n "$IDX_FILE" ] || rs_die "--indexer-url needs --indexer-file"
{ [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; } || { [ -z "$TLS_CERT$TLS_KEY$TLS_PORT$TLS_CA" ] || rs_die "--tls-cert and --tls-key go together (and --tls-port and --tls-client-ca need them)"; }
[ -z "$PUBKEY" ] || [ "$ACCEPT" -eq 1 ] || rs_die "--config-pubkey needs --accept-config"
EXTRA_RE='^[]A-Za-z0-9._:/=@+,%*?[-]+$'   # what an option passed through may contain; each one is single-quoted for the VM, so * ? [ ] are not expanded
for a in "${EXTRA[@]+"${EXTRA[@]}"}"; do [[ "$a" =~ $EXTRA_RE ]] || rs_die "the extra option '$a' has a character that is not allowed here (letters, digits and . _ : / = @ + , % * ? [ ] -)"; done
for f in "$CA" "$TLS_CERT" "$TLS_KEY" "$TLS_CA" "$PUBKEY" "$KEY_FILE" "$IDX_FILE"; do [ -z "$f" ] || { [ -f "$f" ] && [ -r "$f" ] || rs_die "cannot read the file $f"; }; done
KEY=""
if [ "$CHECK" -eq 0 ] && [ -n "$KEY_FILE" ]; then   # the file is checked here too, so a wrong file is found before anything is copied; the key is not printed
  IFS= read -r KEYCHK < "$KEY_FILE" || true; [[ "$KEYCHK" =~ ^asix_ik_[A-Za-z0-9_-]{8,200}$ ]] || rs_die "the first line of $KEY_FILE does not look like an ingest key (asix_ik_...)"; unset KEYCHK
fi
if [ "$CHECK" -eq 0 ] && [ -z "$KEY_FILE" ]; then
  if [ -n "${ASIX_INGEST_KEY:-}" ]; then KEY="$ASIX_INGEST_KEY"; unset ASIX_INGEST_KEY
  else [ -t 0 ] || rs_die "no ingest key: use --key-file, ASIX_INGEST_KEY, or run this on a terminal"; read -r -s -p "ASIX ingest key for $NAME (asix_ik_..., from Settings, Brokers): " KEY; echo; fi
  [[ "$KEY" =~ ^asix_ik_[A-Za-z0-9_-]{8,200}$ ]] || rs_die "that does not look like an ingest key (asix_ik_...)"
fi

rs_collect
rs_open broker-vm
rs_say "Broker VM install for $NAME on $RS_HOST (check only: $CHECK)"
rs_probe
rs_upload "$REPO"

# --- the command lines (secrets stay in files on the VM, not in any text printed here) --------------------------------------------------------------------------------------
F='files'
BOOT="./scripts/deploy/bootstrap-broker.sh --wazuh-manager"
[ "$ALERTS" -eq 0 ] || BOOT="$BOOT --wazuh-alerts"
[ "$JOURNALD" -eq 0 ] || BOOT="$BOOT --journald"
[ "$NOINST" -eq 0 ] || BOOT="$BOOT --no-install"
[ -z "$KEEP" ] || BOOT="$BOOT --wazuh-keep-days $KEEP"
[ -z "$TZ_" ] || BOOT="$BOOT --timezone $(rs_sq "$TZ_")"
[ -z "$PORT" ] || BOOT="$BOOT --port $PORT"
if [ "$CHECK" -eq 1 ]; then
  rs_say "Check only: the manager installer's --check on the VM"
  rs_run_installer "./scripts/deploy/install-wazuh-manager.sh --check"; rs_finish; exit 0
fi
[ -z "$CA" ] || { rs_put "$CA" ca.pem; BOOT="$BOOT --ca $F/ca.pem"; }
[ -z "$TLS_CERT" ] || { rs_put "$TLS_CERT" tls.crt; rs_put "$TLS_KEY" tls.key; BOOT="$BOOT --tls-cert $F/tls.crt --tls-key $F/tls.key"; }
[ -z "$TLS_PORT" ] || BOOT="$BOOT --tls-port $TLS_PORT"
[ -z "$TLS_CA" ] || { rs_put "$TLS_CA" tls-client-ca.pem; BOOT="$BOOT --tls-client-ca $F/tls-client-ca.pem"; }
[ "$ACCEPT" -eq 0 ] || BOOT="$BOOT --accept-config"
[ -z "$PUBKEY" ] || { rs_put "$PUBKEY" config-signing.pub; BOOT="$BOOT --config-pubkey $F/config-signing.pub"; }
if [ -n "$KEY_FILE" ]; then rs_put "$KEY_FILE" ingest.key; else printf '%s\n' "$KEY" > "$RS_TMP/ingest.key"; rs_put "$RS_TMP/ingest.key" ingest.key; fi
for a in "${EXTRA[@]+"${EXTRA[@]}"}"; do BOOT="$BOOT $(rs_sq "$a")"; done
# the key is read from its file ON the VM, inside the command: it is in no argument list here and not in the audit log (the log shows <key from file>).
rs_say "Running on the VM as root: ${BOOT} --url $(rs_sq "$URL") --name $(rs_sq "$NAME") --key <key from file>"
rs_run_installer "$BOOT --url $(rs_sq "$URL") --name $(rs_sq "$NAME") --key \"\$(tr -d '\\r\\n' < $F/ingest.key)\"" || rs_die "bootstrap-broker.sh failed on the VM (its output is above and in the audit log)"
if [ -n "$IDX_FILE" ]; then
  rs_put "$IDX_FILE" indexer.json
  IX="./scripts/deploy/install-wazuh-manager.sh --indexer-file $F/indexer.json"; [ -z "$IDX_URL" ] || IX="$IX --indexer-url $(rs_sq "$IDX_URL")"
  rs_say "Pointing the manager at the central indexer"
  rs_run_installer "$IX" || rs_die "install-wazuh-manager.sh --indexer-file failed on the VM (see the audit log)"
fi
rs_finish
rs_say "Done. Next: open 1514/tcp and 1515/tcp on the VM's firewall for the agents; on the Brokers page the new broker should report within a minute (docs/broker-vm.md)."
