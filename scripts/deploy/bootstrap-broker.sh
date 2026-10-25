#!/bin/bash
# Sets up THIS machine as an ASIX broker VM: Vector (syslog in, ASIX HTTP ingest out) plus a
# one-minute heartbeat. Debian/Ubuntu. Safe to re-run: it only rewrites its own files.
#
# Usage (as root):
#   ./scripts/deploy/bootstrap-broker.sh --url https://asix1:30443/v1/ingest/http --key asix_ik_... \
#       --name broker-1 [--port 514] [--ca /path/to/cert.pem] [--no-install]
#       [--tls-cert server.crt --tls-key server.key [--tls-port 6514] [--tls-client-ca ca.pem]] [--accept-config [--config-pubkey config-signing.pub]]
#       [--timezone America/Toronto]
#       [--file-glob '/var/log/myapp/*.log' [--file-glob '/srv/other/*.log' ...]] [--http-user svc --http-password-file /root/http.pw [--http-port 8088] [--http-tls]]
#       [--journald [--journald-priority 6]] [--wazuh [--wazuh-archives /var/ossec/logs/archives/archives.json]]
#       [--wazuh-manager [--wazuh-keep-days 3]]
#
# --timezone       The time zone (IANA name, default UTC) that senders write in on syslog lines that carry none (RFC 3164). Vector reads those as
#                  UTC, so a sender in another zone shows hours off in search and detections. Written as ASIX_SYSLOG_TIMEZONE. Like every option here it
#                  is only kept if given again on a re-run. RFC 5424 lines carry their own offset and are not touched.
# --file-glob      Also read log FILES on this machine: an absolute glob (letters, digits and . _ - / * ? [ ] only). Give the option again for
#                  more globs (up to 10, the same one twice counts once). Each new line is sent to ASIX with source type "file". The vector
#                  user must be able to read the files. Written as ASIX_FILE_GLOB (comma separated); installs vector-file.yaml with one
#                  include line per glob. Re-running without it turns file reading off again. See docs/broker-vm.md, "More inputs: files and HTTP".
# --http-user      Also accept events over HTTP (POST JSON to http://THIS-VM:8088/events with basic authentication), source type "http". Needs
#   --http-password-file  a file holding the password on ONE line (12 to 128 of letters, digits and . _ ~ @ % + = : , - ; not on the command
#                  line, where `ps` would show it). Both are needed together. --http-port changes 8088. --http-tls serves HTTPS with the
#                  certificate of --tls-cert/--tls-key (needs them). Installs vector-http.yaml; re-running without them turns it off.
# --journald       Also read the systemd JOURNAL of this machine (sshd, sudo, cron, the kernel, every service that logs through systemd) and send
#                  each new entry to ASIX with source type "journald". Adds the vector user to the systemd-journal group so it may read the journal.
#                  Installs vector-journald.yaml; re-running without it turns journal reading off again (the group membership stays).
#   --journald-priority N  With --journald: send only entries at least this important, N from 0 (emerg) to 7 (debug); default 6 (everything but
#                  debug), 4 is warnings and worse. Written as ASIX_JOURNALD_MAX_PRIORITY.
# --wazuh          Also read WINDOWS EVENTS from a Wazuh manager's archive file (default /var/ossec/logs/archives/archives.json, the manager must have
#                  <logall_json>yes</logall_json> in its ossec.conf), apply the tenant's Windows event filter policy (Settings, Windows event filter) and send
#                  what is left with source type "windows-event". Adds the vector user to the wazuh group when there is one. Installs vector-wazuh.yaml and,
#                  when there is none yet, the keep-everything filter /etc/vector/win-filter.vrl (Vector will not start without it; asix-broker-config.sh
#                  keeps it in step with the policy when the broker accepts config). Re-running without --wazuh turns it off (the filter file stays).
#   --wazuh-archives PATH  With --wazuh: another archive file. Written as ASIX_WAZUH_ARCHIVES.
# --wazuh-manager  Also INSTALL a Wazuh manager on this machine (scripts/deploy/install-wazuh-manager.sh: pinned version, held back from upgrades, agents need
#                  an enrolment password, archives.json switched on, a daily clean-up) and read its archive file as with --wazuh, which this implies. Windows
#                  agents then report to this machine on 1514/tcp (agents) and 1515/tcp (enrolment); open them on the firewall. Needs 2+ CPUs, 3.5 GB memory
#                  (8 GB and 4 CPUs recommended) and 20 GB free (100 GB recommended). --port, --tls-port and --http-port must not be 1514, 1515, 1516 or 55000.
#   --wazuh-keep-days N  With --wazuh-manager: keep N days (1 to 90, default 3) of the manager's rotated archive and alert files.
# --no-install     Vector is already installed (offline or pinned install); skip the package repo.
# --tls-cert/key   Also accept syslog over TLS (RFC 5425) on --tls-port (default 6514), with this server certificate.
#                  Both are needed together. Re-running without them turns the TLS listener off again.
# --tls-client-ca  Require every sender to present a certificate issued by this CA (mutual TLS).
# --accept-config  Let ASIX change this broker's syslog port (Brokers page, Syslog port): installs a root timer that asks ASIX every 5
#                  minutes and applies the port only after its own checks (see deploy/broker/asix-broker-config.sh). Without this flag
#                  ASIX cannot change the broker; re-running without it turns the timer off again.
# --config-pubkey  With --accept-config: act only on config that ASIX has SIGNED with the matching private key (Brokers page shows the
#                  public key; scripts/deploy/make-config-signing-key.sh makes the pair). The file may hold several public keys (any one
#                  matches), which lets a signing key be replaced without a gap. Needs openssl. Re-running without it goes back to
#                  accepting unsigned config, so keep it on every re-run.

set -euo pipefail

URL=""; KEY=""; NAME=""; PORT="514"; CA=""; INSTALL=1; TLS_CERT=""; TLS_KEY=""; TLS_PORT="6514"; TLS_CLIENT_CA=""; ACCEPT_CONFIG=0; CONFIG_PUBKEY=""; TIMEZONE="UTC"; FILE_GLOB=""; HTTP_USER=""; HTTP_PW_FILE=""; HTTP_PORT="8088"; HTTP_TLS=0; JOURNALD=0; JOURNALD_PRIORITY="6"; WAZUH=0; WAZUH_ARCHIVES="/var/ossec/logs/archives/archives.json"; WAZUH_ARCHIVES_SET=0; WAZUH_MANAGER=0; WAZUH_KEEP_DAYS="3"; WAZUH_KEEP_SET=0
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="$2"; shift 2;;
    --key) KEY="$2"; shift 2;;
    --name) NAME="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --ca) CA="$2"; shift 2;;
    --no-install) INSTALL=0; shift;;
    --tls-cert) TLS_CERT="$2"; shift 2;;
    --tls-key) TLS_KEY="$2"; shift 2;;
    --tls-port) TLS_PORT="$2"; shift 2;;
    --tls-client-ca) TLS_CLIENT_CA="$2"; shift 2;;
    --accept-config) ACCEPT_CONFIG=1; shift;;
    --config-pubkey) CONFIG_PUBKEY="$2"; shift 2;;
    --timezone) TIMEZONE="$2"; shift 2;;
    --file-glob) FILE_GLOB="${FILE_GLOB:+$FILE_GLOB$'\n'}$2"; shift 2;;   # repeatable: one glob per line
    --http-user) HTTP_USER="$2"; shift 2;;
    --http-password-file) HTTP_PW_FILE="$2"; shift 2;;
    --http-port) HTTP_PORT="$2"; shift 2;;
    --http-tls) HTTP_TLS=1; shift;;
    --journald) JOURNALD=1; shift;;
    --journald-priority) JOURNALD_PRIORITY="$2"; shift 2;;
    --wazuh) WAZUH=1; shift;;
    --wazuh-archives) WAZUH_ARCHIVES="$2"; WAZUH_ARCHIVES_SET=1; shift 2;;
    --wazuh-manager) WAZUH_MANAGER=1; WAZUH=1; shift;;   # reading its archive file is part of it
    --wazuh-keep-days) WAZUH_KEEP_DAYS="$2"; WAZUH_KEEP_SET=1; shift 2;;
    *) echo "Unknown option: $1" >&2; exit 2;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
[ -n "$URL" ] && [ -n "$KEY" ] && [ -n "$NAME" ] || { sed -n '2,10p' "$0"; exit 2; }
[[ "$KEY" == asix_ik_* ]] || { echo "The key must start with asix_ik_ (create it in Settings > Collectors > Installers)." >&2; exit 2; }
[[ "$NAME" =~ ^[A-Za-z0-9._:-]{1,100}$ ]] || { echo "Name: 1-100 chars of letters, digits . _ : -" >&2; exit 2; }
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] || { echo "Port must be a number." >&2; exit 2; }

[[ "$TLS_PORT" =~ ^[0-9]{1,5}$ ]] || { echo "--tls-port must be a number." >&2; exit 2; }
[[ "$TIMEZONE" =~ ^[A-Za-z0-9_+./-]{1,64}$ && "$TIMEZONE" != *..* ]] || { echo "--timezone must be an IANA zone name such as America/Toronto (or UTC)." >&2; exit 2; }
[ "$TIMEZONE" = "UTC" ] || [ ! -d /usr/share/zoneinfo ] || [ -f "/usr/share/zoneinfo/$TIMEZONE" ] || { echo "--timezone: $TIMEZONE is not a time zone on this machine (see: timedatectl list-timezones)." >&2; exit 2; }
if [ -n "$TLS_CERT$TLS_KEY$TLS_CLIENT_CA" ]; then
  [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ] || { echo "--tls-cert and --tls-key are needed together (also with --tls-client-ca)." >&2; exit 2; }
  [ -r "$TLS_CERT" ] || { echo "Cannot read $TLS_CERT" >&2; exit 2; }
  [ -r "$TLS_KEY" ] || { echo "Cannot read $TLS_KEY" >&2; exit 2; }
  [ -z "$TLS_CLIENT_CA" ] || [ -r "$TLS_CLIENT_CA" ] || { echo "Cannot read $TLS_CLIENT_CA" >&2; exit 2; }
  [ "$TLS_PORT" != "$PORT" ] || { echo "--tls-port must differ from --port (UDP and plain TCP use $PORT)." >&2; exit 2; }
  # The certificate and the key must belong together, or Vector would only fail after the restart.
  if command -v openssl >/dev/null 2>&1; then
    a="$(openssl x509 -in "$TLS_CERT" -noout -pubkey 2>/dev/null | openssl md5)"; b="$(openssl pkey -in "$TLS_KEY" -pubout 2>/dev/null | openssl md5)"
    [ "$a" = "$b" ] || { echo "$TLS_CERT and $TLS_KEY do not match (or one is not readable PEM)." >&2; exit 2; }
  fi
fi

if [ -n "$CONFIG_PUBKEY" ]; then
  [ "$ACCEPT_CONFIG" -eq 1 ] || { echo "--config-pubkey only makes sense with --accept-config (it is what the config pull checks)." >&2; exit 2; }
  [ -r "$CONFIG_PUBKEY" ] || { echo "Cannot read $CONFIG_PUBKEY" >&2; exit 2; }
  command -v openssl >/dev/null 2>&1 || { echo "--config-pubkey needs openssl on this machine (apt-get install openssl)." >&2; exit 2; }
  # Every key in the file must be a P-256 public key, or the broker would refuse everything ASIX signs.
  PKTMP="$(mktemp -d)"; trap 'rm -rf "$PKTMP"' EXIT
  awk -v d="$PKTMP" '/-----BEGIN PUBLIC KEY-----/{n++} n{print > (d "/key" n ".pem")}' "$CONFIG_PUBKEY"
  shopt -s nullglob; PKFILES=("$PKTMP"/key*.pem); shopt -u nullglob
  [ "${#PKFILES[@]}" -gt 0 ] || { echo "$CONFIG_PUBKEY holds no PEM public key (-----BEGIN PUBLIC KEY-----)." >&2; exit 2; }
  for k in "${PKFILES[@]}"; do
    openssl pkey -pubin -in "$k" -noout -text 2>/dev/null | grep -q 'prime256v1\|P-256' || { echo "A key in $CONFIG_PUBKEY is not an EC P-256 public key." >&2; exit 2; }
  done
fi

# Extra input: the systemd journal. Checked before anything is written.
JOURNALD_CFG=""   # the config file to validate; empty (not "0") when the journal is not read
if [ "$JOURNALD" -eq 1 ]; then
  JOURNALD_CFG="/etc/vector/vector-journald.yaml"
  [[ "$JOURNALD_PRIORITY" =~ ^[0-7]$ ]] || { echo "--journald-priority must be a number from 0 (emerg) to 7 (debug)." >&2; exit 2; }
  command -v journalctl >/dev/null 2>&1 || { echo "--journald needs journalctl on this machine (a systemd distribution)." >&2; exit 2; }
elif [ "$JOURNALD_PRIORITY" != "6" ]; then
  echo "--journald-priority only makes sense with --journald." >&2; exit 2
fi
# (end of the journal checks)

# Extra input: Windows events from a Wazuh manager. Checked before anything is written; the path goes into broker.env, so only plain characters.
WAZUH_CFG=""   # the config file to validate; empty when Wazuh is not read
if [ "$WAZUH" -eq 1 ]; then
  WAZUH_CFG="/etc/vector/vector-wazuh.yaml"
  [[ "$WAZUH_ARCHIVES" =~ ^/[A-Za-z0-9._/-]{1,200}$ ]] && [[ "$WAZUH_ARCHIVES" != *..* ]] || { echo "--wazuh-archives must be an absolute path of plain characters (letters, digits, . _ - /)." >&2; exit 2; }
elif [ "$WAZUH_ARCHIVES_SET" -eq 1 ]; then
  echo "--wazuh-archives only makes sense with --wazuh." >&2; exit 2
fi
# (end of the Wazuh checks)

# Extra input: a Wazuh manager installed on this machine. Its ports must be free of the ones this script gives to syslog and the other listeners.
if [ "$WAZUH_MANAGER" -eq 1 ]; then
  [[ "$WAZUH_KEEP_DAYS" =~ ^[0-9]{1,2}$ ]] && [ "$WAZUH_KEEP_DAYS" -ge 1 ] && [ "$WAZUH_KEEP_DAYS" -le 90 ] || { echo "--wazuh-keep-days must be a number from 1 to 90." >&2; exit 2; }
  for pair in "--port:$PORT" ${TLS_CERT:+"--tls-port:$TLS_PORT"} ${HTTP_USER:+"--http-port:$HTTP_PORT"}; do
    case "${pair#*:}" in 1514|1515|1516|55000) echo "${pair%%:*} ${pair#*:} is a port of the Wazuh manager (1514 agents, 1515 enrolment, 1516 cluster, 55000 API); choose another with --wazuh-manager." >&2; exit 2;; esac
  done
elif [ "$WAZUH_KEEP_SET" -eq 1 ]; then
  echo "--wazuh-keep-days only makes sense with --wazuh-manager." >&2; exit 2
fi
# (end of the Wazuh manager checks)

# Extra inputs: files and HTTP. Checked before anything is written; the values go into broker.env and into a quoted YAML string, so only plain characters.
if [ -n "$FILE_GLOB" ]; then
  GLOB_RE='^/[]A-Za-z0-9._/*?[-]+$'   # in a bracket expression "]" must come first and "-" last; a backslash is literal there
  FILE_GLOB_N=0; FILE_GLOB_SEEN=$'\n'; FILE_GLOB_UNIQ=""
  while IFS= read -r g; do   # one glob per line (--file-glob can be given more than once); a here-string, so "exit" leaves the script
    [[ "$g" =~ $GLOB_RE && "$g" != *..* ]] || { echo "--file-glob must be an absolute path glob using only letters, digits and . _ - / * ? [ ] (no spaces, no ..)." >&2; exit 2; }
    case "$FILE_GLOB_SEEN" in *$'\n'"$g"$'\n'*) continue;; esac   # the same glob twice counts once
    FILE_GLOB_SEEN="$FILE_GLOB_SEEN$g"$'\n'; FILE_GLOB_UNIQ="${FILE_GLOB_UNIQ:+$FILE_GLOB_UNIQ$'\n'}$g"; FILE_GLOB_N=$((FILE_GLOB_N + 1))
  done <<< "$FILE_GLOB"
  [ "$FILE_GLOB_N" -le 10 ] || { echo "--file-glob can be given at most 10 times (got $FILE_GLOB_N). Use a wider glob." >&2; exit 2; }
  FILE_GLOB="$FILE_GLOB_UNIQ"
fi
HTTP_PW=""
if [ -n "$HTTP_USER$HTTP_PW_FILE" ]; then
  [ -n "$HTTP_USER" ] && [ -n "$HTTP_PW_FILE" ] || { echo "--http-user and --http-password-file are needed together." >&2; exit 2; }
  [[ "$HTTP_USER" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { echo "--http-user: 1-64 chars of letters, digits . _ -" >&2; exit 2; }
  { [[ "$HTTP_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$HTTP_PORT" -ge 1 ] && [ "$HTTP_PORT" -le 65535 ]; } || { echo "--http-port must be a number from 1 to 65535." >&2; exit 2; }
  { [ "$HTTP_PORT" != "$PORT" ] && [ "$HTTP_PORT" != "$TLS_PORT" ]; } || { echo "--http-port must differ from --port ($PORT) and --tls-port ($TLS_PORT)." >&2; exit 2; }
  [ -r "$HTTP_PW_FILE" ] || { echo "Cannot read $HTTP_PW_FILE" >&2; exit 2; }
  HTTP_PW="$(head -n 1 "$HTTP_PW_FILE" | tr -d '\r')"
  [[ "$HTTP_PW" =~ ^[A-Za-z0-9._~@%+=:,-]{12,128}$ ]] || { echo "The HTTP password (first line of $HTTP_PW_FILE) must be 12-128 chars of letters, digits and . _ ~ @ % + = : , -" >&2; exit 2; }
  { [ "$HTTP_TLS" -eq 0 ] || [ -n "$TLS_CERT" ]; } || { echo "--http-tls needs --tls-cert and --tls-key (HTTPS uses the same certificate as syslog over TLS)." >&2; exit 2; }
else
  [ "$HTTP_TLS" -eq 0 ] || { echo "--http-tls only makes sense with --http-user and --http-password-file." >&2; exit 2; }
fi

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../deploy/broker" && pwd)"

echo "== ASIX broker bootstrap =="
if [ "$INSTALL" -eq 1 ] && ! command -v vector >/dev/null 2>&1; then
  echo "-- 1. Installing Vector from the official package repository --"
  command -v curl >/dev/null || apt-get install -y curl
  curl -1sLf 'https://setup.vector.dev' | bash
  apt-get install -y vector
else
  echo "-- 1. Vector: $(command -v vector >/dev/null && vector --version | head -1 || echo 'not found') --"
fi
command -v vector >/dev/null || { echo "Vector is not installed; run without --no-install." >&2; exit 1; }
command -v curl >/dev/null || apt-get install -y curl

echo "-- 2. Writing /etc/asix-broker/broker.env (mode 600) --"
install -d -m 750 -o root -g vector /etc/asix-broker
if [ -n "$CONFIG_PUBKEY" ]; then
  install -m 644 "$CONFIG_PUBKEY" /etc/asix-broker/config-signing.pub
  for k in "${PKFILES[@]}"; do echo "   trusting config signing key $(openssl pkey -pubin -in "$k" -outform DER | openssl dgst -sha256 -hex | sed 's/^.*= //' | cut -c1-12) (compare with the key id on ASIX's Brokers page)"; done
else
  rm -f /etc/asix-broker/config-signing.pub   # re-run without --config-pubkey: signatures are no longer required
fi
{
  echo "ASIX_INGEST_URL=$URL"
  echo "ASIX_INGEST_KEY=$KEY"
  echo "ASIX_BROKER_NAME=$NAME"
  echo "ASIX_SYSLOG_PORT=$PORT"
  [ "$TIMEZONE" = "UTC" ] || echo "ASIX_SYSLOG_TIMEZONE=$TIMEZONE"
  # Vector 0.59 and newer leave ${VAR} in the config as plain text unless this is set (older versions ignore it and always substitute).
  # The substituted values are this file's own settings, readable only by root and the vector user.
  echo "VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true"
  [ "$ACCEPT_CONFIG" -eq 0 ] || echo "ASIX_ACCEPT_CONFIG=true"
  [ -z "$CONFIG_PUBKEY" ] || echo "ASIX_CONFIG_PUBKEY_FILE=/etc/asix-broker/config-signing.pub"
  if [ -n "$CA" ]; then
    install -m 644 "$CA" /etc/asix-broker/ca.pem
    echo "ASIX_CA_FILE=/etc/asix-broker/ca.pem"
  fi
  if [ -n "$TLS_CERT" ]; then
    install -d -m 750 -o root -g vector /etc/asix-broker/tls
    install -m 644 "$TLS_CERT" /etc/asix-broker/tls/server.crt
    install -m 640 -o root -g vector "$TLS_KEY" /etc/asix-broker/tls/server.key
    echo "ASIX_SYSLOG_TLS_PORT=$TLS_PORT"
    echo "ASIX_TLS_CERT_FILE=/etc/asix-broker/tls/server.crt"
    echo "ASIX_TLS_KEY_FILE=/etc/asix-broker/tls/server.key"
    if [ -n "$TLS_CLIENT_CA" ]; then
      install -m 644 "$TLS_CLIENT_CA" /etc/asix-broker/tls/client-ca.pem
      echo "ASIX_TLS_CA_FILE=/etc/asix-broker/tls/client-ca.pem"
      echo "ASIX_TLS_VERIFY_CLIENT=true"
    fi
  fi
  [ -z "$FILE_GLOB" ] || echo "ASIX_FILE_GLOB=$(printf '%s\n' "$FILE_GLOB" | paste -sd, -)"   # all globs, comma separated: for reading; vector-file.yaml has them written out
  [ "$JOURNALD" -eq 0 ] || echo "ASIX_JOURNALD_MAX_PRIORITY=$JOURNALD_PRIORITY"
  [ "$WAZUH" -eq 0 ] || echo "ASIX_WAZUH_ARCHIVES=$WAZUH_ARCHIVES"
  if [ -n "$HTTP_USER" ]; then
    echo "ASIX_HTTP_USER=$HTTP_USER"
    echo "ASIX_HTTP_PASSWORD=$HTTP_PW"
    echo "ASIX_HTTP_PORT=$HTTP_PORT"
    [ "$HTTP_TLS" -eq 0 ] || echo "ASIX_HTTP_TLS=true"
  fi
  # The package's service runs plain /usr/bin/vector, so this variable decides which files it loads.
  CONFIGS="/etc/vector/vector.yaml"
  [ -z "$TLS_CERT" ] || CONFIGS="$CONFIGS,/etc/vector/vector-tls.yaml"
  [ -z "$FILE_GLOB" ] || CONFIGS="$CONFIGS,/etc/vector/vector-file.yaml"
  [ -z "$HTTP_USER" ] || CONFIGS="$CONFIGS,/etc/vector/vector-http.yaml"
  [ "$JOURNALD" -eq 0 ] || CONFIGS="$CONFIGS,/etc/vector/vector-journald.yaml"
  [ "$WAZUH" -eq 0 ] || CONFIGS="$CONFIGS,/etc/vector/vector-wazuh.yaml"
  [ "$CONFIGS" = "/etc/vector/vector.yaml" ] || echo "VECTOR_CONFIG=$CONFIGS"
} > /etc/asix-broker/broker.env
chown root:vector /etc/asix-broker/broker.env; chmod 640 /etc/asix-broker/broker.env

if [ "$WAZUH_MANAGER" -eq 1 ]; then
  echo "-- 2b. Wazuh manager (install-wazuh-manager.sh) --"
  "$(dirname "$0")/install-wazuh-manager.sh" --keep-days "$WAZUH_KEEP_DAYS"
fi

echo "-- 3. Installing Vector config and service drop-in --"
install -m 644 "$SRC/vector.yaml" /etc/vector/vector.yaml
if [ -n "$TLS_CERT" ]; then
  install -m 644 "$SRC/vector-tls.yaml" /etc/vector/vector-tls.yaml
else
  # Re-run without --tls-cert: take the TLS listener and its copy of the key away.
  rm -f /etc/vector/vector-tls.yaml; rm -rf /etc/asix-broker/tls
fi
if [ -n "$FILE_GLOB" ]; then
  # --- file input config: the template's one include line becomes one line per glob (Vector cannot split a list out of one variable) ---
  FILE_CFG_TMP="$(mktemp)"
  awk -v list="$FILE_GLOB" 'BEGIN { n = split(list, a, "\n") }
    $0 == "      - \"${ASIX_FILE_GLOB}\"" { for (i = 1; i <= n; i++) print "      - \"" a[i] "\""; hit++; next }
    { print }
    END { exit (hit == 1 ? 0 : 3) }' "$SRC/vector-file.yaml" > "$FILE_CFG_TMP" || { rm -f "$FILE_CFG_TMP"; echo "vector-file.yaml has no single include line to fill in; refusing to install it." >&2; exit 1; }
  install -m 644 "$FILE_CFG_TMP" /etc/vector/vector-file.yaml; rm -f "$FILE_CFG_TMP"
  # --- end file input config ---
else
  rm -f /etc/vector/vector-file.yaml   # re-run without --file-glob: files are no longer read
fi
if [ -n "$HTTP_USER" ]; then
  install -m 644 "$SRC/vector-http.yaml" /etc/vector/vector-http.yaml
else
  rm -f /etc/vector/vector-http.yaml   # re-run without --http-user: the HTTP listener is gone
fi
if [ "$JOURNALD" -eq 1 ]; then
  install -m 644 "$SRC/vector-journald.yaml" /etc/vector/vector-journald.yaml
  # Reading the journal needs the systemd-journal group. Vector is restarted below, which is what picks the new group up.
  if getent group systemd-journal >/dev/null 2>&1; then
    id -nG vector 2>/dev/null | tr ' ' '\n' | grep -qx systemd-journal || usermod -aG systemd-journal vector
  else
    echo "   note: no systemd-journal group on this machine; make sure the vector user can read the journal." >&2
  fi
else
  rm -f /etc/vector/vector-journald.yaml   # re-run without --journald: the journal is no longer read (the group membership is left alone)
fi
if [ "$WAZUH" -eq 1 ]; then
  install -m 644 "$SRC/vector-wazuh.yaml" /etc/vector/vector-wazuh.yaml
  # Vector will not start when the filter file it loads is missing: put the keep-everything program there, but never over a policy that is already in place.
  [ -e /etc/vector/win-filter.vrl ] || install -m 644 "$SRC/win-filter-identity.vrl" /etc/vector/win-filter.vrl
  # The archive directory belongs to the wazuh group. Vector is restarted below, which is what picks the new group up.
  if getent group wazuh >/dev/null 2>&1; then
    id -nG vector 2>/dev/null | tr ' ' '\n' | grep -qx wazuh || usermod -aG wazuh vector
  else
    echo "   note: no wazuh group on this machine (the manager is not installed here yet); make sure the vector user can read $WAZUH_ARCHIVES." >&2
  fi
else
  rm -f /etc/vector/vector-wazuh.yaml   # re-run without --wazuh: Windows events are no longer read (win-filter.vrl and the group membership are left alone)
fi
install -d /etc/systemd/system/vector.service.d
install -m 644 "$SRC/vector-asix.conf" /etc/systemd/system/vector.service.d/asix.conf
install -d /var/lib/vector && chown vector:vector /var/lib/vector

echo "-- 4. Validating the config before restarting --"
( set -a; . /etc/asix-broker/broker.env; set +a; vector validate --no-environment ${TLS_CERT:+/etc/vector/vector-tls.yaml} ${FILE_GLOB:+/etc/vector/vector-file.yaml} ${HTTP_USER:+/etc/vector/vector-http.yaml} ${WAZUH_CFG} ${JOURNALD_CFG} /etc/vector/vector.yaml )

echo "-- 5. Heartbeat timer --"
install -d /usr/local/lib/asix-broker
install -m 755 "$SRC/asix-broker-heartbeat.sh" /usr/local/lib/asix-broker/asix-broker-heartbeat.sh
install -m 644 "$SRC/asix-broker-heartbeat.service" /etc/systemd/system/asix-broker-heartbeat.service
install -m 644 "$SRC/asix-broker-heartbeat.timer" /etc/systemd/system/asix-broker-heartbeat.timer

if [ "$ACCEPT_CONFIG" -eq 1 ]; then
  install -m 755 "$SRC/asix-broker-config.sh" /usr/local/lib/asix-broker/asix-broker-config.sh
  install -m 644 "$SRC/asix-broker-config.service" /etc/systemd/system/asix-broker-config.service
  install -m 644 "$SRC/asix-broker-config.timer" /etc/systemd/system/asix-broker-config.timer
else
  # Re-run without --accept-config: ASIX can no longer change this broker.
  systemctl disable --now asix-broker-config.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/asix-broker-config.timer /etc/systemd/system/asix-broker-config.service /usr/local/lib/asix-broker/asix-broker-config.sh
fi

echo "-- 6. Starting services --"
systemctl daemon-reload
systemctl enable vector asix-broker-heartbeat.timer >/dev/null
[ "$ACCEPT_CONFIG" -eq 0 ] || systemctl enable --now asix-broker-config.timer >/dev/null
systemctl restart vector
sleep 3
systemctl is-active --quiet vector || { echo "Vector did not start: journalctl -u vector -n 50" >&2; exit 1; }
systemctl restart asix-broker-heartbeat.timer
systemctl start asix-broker-heartbeat.service || echo "First heartbeat failed (check the URL, key and certificate): journalctl -u asix-broker-heartbeat -n 20"

echo
echo "Done. Send a test line:   logger -n 127.0.0.1 -P $PORT -T 'asix broker test'"
echo "Then check Settings > Collectors for '$NAME' (Connected)."
echo "Open $PORT/udp and $PORT/tcp on this VM's firewall for the devices that will send syslog."
[ "$ACCEPT_CONFIG" -eq 0 ] || echo "ASIX may now change this broker's syslog port (Brokers page)$([ -n "$CONFIG_PUBKEY" ] && echo ', but only with a signature from the key above'). Watch it: journalctl -u asix-broker-config -n 20"
[ -z "$TLS_CERT" ] || echo "Syslog over TLS is on $TLS_PORT/tcp$([ -n "$TLS_CLIENT_CA" ] && echo ' (senders must present a certificate from the client CA)'): open it too. Check: openssl s_client -connect 127.0.0.1:$TLS_PORT"
[ -z "$FILE_GLOB" ] || echo "Reading files matching ${FILE_GLOB//$'\n'/, } as source type 'file' (the vector user must be able to read them: ls -l, or setfacl). Watch: journalctl -u vector -n 30"
[ -z "$HTTP_USER" ] || echo "HTTP input is on $HTTP_PORT/tcp$([ "$HTTP_TLS" -eq 1 ] && echo ' (HTTPS)' || echo ' (plain HTTP: the password travels in clear text)'): open it too. Test: curl -u $HTTP_USER:PASSWORD -H 'Content-Type: application/json' -d '{\"message\":\"hello\"}' http$([ "$HTTP_TLS" -eq 1 ] && echo s)://127.0.0.1:$HTTP_PORT/events"
[ "$JOURNALD" -eq 0 ] || echo "Reading the systemd journal as source type 'journald' (entries at priority $JOURNALD_PRIORITY or more important; only entries written from now on). Watch: journalctl -u vector -n 30. Test: logger -t asixtest 'journald test'"
[ "$WAZUH" -eq 0 ] || echo "Reading Windows events from $WAZUH_ARCHIVES as source type 'windows-event', through /etc/vector/win-filter.vrl (the tenant's Windows event filter). The manager needs <logall_json>yes</logall_json>, and the vector user must be able to read the file. Watch: journalctl -u vector -n 30"
[ "$WAZUH_MANAGER" -eq 0 ] || echo "A Wazuh manager runs on this machine: open 1514/tcp (agents) and 1515/tcp (enrolment) for the Windows machines. The enrolment password is the line in /var/ossec/etc/authd.pass. Agent list: /var/ossec/bin/agent_control -l"
