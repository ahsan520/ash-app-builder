#!/bin/bash
# Sets up THIS machine as an ASIX broker VM: Vector (syslog in, ASIX HTTP ingest out) plus a
# one-minute heartbeat. Debian/Ubuntu. Safe to re-run: it only rewrites its own files.
#
# Usage (as root):
#   ./scripts/deploy/bootstrap-broker.sh --url https://asix1/v1/ingest/http --key asix_ik_... \
#       --name broker-1 [--port 514] [--ca /path/to/cert.pem] [--no-install]
#       [--tls-cert server.crt --tls-key server.key [--tls-port 6514] [--tls-client-ca ca.pem]]
#
# --no-install     Vector is already installed (offline or pinned install); skip the package repo.
# --tls-cert/key   Also accept syslog over TLS (RFC 5425) on --tls-port (default 6514), with this server certificate.
#                  Both are needed together. Re-running without them turns the TLS listener off again.
# --tls-client-ca  Require every sender to present a certificate issued by this CA (mutual TLS).

set -euo pipefail

URL=""; KEY=""; NAME=""; PORT="514"; CA=""; INSTALL=1; TLS_CERT=""; TLS_KEY=""; TLS_PORT="6514"; TLS_CLIENT_CA=""
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
    *) echo "Unknown option: $1" >&2; exit 2;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
[ -n "$URL" ] && [ -n "$KEY" ] && [ -n "$NAME" ] || { sed -n '2,10p' "$0"; exit 2; }
[[ "$KEY" == asix_ik_* ]] || { echo "The key must start with asix_ik_ (create it in Settings > Collectors > Installers)." >&2; exit 2; }
[[ "$NAME" =~ ^[A-Za-z0-9._:-]{1,100}$ ]] || { echo "Name: 1-100 chars of letters, digits . _ : -" >&2; exit 2; }
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] || { echo "Port must be a number." >&2; exit 2; }

[[ "$TLS_PORT" =~ ^[0-9]{1,5}$ ]] || { echo "--tls-port must be a number." >&2; exit 2; }
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
{
  echo "ASIX_INGEST_URL=$URL"
  echo "ASIX_INGEST_KEY=$KEY"
  echo "ASIX_BROKER_NAME=$NAME"
  echo "ASIX_SYSLOG_PORT=$PORT"
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
    # The package's service runs plain /usr/bin/vector, so this variable decides which files it loads.
    echo "VECTOR_CONFIG=/etc/vector/vector.yaml,/etc/vector/vector-tls.yaml"
  fi
} > /etc/asix-broker/broker.env
chown root:vector /etc/asix-broker/broker.env; chmod 640 /etc/asix-broker/broker.env

echo "-- 3. Installing Vector config and service drop-in --"
install -m 644 "$SRC/vector.yaml" /etc/vector/vector.yaml
if [ -n "$TLS_CERT" ]; then
  install -m 644 "$SRC/vector-tls.yaml" /etc/vector/vector-tls.yaml
else
  # Re-run without --tls-cert: take the TLS listener and its copy of the key away.
  rm -f /etc/vector/vector-tls.yaml; rm -rf /etc/asix-broker/tls
fi
install -d /etc/systemd/system/vector.service.d
install -m 644 "$SRC/vector-asix.conf" /etc/systemd/system/vector.service.d/asix.conf
install -d /var/lib/vector && chown vector:vector /var/lib/vector

echo "-- 4. Validating the config before restarting --"
( set -a; . /etc/asix-broker/broker.env; set +a; vector validate --no-environment ${TLS_CERT:+/etc/vector/vector-tls.yaml} /etc/vector/vector.yaml )

echo "-- 5. Heartbeat timer --"
install -d /usr/local/lib/asix-broker
install -m 755 "$SRC/asix-broker-heartbeat.sh" /usr/local/lib/asix-broker/asix-broker-heartbeat.sh
install -m 644 "$SRC/asix-broker-heartbeat.service" /etc/systemd/system/asix-broker-heartbeat.service
install -m 644 "$SRC/asix-broker-heartbeat.timer" /etc/systemd/system/asix-broker-heartbeat.timer

echo "-- 6. Starting services --"
systemctl daemon-reload
systemctl enable vector asix-broker-heartbeat.timer >/dev/null
systemctl restart vector
sleep 3
systemctl is-active --quiet vector || { echo "Vector did not start: journalctl -u vector -n 50" >&2; exit 1; }
systemctl restart asix-broker-heartbeat.timer
systemctl start asix-broker-heartbeat.service || echo "First heartbeat failed (check the URL, key and certificate): journalctl -u asix-broker-heartbeat -n 20"

echo
echo "Done. Send a test line:   logger -n 127.0.0.1 -P $PORT -T 'asix broker test'"
echo "Then check Settings > Collectors for '$NAME' (Connected)."
echo "Open $PORT/udp and $PORT/tcp on this VM's firewall for the devices that will send syslog."
[ -z "$TLS_CERT" ] || echo "Syslog over TLS is on $TLS_PORT/tcp$([ -n "$TLS_CLIENT_CA" ] && echo ' (senders must present a certificate from the client CA)'): open it too. Check: openssl s_client -connect 127.0.0.1:$TLS_PORT"
