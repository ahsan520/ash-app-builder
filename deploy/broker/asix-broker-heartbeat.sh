#!/bin/bash
# Tells the ASIX data node this broker is alive, so an idle broker still shows as Connected.
# Run every minute by asix-broker-heartbeat.timer. Sends nothing if Vector is not healthy, so a
# broker whose Vector has stopped turns Disconnected on its own.
set -u
ENV_FILE="${ASIX_BROKER_ENV:-/etc/asix-broker/broker.env}"
# shellcheck disable=SC1090
[ -r "$ENV_FILE" ] && . "$ENV_FILE"

: "${ASIX_INGEST_KEY:?ASIX_INGEST_KEY is not set}"
: "${ASIX_BROKER_NAME:?ASIX_BROKER_NAME is not set}"
URL="${ASIX_HEARTBEAT_URL:-}"
if [ -z "$URL" ]; then
  : "${ASIX_INGEST_URL:?ASIX_INGEST_URL is not set}"
  URL="${ASIX_INGEST_URL%/v1/ingest/http}/v1/ingest/heartbeat"
fi

curl -fsS -m 5 "${ASIX_VECTOR_HEALTH_URL:-http://127.0.0.1:8686/health}" >/dev/null 2>&1 || { echo "vector is not healthy, no heartbeat sent" >&2; exit 1; }

VER="$(vector --version 2>/dev/null | awk '{print $2}')"
OS="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-Linux}")"
# keep the JSON trivially safe: drop quotes and backslashes from free-text values
clean() { printf '%s' "$1" | tr -d '"\\' | cut -c1-"$2"; }

# The inputs this broker runs, from the same broker.env the bootstrap script wrote: "syslog:514,syslog-tls:6514,file,http:8088,journald".
# A name, plus a port where there is one. A bad port is left out rather than sent. The file glob is not sent (a path has no place in a heartbeat); the journal has no setting worth sending.
port_ok() { case "$1" in ''|*[!0-9]*) return 1;; esac; [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
INPUTS="syslog"; port_ok "${ASIX_SYSLOG_PORT:-514}" && INPUTS="syslog:${ASIX_SYSLOG_PORT:-514}"
case ",${VECTOR_CONFIG:-}," in *vector-tls.yaml,*) T="syslog-tls"; port_ok "${ASIX_SYSLOG_TLS_PORT:-6514}" && T="syslog-tls:${ASIX_SYSLOG_TLS_PORT:-6514}"; INPUTS="$INPUTS,$T";; esac
case ",${VECTOR_CONFIG:-}," in *vector-file.yaml,*) INPUTS="$INPUTS,file";; esac
case ",${VECTOR_CONFIG:-}," in *vector-http.yaml,*) H="http"; [ "${ASIX_HTTP_TLS:-}" = "true" ] && H="https"; port_ok "${ASIX_HTTP_PORT:-8088}" && H="$H:${ASIX_HTTP_PORT:-8088}"; INPUTS="$INPUTS,$H";; esac
case ",${VECTOR_CONFIG:-}," in *vector-journald.yaml,*) INPUTS="$INPUTS,journald";; esac

BODY=$(printf '{"collector":{"name":"%s","platform":"linux","os":"%s","version":"%s","inputs":"%s"}}' \
  "$(clean "$ASIX_BROKER_NAME" 100)" "$(clean "Vector broker VM (${OS})" 100)" "$(clean "vector-${VER:-unknown}" 50)" "$(clean "$INPUTS" 120)")

ARGS=(-fsS -m 10 -X POST -H "Authorization: Bearer ${ASIX_INGEST_KEY}" -H "Content-Type: application/json" --data "$BODY")
[ -n "${ASIX_CA_FILE:-}" ] && ARGS+=(--cacert "$ASIX_CA_FILE")
curl "${ARGS[@]}" "$URL" >/dev/null
