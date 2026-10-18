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
BODY=$(printf '{"collector":{"name":"%s","platform":"linux","os":"%s","version":"%s"}}' \
  "$(clean "$ASIX_BROKER_NAME" 100)" "$(clean "Vector broker VM (${OS})" 100)" "$(clean "vector-${VER:-unknown}" 50)")

ARGS=(-fsS -m 10 -X POST -H "Authorization: Bearer ${ASIX_INGEST_KEY}" -H "Content-Type: application/json" --data "$BODY")
[ -n "${ASIX_CA_FILE:-}" ] && ARGS+=(--cacert "$ASIX_CA_FILE")
curl "${ARGS[@]}" "$URL" >/dev/null
