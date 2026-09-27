#!/bin/bash
# Bootstraps the syslog collector on THIS VM (first live ingestion source).
#
# This is intentionally separate from scripts/deploy/deploy-infra.sh, which
# targets the future K8s production pipeline and requires Level 2 approval.
# This script is single-VM dev/bring-up: apply schema, wire rsyslog, run the
# collector as a systemd service. Re-run safely — steps are idempotent.
#
# Usage: sudo ./scripts/bootstrap-syslog-collector.sh <tenant_uuid>

set -euo pipefail

TENANT_ID="${1:?Usage: bootstrap-syslog-collector.sh <tenant_uuid> — the tenant this collector belongs to}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/asix"

echo "== ASIX syslog collector bootstrap =="
echo "Tenant: $TENANT_ID"
echo "Repo:   $REPO_DIR"

echo "-- 1. Applying schema (idempotent — CREATE TABLE/POLICY use IF NOT EXISTS) --"
: "${DB_HOST:=127.0.0.1}"
: "${DB_NAME:=asix_platform}"
: "${DB_USER:=asix_admin}"
if [ -z "${DB_PASSWORD:-}" ]; then
  echo "ERROR: set DB_PASSWORD in the environment before running this script."
  exit 1
fi
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -f "$REPO_DIR/src/db/schema.sql"

echo "-- 2. Creating unprivileged service user (if missing) --"
id -u asix &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin asix

echo "-- 3. Installing app to $INSTALL_DIR --"
mkdir -p "$INSTALL_DIR"
rsync -a --exclude node_modules --exclude .git "$REPO_DIR"/ "$INSTALL_DIR"/
(cd "$INSTALL_DIR" && npm install --omit=dev --silent)
chown -R asix:asix "$INSTALL_DIR"

echo "-- 4. Writing collector env file --"
mkdir -p /etc/asix
cat > /etc/asix/syslog-collector.env <<EOF
SYSLOG_TENANT_ID=$TENANT_ID
DB_HOST=$DB_HOST
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
EOF
chmod 600 /etc/asix/syslog-collector.env

echo "-- 5. Installing systemd unit --"
sed "s/REPLACE_WITH_TENANT_UUID/$TENANT_ID/" "$REPO_DIR/deploy/asix-syslog-collector.service" \
  > /etc/systemd/system/asix-syslog-collector.service
systemctl daemon-reload
systemctl enable --now asix-syslog-collector

echo "-- 6. Wiring rsyslog forwarding (auth/authpriv -> collector) --"
cp "$REPO_DIR/deploy/60-asix-forward.conf" /etc/rsyslog.d/60-asix-forward.conf
systemctl restart rsyslog

echo "-- 7. Status --"
systemctl --no-pager status asix-syslog-collector || true

echo "== Done. Trigger an SSH login or sudo command and check for rows in the events table. =="
