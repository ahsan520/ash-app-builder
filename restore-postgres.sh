#!/usr/bin/env bash
#
# Restore PostgreSQL from a backup deploy.sh took automatically before a
# schema change (see the "6a/9: Backing up PostgreSQL" step).
#
# WARNING: this REPLACES all current data in asix_platform with the
# backup's contents. Anything written since that backup was taken is
# gone after this runs.
#
# Usage:
#   ./restore-postgres.sh              list available backups
#   ./restore-postgres.sh <file>       restore from that backup
#
set -euo pipefail

BACKUP_DIR="/var/backups/asix/postgres"
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

if [[ -z "${1:-}" ]]; then
  echo "Available backups in $BACKUP_DIR:"
  ls -1t "$BACKUP_DIR"/*.sql.gz 2>/dev/null || echo "(none found)"
  echo
  echo "Usage: ./restore-postgres.sh <backup-file>"
  exit 0
fi

BACKUP_FILE="$1"
if [[ ! -f "$BACKUP_FILE" ]]; then
  echo "ERROR: $BACKUP_FILE not found." >&2
  exit 1
fi

echo "This will REPLACE all current data in asix_platform with:"
echo "  $BACKUP_FILE"
read -rp "Type 'yes' to continue: " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
  echo "Aborted."
  exit 1
fi

PG_PW="$(k3s kubectl -n asix-platform get secret postgresql-secret -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d)"

echo "== Restoring =="
gunzip -c "$BACKUP_FILE" | k3s kubectl -n asix-platform exec -i postgresql-0 -- \
  env PGPASSWORD="$PG_PW" psql -U asix_admin -d asix_platform

echo "Restore complete. Worth re-running your test auth/ingest calls to confirm the data looks right."
