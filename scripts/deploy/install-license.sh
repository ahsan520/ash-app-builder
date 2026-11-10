#!/bin/bash
# Installs (or replaces) the license on this platform (docs/licensing.md). Run on the server that runs ./sync-and-deploy.sh (asix1), with a license file the vendor signed for THIS installation.
#   ./scripts/deploy/install-license.sh license.jwt       install or replace
#   ./scripts/deploy/install-license.sh --id              print this installation's id (send it to the vendor to get a license)
#   ./scripts/deploy/install-license.sh --status          show what the platform makes of the license
# The license is stored as the Secret asix-license in the asix-platform namespace; the platform re-reads it within a minute or two, no restart.
set -euo pipefail
NS="${ASIX_NAMESPACE:-asix-platform}"
KUBECTL="${KUBECTL:-kubectl}"
case "${1:-}" in
  --id)
    $KUBECTL -n "$NS" exec -i deploy/asix-api -- node -e "require('./src/db').query('SELECT id::text AS id FROM installation LIMIT 1').then(r=>{console.log(r.rows[0]?r.rows[0].id:'no installation id yet: run the schema job (a normal deploy does)');process.exit(0)}).catch(e=>{console.error(e.message);process.exit(1)})"
    ;;
  --status)
    $KUBECTL -n "$NS" exec -i deploy/asix-api -- node -e "require('./src/modules').snapshot().then(s=>{console.log(JSON.stringify({license:s.license,modules:s.modules.map(m=>m.id+':'+m.state+(m.reason?'('+m.reason+')':''))},null,2));process.exit(0)}).catch(e=>{console.error(e.message);process.exit(1)})"
    ;;
  ''|-h|--help) sed -n 2,7p "$0"; exit 0 ;;
  *)
    F="$1"; [ -f "$F" ] && [ -r "$F" ] || { echo "ERROR: cannot read $F" >&2; exit 2; }
    TOKEN="$(tr -d '[:space:]' < "$F")"
    [[ "$TOKEN" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]] || { echo "ERROR: $F does not look like a license (three dot-separated parts)" >&2; exit 2; }
    $KUBECTL -n "$NS" create secret generic asix-license --from-literal=license.jwt="$TOKEN" --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
    echo "License stored. The platform picks it up within a minute or two. Check with: $0 --status"
    ;;
esac
