#!/usr/bin/env bash
#
# Roll back a broken deploy. Two modes:
#
#   ./rollback.sh --quick
#       Undo the last Kubernetes rollout of asix-api and the syslog
#       collector only. Fast (seconds), but does NOT touch git or the
#       database. Use this when the deployed CODE was fine but something
#       about the rollout itself is broken and you just need the
#       previous image back — deploy.sh tags images by git SHA
#       specifically so this actually restores different code, not just
#       re-applies a manifest pointing at an already-overwritten tag.
#
#   ./rollback.sh <git-commit-ish>
#       Revert the repo to the state at <git-commit-ish> — as new revert
#       commits, pushed to GitHub, not a history rewrite — then redeploy
#       via sync-and-deploy.sh. Use this when the bug is in the code or
#       schema itself, not just a bad rollout.
#
# Run this from inside the git checkout (e.g. /home/ash-app-builder),
# same place as sync-and-deploy.sh.
#
# Neither mode restores the database — see restore-postgres.sh for that,
# using the backups deploy.sh takes automatically before every schema
# change.
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

if [[ "${1:-}" == "--quick" ]]; then
  echo "== Quick rollback: undoing last Kubernetes rollout =="
  export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
  k3s kubectl -n asix-platform rollout undo deployment/asix-api
  k3s kubectl -n asix-platform rollout undo deployment/asix-syslog-collector 2>/dev/null || \
    echo "(no previous revision for asix-syslog-collector — skipped)"
  k3s kubectl -n asix-platform rollout status deployment/asix-api --timeout=90s
  echo
  echo "Done. This did NOT touch git or the database."
  echo "If the bug is in the code or schema itself (not just this rollout), use:"
  echo "  ./rollback.sh <git-commit>"
  exit 0
fi

TARGET="${1:?Usage: ./rollback.sh --quick | ./rollback.sh <git-commit-ish>}"

if [[ ! -d "$REPO_DIR/.git" ]]; then
  echo "ERROR: $REPO_DIR is not a git checkout — run this from /home/ash-app-builder, not /opt." >&2
  exit 1
fi

echo "== Recent history =="
git log --oneline -15
echo

echo "== Reverting everything after $TARGET =="
echo "(this creates new commits that undo the changes — your history stays intact)"
git revert --no-edit "${TARGET}..HEAD"

echo "== Pushing revert commits =="
git push

echo
echo "== Redeploying =="
./sync-and-deploy.sh
