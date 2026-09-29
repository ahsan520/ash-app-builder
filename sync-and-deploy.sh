#!/usr/bin/env bash
#
# Run this from inside the git checkout (e.g. /home/asix/repos/ash-app-builder).
# It pulls the latest commits from GitHub, syncs the tree into /opt/<repo-name>
# (the runtime copy — never a git checkout itself), and runs deploy.sh from there.
#
# This is the ONLY script that should ever write into /opt/<repo-name>. Never
# 'git commit' or hand-edit files inside /opt — always fix things here, in the
# git checkout, then re-run this script.
#
# Usage:
#   ./sync-and-deploy.sh                 pull + sync + deploy, then clean up pods
#   ./sync-and-deploy.sh --pods-only     skip pull/build/deploy: just clean up
#                                        failing pods + offer to restart healthy
#                                        ones (fast break/fix)
#   ./sync-and-deploy.sh --no-pods       deploy only, no pod cleanup step
#   ./sync-and-deploy.sh --no-menu       auto-clean failing pods, skip the
#                                        healthy-pod selection menu
#   ./sync-and-deploy.sh --restart-all   also rolling-restart every Deployment
#                                        (PostgreSQL is never touched)
#   ./sync-and-deploy.sh --dry-run --yes  (pod step only) preview / auto-confirm
# See scripts/pod-manager.sh for exactly what the pod step does.
#
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPT_DIR="/opt/$(basename "$SRC_DIR")"

PODS_ONLY=0
NO_PODS=0
POD_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --pods-only) PODS_ONLY=1 ;;
    --no-pods)   NO_PODS=1 ;;
    --no-menu|--restart-all|--dry-run|--yes|-y) POD_ARGS+=("$arg") ;;
    -h|--help)   sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "sync-and-deploy: unknown option '$arg' (try --help)" >&2; exit 2 ;;
  esac
done

if [[ $PODS_ONLY -eq 1 ]]; then
  exec bash "$SRC_DIR/scripts/pod-manager.sh" ${POD_ARGS[@]+"${POD_ARGS[@]}"}
fi

# Fail fast if the clock is off — apt rejects Release files as "not valid yet"
# otherwise (this runs before any apt-get call below and in deploy.sh).
# shellcheck source=scripts/lib/preflight-clock.sh
source "$SRC_DIR/scripts/lib/preflight-clock.sh"
preflight_clock

if [[ -d "$SRC_DIR/.git" ]]; then
  echo "== Pulling latest from GitHub =="
  git -C "$SRC_DIR" pull
  GIT_SHA="$(git -C "$SRC_DIR" rev-parse --short HEAD)"
else
  echo "NOTE: $SRC_DIR is not a git checkout — skipping pull, syncing as-is."
  GIT_SHA="local"
fi

if ! command -v rsync &>/dev/null; then
  apt-get update -qq && apt-get install -y -qq rsync
fi

echo "== Syncing $SRC_DIR -> $OPT_DIR =="
mkdir -p "$OPT_DIR"
rsync -a --delete --exclude='.git' "$SRC_DIR/" "$OPT_DIR/"

chmod +x "$OPT_DIR/deploy.sh" "$OPT_DIR/rollback.sh" "$OPT_DIR/restore-postgres.sh" 2>/dev/null || true
cd "$OPT_DIR"
# GIT_SHA becomes the image tag deploy.sh builds/deploys — this is what makes
# 'kubectl rollout undo' (and rollback.sh --quick) actually restore old code,
# rather than re-applying a manifest that still points at an already-overwritten
# floating tag. See deploy.sh's own comment at the image-build step.

# Don't let a failed rollout abort the script: the pod step below is most
# useful precisely then (it saves logs of the failing pod before removing it).
DEPLOY_RC=0
./deploy.sh "$OPT_DIR" "$GIT_SHA" || DEPLOY_RC=$?

if [[ $NO_PODS -eq 0 ]]; then
  echo
  echo "== Pod cleanup =="
  if [[ $DEPLOY_RC -ne 0 ]]; then
    echo "Deploy exited with code $DEPLOY_RC - cleaning up failing pods only (no restart menu)."
    POD_ARGS+=(--no-menu)
  fi
  bash "$SRC_DIR/scripts/pod-manager.sh" ${POD_ARGS[@]+"${POD_ARGS[@]}"} || true
fi

if [[ $DEPLOY_RC -ne 0 ]]; then
  echo
  echo "!! deploy.sh failed (exit $DEPLOY_RC). Old pods were left serving if the new revision is unhealthy."
  echo "   Diagnostics of failing pods: /var/log/asix/pod-diagnostics-*.log"
  echo "   Undo the rollout:            ./rollback.sh --quick"
fi
exit "$DEPLOY_RC"
