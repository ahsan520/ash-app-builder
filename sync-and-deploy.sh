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
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPT_DIR="/opt/$(basename "$SRC_DIR")"

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
./deploy.sh "$OPT_DIR" "$GIT_SHA"
