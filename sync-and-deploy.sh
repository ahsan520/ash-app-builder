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

if [[ -d "$SRC_DIR/.git" ]]; then
  echo "== Pulling latest from GitHub =="
  git -C "$SRC_DIR" pull
else
  echo "NOTE: $SRC_DIR is not a git checkout — skipping pull, syncing as-is."
fi

if ! command -v rsync &>/dev/null; then
  apt-get update -qq && apt-get install -y -qq rsync
fi

echo "== Syncing $SRC_DIR -> $OPT_DIR =="
mkdir -p "$OPT_DIR"
rsync -a --delete --exclude='.git' "$SRC_DIR/" "$OPT_DIR/"

chmod +x "$OPT_DIR/deploy.sh"
cd "$OPT_DIR"
./deploy.sh "$OPT_DIR"
