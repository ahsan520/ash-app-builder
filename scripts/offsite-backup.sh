#!/usr/bin/env bash
#
# Copies the nightly encrypted backups to ANOTHER machine, so losing this VM does not lose the backups too, and records the
# result for Settings > Storage & retention > Data safety (a stale or failed copy shows up there).
#
#   sudo bash scripts/offsite-backup.sh --check   --target user@host:/path [--key FILE] [--port N]   test the connection, change nothing
#   sudo bash scripts/offsite-backup.sh           --target user@host:/path [--key FILE] [--port N]   copy now
#   sudo bash scripts/offsite-backup.sh --install-timer --target user@host:/path [--key FILE] [--port N]   save the settings and copy every night at 03:30
#   sudo bash scripts/offsite-backup.sh                                                                   copy now with the saved settings (/etc/asix-offsite.env)
#   sudo bash scripts/offsite-backup.sh --prune-preview --keep-days 60 [--target ...]                     list what pruning would delete on the other machine, delete nothing
#   ... --install-timer --keep-days 60 ...                                                                also prune the other machine after each good copy (--keep-days off turns it off)
#
# The files are AES-256-GCM encrypted already (src/backup/crypto.js), so the other machine learns nothing from them. They are USELESS without the
# backup passphrase (Kubernetes secret asix-backup-secret): keep a copy of that passphrase somewhere that is not this VM, for example a password manager.
#
# What it does: rsync over SSH (new and changed files only; the copy itself never deletes anything on the other machine, so it keeps files this VM has
# already pruned), then a second rsync in dry-run mode that must find nothing left to send (same names and sizes), then one row in backup_runs (kind 'offsite').
# Pruning is OFF unless you give --keep-days N (N of at least 7). Then, only after a copy that was checked and recorded, it deletes on the other machine the
# asix-* files that are BOTH older than N days (by file date, which rsync keeps from this VM) AND no longer on this VM. A file that is still in the backup
# folder here is never deleted there. It never touches other file names, refuses to run with no asix-* files here, and refuses to delete more than half of
# the other machine's asix-* files in one run unless --allow-large-prune is given (use --prune-preview first). A prune failure is a warning, not a failed copy.
# Needs rsync and ssh on both machines, and an SSH key for this VM's root that the other machine accepts (ssh-keygen -t ed25519 -f /root/.ssh/asix-offsite;
# then add the .pub line to ~/.ssh/authorized_keys of the user on the other machine). A first connection trusts the other machine's host key (accept-new).
# --target also accepts a local folder (a mounted disk or share): /mnt/usb/asix-backups.
set -uo pipefail
ENV_FILE="${ASIX_OFFSITE_ENV:-/etc/asix-offsite.env}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/asix/scheduled}"
die() { echo "$*" >&2; exit 2; }

TARGET="" KEY="" PORT="" KEEP="" MODE="run" INSTALL=0 BIGPRUNE=0
[ -r "$ENV_FILE" ] && . "$ENV_FILE"                       # saved settings: OFFSITE_TARGET, OFFSITE_SSH_KEY, OFFSITE_SSH_PORT
TARGET="${OFFSITE_TARGET:-}" KEY="${OFFSITE_SSH_KEY:-}" PORT="${OFFSITE_SSH_PORT:-}" KEEP="${OFFSITE_KEEP_DAYS:-}"
while (( $# )); do case "$1" in
  --target) TARGET="${2:-}"; shift 2 ;; --key) KEY="${2:-}"; shift 2 ;; --port) PORT="${2:-}"; shift 2 ;;
  --keep-days) KEEP="${2:-}"; [ "$KEEP" != off ] || KEEP=""; [ -n "${2:-}" ] || die "--keep-days needs a number (at least 7) or off"; shift 2 ;;
  --prune-preview) MODE="prune-preview"; shift ;; --allow-large-prune) BIGPRUNE=1; shift ;;
  --check) MODE="check"; shift ;; --install-timer) INSTALL=1; shift ;;
  -h|--help) sed -n 2,28p "$0"; exit 0 ;;
  *) die "unknown option: $1 (see --help)" ;;
esac; done

[ -n "$TARGET" ] || die "no target: pass --target user@host:/path (or a local folder), or save it with --install-timer"
if [[ "$TARGET" == *:* ]]; then
  [[ "$TARGET" =~ ^([A-Za-z0-9._-]+@)?[A-Za-z0-9._-]+:/[A-Za-z0-9._/-]*[A-Za-z0-9._-]$ ]] || die "--target must look like user@host:/absolute/path (letters, digits . _ - and / only)"
  REMOTE=1; RHOST="${TARGET%%:*}"; RPATH="${TARGET#*:}"
else
  [[ "$TARGET" =~ ^/[A-Za-z0-9._/-]*[A-Za-z0-9._-]$ ]] || die "--target must be user@host:/absolute/path or an absolute local folder"
  REMOTE=0; RPATH="$TARGET"
fi
[ -z "$PORT" ] || [[ "$PORT" =~ ^[0-9]{1,5}$ ]] || die "--port must be a number"
[ -z "$KEEP" ] || { [[ "$KEEP" =~ ^[0-9]{1,4}$ ]] && [ "$KEEP" -ge 7 ]; } || die "--keep-days must be a number of at least 7 (or off)"
[ "$MODE" != prune-preview ] || [ -n "$KEEP" ] || die "--prune-preview needs --keep-days N (or OFFSITE_KEEP_DAYS in the saved settings)"
[ -z "$KEY" ] || [ -r "$KEY" ] || die "SSH key not readable: $KEY"
command -v rsync >/dev/null || die "rsync is not installed (apt-get install rsync)"
[ "$REMOTE" = 0 ] || command -v ssh >/dev/null || die "ssh is not installed (apt-get install openssh-client)"

SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15)
[ -z "$KEY" ] || SSH+=(-i "$KEY" -o IdentitiesOnly=yes)
[ -z "$PORT" ] || SSH+=(-p "$PORT")
RSYNC=(rsync -rt --partial --chmod=Du=rwx,Fu=rw,go=)
DEST="$RPATH/"
if [ "$REMOTE" = 1 ]; then
  RSYNC+=(-e "${SSH[*]}" --rsync-path="mkdir -p '$RPATH' && rsync"); DEST="$RHOST:$RPATH/"
fi

if [ "$MODE" = check ]; then
  if [ "$REMOTE" = 1 ]; then
    "${SSH[@]}" "$RHOST" "mkdir -p '$RPATH' && test -w '$RPATH' && echo ok" | grep -qx ok || die "cannot write to $TARGET over ssh: check the host, the user, the key and the folder"
  else
    mkdir -p "$RPATH" && [ -w "$RPATH" ] || die "cannot write to $RPATH"
  fi
  echo "ok: $TARGET is reachable and writable"; exit 0
fi

# ---- pruning the other machine (only with --keep-days) -------------------------------------------
# asix-* files on the other machine older than KEEP days that are no longer in BACKUP_DIR. Prints relative paths, one per line. Odd names are left alone.
remote_find() {  # $1 = extra find tests; prints ./relative paths
  if [ "$REMOTE" = 1 ]; then "${SSH[@]}" "$RHOST" "cd '$RPATH' && find . -maxdepth 2 -type f -name 'asix-*' $1"
  else ( cd "$RPATH" && find . -maxdepth 2 -type f -name 'asix-*' $1 ); fi
}
prune_candidates() {
  local f
  remote_find "-mtime +$KEEP" | sed 's|^\./||' | while IFS= read -r f; do
    [[ "$f" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)?$ ]] || continue
    [[ "$f" != *..* ]] || continue
    [ ! -e "$BACKUP_DIR/$f" ] || continue
    echo "$f"
  done
}
need_local_files() {
  [ -d "$BACKUP_DIR" ] && [ -n "$(find "$BACKUP_DIR" -maxdepth 2 -type f -name 'asix-*' -print -quit)" ] || die "no asix-* files in $BACKUP_DIR: pruning needs them to know what is still wanted, so nothing is pruned"
}
if [ "$MODE" = prune-preview ]; then
  need_local_files
  if [ "$REMOTE" = 1 ]; then "${SSH[@]}" "$RHOST" "test -d '$RPATH'" || die "cannot read $TARGET over ssh"; else [ -d "$RPATH" ] || die "no folder $RPATH"; fi
  LIST="$(prune_candidates)" || die "could not list $TARGET"
  TOTAL="$(remote_find '' | wc -l | tr -d ' ')"; N="$(printf '%s' "$LIST" | grep -c .)"
  echo "$TARGET holds $TOTAL asix-* files; $N are older than $KEEP days and no longer on this VM:"
  [ "$N" = 0 ] || printf '%s\n' "$LIST" | sed 's/^/  /'
  if [ "$N" -gt 0 ] && [ $((N * 2)) -gt "$TOTAL" ]; then echo "That is more than half of them: a real run would refuse unless --allow-large-prune is given."; fi
  echo "Nothing was deleted (preview)."; exit 0
fi

if [ "$INSTALL" = 1 ]; then
  [ "$(id -u)" = 0 ] || die "--install-timer must run as root"
  install -d /usr/local/lib/asix-offsite
  install -m 755 "$0" /usr/local/lib/asix-offsite/offsite-backup.sh
  { echo "OFFSITE_TARGET='$TARGET'"; [ -z "$KEY" ] || echo "OFFSITE_SSH_KEY='$KEY'"; [ -z "$PORT" ] || echo "OFFSITE_SSH_PORT='$PORT'"; [ -z "$KEEP" ] || echo "OFFSITE_KEEP_DAYS='$KEEP'"; } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  cat > /etc/systemd/system/asix-offsite-backup.service <<UNIT
[Unit]
Description=Copy the ASIX backups to another machine
[Service]
Type=oneshot
ExecStart=/usr/local/lib/asix-offsite/offsite-backup.sh
UNIT
  cat > /etc/systemd/system/asix-offsite-backup.timer <<UNIT
[Unit]
Description=Copy the ASIX backups to another machine every night (the backup job runs at 02:17)
[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=300
Persistent=true
[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload && systemctl enable --now asix-offsite-backup.timer >/dev/null
  echo "Saved $ENV_FILE and started asix-offsite-backup.timer (every night at 03:30). Copying once now..."
fi

# ---- the copy ----------------------------------------------------------------------------------
[ -d "$BACKUP_DIR" ] || die "no backup folder: $BACKUP_DIR"
FILES="$(find "$BACKUP_DIR" -maxdepth 2 -type f -name 'asix-*' | wc -l | tr -d ' ')"
[ "$FILES" -gt 0 ] || die "nothing to copy: no asix-* files in $BACKUP_DIR (run a backup first)"
BYTES="$(find "$BACKUP_DIR" -type f -name 'asix-*' -printf '%s\n' | awk '{s+=$1} END {printf "%d", s}')"
[ "$REMOTE" = 1 ] || mkdir -p "$RPATH"
TRIGGER=scheduled; [ -t 0 ] && TRIGGER=manual
ERR=""; OK=1

echo "Copying $FILES files ($BYTES bytes) from $BACKUP_DIR to $TARGET ..."
OUT="$("${RSYNC[@]}" --include='asix-*' --include='*/' --exclude='*' "$BACKUP_DIR/" "$DEST" 2>&1)" || { OK=0; ERR="rsync failed: $(echo "$OUT" | tail -3 | tr '\n' ' ')"; }
if [ "$OK" = 1 ]; then
  # verification: nothing may be left to send (a dry run lists every file whose name or size differs)
  LEFT="$("${RSYNC[@]}" --dry-run --size-only --itemize-changes --include='asix-*' --include='*/' --exclude='*' "$BACKUP_DIR/" "$DEST" 2>&1 | grep -c '^>f')" || true
  [ "${LEFT:-0}" = 0 ] || { OK=0; ERR="copy not identical: $LEFT file(s) still differ after the copy"; }
fi

# ---- record it for the Data safety page ----------------------------------------------------------
q() { printf "%s" "${1//\'/\'\'}"; }
if [ "$OK" = 1 ]; then
  SQL="INSERT INTO backup_runs (trigger, status, finished_at, bytes, databases, verified, verified_at, error, kind) VALUES ('$TRIGGER', 'completed', localtimestamp, $BYTES, jsonb_build_array('$(q "$TARGET")'), true, localtimestamp, NULL, 'offsite');"
else
  SQL="INSERT INTO backup_runs (trigger, status, finished_at, bytes, databases, verified, error, kind) VALUES ('$TRIGGER', 'failed', localtimestamp, $BYTES, jsonb_build_array('$(q "$TARGET")'), false, '$(q "${ERR:0:500}")', 'offsite');"
fi
record() {
  if [ -n "${OFFSITE_PSQL:-}" ]; then eval "$OFFSITE_PSQL"; return; fi
  export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
  local K=(k3s kubectl -n "${NAMESPACE:-asix-platform}") pw
  pw="$("${K[@]}" get secret postgresql-secret -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d)" || return 1
  "${K[@]}" exec -i postgresql-0 -- env PGPASSWORD="$pw" psql -U asix_admin -d asix_platform -v ON_ERROR_STOP=1 -q
}
echo "$SQL" | record >/dev/null 2>&1 || echo "warning: could not record the result in the database, so the Data safety page will not show this copy" >&2

# ---- prune the other machine: only after a copy that was checked and recorded; trouble here is a warning, never a failed copy ----
if [ "$OK" = 1 ] && [ -n "$KEEP" ]; then
  prune() {
    local LIST TOTAL N DEL
    LIST="$(prune_candidates)" || { echo "warning: could not list the other machine for pruning; nothing pruned" >&2; return 0; }
    TOTAL="$(remote_find '' | wc -l | tr -d ' ')"; N="$(printf '%s' "$LIST" | grep -c .)"
    [ "$N" -gt 0 ] || { echo "Pruning: nothing older than $KEEP days that this VM no longer has."; return 0; }
    if [ $((N * 2)) -gt "$TOTAL" ] && [ "$BIGPRUNE" != 1 ]; then
      echo "warning: pruning would delete $N of $TOTAL files on the other machine (more than half), so nothing was pruned. Check with --prune-preview, then run once with --allow-large-prune." >&2; return 0
    fi
    if [ "$REMOTE" = 1 ]; then
      DEL="$(printf '%s\n' "$LIST" | "${SSH[@]}" "$RHOST" "cd '$RPATH' && while IFS= read -r f; do rm -f -- \"\$f\" && echo \"\$f\"; done" | grep -c .)"
    else
      DEL="$(printf '%s\n' "$LIST" | ( cd "$RPATH" && while IFS= read -r f; do rm -f -- "$f" && echo "$f"; done ) | grep -c .)"
    fi
    echo "Pruned $DEL of $N old file(s) on the other machine (older than $KEEP days and no longer on this VM)."
    [ "$DEL" = "$N" ] || echo "warning: $((N - DEL)) file(s) could not be deleted on the other machine" >&2
  }
  prune
fi

if [ "$OK" = 1 ]; then echo "Done: $FILES files copied and checked (same names and sizes) at $TARGET"; exit 0; fi
echo "FAILED: $ERR" >&2; exit 1
