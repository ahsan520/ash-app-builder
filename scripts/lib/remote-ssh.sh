#!/usr/bin/env bash
# Helpers for the two "install on a new VM from here" scripts (docs/remote-install.md, task E12). SOURCE this file, do not run it.
#   scripts/deploy/remote-install-broker-vm.sh   scripts/deploy/remote-install-indexer-vm.sh
# What it gives them: ask for the address, ssh user and password (never on a command line), sign in with ssh, become root with sudo, copy this repo's scripts over, run one
# installer there as root, fetch files back, and keep an AUDIT LOG of everything on this machine (and one on the VM). The password is held in a mode-600 file in a private
# temporary directory that is deleted when the script ends, handed to ssh through SSH_ASKPASS (or `sshpass -f` when that is installed) and to sudo on its standard input.
# It is never put in an argument list, an environment variable of a child process that is shown, or a log: the log is filtered for the exact password as well.
# Written for OpenSSH 8.4 or newer (SSH_ASKPASS_REQUIRE). Tested with a stand-in for ssh, NOT against a real VM.

rs_die() { echo "ERROR: $*" >&2; exit 1; }
rs_say() { echo "[$(date -u +%H:%M:%S)] $*"; }

rs_valid_host() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; }
rs_valid_user() { [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }
rs_valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
# Single-quote a string for a POSIX shell on the other side.
rs_sq() { local s=${1//\'/\'\\\'\'}; printf "'%s'" "$s"; }

# rs_collect: fills RS_HOST, RS_USER, RS_PORT and RS_PW (from the options already parsed, else asks). Password: --password-file, else ASIX_SSH_PASSWORD, else asked (hidden).
rs_collect() {
  RS_PORT="${RS_PORT:-22}"
  if [ -z "${RS_HOST:-}" ]; then [ -t 0 ] || rs_die "no --host given and there is no terminal to ask on"; read -r -p "Address or name of the VM: " RS_HOST; fi
  if [ -z "${RS_USER:-}" ]; then [ -t 0 ] || rs_die "no --user given and there is no terminal to ask on"; read -r -p "SSH user on $RS_HOST: " RS_USER; fi
  rs_valid_host "$RS_HOST" || rs_die "the address '$RS_HOST' is not a valid host name or IPv4 address"
  rs_valid_user "$RS_USER" || rs_die "the ssh user '$RS_USER' is not a valid user name"
  rs_valid_port "$RS_PORT" || rs_die "the ssh port '$RS_PORT' is not valid"
  if [ -n "${RS_PWFILE_IN:-}" ]; then
    [ -f "$RS_PWFILE_IN" ] && [ -r "$RS_PWFILE_IN" ] || rs_die "cannot read the password file $RS_PWFILE_IN"
    [ "$(stat -c %a "$RS_PWFILE_IN" 2>/dev/null)" = "600" ] || [ "$(stat -c %a "$RS_PWFILE_IN" 2>/dev/null)" = "400" ] || rs_die "the password file must be readable by you only (chmod 600 $RS_PWFILE_IN)"
    IFS= read -r RS_PW < "$RS_PWFILE_IN" || true
  elif [ -n "${ASIX_SSH_PASSWORD:-}" ]; then RS_PW="$ASIX_SSH_PASSWORD"
  else [ -t 0 ] || rs_die "no password: use --password-file, ASIX_SSH_PASSWORD, or run this on a terminal"; read -r -s -p "Password of $RS_USER@$RS_HOST (also used for sudo): " RS_PW; echo; fi
  unset ASIX_SSH_PASSWORD
  [ -n "$RS_PW" ] || rs_die "the password is empty"
  case "$RS_PW" in *$'\n'*|*$'\r'*) rs_die "the password has a line break" ;; esac
}

# rs_open: the private directory, the audit log (everything printed from here on goes to it too, with the password filtered out), the ssh options.
rs_open() {   # $1 = what the run is called (broker-vm, indexer-vm)
  umask 077
  RS_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
  RS_OUT="${RS_OUT_DIR:-$PWD/remote-install-out}/$RS_HOST-$RS_STAMP"; mkdir -p "$RS_OUT"; chmod 700 "$RS_OUT"
  RS_TMP="$(mktemp -d)"; chmod 700 "$RS_TMP"
  trap 'rs_cleanup' EXIT
  printf '%s\n' "$RS_PW" > "$RS_TMP/pw"; chmod 600 "$RS_TMP/pw"
  printf '#!/bin/sh\ncat %s\n' "$(rs_sq "$RS_TMP/pw")" > "$RS_TMP/askpass"; chmod 700 "$RS_TMP/askpass"
  RS_LOG="$RS_OUT/audit-$1.log"; : > "$RS_LOG"; chmod 600 "$RS_LOG"
  exec > >(RS_REDACT="$RS_PW" awk '{ p=ENVIRON["RS_REDACT"]; while (length(p) > 0 && (i=index($0,p)) > 0) $0 = substr($0,1,i-1) "********" substr($0,i+length(p)); print; fflush() }' | tee -a "$RS_LOG") 2>&1
  RS_SSH_OPTS=(-p "$RS_PORT" -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$RS_OUT/known_hosts" -o ConnectTimeout=15 -o ServerAliveInterval=20 -o ServerAliveCountMax=6
               -o NumberOfPasswordPrompts=1 -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o LogLevel=ERROR)
  rs_say "Audit log of this run: $RS_LOG"
}
rs_cleanup() {
  local rc=$?
  # A run that stopped early still removes what it copied (the files folder may hold keys); the audit log on the VM stays.
  if [ -n "${RS_DIR:-}" ] && [ -z "${RS_FINISHED:-}" ] && [ -n "${RS_TMP:-}" ]; then rs_ssh "rm -rf $(rs_sq "$RS_DIR")" >/dev/null 2>&1 || echo "NOTE: could not remove $RS_DIR on the VM: do it by hand (it may hold copied key files)." >&2; fi
  [ -n "${RS_TMP:-}" ] && rm -rf "$RS_TMP"; [ "$rc" -ne 0 ] && [ -n "${RS_LOG:-}" ] && echo "FAILED (exit $rc). Read the audit log on this machine: $RS_LOG${RS_REMOTE_LOG:+  and on the VM: $RS_REMOTE_LOG}" >&2; return "$rc"; }

# rs_ssh COMMAND...: one ssh call as the ssh user. Standard input goes through to the remote command.
rs_ssh() {
  if command -v sshpass >/dev/null 2>&1; then sshpass -f "$RS_TMP/pw" ssh "${RS_SSH_OPTS[@]}" "$RS_USER@$RS_HOST" "$@"
  else SSH_ASKPASS="$RS_TMP/askpass" SSH_ASKPASS_REQUIRE=force DISPLAY="${DISPLAY:-asix-none}" ssh "${RS_SSH_OPTS[@]}" "$RS_USER@$RS_HOST" "$@"; fi
}
# rs_root 'COMMAND': the same as root. The password goes to sudo on standard input (`sudo -S`); the command reads nothing from the terminal.
rs_root() {
  local c="exec </dev/null; $1"
  if [ "$RS_USER" = "root" ]; then rs_ssh "bash -c $(rs_sq "$c")"
  else printf '%s\n' "$RS_PW" | rs_ssh "sudo -S -p '' bash -c $(rs_sq "$c")"; fi
}
# rs_probe: can we sign in, and does sudo take the password? Says which one failed.
rs_probe() {
  rs_say "Signing in to $RS_USER@$RS_HOST:$RS_PORT"
  local who; who="$(rs_ssh 'id -un' 2>&1)" || rs_die "ssh to $RS_HOST failed: $who"
  [ "$who" = "$RS_USER" ] || rs_die "signed in but the answer to id -un was unexpected: $who"
  rs_say "Host key is recorded in $RS_OUT/known_hosts (compare it with the VM's if you want: ssh-keygen -lf)"
  rs_root 'test "$(id -u)" = 0' >/dev/null 2>&1 || rs_die "signed in, but $RS_USER cannot become root with sudo using this password"
  rs_say "Signed in; root through sudo works"
}
# rs_upload: this repo's scripts/ and deploy/ to ~/asix-remote-install on the VM (replaced each time). Sets RS_DIR to the absolute path there.
rs_upload() {
  local repo="$1"
  RS_DIR="$(rs_ssh 'printf %s "$HOME/asix-remote-install"')" || rs_die "could not read the home directory on the VM"
  [[ "$RS_DIR" =~ ^/[A-Za-z0-9._/-]+$ ]] || rs_die "unexpected home directory on the VM: $RS_DIR"
  rs_say "Copying scripts/ and deploy/ to $RS_DIR on the VM"
  tar czf - -C "$repo" scripts deploy | rs_ssh "umask 077; rm -rf $(rs_sq "$RS_DIR") && mkdir -p $(rs_sq "$RS_DIR")/files && tar xzf - -C $(rs_sq "$RS_DIR")" || rs_die "copying the scripts failed"
}
# rs_put LOCAL NAME: a file into $RS_DIR/files/NAME (mode 600).
rs_put() {
  [ -f "$1" ] && [ -r "$1" ] || rs_die "cannot read the file $1"
  [[ "$2" =~ ^[A-Za-z0-9._-]+$ ]] || rs_die "bad file name $2"
  rs_ssh "umask 077; cat > $(rs_sq "$RS_DIR/files/$2")" < "$1" || rs_die "copying $1 failed"
}
# rs_get REMOTE_ABSOLUTE_PATH LOCAL: a root-owned file from the VM, mode 600 here.
rs_get() {
  [[ "$1" =~ ^/[A-Za-z0-9._/-]+$ ]] || rs_die "bad remote path $1"
  rs_root "cat $(rs_sq "$1")" > "$2" || { rm -f "$2"; return 1; }
  chmod 600 "$2"
}
# rs_run_installer 'COMMAND': runs a command in the uploaded directory as root, copying its output to /var/log on the VM. Returns the command's own exit status.
rs_run_installer() {
  RS_REMOTE_LOG="/var/log/asix-remote-install-$RS_STAMP.log"
  rs_root "cd $(rs_sq "$RS_DIR") && chmod +x scripts/deploy/*.sh deploy/*/*.sh 2>/dev/null; set -o pipefail; { $1; } 2>&1 | tee -a $(rs_sq "$RS_REMOTE_LOG"); exit \${PIPESTATUS[0]}"
}
# rs_finish: removes what was copied (the files folder may hold keys) and says where the logs are.
rs_finish() {
  RS_FINISHED=1
  rs_ssh "rm -rf $(rs_sq "$RS_DIR")" >/dev/null 2>&1 || echo "NOTE: could not remove $RS_DIR on the VM: do it by hand (it may hold copied key files)."
  rs_say "Removed $RS_DIR from the VM. Audit log here: $RS_LOG; on the VM: $RS_REMOTE_LOG"
}
