#!/bin/bash
# A stand-in for `ssh` used by tests/remote-install.test.js. It records every call (arguments, standard input, the askpass file it was given) under $FAKE_SSH_DIR and answers like a VM would.
# Controls (environment): FAKE_SUDO_FAIL=1 (sudo refuses the password), FAKE_FAIL_ON=TEXT (a root command containing TEXT exits 7), FAKE_ECHO_PW=1 (installer output contains the sudo password).
D="${FAKE_SSH_DIR:?}"; n=$(( $(cat "$D/n" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$D/n"
args=("$@"); cmd="${args[${#args[@]}-1]}"
printf '%s\n' "$*" > "$D/argv.$n"
[ -n "${SSH_ASKPASS:-}" ] && { echo "$SSH_ASKPASS" > "$D/askpass-path"; [ -f "$SSH_ASKPASS" ] && cat "$SSH_ASKPASS" > "$D/askpass-script"; }
cat > "$D/stdin.$n"
# What the remote login shell would do with the command line: split it into words the way a shell does, and keep the script that `bash -c` would run.
inner=""; : > "$D/parse-err.$n"
if [[ "$cmd" == "sudo -S"* || "$cmd" == "bash -c"* ]]; then   # a command line of words: split it, keep the script given to bash -c, and check that script parses too
  eval "w=($cmd)" 2>>"$D/parse-err.$n" || echo "PARSE ERROR" >> "$D/parse-err.$n"
  for ((i=0;i<${#w[@]};i++)); do [ "${w[$i]}" = "-c" ] && inner="${w[$((i+1))]}"; done
  bash -n -c "$inner" 2>>"$D/parse-err.$n" || echo "PARSE ERROR (inner)" >> "$D/parse-err.$n"
else bash -n -c "$cmd" 2>>"$D/parse-err.$n" || echo "PARSE ERROR" >> "$D/parse-err.$n"; fi
printf '%s\n' "$inner" > "$D/inner.$n"
echo "$cmd" > "$D/cmd.$n"
cmd_raw="$cmd"; cmd="${inner:-$cmd}"
case "$cmd_raw" in
  'id -un') echo "${FAKE_USER:-ash}";;
  *'printf %s "$HOME/asix-remote-install"'*) printf %s "/home/ash/asix-remote-install";;
  sudo\ -S*|bash\ -c*)
    if [[ "$cmd_raw" == sudo* ]]; then
      pw="$(head -n1 "$D/stdin.$n")"; echo "$pw" > "$D/sudo-pw.$n"
      [ -n "${FAKE_SUDO_FAIL:-}" ] && { echo "Sorry, try again." >&2; exit 1; }
    fi
    [ -n "${FAKE_FAIL_ON:-}" ] && [[ "$cmd" == *"$FAKE_FAIL_ON"* ]] && { echo "installer: something broke"; exit 7; }
    if [[ "$cmd" == *"cat '/root/asix-indexer-registration-"* ]]; then echo '{"url":"https://idx:9200","user":"asix-vuln-x","password":"p1"}'; exit 0; fi
    if [[ "$cmd" == *"cat '/root/asix-manager-indexer-"* ]]; then echo '{"url":"https://idx:9200","user":"asix-mgr-x","password":"p2"}'; exit 0; fi
    [[ "$cmd" == *"test \"\$(id -u)\" = 0"* ]] && exit 0
    echo "installer output"; [ -n "${FAKE_ECHO_PW:-}" ] && echo "leaked: $(head -n1 "$D/stdin.$n")";;
  *tar\ xzf*) ;;
  *rm\ -rf*) echo "$cmd" >> "$D/removed";;
  *cat\ \>*) ;;
esac
exit 0
