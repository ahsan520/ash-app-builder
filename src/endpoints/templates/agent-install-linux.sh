#!/bin/bash
# ASIX endpoint agent installer for Linux. Made by ASIX for ONE tenant (docs/endpoints.md, task E5): it installs the endpoint agent on THIS machine, enrols it with the
# tenant's endpoint manager and starts it. Debian and Ubuntu (apt), RHEL, Rocky, Alma, Fedora and Amazon Linux (dnf or yum); systemd.
#
# Usage (as root):
#   ./asix-endpoint-install.sh --check                     # look only: system, manager reachable, package repository; changes nothing
#   ./asix-endpoint-install.sh [--name NAME] [--password-file FILE] [--key-fingerprint FPR] [--upgrade] [--re-enroll]
#
#   --name NAME          how this machine is listed in ASIX (default: its short host name; letters, digits . _ -, 2 to 128 characters).
#   --password-file F    read the enrolment password from the first line of F. Without it the script uses $ASIX_ENROLL_PASSWORD, then a password that was put
#                        into this script when it was made, then asks. The password is never put on a command line and is not left on this machine.
#   --key-fingerprint F  refuse the package repository key unless its fingerprint is F (40 hex characters). The script always prints the fingerprint.
#   --upgrade            allow replacing an installed agent of a different version.
#   --re-enroll          enrol again although this machine already has an agent key (the old key is kept as client.keys.before-asix).
#
# What it changes, in order (each step is safe to repeat; run it again if it stops half way):
#   1. checks (root, systemd, package manager, this is not a manager machine, the manager answers on its agent and enrolment ports, the repository is reachable)
#   2. adds the package repository and its signing key, installs the agent at exactly the version below and stops package updates from changing it
#   3. enrols the agent (in the package install; if that left no key, with agent-auth) and removes the password file again
#   4. names the service "ASIX Endpoint Security agent" (a systemd drop-in; the unit and the package keep their upstream names), starts it
#   5. waits until the agent says it is connected to the manager
# It does not open any firewall: this machine must reach @MANAGER@ on 1514/tcp (events) and 1515/tcp (enrolment).
set -euo pipefail

MANAGER="@MANAGER@"; GROUP="@GROUP@"; WANT="@VERSION@"
EMBEDDED_PASSWORD='__ASIX_ENROLL_PASSWORD__'; PLACEHOLDER="__ASIX_ENROLL_""PASSWORD__"
NAME=""; PWFILE=""; KEY_FPR=""; CHECK=0; UPGRADE=0; REENROLL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="${2:-}"; shift 2;;
    --password-file) PWFILE="${2:-}"; shift 2;;
    --key-fingerprint) KEY_FPR="$(printf '%s' "${2:-}" | tr -d ' ' | tr 'a-f' 'A-F')"; shift 2;;
    --check) CHECK=1; shift;;
    --upgrade) UPGRADE=1; shift;;
    --re-enroll) REENROLL=1; shift;;
    *) echo "Unknown option: $1" >&2; exit 2;;
  esac
done
[ -n "$NAME" ] || NAME="$( (hostname -s 2>/dev/null || hostname 2>/dev/null || echo endpoint) | tr 'A-Z' 'a-z' | tr -c 'a-z0-9._\n-' '-' | head -n1 | cut -c1-128)"
[[ "$NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$ ]] || { echo "--name must be 2 to 128 characters: letters, digits, dot, underscore, hyphen (it must start with a letter or digit)." >&2; exit 2; }
[ -z "$KEY_FPR" ] || [[ "$KEY_FPR" =~ ^[0-9A-F]{40}$ ]] || { echo "--key-fingerprint must be 40 hex characters." >&2; exit 2; }

# Where things are. The environment variables exist for the tests; on a real machine the defaults are right.
OSSEC="${ASIX_AGENT_DIR:-/var/ossec}"; UNITS="${ASIX_SYSTEMD_DIR:-/etc/systemd/system}"; OSREL="${ASIX_OS_RELEASE:-/etc/os-release}"
KEYRING="${ASIX_APT_KEYRING:-/usr/share/keyrings/wazuh.gpg}"; APTLIST="${ASIX_APT_LIST:-/etc/apt/sources.list.d/wazuh.list}"; YUMREPO="${ASIX_YUM_REPO:-/etc/yum.repos.d/wazuh.repo}"
PORT_EVENTS="${ASIX_AGENT_PORT:-1514}"; PORT_ENROL="${ASIX_ENROL_PORT:-1515}"
APT_URL="https://packages.wazuh.com/4.x/apt/"; YUM_URL="https://packages.wazuh.com/4.x/yum/"; KEY_URL="https://packages.wazuh.com/key/GPG-KEY-WAZUH"

die() { echo "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "Run as root (sudo)."
command -v systemctl >/dev/null 2>&1 || die "This installer needs systemd."
command -v curl >/dev/null 2>&1 || die "Missing 'curl': install it first (apt-get install -y curl, or dnf install -y curl)."

FAMILY=""
if [ -r "$OSREL" ]; then
  IDS="$( . "$OSREL" 2>/dev/null; echo " ${ID:-} ${ID_LIKE:-} " | tr 'A-Z' 'a-z')"
  case "$IDS" in
    *" debian "*|*" ubuntu "*) FAMILY=deb;;
    *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*|*" amzn "*|*" ol "*) FAMILY=rpm;;
  esac
fi
[ -n "$FAMILY" ] || die "This Linux is not one this installer knows (Debian, Ubuntu, RHEL, Rocky, Alma, Fedora, Amazon Linux). Nothing was changed."
PKG=""
if [ "$FAMILY" = deb ]; then command -v apt-get >/dev/null 2>&1 || die "apt-get not found."
else PKG="$(command -v dnf >/dev/null 2>&1 && echo dnf || (command -v yum >/dev/null 2>&1 && echo yum) || true)"; [ -n "$PKG" ] || die "Neither dnf nor yum was found."; fi

PASSWORD=""
if [ -n "$PWFILE" ]; then [ -r "$PWFILE" ] || die "Cannot read $PWFILE."; PASSWORD="$(head -n1 "$PWFILE" | tr -d '\r\n')"
elif [ -n "${ASIX_ENROLL_PASSWORD:-}" ]; then PASSWORD="$ASIX_ENROLL_PASSWORD"
elif [ "$EMBEDDED_PASSWORD" != "$PLACEHOLDER" ]; then PASSWORD="$EMBEDDED_PASSWORD"; fi
unset ASIX_ENROLL_PASSWORD

PROBLEMS=0; WARNINGS=0
problem() { echo "   PROBLEM: $*" >&2; PROBLEMS=$((PROBLEMS + 1)); }
warn() { echo "   warning: $*" >&2; WARNINGS=$((WARNINGS + 1)); }
tcp_open() { timeout 5 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$1" "$2" 2>/dev/null; }

echo "== 1. Checks =="
case "$(uname -m 2>/dev/null)" in x86_64|amd64|aarch64|arm64) ;; *) warn "the CPU type $(uname -m 2>/dev/null) is not one the agent packages are made for.";; esac
if [ "$FAMILY" = deb ]; then
  INSTALLED="$(dpkg-query -W -f='${Version}' wazuh-agent 2>/dev/null || true)"
  if dpkg-query -W wazuh-manager >/dev/null 2>&1; then problem "this machine runs the endpoint MANAGER; an agent must not be installed on it."; fi
else
  INSTALLED=""; if v="$(rpm -q --qf '%{VERSION}-%{RELEASE}' wazuh-agent 2>/dev/null)"; then INSTALLED="$v"; fi
  if rpm -q wazuh-manager >/dev/null 2>&1; then problem "this machine runs the endpoint MANAGER; an agent must not be installed on it."; fi
fi
echo "   installed agent: ${INSTALLED:-none}; wanted: $WANT; this machine will be listed as: $NAME (group $GROUP)"
if [ -n "$INSTALLED" ] && [ "$INSTALLED" != "$WANT" ] && [ "$UPGRADE" -eq 0 ]; then problem "wazuh-agent $INSTALLED is installed, not $WANT. Run again with --upgrade to replace it on purpose."; fi
for p in "$PORT_EVENTS" "$PORT_ENROL"; do
  if tcp_open "$MANAGER" "$p"; then echo "   $MANAGER:$p/tcp answers"; else problem "cannot reach $MANAGER:$p/tcp: check the network and the firewall between this machine and the manager."; fi
done
if [ "$FAMILY" = deb ]; then REPO_PROBE="${APT_URL}dists/stable/InRelease"; else REPO_PROBE="${YUM_URL}repodata/repomd.xml"; fi
if ! curl -fsSI -m 15 "$REPO_PROBE" >/dev/null 2>&1; then problem "cannot reach the package repository ($REPO_PROBE): check DNS, the proxy and the firewall."; fi
KEYS="$OSSEC/etc/client.keys"; ENROLLED=0; [ -s "$KEYS" ] && ENROLLED=1
NEED_PW=1; [ "$ENROLLED" -eq 1 ] && [ "$REENROLL" -eq 0 ] && NEED_PW=0
if [ "$NEED_PW" -eq 1 ] && [ -z "$PASSWORD" ]; then
  if [ "$CHECK" -eq 1 ]; then warn "no enrolment password was given: a real run will ask for it (or use --password-file)."
  elif [ -t 0 ]; then read -rsp "   Enrolment password: " PASSWORD; echo
  fi
  if [ "$CHECK" -eq 0 ] && [ -z "$PASSWORD" ]; then problem "no enrolment password: give --password-file FILE, or set ASIX_ENROLL_PASSWORD, or run this where it can ask."; fi
fi
if [ "$PROBLEMS" -gt 0 ]; then echo "$PROBLEMS problem(s). Nothing was changed." >&2; exit 1; fi
if [ "$CHECK" -eq 1 ]; then echo "Checks passed ($WARNINGS warning(s)). Nothing was changed."; exit 0; fi

echo "== 2. Package repository and agent =="
TMPKEY="$(mktemp)"; trap 'rm -f "$TMPKEY"' EXIT
curl -fsSL -m 30 "$KEY_URL" -o "$TMPKEY" || die "Could not download the repository key from $KEY_URL."
FPR=""; if command -v gpg >/dev/null 2>&1; then FPR="$(gpg --show-keys --with-colons "$TMPKEY" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')"; fi
if [ -n "$FPR" ]; then
  [[ "$FPR" =~ ^[0-9A-F]{40}$ ]] || die "The downloaded file is not a GPG key."
  echo "   repository key fingerprint: $FPR"; echo "   compare it with documentation.wazuh.com (Installation guide, Wazuh agent) before you rely on it."
  [ -z "$KEY_FPR" ] || [ "$FPR" = "$KEY_FPR" ] || die "The key's fingerprint is not the one you gave with --key-fingerprint. Nothing was installed."
else
  [ -z "$KEY_FPR" ] || die "--key-fingerprint was given but gpg is not installed to read the key's fingerprint. Nothing was installed."
  warn "gpg is not installed, so the key's fingerprint cannot be shown; the package signature is still checked by the package manager."
fi
if [ "$FAMILY" = deb ]; then
  install -d -m 755 "$(dirname "$KEYRING")" "$(dirname "$APTLIST")"
  gpg --dearmor < "$TMPKEY" > "$KEYRING.new" && mv "$KEYRING.new" "$KEYRING"; chmod 644 "$KEYRING"
  echo "deb [signed-by=$KEYRING] $APT_URL stable main" > "$APTLIST"
  apt-get update -qq
  if [ "$INSTALLED" != "$WANT" ]; then
    apt-mark unhold wazuh-agent >/dev/null 2>&1 || true
    WAZUH_MANAGER="$MANAGER" WAZUH_REGISTRATION_PASSWORD="$PASSWORD" WAZUH_AGENT_GROUP="$GROUP" WAZUH_AGENT_NAME="$NAME" DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "wazuh-agent=$WANT"
  fi
  apt-mark hold wazuh-agent >/dev/null
else
  rpm --import "$TMPKEY"
  install -d "$(dirname "$YUMREPO")"
  printf '[wazuh]\ngpgcheck=1\ngpgkey=%s\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=%s\nprotect=1\n' "$KEY_URL" "$YUM_URL" > "$YUMREPO"
  if [ "$INSTALLED" != "$WANT" ]; then
    WAZUH_MANAGER="$MANAGER" WAZUH_REGISTRATION_PASSWORD="$PASSWORD" WAZUH_AGENT_GROUP="$GROUP" WAZUH_AGENT_NAME="$NAME" "$PKG" install -y -q "wazuh-agent-$WANT"
  fi
  sed -i 's/^enabled=1/enabled=0/' "$YUMREPO"     # the repository stays off so an ordinary update never changes the agent
fi
[ -d "$OSSEC/etc" ] || die "wazuh-agent is installed but $OSSEC/etc is missing."

echo "== 3. Enrolment =="
if [ ! -s "$KEYS" ] || [ "$REENROLL" -eq 1 ]; then
  [ -n "$PASSWORD" ] || die "The agent has no key and there is no enrolment password to get one with."
  systemctl stop wazuh-agent >/dev/null 2>&1 || true
  [ ! -s "$KEYS" ] || cp -p "$KEYS" "$KEYS.before-asix"
  ( umask 027; printf '%s\n' "$PASSWORD" > "$OSSEC/etc/authd.pass" )
  [ "$REENROLL" -eq 0 ] || : > "$KEYS"      # agent-auth writes a fresh key; the old one is kept above
  "$OSSEC/bin/agent-auth" -m "$MANAGER" -p "$PORT_ENROL" -G "$GROUP" -A "$NAME" || { rm -f "$OSSEC/etc/authd.pass"; die "Enrolment failed. Is the password right, does the group \"$GROUP\" exist on the manager (a group other than default must be created there first), and is there room for another agent? Run this script again after fixing it."; }
  echo "   enrolled as $NAME"
else
  echo "   this machine already has an agent key: kept (use --re-enroll to enrol again)"
fi
rm -f "$OSSEC/etc/authd.pass"

echo "== 4. Service =="
D="$UNITS/wazuh-agent.service.d"; install -d "$D"
printf '[Unit]\nDescription=ASIX Endpoint Security agent\n' > "$D/10-asix.conf"
LOG="$OSSEC/logs/ossec.log"; START_LINE=0; [ -r "$LOG" ] && START_LINE="$(wc -l < "$LOG")"
systemctl daemon-reload
systemctl enable --now wazuh-agent >/dev/null 2>&1 || systemctl enable --now wazuh-agent
systemctl restart wazuh-agent

echo "== 5. Connection =="
ok=0
for _ in $(seq 1 "${ASIX_AGENT_WAIT_S:-60}"); do
  if [ -r "$LOG" ] && tail -n +"$((START_LINE + 1))" "$LOG" 2>/dev/null | grep -q 'Connected to the server'; then ok=1; break; fi
  sleep 1
done
if [ "$ok" -eq 1 ]; then echo "Done: this machine is connected to the endpoint manager as $NAME. It shows in ASIX, Endpoints, Agents."; exit 0; fi
echo "The agent is installed and enrolled but did not say it is connected within ${ASIX_AGENT_WAIT_S:-60} seconds." >&2
[ ! -r "$LOG" ] || { echo "Last problems in $LOG:" >&2; grep -E 'ERROR|WARNING' "$LOG" 2>/dev/null | tail -n 5 >&2 || true; }
echo "Check that 1514/tcp is open from here to $MANAGER, then: systemctl status wazuh-agent" >&2
exit 3
