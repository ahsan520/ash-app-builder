#!/bin/bash
# Installs a Wazuh MANAGER on THIS machine (the broker VM) and sets it up for ASIX: Windows agents report to it, it writes every event to
# /var/ossec/logs/archives/archives.json, and the broker's Vector reads that file (bootstrap-broker.sh --wazuh). Debian/Ubuntu, systemd. docs/endpoints.md, task E4b.
# Only the manager is installed (no indexer, no dashboard): ASIX is the place events are stored and searched.
#
# Usage (as root):
#   ./scripts/deploy/install-wazuh-manager.sh --check                 # look only: resources, ports, repository; changes nothing
#   ./scripts/deploy/install-wazuh-manager.sh [--version 4.14.9-1] [--keep-days 3] [--key-fingerprint FPR] [--force]
# Normally bootstrap-broker.sh runs it for you (--wazuh-manager).
#
#   --version V          the package version to install (default: the one this repo was tested against, see WAZUH_VERSION below). The package is put on
#                        hold afterwards, so `apt upgrade` never changes the manager; upgrade it on purpose with a newer --version and --upgrade.
#   --upgrade            allow replacing an installed manager of a different version.
#   --keep-days N        keep N days (1 to 90, default 3) of rotated archive and alert files; older ones are deleted daily (the events are in ASIX).
#   --key-fingerprint F  refuse the repository key unless its fingerprint is F (40 hex characters). The script always prints the fingerprint: compare it
#                        with the one on https://documentation.wazuh.com (Installation guide, Wazuh server, "Installing the Wazuh server step by step").
#   --force              go on although this machine has less memory or disk than the minimum.
#   --indexer-file F     (task E6g) switch the manager's VULNERABILITY DETECTION ON and point it at the central Wazuh indexer (docs/wazuh-indexer.md). F is the file made on the
#                        indexer machine by  wazuh-indexer-tenant.sh --writer  (JSON: url, user, password, ca_pem, index; root only). Without this option the default stays:
#                        detection and indexer OFF. Once set up, a re-run WITHOUT the option keeps it on (the settings are remembered in etc/asix-indexer.url and the keystore).
#   --indexer-url U      with --indexer-file: use U (https://host[:port]) instead of the file's url, e.g. https://127.0.0.1:9200 when the indexer is on this same machine (lab).
#   --indexer-off        switch detection and the indexer connection OFF again and forget them.
#
# What it changes, in order (each step is safe to repeat):
#   1. checks (root, apt, systemd, 2+ CPUs, memory, disk, ports 1514/1515/55000 free, the Wazuh repository reachable)
#   2. adds the Wazuh apt repository (key in /usr/share/keyrings/wazuh.gpg), installs wazuh-manager=VERSION, holds it
#   3. ossec.conf: keeps the original as ossec.conf.before-asix, makes the four changes of deploy/wazuh/ossec-edit.py (archives.json on; agents need the
#      enrolment password; vulnerability detection and indexer off), and runs the manager's own config test (wazuh-analysisd -t). If the test fails the
#      original is put back and nothing is started.
#   4. enrolment password: /var/ossec/etc/authd.pass (random, readable by root and the wazuh group), created once and never overwritten
#   5. a daily clean-up of rotated files (asix-wazuh-prune.timer; also guards the disk)
#   6. starts the manager, waits for it to listen on 1514 (agents) and 1515 (enrolment)
# It does not open the firewall: open 1514/tcp and 1515/tcp on this VM for the Windows machines.
set -euo pipefail

WAZUH_VERSION="4.14.9-1"      # the stable release of 14 October 2026 (documentation.wazuh.com, Release notes); the same number for agents
VERSION="$WAZUH_VERSION"; KEEP_DAYS="3"; KEY_FPR=""; CHECK=0; FORCE=0; UPGRADE=0; IDX_FILE=""; IDX_URL=""; IDX_OFF=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    --keep-days) KEEP_DAYS="$2"; shift 2;;
    --key-fingerprint) KEY_FPR="$(printf '%s' "$2" | tr -d ' ' | tr 'a-f' 'A-F')"; shift 2;;
    --check) CHECK=1; shift;;
    --force) FORCE=1; shift;;
    --upgrade) UPGRADE=1; shift;;
    --indexer-file) IDX_FILE="$2"; shift 2;;
    --indexer-url) IDX_URL="$2"; shift 2;;
    --indexer-off) IDX_OFF=1; shift;;
    *) echo "Unknown option: $1" >&2; exit 2;;
  esac
done
[[ "$VERSION" =~ ^4\.[0-9]{1,2}\.[0-9]{1,2}-[0-9]{1,2}$ ]] || { echo "--version must look like 4.14.9-1." >&2; exit 2; }
[[ "$KEEP_DAYS" =~ ^[0-9]{1,2}$ ]] && [ "$KEEP_DAYS" -ge 1 ] && [ "$KEEP_DAYS" -le 90 ] || { echo "--keep-days must be a number from 1 to 90." >&2; exit 2; }
[ -z "$KEY_FPR" ] || [[ "$KEY_FPR" =~ ^[0-9A-F]{40}$ ]] || { echo "--key-fingerprint must be 40 hex characters." >&2; exit 2; }

[ -z "$IDX_URL" ] || [ -n "$IDX_FILE" ] || { echo "--indexer-url only makes sense with --indexer-file." >&2; exit 2; }
[ -z "$IDX_URL" ] || [[ "$IDX_URL" =~ ^https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$ ]] || { echo "--indexer-url must look like https://host or https://host:9200." >&2; exit 2; }
[ "$IDX_OFF" -eq 0 ] || [ -z "$IDX_FILE" ] || { echo "--indexer-off and --indexer-file cannot be used together." >&2; exit 2; }

# Where things are. The environment variables exist for the tests; on a broker the defaults are right.
OSSEC="${ASIX_WAZUH_DIR:-/var/ossec}"; ETC="${ASIX_ETC_DIR:-/etc/asix-broker}"; LIB="${ASIX_LIB_DIR:-/usr/local/lib/asix-broker}"
UNITS="${ASIX_SYSTEMD_DIR:-/etc/systemd/system}"; KEYRING="${ASIX_APT_KEYRING:-/usr/share/keyrings/wazuh.gpg}"; APTLIST="${ASIX_APT_LIST:-/etc/apt/sources.list.d/wazuh.list}"
MEMINFO="${ASIX_MEMINFO:-/proc/meminfo}"; HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="${ASIX_WAZUH_SRC:-$HERE/../../deploy/wazuh}"
REPO_URL="https://packages.wazuh.com/4.x/apt/"; KEY_URL="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
MIN_MEM_MB=3500; REC_MEM_MB=7000; MIN_CPU=2; MIN_DISK_GB=20

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
# The indexer settings (E6g): "on" (from --indexer-file), "keep" (an earlier run set it up and this run says nothing) or "off" (the default).
IDX_MODE="off"; IDX_USER=""; IDX_PW=""; IDX_CA_TMP=""; IDX_REMEMBER="$OSSEC/etc/asix-indexer.url"; IDX_CA_KEPT="$OSSEC/etc/indexer-root-ca.pem"
if [ -n "$IDX_FILE" ]; then
  command -v python3 >/dev/null 2>&1 || { echo "--indexer-file needs python3 to read it." >&2; exit 1; }
  [ -s "$IDX_FILE" ] || { echo "No such file (or it is empty): $IDX_FILE" >&2; exit 2; }
  IDX_CA_TMP="$(mktemp)"; trap 'rm -f "${TMPKEY:-}" "$IDX_CA_TMP"' EXIT
  IDX_PARSED="$(IDX_FILE="$IDX_FILE" IDX_CA_TMP="$IDX_CA_TMP" python3 -c '
import json, os, re, sys
try:
    d = json.load(open(os.environ["IDX_FILE"]))
except Exception:
    sys.exit(3)
url, user, pw, ca = (d.get(k) for k in ("url", "user", "password", "ca_pem"))
if not (isinstance(url, str) and re.fullmatch(r"https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?", url)): sys.exit(4)
if not (isinstance(user, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", user)): sys.exit(5)
if not (isinstance(pw, str) and 8 <= len(pw) <= 200 and re.fullmatch(r"[\x21-\x7e]+", pw)): sys.exit(6)
if not (isinstance(ca, str) and ca.count("BEGIN CERTIFICATE") == 1 and ca.count("PRIVATE KEY") == 0): sys.exit(7)
open(os.environ["IDX_CA_TMP"], "w").write(ca.strip() + "\n")
print(url); print(user)' 2>/dev/null; echo "rc=$?")" || true
  case "$IDX_PARSED" in
    *rc=0) :;;
    *rc=3) echo "$IDX_FILE is not JSON (it must be the file wazuh-indexer-tenant.sh --writer wrote)." >&2; exit 2;;
    *rc=4) echo "$IDX_FILE: the url is missing or is not https://host[:port]." >&2; exit 2;;
    *rc=5) echo "$IDX_FILE: the user is missing or has odd characters." >&2; exit 2;;
    *rc=6) echo "$IDX_FILE: the password is missing, too short or has characters this installer will not pass on." >&2; exit 2;;
    *rc=7) echo "$IDX_FILE: ca_pem must be exactly one certificate and no key." >&2; exit 2;;
    *) echo "Could not read $IDX_FILE." >&2; exit 2;;
  esac
  IDX_URL_FILE="$(printf '%s\n' "$IDX_PARSED" | sed -n 1p)"; IDX_USER="$(printf '%s\n' "$IDX_PARSED" | sed -n 2p)"
  [ -n "$IDX_URL" ] || IDX_URL="$IDX_URL_FILE"
  IDX_PW="$(IDX_FILE="$IDX_FILE" python3 -c 'import json,os; print(json.load(open(os.environ["IDX_FILE"]))["password"])')"
  IDX_MODE="on"
elif [ "$IDX_OFF" -eq 0 ] && [ -s "$IDX_REMEMBER" ] && [ -s "$IDX_CA_KEPT" ]; then
  IDX_URL="$(head -n 1 "$IDX_REMEMBER")"; IDX_MODE="keep"
  [[ "$IDX_URL" =~ ^https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$ ]] || { echo "$IDX_REMEMBER does not hold an indexer address: fix it, or give --indexer-file or --indexer-off." >&2; exit 1; }
fi
command -v apt-get >/dev/null 2>&1 || { echo "This installer is for Debian and Ubuntu (apt)." >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "This installer needs systemd." >&2; exit 1; }
for c in curl gpg; do command -v "$c" >/dev/null 2>&1 || { echo "Missing '$c': apt-get install -y curl gnupg" >&2; exit 1; }; done

echo "== 1. Checks =="
PROBLEMS=0; WARNINGS=0
problem() { echo "   PROBLEM: $*" >&2; PROBLEMS=$((PROBLEMS + 1)); }
warn() { echo "   warning: $*" >&2; WARNINGS=$((WARNINGS + 1)); }
CPUS="$(nproc 2>/dev/null || echo 1)"
MEM_MB="$(awk '/^MemTotal:/ { printf "%d", $2 / 1024 }' "$MEMINFO" 2>/dev/null || echo 0)"
DISK_GB="$(df -P -BG "$(dirname "$OSSEC")" 2>/dev/null | awk 'NR == 2 { gsub(/G/, "", $4); print $4 + 0 }')"; DISK_GB="${DISK_GB:-0}"
echo "   $CPUS CPU(s), ${MEM_MB} MB memory, ${DISK_GB} GB free for $(dirname "$OSSEC")"
if [ "$CPUS" -lt "$MIN_CPU" ]; then [ "$FORCE" -eq 1 ] && warn "only $CPUS CPU (minimum $MIN_CPU)" || problem "only $CPUS CPU: the manager needs at least $MIN_CPU (4 recommended). --force to go on."; fi
if [ "$MEM_MB" -lt "$MIN_MEM_MB" ]; then [ "$FORCE" -eq 1 ] && warn "only ${MEM_MB} MB memory (minimum $MIN_MEM_MB)" || problem "only ${MEM_MB} MB memory: the manager needs at least $MIN_MEM_MB MB (8 GB recommended). --force to go on."
elif [ "$MEM_MB" -lt "$REC_MEM_MB" ]; then warn "${MEM_MB} MB memory is enough for a few agents; 8 GB is recommended for up to about 50."; fi
if [ "$DISK_GB" -lt "$MIN_DISK_GB" ]; then [ "$FORCE" -eq 1 ] && warn "only ${DISK_GB} GB free (minimum $MIN_DISK_GB)" || problem "only ${DISK_GB} GB free: archives.json is large (about 2 KB per event). 100 GB recommended. --force to go on."; fi
INSTALLED="$(dpkg-query -W -f='${Version}' wazuh-manager 2>/dev/null || true)"
if [ -z "$INSTALLED" ]; then   # ports only matter before the manager is there: afterwards they are ITS ports
  for p in 1514 1515 55000; do
    if ss -ltnH "( sport = :$p )" 2>/dev/null | grep -q .; then problem "port $p/tcp is already in use on this machine (the Wazuh manager needs 1514 for agents, 1515 for enrolment, 55000 for its API). If it is the ASIX syslog port, move it: bootstrap-broker.sh --port."; fi
  done
fi
if ! curl -fsSI -m 15 "${REPO_URL}dists/stable/InRelease" >/dev/null 2>&1; then problem "cannot reach $REPO_URL (the Wazuh package repository): check DNS, the proxy and the firewall."; fi
if [ "$IDX_MODE" = "on" ]; then   # can the manager's user sign in to the indexer, with the CA it was given? (authinfo works for any signed-in user)
  IDX_HTTP="$(curl -sS -m 20 -o /dev/null -w '%{http_code}' --cacert "$IDX_CA_TMP" -K <(printf 'user = "%s:%s"\n' "$IDX_USER" "$IDX_PW") "$IDX_URL/_plugins/_security/authinfo" 2>/dev/null || true)"
  case "$IDX_HTTP" in
    200) echo "   indexer $IDX_URL: $IDX_USER can sign in";;
    401|403) problem "the indexer $IDX_URL refused the user $IDX_USER (HTTP $IDX_HTTP): is the file the one wazuh-indexer-tenant.sh --writer wrote, and is it current?";;
    *) problem "cannot reach the indexer $IDX_URL with the CA in $IDX_FILE (HTTP ${IDX_HTTP:-none}): check the address, the firewall (9200/tcp) and that the certificate names that address.";;
  esac
elif [ "$IDX_MODE" = "keep" ]; then echo "   indexer: $IDX_URL kept from an earlier run (--indexer-off to switch it off)"; else echo "   indexer: off (--indexer-file to switch vulnerability detection on)"; fi
echo "   installed manager: ${INSTALLED:-none}; wanted: $VERSION"
if [ -n "$INSTALLED" ] && [ "$INSTALLED" != "$VERSION" ] && [ "$UPGRADE" -eq 0 ]; then problem "wazuh-manager $INSTALLED is installed, not $VERSION. Upgrading a manager is a deliberate step: back up /var/ossec/etc, then run again with --upgrade."; fi
if [ "$PROBLEMS" -gt 0 ]; then echo "$PROBLEMS problem(s). Nothing was changed." >&2; exit 1; fi
if [ "$CHECK" -eq 1 ]; then echo "Checks passed ($WARNINGS warning(s)). Nothing was changed."; exit 0; fi

echo "== 2. Wazuh repository and package =="
install -d -m 755 "$(dirname "$KEYRING")"
TMPKEY="$(mktemp)"; trap 'rm -f "$TMPKEY" "${IDX_CA_TMP:-}"' EXIT
curl -fsSL -m 30 "$KEY_URL" -o "$TMPKEY" || { echo "Could not download the Wazuh repository key from $KEY_URL." >&2; exit 1; }
FPR="$(gpg --show-keys --with-colons "$TMPKEY" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')"
[[ "$FPR" =~ ^[0-9A-F]{40}$ ]] || { echo "The downloaded file is not a GPG key." >&2; exit 1; }
echo "   repository key fingerprint: $FPR"
echo "   compare it with documentation.wazuh.com (Installation guide, Wazuh server) before you rely on it."
[ -z "$KEY_FPR" ] || [ "$FPR" = "$KEY_FPR" ] || { echo "The key's fingerprint is not the one you gave with --key-fingerprint. Nothing was installed." >&2; exit 1; }
gpg --dearmor < "$TMPKEY" > "$KEYRING.new" && mv "$KEYRING.new" "$KEYRING"; chmod 644 "$KEYRING"
echo "deb [signed-by=$KEYRING] $REPO_URL stable main" > "$APTLIST"
apt-get update -qq
if [ "$INSTALLED" != "$VERSION" ]; then
  apt-mark unhold wazuh-manager >/dev/null 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "wazuh-manager=$VERSION"
fi
apt-mark hold wazuh-manager >/dev/null
[ -d "$OSSEC/etc" ] || { echo "wazuh-manager is installed but $OSSEC/etc is missing." >&2; exit 1; }

echo "== 3. ossec.conf =="
CONF="$OSSEC/etc/ossec.conf"; ORIG="$CONF.before-asix"
[ -e "$ORIG" ] || cp -p "$CONF" "$ORIG"
PY="$OSSEC/framework/python/bin/python3"; [ -x "$PY" ] || PY="python3"
command -v "$PY" >/dev/null 2>&1 || { echo "No python3 to edit ossec.conf with." >&2; exit 1; }
cp -p "$CONF" "$CONF.asix-tmp"
EDIT_ARGS=()
if [ "$IDX_MODE" = "on" ]; then
  install -m 640 "$IDX_CA_TMP" "$IDX_CA_KEPT"; chown root:wazuh "$IDX_CA_KEPT" 2>/dev/null || true
fi
[ "$IDX_MODE" = "off" ] || EDIT_ARGS=(--indexer-url "$IDX_URL" --indexer-ca "$IDX_CA_KEPT")
"$PY" "$SRC/ossec-edit.py" "$CONF" "${EDIT_ARGS[@]}" || { mv -f "$CONF.asix-tmp" "$CONF"; echo "ossec.conf was not changed." >&2; exit 1; }
if [ -x "$OSSEC/bin/wazuh-analysisd" ] && ! "$OSSEC/bin/wazuh-analysisd" -t >/dev/null 2>&1; then
  mv -f "$CONF.asix-tmp" "$CONF"
  echo "The manager's own config test (wazuh-analysisd -t) failed with the edited ossec.conf. The previous file was put back and nothing was started." >&2
  echo "Look: $OSSEC/bin/wazuh-analysisd -t   and send deploy/wazuh/ossec-edit.py's output with the error." >&2; exit 1
fi
rm -f "$CONF.asix-tmp"
if [ "$IDX_MODE" = "on" ]; then   # the user name and password go in the manager's keystore, never in ossec.conf
  KS="$OSSEC/bin/wazuh-keystore"
  [ -x "$KS" ] || { echo "No $KS: this Wazuh version has no keystore tool, so the indexer user cannot be stored. ossec.conf was changed; see docs/wazuh-indexer.md, step 4." >&2; exit 1; }
  "$KS" -f indexer -k username -v "$IDX_USER" >/dev/null && "$KS" -f indexer -k password -v "$IDX_PW" >/dev/null || { echo "The keystore refused the indexer user (wazuh-keystore -f indexer ...). Nothing was started." >&2; exit 1; }
  ( umask 077; printf '%s\n' "$IDX_URL" > "$IDX_REMEMBER" ); chown root:wazuh "$IDX_REMEMBER" 2>/dev/null || true; chmod 640 "$IDX_REMEMBER"
  echo "   vulnerability detection ON, indexer $IDX_URL (user and password stored in the keystore)"
elif [ "$IDX_MODE" = "keep" ]; then echo "   vulnerability detection kept ON, indexer $IDX_URL"
else rm -f "$IDX_REMEMBER" "$IDX_CA_KEPT"; fi

echo "== 4. Enrolment password =="
PW="$OSSEC/etc/authd.pass"
if [ ! -s "$PW" ]; then
  ( umask 077; head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-32 > "$PW" )
  echo "   created $PW"
else
  echo "   $PW already exists: kept"
fi
chown root:wazuh "$PW" 2>/dev/null || true; chmod 640 "$PW"

echo "== 5. Daily clean-up of rotated files =="
install -d "$ETC" "$LIB"
printf 'ASIX_WAZUH_KEEP_DAYS=%s\n' "$KEEP_DAYS" > "$ETC/wazuh.env"; chmod 644 "$ETC/wazuh.env"
install -m 755 "$SRC/asix-wazuh-prune.sh" "$LIB/asix-wazuh-prune.sh"
install -m 644 "$SRC/asix-wazuh-prune.service" "$UNITS/asix-wazuh-prune.service"
install -m 644 "$SRC/asix-wazuh-prune.timer" "$UNITS/asix-wazuh-prune.timer"

echo "== 6. Starting the manager =="
systemctl daemon-reload
systemctl enable --now wazuh-manager >/dev/null 2>&1 || systemctl enable --now wazuh-manager
systemctl enable --now asix-wazuh-prune.timer >/dev/null
systemctl restart wazuh-manager
ok=0
for _ in $(seq 1 "${ASIX_WAZUH_WAIT_S:-60}"); do
  if ss -ltnH "( sport = :1514 )" 2>/dev/null | grep -q . && ss -ltnH "( sport = :1515 )" 2>/dev/null | grep -q .; then ok=1; break; fi
  sleep 1
done
[ "$ok" -eq 1 ] || { echo "The manager did not start listening on 1514 and 1515 in time: systemctl status wazuh-manager; tail -n 50 $OSSEC/logs/ossec.log" >&2; exit 1; }

echo
echo "Done. Wazuh manager $VERSION is running (held back from upgrades) and writes $OSSEC/logs/archives/archives.json."
echo "Next:"
echo "  1. Open 1514/tcp (agents) and 1515/tcp (enrolment) on this VM's firewall for the Windows machines."
echo "  2. Let the broker read the file:  re-run bootstrap-broker.sh with --wazuh (it joins the vector user to the wazuh group)."
echo "  3. Enrol a Windows machine (the agent must be $(printf '%s' "$VERSION" | sed 's/-.*//') or older), in an elevated PowerShell:"
echo "       Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-${VERSION}.msi -OutFile wazuh-agent.msi"
echo "       msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER='THIS-VM-ADDRESS' WAZUH_REGISTRATION_PASSWORD='<the line in $PW>' WAZUH_AGENT_NAME='PC-NAME'"
echo "       NET START WazuhSvc"
if [ "$IDX_MODE" != "off" ]; then
  echo "  5. Vulnerability detection is ON, writing to $IDX_URL. The first scan takes a while (the manager downloads its feed first). Look for refusals:  grep -i indexer $OSSEC/logs/ossec.log | tail"
  echo "     When it has written, ask the indexer for the real index name (as admin):  GET /_cat/indices/wazuh-states-vulnerabilities-*?v   -- it must be the one in the file's \"index\"."
fi
echo "  4. Watch:  $OSSEC/bin/agent_control -l     tail -f $OSSEC/logs/ossec.log     ls -l $OSSEC/logs/archives/archives.json"
[ "$WARNINGS" -eq 0 ] || echo "($WARNINGS warning(s) above.)"
