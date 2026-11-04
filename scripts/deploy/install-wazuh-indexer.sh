#!/bin/bash
# Installs the central Wazuh INDEXER on THIS machine (a VM of its own, or in the lab the broker VM) for ASIX's Vulnerabilities tab
# (docs/wazuh-indexer.md, task E6h). Debian/Ubuntu, systemd. ONE node. It holds the vulnerability findings and nothing else.
#
# Usage (as root):
#   ./scripts/deploy/install-wazuh-indexer.sh --check                       # look only: resources, ports, repository; changes nothing
#   ./scripts/deploy/install-wazuh-indexer.sh [--version 4.14.9-1] [--address ADDR] [--node-name N] [--heap-gb N] [--lab] [--key-fingerprint F] [--force] [--upgrade]
#
#   --version V          package version (default WAZUH_VERSION below, the same number as the manager). Held back from `apt upgrade` afterwards.
#   --address ADDR       the address or name the managers and ASIX will use (written into the node certificate's names). Default: this machine's host name.
#   --node-name N        the node's name (default asix-indexer-1).
#   --heap-gb N          JVM heap in GB (default: half of the memory, 31 at most; in --lab a quarter, 8 at most). Set equal as -Xms and -Xmx.
#   --lab                this machine ALSO runs other things (the Wazuh manager on a broker VM): lower minimums, smaller default heap, and the warnings say so.
#   --key-fingerprint F  refuse the repository key unless its fingerprint is F (40 hex characters). The script prints it always.
#   --force              go on although memory, CPU or disk is under the minimum.
#   --upgrade            allow replacing an installed indexer of a different version.
#
# What it changes, in order (each step is safe to repeat):
#   1. checks (root, apt, systemd, openssl, CPU, memory, disk, ports 9200 and 9300 free, the Wazuh repository reachable)
#   2. adds the Wazuh apt repository, installs wazuh-indexer=VERSION, holds it
#   3. vm.max_map_count=262144 (/etc/sysctl.d/99-asix-indexer.conf) and the heap (a file in /etc/wazuh-indexer/jvm.options.d/)
#   4. certificates in /etc/wazuh-indexer/certs, made ONCE and never overwritten: a root CA, the node certificate (names: --address, the host name, 127.0.0.1), an admin certificate
#   5. opensearch.yml: one node, listening on all addresses, the certificates above (the original is kept as opensearch.yml.before-asix)
#   6. the admin password: random, kept readable by root only in /etc/wazuh-indexer/asix-admin.pass, hashed into the security plugin's users file, then the security
#      configuration is loaded (indexer-security-init.sh)
#   7. starts the indexer and waits until it answers as `admin` with a cluster status of green or yellow
# One exception to "no password on a command line": the security plugin's own hash.sh takes the password only as `-p PASSWORD` (it needs a terminal otherwise), so for the
# moment it runs the password of the NEW admin is visible to other users of this machine. Run this on a machine only administrators can sign in to (it is the indexer's own VM).
# Then run wazuh-indexer-tenant.sh once per tenant (a read-only user for ASIX). It does NOT open the firewall: 9200/tcp from the managers and the ASIX API node ONLY.
# Written from the Wazuh 4.x step-by-step guide as I know it and tested with stand-ins for every system command, NOT on a real indexer: where the real one differs the script
# stops with a message instead of going on (docs/wazuh-indexer.md says so).
set -euo pipefail

WAZUH_VERSION="4.14.9-1"
VERSION="$WAZUH_VERSION"; ADDRESS=""; NODE="asix-indexer-1"; HEAP=""; LAB=0; KEY_FPR=""; CHECK=0; FORCE=0; UPGRADE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    --address) ADDRESS="$2"; shift 2;;
    --node-name) NODE="$2"; shift 2;;
    --heap-gb) HEAP="$2"; shift 2;;
    --lab) LAB=1; shift;;
    --key-fingerprint) KEY_FPR="$(printf '%s' "$2" | tr -d ' ' | tr 'a-f' 'A-F')"; shift 2;;
    --check) CHECK=1; shift;;
    --force) FORCE=1; shift;;
    --upgrade) UPGRADE=1; shift;;
    *) echo "Unknown option: $1" >&2; exit 2;;
  esac
done
[[ "$VERSION" =~ ^4\.[0-9]{1,2}\.[0-9]{1,2}-[0-9]{1,2}$ ]] || { echo "--version must look like 4.14.9-1." >&2; exit 2; }
[[ "$NODE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ ]] || { echo "--node-name must be letters, digits, dots, dashes or underscores." >&2; exit 2; }
[ -z "$ADDRESS" ] || [[ "$ADDRESS" =~ ^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$ ]] || { echo "--address must be a host name or an IP address." >&2; exit 2; }
[ -z "$HEAP" ] || { [[ "$HEAP" =~ ^[0-9]{1,2}$ ]] && [ "$HEAP" -ge 1 ] && [ "$HEAP" -le 31 ]; } || { echo "--heap-gb must be a whole number from 1 to 31." >&2; exit 2; }
[ -z "$KEY_FPR" ] || [[ "$KEY_FPR" =~ ^[0-9A-F]{40}$ ]] || { echo "--key-fingerprint must be 40 hex characters." >&2; exit 2; }
case "${ADDRESS:-x}" in 127.*|localhost|::1) echo "--address must be an address the managers and ASIX can reach, not a loopback address." >&2; exit 2;; esac

# Where things are. The environment variables exist for the tests; on a real machine the defaults are right.
CONF_DIR="${ASIX_INDEXER_CONF_DIR:-/etc/wazuh-indexer}"; SYSCTL_DIR="${ASIX_SYSCTL_DIR:-/etc/sysctl.d}"; KEYRING="${ASIX_APT_KEYRING:-/usr/share/keyrings/wazuh.gpg}"
APTLIST="${ASIX_APT_LIST:-/etc/apt/sources.list.d/wazuh.list}"; MEMINFO="${ASIX_MEMINFO:-/proc/meminfo}"; SHARE="${ASIX_INDEXER_SHARE:-/usr/share/wazuh-indexer}"
BASE="${ASIX_INDEXER_BASE:-https://127.0.0.1:9200}"
REPO_URL="https://packages.wazuh.com/4.x/apt/"; KEY_URL="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
if [ "$LAB" -eq 1 ]; then MIN_MEM_MB=6000; REC_MEM_MB=12000; else MIN_MEM_MB=12000; REC_MEM_MB=15000; fi
MIN_CPU=2; MIN_DISK_GB=20; [ "$LAB" -eq 1 ] || MIN_CPU=4

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
command -v apt-get >/dev/null 2>&1 || { echo "This installer is for Debian and Ubuntu (apt)." >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "This installer needs systemd." >&2; exit 1; }
for c in curl gpg openssl; do command -v "$c" >/dev/null 2>&1 || { echo "Missing '$c': apt-get install -y curl gnupg openssl" >&2; exit 1; }; done

echo "== 1. Checks =="
PROBLEMS=0; WARNINGS=0
problem() { echo "   PROBLEM: $*" >&2; PROBLEMS=$((PROBLEMS + 1)); }
warn() { echo "   warning: $*" >&2; WARNINGS=$((WARNINGS + 1)); }
CPUS="$(nproc 2>/dev/null || echo 1)"
MEM_MB="$(awk '/^MemTotal:/ { printf "%d", $2 / 1024 }' "$MEMINFO" 2>/dev/null || echo 0)"
DISK_GB="$(df -P -BG "$(dirname "$CONF_DIR")" 2>/dev/null | awk 'NR == 2 { gsub(/G/, "", $4); print $4 + 0 }')"; DISK_GB="${DISK_GB:-0}"
echo "   $CPUS CPU(s), ${MEM_MB} MB memory, ${DISK_GB} GB free"
if [ "$CPUS" -lt "$MIN_CPU" ]; then [ "$FORCE" -eq 1 ] && warn "only $CPUS CPU (minimum $MIN_CPU)" || problem "only $CPUS CPU: the indexer needs at least $MIN_CPU (4 recommended). --force to go on."; fi
if [ "$MEM_MB" -lt "$MIN_MEM_MB" ]; then [ "$FORCE" -eq 1 ] && warn "only ${MEM_MB} MB memory (minimum $MIN_MEM_MB)" || problem "only ${MEM_MB} MB memory: the minimum is $MIN_MEM_MB MB$([ "$LAB" -eq 1 ] || echo ", 16 GB is the start-here size") (docs/wazuh-indexer.md). --force to go on."
elif [ "$MEM_MB" -lt "$REC_MEM_MB" ]; then warn "${MEM_MB} MB memory works for a lab; $([ "$LAB" -eq 1 ] && echo "16 GB is comfortable with the manager on the same machine" || echo "16 GB is the start-here size")."; fi
if [ "$DISK_GB" -lt "$MIN_DISK_GB" ]; then [ "$FORCE" -eq 1 ] && warn "only ${DISK_GB} GB free (minimum $MIN_DISK_GB)" || problem "only ${DISK_GB} GB free (minimum $MIN_DISK_GB, 100 recommended; OpenSearch stops allocating at 85% full). --force to go on."; fi
INSTALLED="$(dpkg-query -W -f='${Version}' wazuh-indexer 2>/dev/null || true)"
if [ -z "$INSTALLED" ]; then   # ports only matter before the indexer is there: afterwards they are ITS ports
  for p in 9200 9300; do
    if ss -ltnH "( sport = :$p )" 2>/dev/null | grep -q .; then problem "port $p/tcp is already in use on this machine (the indexer needs 9200 for clients and 9300 between nodes)."; fi
  done
fi
if ! curl -fsSI -m 15 "${REPO_URL}dists/stable/InRelease" >/dev/null 2>&1; then problem "cannot reach $REPO_URL (the Wazuh package repository): check DNS, the proxy and the firewall."; fi
echo "   installed indexer: ${INSTALLED:-none}; wanted: $VERSION"
if [ -n "$INSTALLED" ] && [ "$INSTALLED" != "$VERSION" ] && [ "$UPGRADE" -eq 0 ]; then problem "wazuh-indexer $INSTALLED is installed, not $VERSION. Upgrading is a deliberate step: back up $CONF_DIR, then run again with --upgrade."; fi
if [ "$PROBLEMS" -gt 0 ]; then echo "$PROBLEMS problem(s). Nothing was changed." >&2; exit 1; fi
if [ "$CHECK" -eq 1 ]; then echo "Checks passed ($WARNINGS warning(s)). Nothing was changed."; exit 0; fi

# the heap: half of the memory (a quarter in the lab), at most 31 (above that the JVM loses compressed pointers; the lab keeps it small for the manager next door)
if [ -z "$HEAP" ]; then
  if [ "$LAB" -eq 1 ]; then HEAP=$((MEM_MB / 4 / 1024)); [ "$HEAP" -le 8 ] || HEAP=8; else HEAP=$((MEM_MB / 2 / 1024)); [ "$HEAP" -le 31 ] || HEAP=31; fi
  [ "$HEAP" -ge 1 ] || HEAP=1
fi
[ $((HEAP * 1024 * 2)) -le "$MEM_MB" ] || [ "$FORCE" -eq 1 ] || { echo "--heap-gb $HEAP is more than half of the ${MEM_MB} MB memory. --force to go on." >&2; exit 1; }
[ -n "$ADDRESS" ] || ADDRESS="$(hostname 2>/dev/null || echo wazuh-indexer)"

echo "== 2. Wazuh repository and package =="
install -d -m 755 "$(dirname "$KEYRING")"
TMPKEY="$(mktemp)"; trap 'rm -f "$TMPKEY"' EXIT
curl -fsSL -m 30 "$KEY_URL" -o "$TMPKEY" || { echo "Could not download the Wazuh repository key from $KEY_URL." >&2; exit 1; }
FPR="$(gpg --show-keys --with-colons "$TMPKEY" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')"
[[ "$FPR" =~ ^[0-9A-F]{40}$ ]] || { echo "The downloaded file is not a GPG key." >&2; exit 1; }
echo "   repository key fingerprint: $FPR"
echo "   compare it with documentation.wazuh.com before you rely on it."
[ -z "$KEY_FPR" ] || [ "$FPR" = "$KEY_FPR" ] || { echo "The key's fingerprint is not the one you gave with --key-fingerprint. Nothing was installed." >&2; exit 1; }
gpg --dearmor < "$TMPKEY" > "$KEYRING.new" && mv "$KEYRING.new" "$KEYRING"; chmod 644 "$KEYRING"
echo "deb [signed-by=$KEYRING] $REPO_URL stable main" > "$APTLIST"
apt-get update -qq
if [ "$INSTALLED" != "$VERSION" ]; then
  apt-mark unhold wazuh-indexer >/dev/null 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "wazuh-indexer=$VERSION"
fi
apt-mark hold wazuh-indexer >/dev/null
[ -d "$CONF_DIR" ] || { echo "wazuh-indexer is installed but $CONF_DIR is missing." >&2; exit 1; }

echo "== 3. Kernel setting and heap =="
install -d "$SYSCTL_DIR"
printf 'vm.max_map_count=262144\n' > "$SYSCTL_DIR/99-asix-indexer.conf"
sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 || warn "could not set vm.max_map_count now; it is set for the next boot. OpenSearch will not start without it."
install -d "$CONF_DIR/jvm.options.d"
printf -- '-Xms%sg\n-Xmx%sg\n' "$HEAP" "$HEAP" > "$CONF_DIR/jvm.options.d/asix-heap.options"
echo "   heap ${HEAP} GB (of ${MEM_MB} MB)"

echo "== 4. Certificates =="
CERTS="$CONF_DIR/certs"; install -d -m 750 "$CERTS"
if [ ! -s "$CERTS/root-ca.pem" ] || [ ! -s "$CERTS/indexer.pem" ] || [ ! -s "$CERTS/admin.pem" ]; then
  ( umask 077
    W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
    openssl genrsa -out "$W/root-ca-key.pem" 2048 2>/dev/null
    openssl req -new -x509 -sha256 -key "$W/root-ca-key.pem" -out "$CERTS/root-ca.pem" -days 3650 -subj "/C=US/L=California/O=ASIX/OU=ASIX/CN=root-ca" 2>/dev/null
    SAN="DNS:$ADDRESS,DNS:$(hostname 2>/dev/null || echo localhost),DNS:localhost,IP:127.0.0.1"; [[ "$ADDRESS" =~ ^[0-9.]+$ ]] && SAN="$SAN,IP:$ADDRESS"
    printf 'subjectAltName=%s\n' "$SAN" > "$W/san.ext"
    openssl genrsa -out "$W/indexer-key-trad.pem" 2048 2>/dev/null
    openssl pkcs8 -inform PEM -outform PEM -in "$W/indexer-key-trad.pem" -topk8 -nocrypt -v1 PBE-SHA1-3DES -out "$CERTS/indexer-key.pem" 2>/dev/null
    openssl req -new -key "$CERTS/indexer-key.pem" -out "$W/indexer.csr" -subj "/C=US/L=California/O=ASIX/OU=ASIX/CN=$NODE" 2>/dev/null
    openssl x509 -req -in "$W/indexer.csr" -CA "$CERTS/root-ca.pem" -CAkey "$W/root-ca-key.pem" -CAcreateserial -sha256 -out "$CERTS/indexer.pem" -days 3650 -extfile "$W/san.ext" 2>/dev/null
    openssl genrsa -out "$W/admin-key-trad.pem" 2048 2>/dev/null
    openssl pkcs8 -inform PEM -outform PEM -in "$W/admin-key-trad.pem" -topk8 -nocrypt -v1 PBE-SHA1-3DES -out "$CERTS/admin-key.pem" 2>/dev/null
    openssl req -new -key "$CERTS/admin-key.pem" -out "$W/admin.csr" -subj "/C=US/L=California/O=ASIX/OU=ASIX/CN=admin" 2>/dev/null
    openssl x509 -req -in "$W/admin.csr" -CA "$CERTS/root-ca.pem" -CAkey "$W/root-ca-key.pem" -CAcreateserial -sha256 -out "$CERTS/admin.pem" -days 3650 2>/dev/null )
  [ -s "$CERTS/root-ca.pem" ] && [ -s "$CERTS/indexer.pem" ] && [ -s "$CERTS/admin.pem" ] || { echo "Could not make the certificates (openssl)." >&2; exit 1; }
  echo "   made a root CA, the node certificate and an admin certificate in $CERTS"
  echo "   NOTE: the root CA's PRIVATE key is not kept on this machine. To issue more certificates later, make a new CA and replace all of them."
else
  echo "   certificates already there: left as they are"
fi
chmod 400 "$CERTS"/*.pem; chmod 750 "$CERTS"
# A certificate set that was already there (made by Wazuh'"'"'s own tool, say) may name only the machine'"'"'s address. Then a client that checks the certificate
# cannot use https://127.0.0.1:9200; say so now, and let the closing check below fall back to --address instead of calling a healthy indexer broken.
LOOPBACK_NAMED=1
if ! openssl x509 -in "$CERTS/indexer.pem" -noout -ext subjectAltName 2>/dev/null | grep -Eq 'IP Address:127\.0\.0\.1([^0-9]|$)'; then
  LOOPBACK_NAMED=0
  warn "the node certificate does not name 127.0.0.1, so a client on this machine must use https://$ADDRESS:9200 (not loopback) when it checks the certificate: pass --address $ADDRESS to wazuh-indexer-tenant.sh and use that address for the manager (E6g)."
fi
if id wazuh-indexer >/dev/null 2>&1; then chown -R wazuh-indexer:wazuh-indexer "$CERTS"; fi

echo "== 5. opensearch.yml =="
YML="$CONF_DIR/opensearch.yml"; [ -e "$YML.before-asix" ] || { [ ! -e "$YML" ] || cp -p "$YML" "$YML.before-asix"; }
ADMIN_DN="$(openssl x509 -in "$CERTS/admin.pem" -noout -subject -nameopt RFC2253 | sed 's/^subject=\s*//')"
NODE_DN="$(openssl x509 -in "$CERTS/indexer.pem" -noout -subject -nameopt RFC2253 | sed 's/^subject=\s*//')"
cat > "$YML.asix-tmp" <<OSYML
# Written by install-wazuh-indexer.sh (ASIX). One node. Edit by re-running the installer, not by hand.
network.host: "0.0.0.0"
node.name: "$NODE"
cluster.name: "asix-indexer"
discovery.type: single-node
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer
plugins.security.ssl.http.pemcert_filepath: $CERTS/indexer.pem
plugins.security.ssl.http.pemkey_filepath: $CERTS/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: $CERTS/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: $CERTS/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: $CERTS/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: $CERTS/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false
plugins.security.authcz.admin_dn:
  - "$ADMIN_DN"
plugins.security.nodes_dn:
  - "$NODE_DN"
plugins.security.restapi.roles_enabled:
  - "all_access"
  - "security_rest_api_access"
plugins.security.allow_default_init_securityindex: true
compatibility.override_main_response_version: true
OSYML
mv -f "$YML.asix-tmp" "$YML"
chmod 660 "$YML"; if id wazuh-indexer >/dev/null 2>&1; then chown wazuh-indexer:wazuh-indexer "$YML"; fi

echo "== 6. The admin password =="
PW="$CONF_DIR/asix-admin.pass"; USERS="$CONF_DIR/opensearch-security/internal_users.yml"
if [ ! -s "$PW" ]; then
  ( umask 077; R="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-24)"; printf '%sAa1!\n' "$R" > "$PW" )   # 24 hex characters and a symbol, a digit, an upper and a lower case letter
  NEW_PW=1
else NEW_PW=0; fi
chmod 600 "$PW"
if [ "$NEW_PW" -eq 1 ] || [ -n "${ASIX_INDEXER_REHASH:-}" ]; then
  HASHER="$SHARE/plugins/opensearch-security/tools/hash.sh"
  [ -x "$HASHER" ] || { echo "Cannot find the password hasher $HASHER. The package layout is not the one this script expects: set the admin password by hand (docs/wazuh-indexer.md) and run again." >&2; exit 1; }
  HASH="$(OPENSEARCH_JAVA_HOME="$SHARE/jdk" "$HASHER" -p "$(cat "$PW")" 2>/dev/null | tail -n 1)"
  [[ "$HASH" =~ ^\$2[aby]\$[0-9]{2}\$.{53}$ ]] || { echo "The password hasher did not give a bcrypt hash. Nothing was changed in $USERS." >&2; exit 1; }
  [ -f "$USERS" ] || { echo "No $USERS: the security plugin's configuration is not where this script expects." >&2; exit 1; }
  [ -e "$USERS.before-asix" ] || cp -p "$USERS" "$USERS.before-asix"
  ASIX_HASH="$HASH" python3 - "$USERS" <<'PY' || { echo "Could not set the admin hash in $USERS." >&2; exit 1; }
import os, re, sys
p = sys.argv[1]; t = open(p).read(); h = os.environ["ASIX_HASH"]
m = re.search(r'(?m)^admin:\s*\n((?:[ \t]+.*\n?)*)', t)
if not m: sys.exit(1)
body = m.group(1); new, n = re.subn(r'(?m)^([ \t]+hash:\s*).*$', lambda x: x.group(1) + '"' + h + '"', body, count=1)
if n != 1: sys.exit(1)
open(p, 'w').write(t[:m.start(1)] + new + t[m.end(1):])
PY
  echo "   a new admin password was made and hashed into $USERS (the plain one is in $PW, readable by root only)"
else
  echo "   the admin password already exists: left as it is"
fi

echo "== 7. Starting the indexer =="
systemctl daemon-reload
systemctl enable --now wazuh-indexer >/dev/null 2>&1 || systemctl enable --now wazuh-indexer
systemctl restart wazuh-indexer
ok=0
for _ in $(seq 1 "${ASIX_INDEXER_WAIT_S:-90}"); do
  if ss -ltnH "( sport = :9200 )" 2>/dev/null | grep -q .; then ok=1; break; fi
  sleep 1
done
[ "$ok" -eq 1 ] || { echo "The indexer did not start listening on 9200 in time: systemctl status wazuh-indexer; tail -n 50 /var/log/wazuh-indexer/asix-indexer.log" >&2; exit 1; }
SEC="$SHARE/plugins/opensearch-security/tools/securityadmin.sh"
INIT="$SHARE/bin/indexer-security-init.sh"
if [ -x "$INIT" ]; then "$INIT" >/dev/null 2>&1 || { echo "indexer-security-init.sh failed: run it by hand and read its output." >&2; exit 1; }
elif [ -x "$SEC" ]; then echo "   (no indexer-security-init.sh; $SEC is there, run it by hand as in docs/wazuh-indexer.md)" >&2
else echo "   warning: no security initialisation script found under $SHARE." >&2; fi
ADMIN_PW="$(cat "$PW")"
cfg_for() { printf 'silent\nmax-time = 20\nuser = "admin:%s"\nurl = "%s/_cluster/health"\n' "$ADMIN_PW" "$1"; }
CHECK_URLS=("$BASE")
# only when the caller did not choose the address to check (ASIX_INDEXER_BASE is for the tests) and the certificate does not name loopback
if [ -z "${ASIX_INDEXER_BASE:-}" ] && [ "$LOOPBACK_NAMED" -eq 0 ]; then CHECK_URLS=("https://$ADDRESS:9200" "$BASE"); fi
status=""; CHECKED_AT=""
for _ in $(seq 1 "${ASIX_INDEXER_WAIT_S:-90}"); do
  for u in "${CHECK_URLS[@]}"; do
    status="$(curl -K <(cfg_for "$u") --cacert "$CERTS/root-ca.pem" 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin).get("status",""))' 2>/dev/null || true)"
    case "$status" in green|yellow) CHECKED_AT="$u"; break 2;; esac
  done
  sleep 2
done
case "$status" in green|yellow) :;; *) echo "The indexer is listening but does not answer as admin with a green or yellow status (last answer: '${status:-none}'). Look: tail -n 50 /var/log/wazuh-indexer/asix-indexer.log$([ "$LOOPBACK_NAMED" -eq 1 ] || echo "; the node certificate does not name 127.0.0.1, so also check that $ADDRESS is in its names (openssl x509 -in $CERTS/indexer.pem -noout -ext subjectAltName)")" >&2; exit 1;; esac
[ "$CHECKED_AT" = "$BASE" ] || echo "   (checked at $CHECKED_AT: the node certificate does not name 127.0.0.1)"

echo
echo "Done. Wazuh indexer $VERSION (one node, heap ${HEAP} GB) answers on https://$ADDRESS:9200 with status $status."
echo "Next:"
echo "  1. Firewall: open 9200/tcp to the managers and the ASIX API node ONLY (never the internet)."
echo "  2. Make a read-only user per tenant:   ./scripts/deploy/wazuh-indexer-tenant.sh --tenant-name 'Acme Corp' --manager-name <the manager's name> --address $ADDRESS"
echo "  3. Point the manager at this indexer (task E6g, by hand until built: step 4 of docs/wazuh-indexer.md); then register the file step 2 writes."
echo "  Keep $CERTS and $PW safe: they are the keys of the indexer."
[ "$WARNINGS" -eq 0 ] || echo "($WARNINGS warning(s) above.)"
