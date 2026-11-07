#!/bin/bash
# Installs and sets up a NEW central Wazuh INDEXER VM from THIS machine over ssh (docs/remote-install.md, task E12; the indexer itself is docs/wazuh-indexer.md). Run it on asix1.
# It asks for the VM's address, the ssh user and the password (also used for sudo), signs in, becomes root with sudo, copies scripts/ and deploy/ over and runs there as root:
#   scripts/deploy/install-wazuh-indexer.sh --address ADDRESS ...
#   then, with --tenant-name and --manager-name, once per tenant:  scripts/deploy/wazuh-indexer-tenant.sh  (the READ-ONLY user ASIX uses)
#   and, with --writer, the same with --writer (the user the Wazuh manager writes with).
# and FETCHES the two files they make back to this machine (mode 600, in remote-install-out/<host>-<time>/), ready for:
#   kubectl -n asix-platform exec -i deploy/asix-api -- node src/endpoints/wazuh-indexer-cli.js register --tenant "NAME" < asix-indexer-registration-<slug>.json
#   ./scripts/deploy/remote-install-broker-vm.sh ... --indexer-file asix-manager-indexer-<slug>.json
#
# Usage:
#   ./scripts/deploy/remote-install-indexer-vm.sh --check [--host H --user U --address A]       # look only: signs in, runs the installer's own --check, changes nothing
#   ./scripts/deploy/remote-install-indexer-vm.sh [--host H] [--user U] [--ssh-port 22] [--password-file F] --address ADDRESS [--node-name N] [--heap-gb N] [--version V] [--lab]
#         [--tenant-name "Acme Corp" --manager-name acme-mgr [--writer] [--writer-address A]] [--reload-security] [--out-dir DIR] [-- more options for install-wazuh-indexer.sh]
#
#   --address        the address or name the managers and ASIX will use to reach this indexer (written into its certificate): required.
#   --tenant-name / --manager-name   also make this tenant's read-only user and registration file (both needed together). --writer also makes the manager's write user and file;
#                    --writer-address is the address the manager uses (default: --address; 127.0.0.1 when the manager runs on this same machine, the lab).
#   The password: --password-file (mode 600), ASIX_SSH_PASSWORD, or typed. Never an argument.
# It does not open the firewall: 9200/tcp from the managers and the ASIX API node ONLY. A re-run is safe (the installer repeats its steps); see docs/wazuh-indexer.md for --reload-security.
# Every run writes an AUDIT LOG (remote-install-out/<host>-<time>/audit-indexer-vm.log here, /var/log/asix-remote-install-<time>.log on the VM). Read those when it stops.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
# shellcheck source=../lib/remote-ssh.sh
. "$REPO/scripts/lib/remote-ssh.sh"

CHECK=0; ADDRESS=""; NODE=""; HEAP=""; VERSION=""; LAB=0; TENANT=""; MANAGER=""; WRITER=0; WADDR=""; RELOAD=0; EXTRA=()
RS_HOST=""; RS_USER=""; RS_PORT=""; RS_PWFILE_IN=""; RS_OUT_DIR=""
need() { [ $# -ge 2 ] || rs_die "the option $1 needs a value"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK=1; shift;;
    --host) need "$@"; RS_HOST="$2"; shift 2;;
    --user) need "$@"; RS_USER="$2"; shift 2;;
    --ssh-port) need "$@"; RS_PORT="$2"; shift 2;;
    --password-file) need "$@"; RS_PWFILE_IN="$2"; shift 2;;
    --out-dir) need "$@"; RS_OUT_DIR="$2"; shift 2;;
    --address) need "$@"; ADDRESS="$2"; shift 2;;
    --node-name) need "$@"; NODE="$2"; shift 2;;
    --heap-gb) need "$@"; HEAP="$2"; shift 2;;
    --version) need "$@"; VERSION="$2"; shift 2;;
    --lab) LAB=1; shift;;
    --tenant-name) need "$@"; TENANT="$2"; shift 2;;
    --manager-name) need "$@"; MANAGER="$2"; shift 2;;
    --writer) WRITER=1; shift;;
    --writer-address) need "$@"; WADDR="$2"; shift 2;;
    --reload-security) RELOAD=1; shift;;
    --) shift; EXTRA=("$@"); break;;
    -h|--help) sed -n 2,26p "$0"; exit 0;;
    *) rs_die "unknown option $1 (see --help)";;
  esac
done

[[ "$ADDRESS" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || rs_die "--address is required: the address or name the managers and ASIX will use to reach the indexer"
[[ -z "$NODE" || "$NODE" =~ ^[A-Za-z0-9._-]{1,40}$ ]] || rs_die "--node-name is not valid"
[[ -z "$HEAP" || "$HEAP" =~ ^[0-9]{1,2}$ ]] || rs_die "--heap-gb must be a number"
[[ -z "$VERSION" || "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+)?$ ]] || rs_die "--version must look like 4.14.9-1"
[[ -z "$WADDR" || "$WADDR" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || rs_die "--writer-address is not valid"
{ [ -n "$TENANT" ] && [ -n "$MANAGER" ]; } || [ -z "$TENANT$MANAGER" ] || rs_die "--tenant-name and --manager-name go together"
[ "$WRITER" -eq 0 ] || [ -n "$TENANT" ] || rs_die "--writer needs --tenant-name and --manager-name"
[ -z "$WADDR" ] || [ "$WRITER" -eq 1 ] || rs_die "--writer-address needs --writer"
[[ -z "$TENANT" || "$TENANT" =~ ^[A-Za-z0-9][A-Za-z0-9\ ._-]{0,63}$ ]] || rs_die "--tenant-name may have letters, digits, spaces and . _ - only (up to 64)"
[[ -z "$MANAGER" || "$MANAGER" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]] || rs_die "--manager-name must be lower case letters, digits, dots, dashes, underscores"
for a in "${EXTRA[@]+"${EXTRA[@]}"}"; do [[ "$a" =~ ^[A-Za-z0-9._:/=@+,%-]+$ ]] || rs_die "the extra option '$a' has a character that is not allowed here"; done

rs_collect
rs_open indexer-vm
rs_say "Indexer VM install on $RS_HOST for address $ADDRESS (check only: $CHECK)"
rs_probe
rs_upload "$REPO"

IXC="./scripts/deploy/install-wazuh-indexer.sh --address $(rs_sq "$ADDRESS")"
[ -z "$NODE" ] || IXC="$IXC --node-name $(rs_sq "$NODE")"
[ -z "$HEAP" ] || IXC="$IXC --heap-gb $HEAP"
[ -z "$VERSION" ] || IXC="$IXC --version $(rs_sq "$VERSION")"
[ "$LAB" -eq 0 ] || IXC="$IXC --lab"
[ "$RELOAD" -eq 0 ] || IXC="$IXC --reload-security"
if [ "$CHECK" -eq 1 ]; then
  rs_say "Check only: the indexer installer's --check on the VM"
  rs_run_installer "$IXC --check"; rs_finish; exit 0
fi
for a in "${EXTRA[@]+"${EXTRA[@]}"}"; do IXC="$IXC $(rs_sq "$a")"; done
rs_say "Running on the VM as root: $IXC"
rs_run_installer "$IXC" || rs_die "install-wazuh-indexer.sh failed on the VM (its output is above and in the audit log)"

if [ -n "$TENANT" ]; then
  SLUG="$(printf '%s' "$MANAGER" | tr -c 'a-z0-9\n-' '-' | sed 's/^-*//; s/-*$//' | cut -c1-40)"   # the same default slug wazuh-indexer-tenant.sh makes from the manager name
  TC="./scripts/deploy/wazuh-indexer-tenant.sh --tenant-name $(rs_sq "$TENANT") --manager-name $(rs_sq "$MANAGER") --address $(rs_sq "$ADDRESS") --out-dir /root"
  rs_say "Making the read-only user for tenant '$TENANT'"
  rs_run_installer "$TC" || rs_die "wazuh-indexer-tenant.sh failed on the VM (see the audit log)"
  rs_get "/root/asix-indexer-registration-$SLUG.json" "$RS_OUT/asix-indexer-registration-$SLUG.json" || rs_die "could not fetch the registration file /root/asix-indexer-registration-$SLUG.json (see the audit log: the script prints the name it wrote)"
  rs_say "Fetched $RS_OUT/asix-indexer-registration-$SLUG.json"
  if [ "$WRITER" -eq 1 ]; then
    WC="./scripts/deploy/wazuh-indexer-tenant.sh --writer --tenant-name $(rs_sq "$TENANT") --manager-name $(rs_sq "$MANAGER") --address $(rs_sq "${WADDR:-$ADDRESS}") --out-dir /root"
    rs_say "Making the write user for the manager"
    rs_run_installer "$WC" || rs_die "wazuh-indexer-tenant.sh --writer failed on the VM (see the audit log)"
    rs_get "/root/asix-manager-indexer-$SLUG.json" "$RS_OUT/asix-manager-indexer-$SLUG.json" || rs_die "could not fetch /root/asix-manager-indexer-$SLUG.json"
    rs_say "Fetched $RS_OUT/asix-manager-indexer-$SLUG.json"
  fi
fi
rs_finish
rs_say "Done. Open 9200/tcp on the VM for the managers and the ASIX API node only. Files for the next steps are in $RS_OUT (mode 600: they hold passwords; delete them when used)."
