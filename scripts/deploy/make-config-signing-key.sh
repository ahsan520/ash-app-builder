#!/usr/bin/env bash
#
# Makes the key pair that signs ASIX's broker config answers (Brokers page > Syslog port; src/brokers/config-signing.js), and with --apply
# stores the PRIVATE key as the Kubernetes Secret asix-platform/asix-config-signing and restarts the API so it starts signing.
# Needs only openssl (and k3s for --apply). Brokers that should accept only signed config get the PUBLIC key:
#   bootstrap-broker.sh ... --accept-config --config-pubkey config-signing.pub
#
#   scripts/deploy/make-config-signing-key.sh [--dir DIR] [--apply]
#
# It never overwrites an existing key file or Secret: replacing a signing key needs a plan (see docs/broker-vm.md, "Signed config").
# Keep a copy of config-signing.key somewhere safe; if it is lost, make a new pair and give every broker the new public key.
set -euo pipefail

DIR="."; APPLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="$2"; shift 2;;
    --apply) APPLY=1; shift;;
    *) echo "Unknown option: $1" >&2; sed -n '2,12p' "$0" >&2; exit 2;;
  esac
done
command -v openssl >/dev/null 2>&1 || { echo "openssl is needed." >&2; exit 1; }
NAMESPACE="${NAMESPACE:-asix-platform}"; SECRET="asix-config-signing"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
KEY="$DIR/config-signing.key"; PUB="$DIR/config-signing.pub"
mkdir -p "$DIR"
[ ! -e "$KEY" ] && [ ! -e "$PUB" ] || { echo "$KEY or $PUB already exists; not overwriting. Use --dir for a new place." >&2; exit 1; }
if [ "$APPLY" -eq 1 ] && k3s kubectl -n "$NAMESPACE" get secret "$SECRET" >/dev/null 2>&1; then
  echo "The Secret $NAMESPACE/$SECRET already exists; not replacing it (brokers that pin the old public key would refuse every answer). See docs/broker-vm.md, \"Signed config\"." >&2; exit 1
fi

( umask 077; openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$KEY" )
openssl pkey -in "$KEY" -pubout -out "$PUB"; chmod 644 "$PUB"; chmod 600 "$KEY"
ID="$(openssl pkey -pubin -in "$PUB" -outform DER | openssl dgst -sha256 -hex | sed 's/^.*= //' | cut -c1-12)"
echo "Made $KEY (private, owner only) and $PUB (public). Key id: $ID"

if [ "$APPLY" -eq 1 ]; then
  k3s kubectl -n "$NAMESPACE" create secret generic "$SECRET" --from-file=ASIX_CONFIG_SIGNING_KEY="$KEY"
  k3s kubectl -n "$NAMESPACE" rollout restart deployment/asix-api
  k3s kubectl -n "$NAMESPACE" rollout status deployment/asix-api --timeout=180s
  echo "ASIX now signs broker config answers. The Brokers page shows 'Answers signed (key $ID)'."
else
  echo "Not applied. To make ASIX sign with it:"
  echo "  k3s kubectl -n $NAMESPACE create secret generic $SECRET --from-file=ASIX_CONFIG_SIGNING_KEY=$KEY"
  echo "  k3s kubectl -n $NAMESPACE rollout restart deployment/asix-api"
fi
echo "Give brokers the public key: bootstrap-broker.sh <your usual options> --accept-config --config-pubkey $PUB"
