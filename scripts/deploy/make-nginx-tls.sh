#!/usr/bin/env bash
#
# Create the self-signed TLS certificate used by nginx-control and store it as
# the Kubernetes Secret asix-platform/nginx-tls (keys tls.crt / tls.key).
#
# Idempotent: if the Secret already exists it is left alone, so redeploys don't
# invalidate certificates people have already accepted in their browsers.
#
#   sudo scripts/deploy/make-nginx-tls.sh                 # create if missing
#   sudo ASIX_TLS_REGENERATE=1 scripts/deploy/make-nginx-tls.sh   # force new cert
#
# Optional environment:
#   ASIX_TLS_SANS   extra Subject Alternative Names, comma separated, e.g.
#                   "IP:10.0.0.5,DNS:asix.example.internal"
#   ASIX_TLS_DAYS   validity in days (default 825)
#
# The certificate always covers: localhost, 127.0.0.1, this host's short name
# and FQDN, and every IPv4 address on the machine (from `hostname -I`).
set -euo pipefail

NAMESPACE="${NAMESPACE:-asix-platform}"
SECRET="nginx-tls"
DAYS="${ASIX_TLS_DAYS:-825}"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
KUBECTL=(k3s kubectl)
command -v k3s >/dev/null 2>&1 || KUBECTL=(kubectl)

"${KUBECTL[@]}" get namespace "$NAMESPACE" >/dev/null 2>&1 \
  || "${KUBECTL[@]}" create namespace "$NAMESPACE"

if [[ "${ASIX_TLS_REGENERATE:-0}" != "1" ]] \
   && "${KUBECTL[@]}" -n "$NAMESPACE" get secret "$SECRET" >/dev/null 2>&1; then
  echo "Secret $NAMESPACE/$SECRET already exists - keeping it (ASIX_TLS_REGENERATE=1 to replace)."
  exit 0
fi

# ---- Subject Alternative Names ------------------------------------------------
SANS=("DNS:localhost" "IP:127.0.0.1")
short="$(hostname -s 2>/dev/null || true)"
fqdn="$(hostname -f 2>/dev/null || true)"
[[ -n "$short" ]] && SANS+=("DNS:$short")
[[ -n "$fqdn" && "$fqdn" != "$short" ]] && SANS+=("DNS:$fqdn")
for ip in $(hostname -I 2>/dev/null || true); do
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && SANS+=("IP:$ip")
done
if [[ -n "${ASIX_TLS_SANS:-}" ]]; then
  IFS=',' read -r -a extra <<<"$ASIX_TLS_SANS"
  SANS+=("${extra[@]}")
fi
SAN_LIST="$(printf '%s\n' "${SANS[@]}" | awk '!seen[$0]++' | paste -sd, -)"

CN="${short:-asix}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Generating self-signed certificate (CN=$CN, ${DAYS}d)"
echo "  SANs: $SAN_LIST"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days "$DAYS" \
  -keyout "$TMP/tls.key" -out "$TMP/tls.crt" \
  -subj "/O=ASIX Platform/CN=$CN" \
  -addext "subjectAltName=$SAN_LIST" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" 2>/dev/null

"${KUBECTL[@]}" -n "$NAMESPACE" create secret tls "$SECRET" \
  --cert="$TMP/tls.crt" --key="$TMP/tls.key" \
  --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f -

# Keep a copy of the public cert (not the key) so clients can trust it:
#   curl --cacert /root/asix-nginx-tls.crt https://<ip>:30443/
install -m 644 "$TMP/tls.crt" /root/asix-nginx-tls.crt 2>/dev/null || true
echo "Secret $NAMESPACE/$SECRET created. Public cert copy: /root/asix-nginx-tls.crt"
