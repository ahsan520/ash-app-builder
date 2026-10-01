#!/usr/bin/env bash
#
# Roll out nginx TLS on an ALREADY-DEPLOYED cluster without re-running the
# whole deploy.sh: creates the cert Secret, re-applies Keycloak (adds
# --proxy-headers=xforwarded) and the nginx manifest.
#
#   sudo scripts/deploy/enable-nginx-tls.sh
#
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="$(cd "$HERE/../../k8s" && pwd)"
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
K=(k3s kubectl)
NS=asix-platform

"$HERE/make-nginx-tls.sh"

echo "== Re-applying Keycloak Deployment/Service (skips the realm ConfigMap) =="
awk '/^---/{found=1} found' "$K8S_DIR/20-keycloak.yaml" | "${K[@]}" apply -f -
"${K[@]}" -n "$NS" rollout status deployment/keycloak --timeout=300s

echo "== Applying nginx =="
SHA="$(sha256sum "$K8S_DIR/40-nginx.yaml" | cut -c1-16)"
sed "s|__NGINX_CONFIG_SHA__|${SHA}|" "$K8S_DIR/40-nginx.yaml" | "${K[@]}" apply -f -
"${K[@]}" -n "$NS" rollout status deployment/nginx-control --timeout=120s

IP="$(hostname -I | awk '{print $1}')"
echo
echo "https://$IP:30443/        asix-api   (self-signed - use -k / accept the warning)"
echo "https://$IP:30443/auth/   Keycloak via sub-path"
echo "https://$IP:30444/        Keycloak admin console / login pages"
