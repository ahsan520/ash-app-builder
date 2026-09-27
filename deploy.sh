#!/usr/bin/env bash
#
# ASIX Platform — end-to-end deploy for a fresh Ubuntu server
#
# What this actually deploys (see README notes at the bottom of the chat
# response this shipped with): asix-api (Express skeleton) + PostgreSQL +
# Keycloak, on a single-node k3s cluster. It does NOT deploy Kafka,
# OpenSearch, or ClickHouse — that code doesn't exist in the repo yet.
#
# Usage:
#   sudo ./deploy.sh /path/to/ash-app-builder-main
#
set -euo pipefail

REPO_DIR="${1:?Usage: sudo ./deploy.sh /path/to/ash-app-builder-main}"
NAMESPACE="asix-platform"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="$SCRIPT_DIR/k8s"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo ./deploy.sh <repo_dir>) — installs system packages." >&2
  exit 1
fi

if [[ ! -f "$REPO_DIR/Dockerfile" ]]; then
  echo "ERROR: $REPO_DIR doesn't look like the ash-app-builder repo (no Dockerfile found)." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "== 0/8: Creating 'asix' user (passwordless sudo) + OpenSSH server =="
if id -u asix &>/dev/null; then
  echo "User 'asix' already exists — skipping creation and password setup."
else
  useradd -m -s /bin/bash asix
  ASIX_PASSWORD="$(openssl rand -base64 18)"
  echo "asix:${ASIX_PASSWORD}" | chpasswd
  echo "$ASIX_PASSWORD" > /root/asix-login-password.txt
  chmod 600 /root/asix-login-password.txt
  echo "Created user 'asix' with generated login password -> /root/asix-login-password.txt (root-only)."
fi
usermod -aG sudo asix
echo "asix ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/90-asix-nopasswd
chmod 440 /etc/sudoers.d/90-asix-nopasswd
visudo -cf /etc/sudoers.d/90-asix-nopasswd

install -d -m 700 -o asix -g asix /home/asix/.ssh
touch /home/asix/.ssh/authorized_keys
chmod 600 /home/asix/.ssh/authorized_keys
chown asix:asix /home/asix/.ssh/authorized_keys
echo "NOTE: /home/asix/.ssh/authorized_keys is empty — add a public key before relying on SSH for this user."

if [[ ! -f /home/asix/.ssh/id_rsa ]]; then
  sudo -u asix ssh-keygen -t rsa -b 4096 -f /home/asix/.ssh/id_rsa -N "" -C "asix@$(hostname)"
  echo "Generated RSA keypair for 'asix' -> /home/asix/.ssh/id_rsa(.pub)"
fi

apt-get update -qq
apt-get install -y -qq openssh-server

# Lab setup: make sure password auth is explicitly on (key auth already works by default)
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
if ! grep -q '^PasswordAuthentication yes' /etc/ssh/sshd_config; then
  echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
fi
systemctl enable --now ssh
systemctl restart ssh

echo "== 1/8: Installing prerequisites =="
apt-get install -y -qq ca-certificates curl gnupg jq

echo "== 2/8: Installing Docker (used only to build the image) =="
if ! command -v docker &>/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io
fi

echo "== 3/8: Installing k3s (single-node Kubernetes) =="
if ! command -v k3s &>/dev/null; then
  curl -sfL https://get.k3s.io | sh -
  # wait for k3s to be ready
  until k3s kubectl get nodes &>/dev/null; do sleep 2; done
fi
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
alias kubectl="k3s kubectl"
K=/usr/local/bin/k3s

echo "== 4/8: Building and importing the asix-api image =="
docker build -t asix-api:local "$REPO_DIR"
docker save asix-api:local | k3s ctr images import -

echo "== 5/8: Creating namespace + secrets =="
$K kubectl apply -f "$K8S_DIR/00-namespace.yaml"

if ! $K kubectl -n "$NAMESPACE" get secret postgresql-secret &>/dev/null; then
  PG_PASSWORD="$(openssl rand -base64 24)"
  $K kubectl -n "$NAMESPACE" create secret generic postgresql-secret \
    --from-literal=POSTGRES_PASSWORD="$PG_PASSWORD"
  echo "Generated PostgreSQL password -> stored in k8s secret 'postgresql-secret' (namespace $NAMESPACE)"
  echo "$PG_PASSWORD" > /root/asix-postgres-password.txt
  chmod 600 /root/asix-postgres-password.txt
  echo "  (also saved to /root/asix-postgres-password.txt, root-only — move it to a real vault)"
fi

if ! $K kubectl -n "$NAMESPACE" get secret keycloak-secret &>/dev/null; then
  KC_PASSWORD="$(openssl rand -base64 24)"
  $K kubectl -n "$NAMESPACE" create secret generic keycloak-secret \
    --from-literal=ADMIN_PASSWORD="$KC_PASSWORD"
  echo "Generated Keycloak admin password -> stored in k8s secret 'keycloak-secret'"
  echo "$KC_PASSWORD" > /root/asix-keycloak-password.txt
  chmod 600 /root/asix-keycloak-password.txt
fi

if ! $K kubectl -n "$NAMESPACE" get secret keycloak-db-secret &>/dev/null; then
  KC_DB_PASSWORD="$(openssl rand -base64 24)"
  $K kubectl -n "$NAMESPACE" create secret generic keycloak-db-secret \
    --from-literal=PASSWORD="$KC_DB_PASSWORD"
  echo "Generated Keycloak DB password -> stored in k8s secret 'keycloak-db-secret'"
fi

echo "== 6/8: Deploying PostgreSQL =="
$K kubectl apply -f "$K8S_DIR/10-postgresql.yaml"
$K kubectl -n "$NAMESPACE" rollout status statefulset/postgresql --timeout=180s

echo "== 6b/8: Applying the ASIX schema (tenants, roles, identity_mappings, etc.) =="
# Jobs are immutable, so drop any previous run before re-applying.
$K kubectl -n "$NAMESPACE" delete job/asix-schema-init --ignore-not-found
$K kubectl apply -f "$K8S_DIR/12-schema-init.yaml"
$K kubectl -n "$NAMESPACE" wait --for=condition=complete job/asix-schema-init --timeout=120s

echo "== 7/8: Provisioning the dedicated Keycloak database =="
# Jobs are immutable, so drop any previous run before re-applying.
$K kubectl -n "$NAMESPACE" delete job/keycloak-db-init --ignore-not-found
$K kubectl apply -f "$K8S_DIR/15-keycloak-db-init.yaml"
$K kubectl -n "$NAMESPACE" wait --for=condition=complete job/keycloak-db-init --timeout=120s

# Inline the realm export into the ConfigMap manifest at deploy time
REALM_JSON="$REPO_DIR/keycloak/realm-export.json"
if [[ -f "$REALM_JSON" ]]; then
  TMP_KC_MANIFEST="$(mktemp)"
  {
    echo "apiVersion: v1"
    echo "kind: ConfigMap"
    echo "metadata:"
    echo "  name: keycloak-realm"
    echo "  namespace: asix-platform"
    echo "data:"
    echo "  realm-export.json: |"
    sed 's/^/    /' "$REALM_JSON"
  } > "$TMP_KC_MANIFEST"
  $K kubectl apply -f "$TMP_KC_MANIFEST"
  rm -f "$TMP_KC_MANIFEST"
  # apply the rest of 20-keycloak.yaml minus the placeholder ConfigMap block
  awk '/^---/{found=1} found' "$K8S_DIR/20-keycloak.yaml" | $K kubectl apply -f -
else
  echo "WARNING: keycloak/realm-export.json not found in repo — skipping realm import, applying Keycloak without it."
  awk '/^---/{found=1} found' "$K8S_DIR/20-keycloak.yaml" | $K kubectl apply -f -
fi

echo "== 8/8: Deploying Keycloak and asix-api =="
$K kubectl apply -f "$K8S_DIR/30-asix-api.yaml"

echo "== Waiting for rollout =="
$K kubectl -n "$NAMESPACE" rollout status deployment/keycloak --timeout=180s
$K kubectl -n "$NAMESPACE" rollout status deployment/asix-api --timeout=120s

echo
echo "=== Deploy complete ==="
$K kubectl -n "$NAMESPACE" get pods -o wide
NODEPORT=$($K kubectl -n "$NAMESPACE" get svc asix-api -o jsonpath='{.spec.ports[0].nodePort}')
echo
echo "asix-api reachable at: http://<server-ip>:${NODEPORT}/v1/health/status"
echo "Postgres password:   /root/asix-postgres-password.txt"
echo "Keycloak admin pass:  /root/asix-keycloak-password.txt"
if [[ -f /root/asix-login-password.txt ]]; then
  echo "'asix' login password: /root/asix-login-password.txt (password AND key SSH both enabled — lab mode)"
else
  echo "'asix' user already existed — login password unchanged (key SSH also enabled — lab mode)"
fi
echo
echo "=== 'asix' SSH public key — copy this into ~/.ssh/authorized_keys on the target machine ==="
cat /home/asix/.ssh/id_rsa.pub
echo "==============================================================================="
echo "  e.g. from the target machine:"
echo "  echo '<paste the line above>' >> ~/.ssh/authorized_keys"
echo "  then from here: sudo -u asix ssh <user>@<target-ip>"
echo
echo "NOTE: Keycloak now runs in production mode ('kc.sh start') against its own"
echo "'keycloak' Postgres database, so realm/client/user data survives restarts."
echo "It's still served over plain HTTP with --hostname-strict=false for the"
echo "internal network — put a TLS-terminating reverse proxy/ingress in front"
echo "and set KC_HOSTNAME before exposing it beyond the cluster."
