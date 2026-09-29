#!/usr/bin/env bash
#
# ASIX Platform — end-to-end deploy for a fresh Ubuntu server
#
# What this actually deploys (see README notes at the bottom of the chat
# response this shipped with): asix-api (Express skeleton) + PostgreSQL +
# Keycloak + a syslog ingestion collector, on a single-node k3s cluster.
# It does NOT deploy Kafka, OpenSearch, or ClickHouse — that code doesn't
# exist in the repo yet.
#
# Usage:
#   sudo ./deploy.sh /path/to/ash-app-builder-main
#
set -euo pipefail

REPO_DIR="${1:?Usage: sudo ./deploy.sh /path/to/ash-app-builder-main [git-sha]}"
GIT_SHA="${2:-local}"
IMAGE_TAG="asix-api:${GIT_SHA}"
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

# Also checked in sync-and-deploy.sh; repeated here so deploy.sh is safe to run directly.
# shellcheck source=scripts/lib/preflight-clock.sh
source "$SCRIPT_DIR/scripts/lib/preflight-clock.sh"
preflight_clock

echo "== 0/9: Creating 'asix' user (passwordless sudo) + OpenSSH server =="
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

echo "== 1/9: Installing prerequisites =="
apt-get install -y -qq ca-certificates curl gnupg jq

echo "== 2/9: Installing Docker (used only to build the image) =="
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

echo "== 3/9: Installing k3s (single-node Kubernetes) =="
if ! command -v k3s &>/dev/null; then
  curl -sfL https://get.k3s.io | sh -
  # wait for k3s to be ready
  until k3s kubectl get nodes &>/dev/null; do sleep 2; done
fi
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
alias kubectl="k3s kubectl"
K=/usr/local/bin/k3s

echo "== 4/9: Building and importing the asix-api image =="
# Tagging with the git SHA (not just the floating :local) is what makes
# 'kubectl rollout undo' and rollback.sh --quick actually restore the
# PREVIOUS code — a Deployment pinned to a SHA tag has a genuinely
# different image per revision, so k8s's own rollout history means
# something. Both tags point at the same build; :local stays as a
# convenience alias for manual `docker run` etc.
echo "Tagging image as ${IMAGE_TAG} (and asix-api:local)"
docker build -t "$IMAGE_TAG" -t asix-api:local "$REPO_DIR"
docker save "$IMAGE_TAG" asix-api:local | k3s ctr images import -

echo "== 5/9: Creating namespace + secrets =="
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

if ! $K kubectl -n "$NAMESPACE" get secret broker-ingest-secret &>/dev/null; then
  BROKER_TOKEN="$(openssl rand -base64 32)"
  $K kubectl -n "$NAMESPACE" create secret generic broker-ingest-secret \
    --from-literal=BROKER_INGEST_TOKEN="$BROKER_TOKEN"
  echo "Generated broker ingest token -> stored in k8s secret 'broker-ingest-secret'"
  echo "$BROKER_TOKEN" > /root/asix-broker-ingest-token.txt
  chmod 600 /root/asix-broker-ingest-token.txt
  echo "  (also saved to /root/asix-broker-ingest-token.txt — any external broker VM needs this value"
  echo "   as INGEST_API_TOKEN; treat it like the HEC token it's modeled on)"
fi

echo "== 6/9: Deploying PostgreSQL =="
$K kubectl apply -f "$K8S_DIR/10-postgresql.yaml"
$K kubectl -n "$NAMESPACE" rollout status statefulset/postgresql --timeout=180s

echo "== 6a/9: Backing up PostgreSQL before schema changes =="
BACKUP_DIR="/var/backups/asix/postgres"
mkdir -p "$BACKUP_DIR"
if $K kubectl -n "$NAMESPACE" get pod postgresql-0 &>/dev/null; then
  PG_PW="$($K kubectl -n "$NAMESPACE" get secret postgresql-secret -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d)"
  BACKUP_FILE="$BACKUP_DIR/asix_platform-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"
  if $K kubectl -n "$NAMESPACE" exec postgresql-0 -- env PGPASSWORD="$PG_PW" \
      pg_dump -U asix_admin -d asix_platform 2>/dev/null | gzip > "$BACKUP_FILE" \
      && [ -s "$BACKUP_FILE" ]; then
    echo "Backup saved: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
    ls -1t "$BACKUP_DIR"/*.sql.gz 2>/dev/null | tail -n +11 | xargs -r rm --
  else
    echo "NOTE: backup produced nothing (likely first-ever deploy, database still empty) - continuing"
    rm -f "$BACKUP_FILE"
  fi
else
  echo "PostgreSQL pod not up yet - skipping backup (first deploy)"
fi

echo "== 6b/9: Applying the ASIX schema (tenants, roles, identity_mappings, etc.) =="
# Jobs are immutable, so drop any previous run before re-applying.
$K kubectl -n "$NAMESPACE" delete job/asix-schema-init --ignore-not-found
$K kubectl apply -f "$K8S_DIR/12-schema-init.yaml"
$K kubectl -n "$NAMESPACE" wait --for=condition=complete job/asix-schema-init --timeout=120s

echo "== 7/9: Provisioning the dedicated Keycloak database =="
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

echo "== 8/9: Deploying Keycloak and asix-api =="
sed "s|asix-api:local|${IMAGE_TAG}|g" "$K8S_DIR/30-asix-api.yaml" | $K kubectl apply -f -

echo "== Waiting for rollout =="
$K kubectl -n "$NAMESPACE" rollout status deployment/keycloak --timeout=180s

echo "== 8b/9: Seeding default tenant + asix-api service identity =="
$K kubectl -n "$NAMESPACE" delete job/asix-seed-identity --ignore-not-found
$K kubectl apply -f "$K8S_DIR/25-seed-identity.yaml"
$K kubectl -n "$NAMESPACE" wait --for=condition=complete job/asix-seed-identity --timeout=120s

$K kubectl -n "$NAMESPACE" rollout status deployment/asix-api --timeout=120s

echo "== 9/9: Deploying the syslog collector (first ingestion source) =="
sed "s|asix-api:local|${IMAGE_TAG}|g" "$K8S_DIR/35-syslog-collector.yaml" | $K kubectl apply -f -
$K kubectl -n "$NAMESPACE" rollout status deployment/asix-syslog-collector --timeout=120s

echo "== 9b/9: Deploying the nginx reverse proxy (asix-api + Keycloak front door) =="
# Applied last: nginx resolves its upstream service names at startup. The pod
# template carries a hash of the manifest so a changed nginx config rolls the
# pod (nginx doesn't reload on ConfigMap changes) and an unchanged one doesn't.
NGINX_SHA="$(sha256sum "$K8S_DIR/40-nginx.yaml" | cut -c1-16)"
sed "s|__NGINX_CONFIG_SHA__|${NGINX_SHA}|" "$K8S_DIR/40-nginx.yaml" | $K kubectl apply -f -
$K kubectl -n "$NAMESPACE" rollout status deployment/nginx-control --timeout=120s

echo
echo "=== Deploy complete ==="
$K kubectl -n "$NAMESPACE" get pods -o wide
NODEPORT=$($K kubectl -n "$NAMESPACE" get svc asix-api -o jsonpath='{.spec.ports[0].nodePort}')
echo
echo "asix-api reachable at: http://<server-ip>:${NODEPORT}/v1/health/status"
echo "nginx front door:  http://<server-ip>:30880/  (asix-api)   http://<server-ip>:30880/auth/  (Keycloak)"
echo "Syslog broker/collector reachable at: <server-ip>:30514 (UDP + TCP)"
echo "  Point rsyslog at it: auth,authpriv.*  @@127.0.0.1:30514   (see deploy/60-asix-forward.conf)"
echo "  Broker ingest token (for any external broker VM) is in: /root/asix-broker-ingest-token.txt"
echo "Postgres password:   /root/asix-postgres-password.txt"
echo "Keycloak admin pass:  /root/asix-keycloak-password.txt"
echo "Image deployed:       ${IMAGE_TAG}"
echo "Postgres backups:     $BACKUP_DIR (last 10 kept) — restore with ./restore-postgres.sh"
echo "If this deploy broke something:"
echo "  ./rollback.sh --quick        undo the last k8s rollout only (fast; needs the"
echo "                               previous image still cached locally)"
echo "  ./rollback.sh <git-commit>   revert code/schema to an earlier commit and redeploy"
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
