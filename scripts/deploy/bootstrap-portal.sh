#!/usr/bin/env bash
#
# One-time (idempotent) setup so a person can sign in to the ASIX Portal:
#
#   1. Keycloak realm 'asix': public client 'asix-portal' (auth-code + PKCE),
#      with an audience mapper so its tokens are accepted by asix-api.
#   2. A Keycloak user in realm 'asix' (this is NOT the master-realm 'admin').
#   3. The matching ASIX user + 'portal-admin' role + identity mapping in
#      Postgres, so the API accepts that user and lets them search events.
#
#   sudo scripts/deploy/bootstrap-portal.sh <username> [email]
#
# Re-running with the same username keeps the user, resets nothing unless
# ASIX_PORTAL_RESET_PASSWORD=1 is set. Extra portal hostnames/IPs (beyond this
# machine's own addresses): ASIX_PORTAL_HOSTS="portal.example.internal,10.0.0.9"
# and, if the port-forwarded VirtualBox port differs: ASIX_PORTAL_HTTPS_PORT=30443
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }

USERNAME="${1:?Usage: bootstrap-portal.sh <username> [email]}"
EMAIL="${2:-${USERNAME}@asix.local}"
[[ "$USERNAME" =~ ^[a-z0-9._-]+$ ]] || { echo "username: lowercase letters, digits . _ - only" >&2; exit 1; }
PORT="${ASIX_PORTAL_HTTPS_PORT:-30443}"
NS=asix-platform
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
K=(k3s kubectl -n "$NS")

# ---- portal origins (same idea as the TLS cert SANs) ---------------------------
HOSTS=(localhost 127.0.0.1)
for ip in $(hostname -I 2>/dev/null); do [[ "$ip" =~ ^[0-9.]+$ ]] && HOSTS+=("$ip"); done
[[ -n "$(hostname -s)" ]] && HOSTS+=("$(hostname -s)")
if [[ -n "${ASIX_PORTAL_HOSTS:-}" ]]; then IFS=',' read -r -a more <<<"$ASIX_PORTAL_HOSTS"; HOSTS+=("${more[@]}"); fi
REDIRECTS="$(printf '%s\n' "${HOSTS[@]}" | awk '!s[$0]++' | sed "s|.*|\"https://&:${PORT}/portal/*\"|" | paste -sd, -)"

# ---- password ---------------------------------------------------------------------
PWFILE="/root/asix-portal-${USERNAME}-password.txt"
if [[ -f "$PWFILE" ]]; then PASSWORD="$(cat "$PWFILE")"; else
  PASSWORD="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)Aa1"
  ( umask 077; echo "$PASSWORD" > "$PWFILE" )
fi

# ---- Keycloak (kcadm.sh runs inside the keycloak pod) ------------------------------
KC="deploy/keycloak"
KCFG=/tmp/kcadm.config   # the keycloak user may not have a writable $HOME
kc() { "${K[@]}" exec -i "$KC" -- /opt/keycloak/bin/kcadm.sh "$@" --config "$KCFG"; }
echo "== Keycloak: logging in to admin API =="
"${K[@]}" exec -i "$KC" -- sh -c '/opt/keycloak/bin/kcadm.sh config credentials --config /tmp/kcadm.config --server http://localhost:8080 --realm master --user "$KEYCLOAK_ADMIN" --password "$KEYCLOAK_ADMIN_PASSWORD"' >/dev/null

CID="$(kc get clients -r asix -q clientId=asix-portal --fields id --format csv --noquotes | head -1 | tr -d '\r')"
CLIENT_JSON="{\"clientId\":\"asix-portal\",\"name\":\"ASIX Portal\",\"enabled\":true,\"publicClient\":true,\"standardFlowEnabled\":true,\"directAccessGrantsEnabled\":false,\"implicitFlowEnabled\":false,\"redirectUris\":[${REDIRECTS}],\"webOrigins\":[\"+\"],\"attributes\":{\"pkce.code.challenge.method\":\"S256\",\"post.logout.redirect.uris\":\"+\"}}"
if [[ -z "$CID" ]]; then
  echo "== Keycloak: creating client asix-portal =="
  CID="$(echo "$CLIENT_JSON" | kc create clients -r asix -f - -i | tr -d '\r')"
  echo '{"name":"audience-asix-api","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.client.audience":"asix-api","access.token.claim":"true","id.token.claim":"false"}}' \
    | kc create "clients/${CID}/protocol-mappers/models" -r asix -f -
else
  echo "== Keycloak: client asix-portal exists - refreshing redirect URIs =="
  echo "$CLIENT_JSON" | kc update "clients/${CID}" -r asix -f -
fi

UID_KC="$(kc get users -r asix -q "username=${USERNAME}" -q exact=true --fields id --format csv --noquotes | head -1 | tr -d '\r')"
if [[ -z "$UID_KC" ]]; then
  echo "== Keycloak: creating user ${USERNAME} =="
  UID_KC="$(echo "{\"username\":\"${USERNAME}\",\"email\":\"${EMAIL}\",\"enabled\":true,\"emailVerified\":true}" | kc create users -r asix -f - -i | tr -d '\r')"
  kc set-password -r asix --userid "$UID_KC" --new-password "$PASSWORD"
elif [[ "${ASIX_PORTAL_RESET_PASSWORD:-0}" == "1" ]]; then
  kc set-password -r asix --userid "$UID_KC" --new-password "$PASSWORD"
fi

# ---- Postgres: ASIX user + role + identity mapping ---------------------------------
echo "== Postgres: mapping Keycloak subject ${UID_KC} =="
PGPW="$("${K[@]}" get secret postgresql-secret -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d)"
"${K[@]}" exec -i postgresql-0 -- env PGPASSWORD="$PGPW" psql -U asix_admin -d asix_platform -v ON_ERROR_STOP=1 \
  -v kc_subject="$UID_KC" -v uname="$USERNAME" -v email="$EMAIL" <<'SQL'
INSERT INTO roles (tenant_id, name, permissions)
SELECT t.id, 'portal-admin', ARRAY['auth:identity:read', 'search:events:read', 'settings:access:read',
  'detections:rules:read', 'detections:rules:write', 'alerts:read', 'alerts:write']
FROM tenants t
WHERE t.name = 'Default Tenant'
  AND NOT EXISTS (SELECT 1 FROM roles r WHERE r.tenant_id = t.id AND r.name = 'portal-admin');

-- keep the role current when new portal pages need new permissions
UPDATE roles SET permissions = ARRAY['auth:identity:read', 'search:events:read', 'settings:access:read',
  'detections:rules:read', 'detections:rules:write', 'alerts:read', 'alerts:write']
WHERE name = 'portal-admin' AND tenant_id = (SELECT id FROM tenants WHERE name = 'Default Tenant');

INSERT INTO users (tenant_id, username, email, role_ids)
SELECT t.id, :'uname', :'email', ARRAY[r.id]
FROM tenants t JOIN roles r ON r.tenant_id = t.id AND r.name = 'portal-admin'
WHERE t.name = 'Default Tenant'
ON CONFLICT (username) DO UPDATE SET email = EXCLUDED.email, role_ids = EXCLUDED.role_ids;

INSERT INTO identity_mappings (provider, subject, identity_type, user_id, tenant_id, status)
SELECT 'keycloak', :'kc_subject', 'human', u.id, u.tenant_id, 'active'
FROM users u WHERE u.username = :'uname'
ON CONFLICT (provider, subject)
DO UPDATE SET user_id = EXCLUDED.user_id, tenant_id = EXCLUDED.tenant_id, status = 'active';
SQL

IP="$(hostname -I | awk '{print $1}')"
echo
echo "Portal:    https://${IP}:${PORT}/portal/"
echo "Username:  ${USERNAME}"
echo "Password:  ${PWFILE}   (root-only file)"
echo "First visit: also open https://${IP}:30444/ once and accept its certificate warning,"
echo "             otherwise the browser blocks the portal's login requests."
