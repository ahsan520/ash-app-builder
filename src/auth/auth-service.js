const { createRemoteJWKSet, jwtVerify } = require('jose');

const db = require('../db');

const KEYCLOAK_ISSUER =
  process.env.KEYCLOAK_ISSUER ||
  'http://keycloak:8080/realms/asix';

const KEYCLOAK_JWKS_URL =
  process.env.KEYCLOAK_JWKS_URL ||
  `${KEYCLOAK_ISSUER}/protocol/openid-connect/certs`;

// Tokens minted for the browser portal carry the PUBLIC issuer (Keycloak derives
// it from the Host header nginx forwards, e.g. https://10.1.1.3:30444/realms/asix),
// while in-cluster clients get http://keycloak:8080/realms/asix. Signatures are
// still verified against this realm's own JWKS above, so the host part of `iss`
// cannot be forged into acceptance - we only allow the same realm name under
// any https origin. Override with KEYCLOAK_ALLOWED_ISSUER_REGEX.
const ALLOWED_ISSUER_RE = new RegExp(
  process.env.KEYCLOAK_ALLOWED_ISSUER_REGEX || '^https://[^/]+/realms/asix$'
);

function issuerAllowed(iss) {
  return iss === KEYCLOAK_ISSUER || ALLOWED_ISSUER_RE.test(String(iss || ''));
}

const KEYCLOAK_AUDIENCE =
  process.env.KEYCLOAK_AUDIENCE ||
  'asix-api';

const JWKS = createRemoteJWKSet(new URL(KEYCLOAK_JWKS_URL));

async function validateToken(token) {
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      audience: KEYCLOAK_AUDIENCE,
    });

    if (!issuerAllowed(payload.iss)) {
      throw new Error(`unexpected token issuer: ${payload.iss}`);
    }

    return {
      valid: true,
      subject: payload.sub || null,
      session_id: payload.sid || null,
      claims: payload,
    };
  } catch (error) {
    return {
      valid: false,
      error: error.code || 'TOKEN_INVALID',
      message: error.message,
    };
  }
}

/**
 * Resolve a cryptographically validated external identity
 * to an ASIX-local identity and tenant scope.
 *
 * Keycloak sub != ASIX users.id.
 *
 * Identity resolution happens before tenant context exists,
 * so it uses the narrowly scoped SECURITY DEFINER database
 * function instead of directly querying RLS-protected tables.
 */
async function resolveIdentity(provider, subject) {
  if (!provider || !subject) {
    return {
      resolved: false,
      error: 'IDENTITY_INPUT_MISSING',
    };
  }

  const result = await db.query(
    `
    SELECT
        identity_id,
        identity_type,
        user_id,
        service_name,
        tenant_id,
        tenant_name,
        status
    FROM resolve_external_identity($1::varchar, $2::varchar)
    `,
    [provider, subject]
  );

  if (result.rows.length === 0) {
    return {
      resolved: false,
      error: 'IDENTITY_NOT_MAPPED',
    };
  }

  const identity = result.rows[0];

  if (!identity.tenant_id) {
    return {
      resolved: false,
      error: 'TENANT_SCOPE_MISSING',
    };
  }

  return {
    resolved: true,
    identity_id: identity.identity_id,
    identity_type: identity.identity_type,
    user_id: identity.user_id,
    service_name: identity.service_name,
    tenant_id: identity.tenant_id,
    tenant_name: identity.tenant_name,
  };
}

async function createSession(user_id, tenant_id, token_ref) {
  return {
    id: 'session-uuid-placeholder',
    user_id,
    tenant_id,
    token_ref,
  };
}

async function revokeSession(session_id) {
  return { revoked: true };
}

module.exports = {
  validateToken,
  resolveIdentity,
  createSession,
  revokeSession,
};
