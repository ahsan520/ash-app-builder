const { createRemoteJWKSet, jwtVerify } = require('jose');

const db = require('../db');

const KEYCLOAK_ISSUER =
  process.env.KEYCLOAK_ISSUER ||
  'http://keycloak:8080/realms/asix';

const KEYCLOAK_JWKS_URL =
  process.env.KEYCLOAK_JWKS_URL ||
  `${KEYCLOAK_ISSUER}/protocol/openid-connect/certs`;

const KEYCLOAK_AUDIENCE =
  process.env.KEYCLOAK_AUDIENCE ||
  'asix-api';

const JWKS = createRemoteJWKSet(new URL(KEYCLOAK_JWKS_URL));

async function validateToken(token) {
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: KEYCLOAK_ISSUER,
      audience: KEYCLOAK_AUDIENCE,
    });

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
