// Phase 1 Session Service (authoritative DB session store — DESIGN DECISION)
// Session model: browser cookie/session ID + Keycloak JWT reference
// DB session table: session_id, user_id, tenant_id, token_ref, created_at, expires_at, revoked_at, refreshed_at

const auth = require('../auth/auth-service');

async function getSession(session_id) {
  // Query DB sessions table; enforce RLS (SET app.current_tenant_id from session.tenant_id)
  // Return session or null if revoked/expired
  return null;
}

async function refreshSession(session_id) {
  // Call Keycloak refresh endpoint; update DB session (refreshed_at, token_ref, expires_at)
  return { refreshed: true, session_id };
}

async function globalLogout(user_id) {
  // Revoke all sessions for user (DB revoked_at = now); audit event; optionally Keycloak global revocation
  return { revoked_count: 0 };
}

module.exports = { getSession, refreshSession, globalLogout };
