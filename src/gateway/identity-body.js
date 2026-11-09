'use strict';
// The answer of GET /v1/auth/me, kept apart from the route so its shape can be tested without a database.
// `permissions` is the caller's own permission names (sorted, no duplicates) so the portal can leave out menu entries the
// role cannot use (docs/portal-shell.md). It is a convenience only: the server checks the permission again on every call.
function identityBody(req, tenant) {
  return {
    success: true,
    authenticated: true,
    user_id: req.user_id,
    tenant_id: req.tenant_id,
    tenant_name: tenant.name,
    permissions: Array.isArray(req.rbac_permissions) ? [...new Set(req.rbac_permissions.filter((p) => typeof p === 'string'))].sort() : [],
    tenant_status: tenant.status,
    session_id: req.session_id,
  };
}

module.exports = { identityBody };
