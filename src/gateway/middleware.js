const {
  validateToken,
  resolveIdentity,
} = require('../auth/auth-service');

const db = require('../db');
const { checkRBAC } = require('../rbac/rbac-policy');

async function authMiddleware(req, res, next) {
  try {
    const authorization = req.headers.authorization;

    if (!authorization || !authorization.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'AUTH_MISSING',
          message: 'Bearer token required',
        },
      });
    }

    const token = authorization.slice('Bearer '.length).trim();

    if (!token) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'AUTH_MISSING',
          message: 'Bearer token required',
        },
      });
    }

    // Step 1: cryptographically validate the Keycloak JWT.
    const tokenResult = await validateToken(token);

    if (!tokenResult.valid) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'AUTH_INVALID',
          message: 'Invalid or expired token',
        },
      });
    }

    // Step 2: resolve the external Keycloak identity
    // to an ASIX-local identity and tenant scope.
    const identity = await resolveIdentity(
      'keycloak',
      tokenResult.subject
    );

    if (!identity.resolved) {
      return res.status(403).json({
        success: false,
        error: {
          code: identity.error,
          message: 'Authenticated identity is not authorized in ASIX',
        },
      });
    }

    req.identity_id = identity.identity_id;
    req.identity_type = identity.identity_type;

    // Human identity.
    req.user_id = identity.user_id || null;

    // Service identity.
    req.service_name = identity.service_name || null;

    // ASIX tenant context comes from the identity mapping,
    // NOT from a tenant_id JWT claim.
    req.tenant_id = identity.tenant_id;
    req.tenant_name = identity.tenant_name || null;

    req.session_id = tokenResult.session_id;
    req.auth_claims = tokenResult.claims;

    next();
  } catch (error) {
    console.error('Authentication middleware failed:', error.message);

    return res.status(401).json({
      success: false,
      error: {
        code: 'AUTH_ERROR',
        message: 'Authentication processing failed',
      },
    });
  }
}

function tenantMiddleware(req, res, next) {
  if (!req.tenant_id) {
    return res.status(403).json({
      success: false,
      error: {
        code: 'TENANT_MISSING',
        message: 'Tenant context missing',
      },
    });
  }

  next();
}

async function rbacMiddleware(req, res, next) {
  try {
    const permission =
      req.required_permission ||
      `${req.module || 'api'}:` +
      `${req.resource || 'general'}:` +
      `${req.method || 'read'}`;

    req.required_permission = permission;

    const result = await db.withTenant(req.tenant_id, async (client) => {
      if (req.identity_type === 'service') {
        return client.query(
          `
          SELECT DISTINCT unnest(r.permissions) AS permission
          FROM service_identity_roles sir
          JOIN roles r
            ON r.id = sir.role_id
          WHERE sir.service_identity_id = $1
            AND r.tenant_id = $2
          `,
          [req.identity_id, req.tenant_id]
        );
      }

      if (req.identity_type === 'human' && req.user_id) {
        return client.query(
          `
          SELECT DISTINCT unnest(r.permissions) AS permission
          FROM users u
          JOIN roles r
            ON r.id = ANY(u.role_ids)
          WHERE u.id = $1
            AND u.tenant_id = $2
            AND r.tenant_id = $2
          `,
          [req.user_id, req.tenant_id]
        );
      }

      return { rows: [] };
    });

    const rolePermissions = result.rows.map((row) => row.permission);

    if (!checkRBAC(rolePermissions, permission)) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'RBAC_DENIED',
          message: 'Required permission is not assigned to the authenticated identity',
        },
      });
    }

    req.rbac_permissions = rolePermissions;

    next();
  } catch (error) {
    console.error('RBAC authorization failed:', error.message);

    return res.status(403).json({
      success: false,
      error: {
        code: 'RBAC_ERROR',
        message: 'Authorization processing failed',
      },
    });
  }
}

function auditMiddleware(req, res, next) {
  req.audit_event = {
    action: req.path,
    method: req.method,
    tenant: req.tenant_id,
    identity: req.identity_id || 'unknown',
    user: req.user_id || null,
    service: req.service_name || null,
    timestamp: new Date().toISOString(),
  };

  next();
}

module.exports = {
  authMiddleware,
  tenantMiddleware,
  rbacMiddleware,
  auditMiddleware,
};
