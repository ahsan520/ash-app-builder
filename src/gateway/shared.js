'use strict';
// Shared helpers for every src/gateway/routes/*.js router. Keeping this file tiny and these
// names stable means route files can be edited independently without touching each other.
const db = require('../db');

const {
  authMiddleware,
  tenantMiddleware,
  rbacMiddleware,
  auditMiddleware,
  brokerAuthMiddleware,
} = require('./middleware');

// Standard auth chain for a permission-gated route: requires a permission string, then
// JWT auth -> tenant context -> RBAC -> audit log, in that order.
const guarded = (permission) => [
  (req, res, next) => {
    req.required_permission = permission;
    next();
  },
  authMiddleware,
  tenantMiddleware,
  rbacMiddleware,
  auditMiddleware,
];

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const ALERT_STATUSES = ['open', 'acknowledged', 'closed'];
const apiError = (res, status, code, message) =>
  res.status(status).json({ success: false, error: { code, message } });

module.exports = {
  db, authMiddleware, tenantMiddleware, rbacMiddleware, auditMiddleware, brokerAuthMiddleware,
  guarded, UUID_RE, SEVERITIES, ALERT_STATUSES, apiError,
};
