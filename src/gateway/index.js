// Phase 1 API Gateway (Node/Express) — DESIGNED, NOT FULLY IMPLEMENTED
// Flow: Web UI → Gateway → Auth/Keycloak → Tenant Context → RBAC/ABAC → Module → DB
// No infrastructure commands through gateway.

const express = require('express');
const app = express();

// Design: middleware chain
// 1. TLS termination / rate limit
// 2. Auth validation (Keycloak JWT or session token)
// 3. Tenant extraction from token claim
// 4. DB session context: SET app.current_tenant_id
// 5. RBAC / ABAC check
// 6. Audit event creation
// 7. Route to module

// Not fully implemented — framework for Phase 1 approval
app.use(express.json());

// Design endpoint: health (verified by tests)
app.get('/v1/health/status', (req, res) => {
  res.json({ success: true, status: 'ok', tenant: req.tenant_id || 'unknown' });
});

module.exports = app;
