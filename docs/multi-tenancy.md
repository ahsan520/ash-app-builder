# Multi-Tenancy Design

## Foundational Requirement
Multi-tenancy must be built from the start. Not added later. Every model, API, database query, and UI view must include tenant context.

## Tenant Model
- Tenant identity: UUID, name, organization/MSSP parent, status (active, suspended, trial)
- Tenant configuration: settings, retention, quotas, AI policies, notification policies
- Tenant isolation: data, API, settings, modules, audit, secrets, events
- MSP / MSSP support: MSP parent tenant; child customer tenants; MSP admin has controlled visibility only (not full access unless explicitly granted); customer admin never sees other customers

## Isolation Mechanisms
- Database: schema isolation (tenant-scoped tables) or row-level security (tenant_id in every row); decision needed based on performance/scalability
- Search / Storage: tenant-scoped indices or index-level isolation; query filtering enforces tenant_id
- API: tenant context extracted from auth token; rejected if missing or invalid; every endpoint checks tenant access before processing
- Module: module settings, rules, playbooks, detections, dashboards scoped by tenant
- Control Plane: all resource actions include tenant; resource identity includes tenant ID; cross-tenant resource actions blocked by default
- Audit: audit events include tenant; audit logs filtered by tenant for non-MSP users; MSP admin audit filtered by allowed scope

## Quotas and Limits
- Storage quota per tenant (hot / warm / cold)
- Event ingestion rate limit
- Query concurrency / timeout limits
- API rate limits
- AI usage / cost limits
- Module access (optional modules enabled per tenant)

## Administration
- Tenant creation: admin interface; requires approval for high-trust actions
- Tenant suspension: immediate isolation of data and APIs; retention policy continues
- Tenant deletion: data retention / legal hold before deletion; audit logged; rollback window available
- MSP cross-tenant management: dashboard showing health, usage, alerts for allowed child tenants; no data access unless explicitly authorized

## Database Isolation: PostgreSQL Row Level Security (DESIGN DECISION)
FACT: Application-level filtering alone is not a security boundary.
DESIGN DECISION: RLS is explicitly required for Phase 1.

### RLS Design (DESIGN DECISION)
- Every table that holds multi-tenant data must include tenant_id (UUID, NOT NULL, indexed).
- RLS policies enforce: SELECT/UPDATE/DELETE only where current_setting('app.current_tenant_id') matches row.tenant_id.
- DB session context: SET app.current_tenant_id = '<uuid>' must be performed by application connection pool after acquiring connection and before any query.
- If DB session context is missing or mismatched, RLS should deny (default deny), not allow.

### Parent/MSP Tenant Relationship (DESIGN DECISION)
- Parent/MSP tenant: parent_tenant_id references parent tenant UUID (nullable).
- Customer tenant: parent_tenant_id set to MSP parent UUID.
- Cross-tenant access: MSP admin role grants explicit cross-tenant access only for allowed child tenant IDs; not automatic inheritance.
- Permission naming convention must include tenant scope explicitly when needed.

### Application Tenant Context (DESIGN DECISION)
- Every request: extract tenant from auth token claim (tenant_id) or from user session.
- DB connection: set session variable before query.
- Middleware rejects request if tenant claim missing, invalid, or does not match DB session.
- RLS policy uses DB session value, not application variable, so application bug cannot bypass isolation by forgetting filter.

### Platform Admin Access (DESIGN DECISION)
- Platform admin is a special role; it does NOT automatically get full tenant data access.
- Platform admin actions that span tenants (audit review, health, config) use separate audit-authorized endpoints with explicit authorization check.
- If a platform admin accesses tenant-specific resources, the same RBAC + ABAC + tenant filter applies.

### Cross-Tenant Access (DESIGN DECISION)
- Cross-tenant queries blocked by RLS by default.
- MSP parent access to authorized child tenant requires: (1) role with cross-tenant permission; (2) ABAC policy allowing access to that child tenant UUID; (3) DB session set to child tenant UUID; (4) audit event recorded.
- Unauthorized child tenant access must fail with audit event.

### Audit Isolation (DESIGN DECISION)
- Audit events include tenant_id.
- Audit table has RLS policy enforcing tenant isolation.
- MSP audit view: only audit events for authorized child tenants; DB session set accordingly; audit query must use RLS filter.
- Audit export: restricted by role + ABAC; requires approval if bulk.

### Security Tests Proving Isolation (DESIGN DECISION — for docs/testing-strategy.md update)
Tests must prove:
- API request with tenant A token accessing tenant B endpoint fails.
- DB query with session set to tenant A cannot read tenant B rows.
- RLS bypass attempt (manipulating session variable) fails.
- MSP parent can access authorized child; unauthorized child fails.
- Platform admin cannot access tenant data without explicit authorization.
