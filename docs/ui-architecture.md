# UI Architecture

Status: DESIGN (Phase 1 skeleton — real backend behind, no fake pages)

## Principles
- Modular routing: new module = new navigation section / sub-navigation
- Settings: expandable categories, never one huge page
- Real backend required for every page; no placeholders that pretend backend exists
- Professional enterprise security UI (comparable to Cortex XSIAM, Sentinel, Elastic Security)

## Navigation Structure (Modular)
Main Nav (expandable sections):
- Dashboard (platform health, quick alerts, tenant overview — Phase 2+; Phase 1: basic status)
- Cases & Incidents (Phase 7)
- Investigation (Phase 7)
- Threat Management (Phase 9)
- Detection (Phase 6)
- Response / Playbooks (Phase 8)
- Posture (Phase 2+)
- Inventory (Phase 2+)
- Data Collection (Phase 3)
- Analytics / Reports (Phase 5)
- AI Assistant (Phase 10)
- Settings (Phase 1 — fully working)
- Tenant Management (Phase 1 — for MSP/admin)
- Platform Health (Phase 2; Phase 1: basic health endpoint display)

## Settings Framework (Phase 1 — critical)
Categories (expandable sections):
- General (server settings, notifications, query, repository)
- Security (auth policies, IP restrictions, password policies, session policies)
- Identity & Access (users, groups, roles, RBAC, MFA, SSO, API keys, service accounts, sessions, policies)
- Tenants (creation, configuration, quotas, retention, admins, health, usage)
- Agents / Collectors (configuration, groups, profiles — Phase 3+; Phase 1: framework only)
- Data Classification (patterns, labels — Phase 4+)
- Storage (retention, compression — Phase 4+)
- Audit / Compliance (audit log viewer, compliance settings)
- AI (providers, permissions — Phase 10+; Phase 1: framework only)

## Phase 1 UI Boundaries
Real backend pages for Phase 1 ONLY:
- Login / MFA / SSO
- Tenant selection / dashboard
- User management (add/remove/deactivate within tenant)
- Role / permission management
- API key / service account management
- Session management
- Settings (all Phase 1 categories)
- Audit event viewer (filtered by tenant)
- Basic health status page (from /v1/health/status)
NO fake cases, detections, playbooks, threats, or analytics pages.

## Component Approach
- Framework (React/TypeScript): modular routing, layout, settings expandable sections, audit viewer, tenant context provider
- No heavy component library needed; build modular navigation from scratch for long-term flexibility
- Real backend connection via API Gateway; authentication handled at framework level
