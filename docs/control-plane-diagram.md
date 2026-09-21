# Control Plane Diagram (Text)

Web UI
  ↓ (API call / request)
API Gateway
  ↓
Auth / MFA (Keycloak)
  ↓
Tenant Context + RBAC/ABAC
  ↓
Policy Engine (approval rules, risk classification, autonomy levels)
  ↓
Control Plane
  ↓ (desired state / job created)
Orchestrator
  ↓ (provider abstraction)
Backend Infrastructure (K8s / Docker / VM)
  ↓
Health Verification
  ↓
Audit / Event → Back to UI (status + audit log)

Key Rule: UI never executes infrastructure commands directly.
Every control action is a job with approval, rollback plan, and audit event.
