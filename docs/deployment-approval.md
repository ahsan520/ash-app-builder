# Deployment Approval — Level 2 (User-Approved Action Classes)
APPROVER: User (explicit instruction)
APPROVED COMPONENTS: PostgreSQL (DB cluster with RLS), Keycloak (external HA container), Kong (API Gateway)
ACTION CLASS: Infrastructure deployment — medium risk (reversible with rollback plan)
AUTONOMY LEVEL: Level 2 (prepare + request approval — APPROVED by user instruction)
APPROVAL STATUS: APPROVED — no Level 4 autonomous execution
TIMESTAMP: 2026-09-21
AUDIT EVENT: deployment/approval/user/level-2/postgresql/keycloak/kong
ROLLBACK PLAN: DB snapshot + Keycloak config backup + Kong config backup (recorded before execution)
VERIFICATION: Health checks after deployment
