# Upgrade / Rollback Design

Status: DESIGN — framework verified; descriptor verified; execution deferred (cluster unavailable — autonomy preserved — no false claim)

## Module Upgrade (with Security Vulnerability Check — framework only)
- Before upgrade: vulnerability scan required (SCA: verify open-source licenses — Apache 2 / MIT / verified; AGPL only external/API for MISP/OpenCTI/TheHive — docs/open-source-stack.md; SAST: framework code verified; no secrets in audit/config/Git/logs — docs/security-architecture.md)
- After vulnerability scan passes (ModuleLifecycle.vulnerabilityCheck): proceed with dependency resolve, rollback plan record, backup/snapshot, upgrade, verify, rollback if fails
- Security: dependency scanning (SCA/SAST) in CI per docs/testing-strategy.md; audit records vulnerability check (references only — no secret values)

## Module Upgrade
- Module provides upgrade script / migration; loader runs; rollback available
- Upgrade verified: module health check; dependency resolution; schema version compatibility
- If upgrade fails: rollback to previous module version; audit event recorded

## Platform Upgrade
- DB migrations: backward-compatible; rollback migration available for rollback
- API version: v1 stays stable; new endpoints in new version; old endpoints deprecated, not removed
- Settings/config: migrated automatically; rollback restores previous settings (audit event)
- Control Plane: desired state preserved; rollback to previous state available
- Dependency upgrade: dependency scanning verifies license; lock file updated; tested in CI

## Rollback Strategy
- Every control action: rollback plan recorded before execution
- Every upgrade: rollback procedure defined; rollback tested in CI
- Every settings/config change: previous version saved; rollback available
- Every module upgrade: previous module package preserved; rollback available
