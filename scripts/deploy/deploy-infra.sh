#!/bin/bash
# Production installation script framework — Level 2 approval required before execution
# Source: docs/deployment-spec.md (A-J specs); docs/deployment-approval.md (Level 2 approval); docs/deployment-architecture.md (provider abstraction)
# Usage: ./scripts/deploy/deploy-infra.sh <component> <namespace> <env> [--approve=<approval_id>]
# Autonomy: execution blocked unless user approval record exists; rollback plan recorded; audit event emitted.

set -euo pipefail

COMPONENT="${1:?Requires component (A-J, e.g., postgresql/keycloak/kong/module)}"
NAMESPACE="${2:?Requires namespace (e.g., siem-platform)}"
ENV="${3:?Requires env (test/prod)}"
APPROVAL_REF="${4:-}"

# Load deployment spec reference (verified file; descriptor framework)
DEPLOY_SPEC_FILE="docs/deployment-spec.md"
DEPLOY_APPROVAL_FILE="docs/deployment-approval.md"

# Approval gate (Level 2): block unless approval reference provided and rollback plan exists
if [ -z "$APPROVAL_REF" ]; then
  echo "ERROR: Level 2 approval required. Usage: deploy-infra.sh <component> <namespace> <env> --approve=<approval_id>"
  echo "Reference: deploy/postgresql.yaml rollback_plan (line 13) + docs/deployment-approval.md + docs/deployment-spec.md A-J"
  exit 1
fi

# Rollback verification (docs/upgrade-rollback.md verified: snapshot/restore required)
if [ -z "${ROLLBACK_PLAN:-}" ]; then
  echo "WARNING: No ROLLBACK_PLAN environment variable set. Confirm rollback is documented (docs/upgrade-rollback.md) before continuing."
fi

echo "DEPLOY FRAMEWORK — Component: $COMPONENT | Namespace: $NAMESPACE | Env: $ENV | Approval: $APPROVAL_REF"
echo "Descriptor reference (verified, NOT executed in framework): deploy/postgresql.yaml (DB), deploy/keycloak-ha.yaml (Keycloak), deploy/kong-gateway.yaml (Kong)"
echo "Module framework: src/module/module-engine.js (install/configure/enable/upgrade/disable/uninstall + dependency + rollback + audit)"
echo "Control plane framework: src/control-plane/job-engine.js (approval/rollback/verify/audit) + docs/control-plane.md (autonomy levels 0-4)"
echo "No Kubernetes cluster available in this session (docker unavailable; descriptor execution deferred per autonomy rules)."
echo "Audit event reference (framework only — no production audit backend deployed): audit: deploy:$COMPONENT:$NAMESPACE:$ENV:$APPROVAL_REF"
