# Control Plane Design

## Why It Exists
The Control Plane is the primary differentiator. It separates the UI from direct infrastructure manipulation. The platform must manage its own backend safely: restart brokers, scale workers, renew certificates, deploy new detection services, manage storage — without giving users raw infrastructure access.

## Flow (Verified Architecture)
Web UI → API Gateway → Auth / MFA → Tenant Context → RBAC / ABAC → Policy Engine → Control Plane → Desired State / Job → Orchestrator → Backend (K8s / Docker / VM) → Health Verification → Audit / Event → UI

## Abstraction Layer (Critical)
Not hard-coded to Kubernetes. Abstraction supports:
- Kubernetes: Pods, Deployments, StatefulSets, Jobs, ConfigMaps, Secrets, Services
- Docker: Containers, networks, volumes, compose stacks
- VMs: System services, package updates, disk, certificates
- Cloud: Managed services, serverless, storage buckets (future)

The Control Plane should translate a "desired resource" (e.g., Broker-02 restart, new collector deployment, storage expansion) into the correct backend call through a provider interface.

## Desired State / Job Model
Every control action is modeled as:
- Type: resource action (start, stop, restart, scale, deploy, rollback)
- Target: resource identity (broker-X, collector-Y, detection-Z, playbook-W)
- Tenant: multi-tenant isolation enforced
- Policy: which users/roles can approve/request
- Approval: required for high-risk / non-reversible actions; optional for low-risk/reversible
- Execution: orchestrator executes; rollback plan recorded before execution
- Verification: health checks confirm expected state after execution
- Audit: full event log: who, when, what action, what resource, result, rollback state

## Self-Managing SIEM (Observe → Diagnose → Explain → Recommend → Request Approval → Remediate → Verify → Rollback → Audit)

Observations handled by Control Plane:
- Platform health monitoring (services, APIs)
- Collector health (heartbeat, version, last seen, metrics)
- Broker health (service status, capacity, failover)
- Ingestion health (queue depth, parsing rate, error rate)
- Search health (latency, index health, query errors)
- Detection health (rule failures, false-positive rates)
- Playbook health (execution failures, timeouts, rollback state)
- Integration health (API status, auth validity)
- API health (request rate, error rate, latency)
- Storage health (disk usage, replication, archive status)
- Certificate / credential expiration monitoring
- Capacity / resource utilization
- Data quality monitoring (missing fields, parsing errors, source gaps)
- Detection coverage monitoring (MITRE coverage, source-to-detection mapping)
- Configuration drift detection (expected vs actual config differences)
- Failed automation detection (playbook failures, detection execution errors)

Autonomy Levels (Admin Configurable per Tenant / Resource / Action):
- Level 0: Observe only
- Level 1: Recommend only
- Level 2: Prepare remediation + request human approval
- Level 3: Auto-perform approved low-risk/reversible actions
- Level 4: Autonomous remediation for explicitly approved action classes

## Risk Classification
Every control action has a risk category:
- Low-risk / reversible: restart collector, scale worker, refresh token
- Medium-risk / partially reversible: restart broker, redeploy parser, update detection rule
- High-risk / non-reversible: delete storage volume, delete tenant data, disable security integration
- High-risk actions always require approval (Level 2+ minimum, never Level 4 without explicit approval class)

## Change Impact Analysis (Before Action)
Before any control action:
1. Identify affected resources (tenants, collectors, brokers, data sources)
2. Check dependency graph (what depends on this resource)
3. Show affected detections, playbooks, integrations, cases, dashboards
4. Show current queue depth and expected ingestion impact
5. Show failover availability
6. Estimate downtime / risk
7. Propose rollback plan
8. Require approval if high-risk
