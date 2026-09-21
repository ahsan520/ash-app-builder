# Automation / Autonomy Design

Status: DESIGN (self-managing SIEM + autonomy levels + playbook execution)

## Autonomy Levels (Configurable per Tenant / Resource / Action / Integration / Playbook / Collector / Broker / Component)
- Level 0: Observe only. System monitors, reports, no recommendations or actions.
- Level 1: Recommend only. System produces recommendations; human reviews; no automated action.
- Level 2: Prepare remediation + request approval. System prepares rollback plan, change impact analysis, desired state; requires human approval before execution.
- Level 3: Auto-perform approved low-risk/reversible actions. System executes only for explicitly approved action classes (low-risk/reversible: restart collector, scale worker, refresh token, deploy detection update with rollback).
- Level 4: Autonomous remediation only for explicitly approved action classes. System executes high-risk actions only when explicitly configured and approved for specific classes; audit + verification + rollback required.

## Self-Managing SIEM Lifecycle
Observe (metrics/logs/health) → Diagnose (root cause analysis; dependency graph) → Explain (evidence; affected resources; detection impact) → Recommend (remediation; rollback plan; impact analysis) → Request Approval (Level 2+; approval required for medium/high risk) → Remediate (execute through Control Plane; provider abstraction; rollback available) → Verify (health check; state matches desired) → Rollback (if verification fails; rollback plan executed; audit) → Audit (full event log: who/what/why/result/rollback/audit)

## Playbook Execution Flow
Trigger (event/alert/schedule) → Conditions (check) → Actions (modular actions; connector framework) → Approval (if configured; Level 2+) → Execution (through Control Plane; not UI) → Verification (success/failure check) → Rollback (if failure; rollback actions executed) → Audit (execution history; approval records)
