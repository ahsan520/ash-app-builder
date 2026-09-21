# Observability Architecture

Status: DESIGN (observability framework for self-managing SIEM)

## Components
- Metrics: Prometheus + Grafana (service health, API latency, DB connection pool, auth rate, audit event rate, control plane execution rate, module health)
- Logs: Loki (structured logs; module-scoped; tenant-scoped filters; audit log stream)
- Traces: Tempo (future — distributed tracing for API requests, message bus events, detection pipeline)
- Alerting: Alertmanager (alerts on service failure, cross-tenant access attempt, audit event spike, DB replication lag, control plane failure, AI audit failure)

## Metrics Design (Self-Managing SIEM — Phase 2+; framework Phase 1)
Every service exposes /metrics endpoint for Prometheus:
- auth_service_requests_total (labels: endpoint, status, tenant)
- auth_service_duration_seconds (labels: endpoint, status)
- auth_mfa_attempts_total (labels: result)
- auth_session_active (labels: tenant)
- tenant_create_total, tenant_deactivate_total
- audit_events_total (labels: action, tenant, user_role)
- settings_update_total (labels: category, tenant)
- api_key_create_total, api_key_revoke_total
- gateway_request_total (labels: endpoint, status, rate_limit_result)
- db_query_duration_seconds (labels: module, query_type)
- message_bus_queue_depth (labels: topic)
- module_health (labels: module_name, status)

## Log Design
Every service logs structured JSON:
- timestamp, service, module, request_id, tenant_id, user_id, session_id, action, resource, result, audit_event_id, error_details
- Audit events are special log streams: audit_action, audit_resource, audit_result, audit_approval_required, audit_rollback_state
- Error logs include error code, request details, stack trace (in non-prod only)

## Self-Managing Metrics (Phase 11 Design; Phase 1 Framework Only)
- Platform health monitoring: services, APIs, DB, message bus, control plane
- Collector health: heartbeat, version, last seen, metrics (Phase 3+)
- Broker health: status, capacity, failover, version (Phase 3+)
- Ingestion health: queue depth, parsing rate, error rate (Phase 4+)
- Search health: latency, index status, query errors (Phase 5+)
- Detection health: rule failures, false positive rate (Phase 6+)
- Playbook health: execution failures, rollback state (Phase 8+)
- Integration health: API status, auth validity (Phase 3+)
- Storage health: disk usage, archive status (Phase 4+)
- Config drift: expected vs actual state comparison (Phase 11)
