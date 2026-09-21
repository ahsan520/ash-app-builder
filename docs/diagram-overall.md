# Overall Platform Diagram (Text/Design)

[Web UI] → [API Gateway] → [Auth (Keycloak)] → [Tenant Context] → [RBAC/ABAC] → [Policy Engine] → [Module Services (SIEM/XDR/SOAR/AI)] → [DB / Search / Message Bus] → [Observability] → [Audit]

Control Plane (separate): [Policy Engine] → [Control Plane] → [Desired State / Job] → [Orchestrator] → [Infrastructure Provider (K8s/Docker/VM)] → [Health Verification] → [Audit/Event] → [UI]

Three Planes:
- Data Plane: Collectors → Brokers → Kafka → Normalization → Storage → Search → Detection → Alert
- Control Plane: Policy → Job → Execution → Verification → Rollback
- Management Plane: Settings → Health → Self-Management → Audit
