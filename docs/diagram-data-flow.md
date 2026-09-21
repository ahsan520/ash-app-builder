# Data Flow Diagram

Data Source (syslog, endpoint, cloud, webhooks, file) → Collector (Fluent Bit / Vector) → Broker (collection gateway) → Kafka (message bus) → Normalization / Parser → Enrichment → Storage (OpenSearch hot / ClickHouse analytics) → Search / Analytics / Detection → Alert / Incident → Case / Playbook → Response / Audit

Multi-tenant isolation enforced at: Collector (label), Broker (tenant filter), Kafka (topic naming or filtering), Normalization (tenant field), Storage (index filter / DB filter), Search (query filter), Detection (rule scoping), Case (tenant scoping), Audit (tenant scoping)
