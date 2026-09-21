# Data Architecture

## Principles
- Multi-tenant isolation at storage layer
- Hot / warm / cold lifecycle
- Normalized schema (ECS/OCSF target) for interoperability
- Enrichment at ingestion and search time
- Data quality monitoring

## Event Flow (Verified Path)
Data Sources → Collectors (Vector / Fluent Bit) → Broker / Gateway → Kafka → Normalization / Parser → Enrichment → OpenSearch (hot) / ClickHouse (analytics / cold) → Search / Detection / Case / AI

## Storage Layers
- Hot: OpenSearch index (real-time search, detection, dashboards)
- Warm: ClickHouse (analytics, reporting, long-term aggregation)
- Cold / Archive: Object storage (S3 / MinIO) with compression; legal hold capability
- Feature: compression, archive policies, data deletion policies, retention per tenant

## Normalization
- Target schema: ECS (Elastic Common Schema) and OCSF (Open Cybersecurity Schema Framework) compatibility where practical
- Parsers: syslog, Windows Event, Linux, cloud APIs (AWS/Azure/GCP), network devices, database logs, SaaS events, endpoint telemetry
- Enrichment: asset context, user context, threat intelligence (IOC lookup), IP/domain reputation, vulnerability info, geo/IP labeling

## Data Classification
- Data patterns / topics / profiles
- IP / asset / sensitivity labels
- PII detection / secret detection
- Data tagging
- Classification impacts retention, access control, and AI permissions

## Data Quality / Monitoring
- Source-to-detection dependency mapping
- Ingestion diagnosis: collector → broker → network → auth → source → queue → parser → ingestion → storage
- Missing fields / parsing errors / source gaps tracked
- Quality metrics exposed to self-managing SIEM

## Entity Model (Cross-module)
User, Device, IP, Domain, Process, File, Cloud resource, Application, Alert, Incident, Threat actor, IOC
Every module references these entities; relationships tracked.
