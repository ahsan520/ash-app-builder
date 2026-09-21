# HA / DR Design

Status: DESIGN

## Availability Targets (Design — not Phase 1 verified)
- Phase 1: basic availability; no automatic failover; manual promotion if needed
- Production target: 99.9% uptime; automated failover for critical services; multi-region option

## Replication
- PostgreSQL: streaming replication (primary + replicas); manual or automated promotion
- Message Bus (Kafka): multiple brokers; replication factor 3; partition replicas
- Storage (OpenSearch): index replicas; shard allocation; backup/restore per index
- Audit / Config: exported regularly; versioned; stored in separate storage

## Failover
- Gateway: health check; if primary gateway fails, load balancer routes to secondary
- Auth (Keycloak): clustered; session store shared; no single point of failure
- Module Services: multiple instances; load-balanced; stateless where possible
- DB: automated failover with tool (Patroni or manual); Phase 1 uses manual
- Message Bus: broker failover; consumer group rebalance; no message loss with durable storage

## Disaster Recovery
- Backup frequency: DB daily; audit logs continuous; settings/config on every change (versioned)
- Recovery Point Objective (RPO): < 15 min for critical audit; < 1 hour for DB; < 1 day for settings
- Recovery Time Objective (RTO): < 2 hours for core services; < 4 hours for full platform
- Multi-region: optional; data replication; legal/territorial constraints for audit
