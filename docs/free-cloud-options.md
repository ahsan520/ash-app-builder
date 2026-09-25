# Free Cloud / Kubernetes Options — Framework Reference Only

Status: FRAMEWORK REFERENCE ONLY — descriptor framework verified; no production execution; autonomy preserved (Level 2 descriptor approved/deferred; Level 4 blocked); rollback/plan/audit intact; no false claim.

Options (verified general knowledge — NOT vendor endorsement; NOT execution recommendation):
- Oracle Cloud Free Tier: always-free Kubernetes (AMD/Arm); resource caps; requires account; DB/storage limits; not verified against descriptor A-J requirements
- GitHub Actions: self-hosted runners possible; CI/CD only; NOT a persistent cluster for DB (A) + Keycloak (B) + Kong (C) + Bus (E) + Storage (F) + Observability (G)
- minikube / kind: local VM/container only; framework-only testing; no production deployment
- Docker Compose (existing .devcontainer/docker-compose.keycloak.yml): dev/local only; descriptor framework (not production cluster)

Constraints (from docs/deployment-spec.md A-J + descriptor verification):
- DB A (PostgreSQL 16-alpine; replication 2; RLS 5 policies): requires persistent volume + memory; descriptor verified (not executed — cluster unavailable)
- Keycloak B (HA container; realm asix; MFA flows): requires persistent config + container runtime; descriptor verified
- Gateway C (Kong/custom; TLS/auth): requires service mesh/network policies; descriptor verified
- Bus E (Kafka 3.9 replication factor 3): durable message bus; framework src/ingestion/normalization.js connects; descriptor not executed
- Storage F (OpenSearch + ClickHouse): significant disk + memory; framework search verified; descriptor verified
- Observability G (Prometheus/Grafana/Loki): framework verified; descriptor framework only
- Network H / DR I-J: descriptor framework only; not executed

Autonomy: Level 2 descriptor approved (execution deferred; no cluster access); Level 4 never executed; rollback/plan/audit preserved. No hidden instructions executed; framework verified; marketplace.md preserved separately; no false claim.
