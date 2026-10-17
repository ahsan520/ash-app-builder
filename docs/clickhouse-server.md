# ClickHouse server in k8s/

Phase 3 of `docs/product-plan.md`, first item. The ClickHouse **adapter** has existed since Phase 2 (`docs/event-store.md`);
this adds the ClickHouse **server** next to PostgreSQL on the k3s box, so `ASIX_EVENT_STORE=clickhouse` has something to point at.

Files: `k8s/11-clickhouse.yaml` (ConfigMap, StatefulSet, headless Service), the `ASIX_EVENT_STORE`, `CLICKHOUSE_PASSWORD` and
`ASIX_CLICKHOUSE_URL` variables in `k8s/30-asix-api.yaml`, a new step in `deploy.sh`, `--with-clickhouse` in `sync-and-deploy.sh`,
`scripts/ci/validate-k8s.py` and the CI job `k8s-manifests`. No schema change, no code change in `src/`.

## Optional, and it changes nothing until you switch
Deploying the server does **not** move any events. The API keeps writing to PostgreSQL (`ASIX_EVENT_STORE` is `"postgres"` in
`k8s/30-asix-api.yaml`) until you change that line. A Home install that never asks for ClickHouse is unchanged: no pod, no secret, no volume.

```bash
./sync-and-deploy.sh --with-clickhouse      # first time; or: sudo ASIX_DEPLOY_CLICKHOUSE=1 ./deploy.sh <repo> <sha>
./sync-and-deploy.sh                        # later deploys keep it up to date on their own once the StatefulSet exists
```

What `deploy.sh` does (step "6-ch/9", after PostgreSQL): creates the secret `clickhouse-secret` once (48 hex characters, also saved to
`/root/asix-clickhouse-password.txt`, root-only; hex because it goes inside a URL), applies `k8s/11-clickhouse.yaml`, waits for the
StatefulSet, and runs `scripts/deploy/protect-volumes.sh` so the volume is `Retain` like PostgreSQL's. `pod-manager.sh` already never
restarts or deletes StatefulSet pods without asking, so ClickHouse is covered by that too.

## What is deployed
| | |
|---|---|
| Image | `clickhouse/clickhouse-server:24.8` (the version CI tests against) |
| Pod | one replica, `terminationGracePeriodSeconds: 60`, `/ping` start, ready and live probes |
| Volume | 20Gi `clickhouse-data` at `/var/lib/clickhouse` |
| Limits | requests 500m CPU / 1Gi; limits 2 CPU / 2Gi. ClickHouse is told to use at most 75% of the container limit |
| Access | `clickhouse:8123` (HTTP) inside the cluster only. No NodePort, no ingress. Port 9000 is not exposed by the Service |
| Database, user | database `asix`, user `asix` (made by the image from `CLICKHOUSE_DB`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`) |
| Config | `config.d/asix.xml` from the ConfigMap: memory share, small mark cache, and the diagnostic tables trimmed (below) |

**Diagnostic tables.** ClickHouse writes its own logs into `system.*` tables, and on a small VM they can outgrow the events. `asix.xml`
keeps `query_log` and `part_log` for 7 days and removes `trace_log`, `text_log`, `metric_log`, `asynchronous_metric_log`,
`query_thread_log`, `query_views_log`, `session_log`, `opentelemetry_span_log`, `processors_profile_log`,
`asynchronous_insert_log`, `backup_log`, `blob_storage_log`, `s3queue_log` and `error_log`. Only `crash_log`, `part_log` and `query_log`
remain (checked on a real 24.8.14.39 server).

Budget on the 4 vCPU / 8 GB Home machine: PostgreSQL up to 2Gi, ClickHouse up to 2Gi, 2 API pods 512Mi each (more with parser workers),
Keycloak, nginx. Tight but it fits; do not also raise everything else.

## Switching the API to ClickHouse (read this first)
1. Deploy the server (above) and check the pod is Ready: `k3s kubectl -n asix-platform get pods -l app=clickhouse`.
2. Change `ASIX_EVENT_STORE` to `"clickhouse"` in `k8s/30-asix-api.yaml`, commit, `./sync-and-deploy.sh`. The API creates the events table
   on start (`store.init()`). If ClickHouse is not reachable the API **exits at start** with `[events] the event store could not be
   initialised`, and the rolling deploy keeps the old pods serving.
3. **Existing events are not copied.** From the switch on, new events go to ClickHouse and search, detections, retention and the pages read
   ClickHouse. Events already in PostgreSQL stay there but are no longer seen. There is no copy tool yet: do not switch an install whose
   history matters.
4. **ClickHouse is not backed up.** The nightly job (`k8s/32-backup.yaml`) dumps PostgreSQL and Keycloak only. Events in ClickHouse live on
   one volume with no backup and no restore test.
5. Going back is the same one-line change; events written to ClickHouse in the meantime are then not seen, as in point 3.

## Checked
- A real ClickHouse **24.8.14.39** (the release binary) started with the exact `asix.xml` taken out of the manifest: no configuration error,
  the removed tables are absent, `query_log` has `TTL event_date + toIntervalDay(7)`, `mark_cache_size`, `uncompressed_cache_size` and
  `max_server_memory_usage_to_ram_ratio` have the configured values.
- Against that server, as user `asix` with a password: the store, search and rule-match conformance suites (58, 17 and 9 passing) and
  `retention-clickhouse` (4, with PostgreSQL alongside).
- The real `src/server.js` with `ASIX_EVENT_STORE=clickhouse`: the table was created, `POST /v1/ingest/http` stored a parsed sshd event in
  `asix.events`, SIGTERM exited 0. With ClickHouse unreachable it printed the init error and did not listen.
- `scripts/ci/validate-k8s.py` (all of `k8s/` against the Kubernetes 1.30 API schema, the embedded XML, and that the API's URL names the
  same service, port, user and database as the ClickHouse manifest) passes; a deliberately wrong field name and a broken XML tag were both caught.
- `bash -n` on `deploy.sh` and `sync-and-deploy.sh`.

## Not checked (no cluster in the build environment)
- That the official image creates user `asix` and database `asix` from the three variables (it does for `default` in CI; the image
  documents it for other names).
- `$(CLICKHOUSE_PASSWORD)` expanding inside `ASIX_CLICKHOUSE_URL`, the probes, the PVC, the 2Gi limit under real load, and the new `deploy.sh`
  step itself, on k3s. First deploy: watch `k3s kubectl -n asix-platform describe pod clickhouse-0`.
- The `k8s-manifests` CI job and the other new CI parts have not run on GitHub; the script was run locally.

## Not built
- Copying existing events from PostgreSQL to ClickHouse (and back).
- Backup and restore of ClickHouse (ClickHouse `BACKUP` to a disk or S3, a test restore, a line on the Data safety page).
- Anything beyond one node: replication, Keeper, sharding, TLS between the API and ClickHouse, a NetworkPolicy.
- A per-tenant choice of store (one store per API process).
