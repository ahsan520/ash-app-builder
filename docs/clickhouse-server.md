# ClickHouse server in k8s/

Phase 3 of `docs/product-plan.md`, first item (backup: `docs/clickhouse-backup.md`; copying events: below). The ClickHouse **adapter** has existed since Phase 2 (`docs/event-store.md`);
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
2. **Copy the history first**, while the API still writes to PostgreSQL (see "Copying events" below):
   ```bash
   N="k3s kubectl -n asix-platform"
   $N exec deploy/asix-api -- node src/events/copy-events.js --from postgres --to clickhouse --dry-run     # what would be copied
   $N exec deploy/asix-api -- node src/events/copy-events.js --from postgres --to clickhouse               # copy and verify
   ```
   Keep the `--since` time it prints at the end.
3. Change `ASIX_EVENT_STORE` to `"clickhouse"` in `k8s/30-asix-api.yaml`, commit, `./sync-and-deploy.sh`. The API creates the events table
   on start (`store.init()`). If ClickHouse is not reachable the API **exits at start** with `[events] the event store could not be
   initialised`, and the rolling deploy keeps the old pods serving.
4. **Catch up:** events that reached PostgreSQL after the copy and before the old pods stopped are not in ClickHouse yet. Run the copy again
   with the time from step 2: `... copy-events.js --from postgres --to clickhouse --since <that time>`. Events already there are skipped, so
   this is safe to repeat.
5. **ClickHouse is backed up by the nightly job** (`docs/clickhouse-backup.md`): one encrypted file per day, incremental, test-restored about weekly,
   restorable with `scripts/restore-backup.sh ch-restore`. On the k3s box `ch-verify` and `ch-restore --as <table>` were run on 2026-10-17 and passed;
   run `ch-verify` again after the first nightly job that follows a switch. PostgreSQL keeps its copy of the history (the copy tool deletes nothing),
   which is your fallback until you have seen a ClickHouse backup and test restore succeed.
6. Going back is the same one-line change, preceded by `copy-events.js --from clickhouse --to postgres` for what was written to ClickHouse in the meantime.
- Everything that is not an event (rules, alerts, tenants, users, collectors, settings) stays in PostgreSQL and is unaffected by the switch.
  The IOC matcher keeps its place in PostgreSQL as an event time and id, so it carries on after a switch (from reading the code: events inside
  the last millisecond of its position could be looked at twice).
- Retention keeps working on ClickHouse (partition drops), but the copy brings old events with it: the next retention run applies your policy to them.

## Copying events (`src/events/copy-events.js`)
```
node src/events/copy-events.js --from postgres --to clickhouse [--tenant <uuid>] [--since <ISO>] [--until <ISO>] [--batch 1-1000] [--dry-run] [--no-verify]
```
Runs inside an API pod (they have both databases' settings; the tenant list comes from PostgreSQL). Exit code 0 only if nothing failed or differed.
- **Per tenant, in time order, in batches** (500 by default). Each batch is (1) looked up in the destination **by event id**, and events already
  there are left alone; (2) inserted with the same id, received time and fields; (3) read back from the destination and compared field by
  field (source type, collector, raw, parsed, event time, received time; times to the millisecond). Every event is checked, not a sample.
- **By id, not by `(id, received_at)`**: ClickHouse keeps received times to the millisecond and PostgreSQL to the microsecond, so the stores' own
  idempotency would see a copied-back event as new. Shown on a real pair of servers: without the id check, copying 20 events back from ClickHouse
  made PostgreSQL hold 39; with it, the tool copied 0.
- **Safe to repeat and to interrupt.** A second run copies nothing; `--since` skips the part already done. A different event that already holds an
  id in the destination is reported (`CHECK ... differs in raw`) and **not** overwritten.
- **Deletes nothing** from either store, and touches nothing but events.
- `--dry-run` reads and counts, writes nothing. A failing tenant is reported and the others still run; the final line is `RESULT: OK` or `RESULT: NOT OK`.
- Events that reach the source while it runs, or after it, are not in the copy: that is what the catch-up run in step 4 is for.

## Checked on the k3s box (2026-10-17, first deploy)
- `./sync-and-deploy.sh --with-clickhouse` deployed it: `clickhouse-0` was `1/1 Running` about a minute after the apply, the secret was created, and the rest of the deploy was unaffected.
- The image created user `asix` and database `asix` from the three variables (`SELECT currentUser(), currentDatabase()` gave `asix`, `default`; `SHOW DATABASES` lists `asix`), version 24.8.14.39.
- `asix.xml` was loaded: the only diagnostic tables present are `query_log` (and an empty `mysql_binlogs`); `part_log` and `crash_log` are created on first use.
- `$(CLICKHOUSE_PASSWORD)` expanded inside `ASIX_CLICKHOUSE_URL` in the API pods, and `ClickHouseEventStore.init()` run inside an API pod succeeded (so the Service name, port, user and password all work from the API). This created the empty `events` table in ClickHouse, which is harmless.
- `ASIX_EVENT_STORE` is `postgres` in the API pods, as shipped.
- The volume's reclaim policy is `Retain` (`protect-volumes.sh` ran).
- Idle use: 152Mi of memory and 84m CPU for ClickHouse, against a 2Gi limit.
- The startup and probe settings held: no restarts.

## Checked: the copy tool (on a real PostgreSQL 16 and ClickHouse 24.8.14.39)
- `tests/copy-events.test.js` (in-memory stores, 10 tests) and `tests/copy-events-db.test.js` (3 tests, through the real command line): 3,000 events with
  microsecond received times, null collectors and event times, unicode and nested JSON copied PostgreSQL to ClickHouse and every one verified; same events per day on both
  sides; a second run copies 0; `--since` catches a late event; `--dry-run` writes nothing; another tenant untouched; copied back ClickHouse to PostgreSQL with no
  duplicates and only the 40 ClickHouse-only events added; all tenants including an empty one; bad arguments refused. CI runs the second file in the `clickhouse` job.

## Checked on the k3s box: the copy tool (2026-10-17)
- `copy-events.js --from postgres --to clickhouse --dry-run`: 1 tenant, read 2679, would copy 2679, already there 0.
- The copy: read 2679, copied 2679, verified 2679 (each copy read back and compared). It printed a `--since` time to catch events written after the run.
- `ASIX_EVENT_STORE` was still `postgres` after this step (the switch is below). Not measured: speed and memory with large histories.

## Switched on the k3s box (2026-10-17)
- Catch-up copy before the switch (`--since` from the first copy): read 0. Setting changed to `"clickhouse"` in `k8s/30-asix-api.yaml`, deployed with `./sync-and-deploy.sh`: both API pods Running with 0 restarts, `printenv ASIX_EVENT_STORE` gave `clickhouse`, no `[events]` error in the log.
- Catch-up copy after the switch: read 4, copied 4, verified 4 (events that reached PostgreSQL before the pods were replaced). Counts then matched: PostgreSQL 2683, ClickHouse 2683.
- One syslog test line sent to the collector's NodePort (UDP 30514) appeared in ClickHouse (count 2684) and PostgreSQL stayed at 2683: new events go only to ClickHouse.
- Restart test: `kubectl delete pod clickhouse-0`; the StatefulSet recreated it (`1/1 Running`, 0 restarts, a few seconds after the delete, so an immediate `kubectl wait` can say NotFound) and the count was still 2684.
- Not checked: ClickHouse under real load, speed and memory with large histories, the first nightly backup after the switch.

## Not checked
- Behaviour under real load: memory against the 2Gi limit while ingesting and searching, merges and disk growth.
- The copy tool at scale: it has been run on thousands of events, not millions, and its speed and memory use in the API pod (512Mi limit) are not measured. Run `--dry-run` first and watch the pod.
- A pod restart or VM reboot with data in it (the volume is `Retain`, but a restart with events in it has not been tried).
- The `k8s-manifests` CI job and the other new CI parts have not run on GitHub; the script was run locally.

## Not built
- Off-VM copies of the ClickHouse backup, and ClickHouse's own `BACKUP` command (see `docs/clickhouse-backup.md`).
- Anything beyond one node: replication, Keeper, sharding, TLS between the API and ClickHouse, a NetworkPolicy.
- A per-tenant choice of store (one store per API process).
