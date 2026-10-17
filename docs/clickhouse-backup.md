# ClickHouse backup

Phase 3 of `docs/product-plan.md`. The nightly backup job used to cover PostgreSQL and Keycloak only; when events live in ClickHouse
(`ASIX_EVENT_STORE=clickhouse`) they were on one volume with no copy. Now the same job backs up the events held in ClickHouse,
test-restores them, and `scripts/restore-backup.sh` can restore them.

Files: `src/backup/clickhouse-backup.js` (new), `src/backup/backup.js` and `src/backup/restore.js` (call it), `ClickHouseEventStore.dropTable()`,
`k8s/32-backup.yaml` (ClickHouse variables), `k8s/12-schema-init.yaml` (`backup_runs.kind`), `src/storage/safety.js` (the Data safety page),
`scripts/restore-backup.sh` (`ch-list`, `ch-verify`, `ch-restore`).

## What it does each night (02:17, the existing CronJob `asix-backup`)
1. PostgreSQL first, exactly as before. Then ClickHouse. One failing does not stop the other; the job exits 1 if either failed.
2. ClickHouse is backed up **when its secret exists** (`clickhouse-secret`, made by `./sync-and-deploy.sh --with-clickhouse`). An install that never
   deployed ClickHouse is unchanged. `BACKUP_CLICKHOUSE` in `k8s/32-backup.yaml`: `auto` (default), `1` (always, fail if unreachable), `0` (never).
3. **One encrypted file per UTC day** of received time, all tenants, in `/var/backups/asix/scheduled/clickhouse/` on the VM:
   `events-<day>.<time>-<id>.ndjson.gz.enc` (gzip of one JSON event per line, then AES-256-GCM with the same passphrase as the PostgreSQL backups,
   `/root/asix-backup-key.txt`) and `manifest.json` (per day: file, rows, a content digest, size, checksum, tenants). The manifest is written last, atomically.
4. **Incremental.** A day is exported again only when its event count changed, or when it is one of the last two UTC days. The first run reads
   everything; later runs read about two days. A day that disappears from ClickHouse (retention) stays in the backup for `BACKUP_KEEP` more days
   (14), then its file is removed, like the PostgreSQL sets.
5. Events received in the last 5 seconds are left for the next run, so a day is never exported half-written.
6. **Test restore, about weekly** (`BACKUP_VERIFY_EVERY_DAYS`, 7): every day file is decrypted and loaded into a scratch table
   (`events_verify_<random>`), and each day's row count and content digest (every field of every event) are compared with what the manifest
   recorded at export time. The scratch table is dropped afterwards, also when the test fails. This proves the files are readable and complete.
7. The run is recorded in `backup_runs` with `kind = 'clickhouse'`, so the Data safety page shows it and a ClickHouse success can never hide a
   PostgreSQL failure (the PostgreSQL view only reads `kind = 'postgres'`).

If a run fails part way, the previous backup is exactly as it was (new files are removed, the manifest is untouched). Two runs cannot overlap
(a lock file; one older than 6 hours is treated as dead).

## Data safety page
New findings, serious (`critical`) when ClickHouse is where events go (`ASIX_EVENT_STORE=clickhouse`) and a warning otherwise:
no ClickHouse backup has ever run (critical only when active), the last one failed, the last good one is over 36 hours (warning) or 72 hours old,
the backup has not been test-restored, or the last restore test is over two weeks old. The report also carries a `clickhouse` section
(last success, last verified, recent runs). The portal lists these findings with the existing ones; there is no new portal screen.

## Restoring
```bash
sudo scripts/restore-backup.sh ch-list                                   # days, rows, sizes, when each was exported
sudo scripts/restore-backup.sh ch-verify                                 # the test restore on demand; changes nothing
sudo scripts/restore-backup.sh ch-restore --as events_copy [--from 2026-10-01] [--to 2026-10-05]   # into a NEW table to look at it
sudo scripts/restore-backup.sh ch-restore --yes [--from D] [--to D]      # ADD the backed-up events to the live events table
```
- Restoring **only adds**: events already in the table are skipped (same id and time), nothing is deleted and nothing is replaced, so it is
  safe to run on a table that has new events in it. A restore into a new table must end identical to the backup, and is checked day by day.
- After losing the ClickHouse volume: deploy ClickHouse again (`./sync-and-deploy.sh --with-clickhouse`), let the API create the table
  (it does on start), then `ch-restore --yes`. The passphrase is needed: keep a copy of `/root/asix-backup-key.txt` off the VM.
- Checksums and the encryption's authentication are checked before anything is loaded; a damaged file stops the restore with its name.

## Checked
- `tests/clickhouse-backup.test.js` (in-memory stores, 11 tests, in `npm test`): files and manifest, nothing readable in the files, incremental behaviour,
  the snapshot rule, a test restore that passes and one that fails on a damaged file / missing file / wrong passphrase / content that differs from the
  manifest, restores (new table identical, live table additive, day ranges), retention pruning, a failure part way leaving the old backup intact,
  the lock, two runs in the same second (they used to be able to share a file name; the test fails on the old naming), the digest, and the nightly
  entry point (skipped, recorded, verified when due, failure recorded). The two verification checks were also tested by breaking them on purpose.
- `tests/clickhouse-backup-db.test.js` (gated; real ClickHouse 24.8.14.39 and PostgreSQL 16, 5 tests, run by the CI job `clickhouse`): a real backup,
  test restore and exact restore of 1,400 events over several days and two tenants; a damaged file; incremental runs; the live table cannot be
  dropped; the entry point recording `kind = 'clickhouse'` and the Data safety report reading it, including critical / warning by store.
- The real nightly job (`node src/backup/backup.js`) on a real PostgreSQL and ClickHouse: both backups ran and verified, a second run re-exported
  only the last two days, and `restore.js ch-list`, `ch-verify`, `ch-restore --as` (601 events restored, 600 for the test tenant) and
  `ch-restore --yes` (adds nothing: all there) worked; the refusals (`--yes` missing, `--as events`) refused.
- `scripts/restore-backup.sh` argument handling with a stubbed `k3s`: every `ch-*` form builds the right Job and passes the ClickHouse settings;
  each refused form creates no Job; the existing commands are unchanged. Not run against a real cluster.

## Not checked
- On the k3s box: the CronJob with the new variables, the schema change (`ALTER TABLE backup_runs ADD COLUMN IF NOT EXISTS kind`, applied twice on a
  local PostgreSQL), a real `ch-restore` Job. Run `ch-verify` and one `ch-restore --as` there before relying on it.
- Size: tested on thousands of events. The first run reads the whole history through the API pod's 512Mi limit and the Job's 2-hour limit
  (`activeDeadlineSeconds: 7200`); a large history may need more of either, and the weekly test restore writes a full second copy into ClickHouse
  while it runs. Not measured.
- Copying the backups off the VM (they sit on the same disk as the data, like the PostgreSQL sets).

## Not built
- ClickHouse's own `BACKUP` command, point-in-time restore, and restoring one tenant.
- A portal screen for the ClickHouse backup (the findings appear in the existing Data safety list).
- Off-VM copies or S3.
