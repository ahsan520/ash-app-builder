# Backup control: "Back up now", the schedule, and how long backups are kept

Built 2026-10-30. Lives on **Settings, Storage & retention, Data safety**, in the card **Backup control**.

## What you can do there
- **Back up now**: starts a backup within a few seconds (PostgreSQL + Keycloak + roles, then ClickHouse when it is deployed). The button is greyed while one is waiting or running.
- **Run on a schedule**: on/off, a time of day in **UTC**, and the weekdays it runs on. Default: every day at 02:17 UTC (the old nightly time). The card also shows the next run in UTC and in your computer's time.
- **Keep backups for N days** (1 to 365, default **2**).

## What retention does
Before every backup, scheduled or manual, the job deletes every backup **set** (the encrypted dumps, the roles file and the manifest) made more than N days earlier from `/var/backups/asix/scheduled`, and then runs.
- **The newest complete set is never deleted**, however old. If backups have been failing for days, the last good one stays until a new good one exists. This is why, with the last backup 5 days old, the first run keeps it, and the run after the new backup succeeded removes it.
- After a good run the same rule runs once more, so the old survivor goes straight away.
- Left-overs of a run that died (files with no manifest) go once they are older than N days. A set that is being written right now is younger than that and is never touched.
- "Older than 2 days" means more than 48 hours. With a daily schedule you normally end up with yesterday's set and today's (two sets), because the one from two nights ago is just past 48 hours when today's run starts.
- It only touches `asix-<date>T<time>Z.*` files directly in that folder. **The ClickHouse event files (`clickhouse/` sub-folder) are not cut by age**: they are one file per day of *events* (a copy of your data), not daily snapshots, so deleting the old ones would delete the copy of old events. Days that have left ClickHouse are still dropped from that backup after `BACKUP_KEEP` days (14, `k8s/32-backup.yaml`), as before.
- The off-VM copy (`docs/offsite-backup.md`) is unaffected: it never deletes unless you turned on `--keep-days`, so it keeps what this VM has dropped.
- `BACKUP_RETAIN_DAYS` in the environment of the job overrides the portal value (not set by default).

## How it works (no new permission on the cluster)
- The settings and the "Back up now" request are one row in the table `backup_settings` (created by the schema job, `k8s/12-schema-init.yaml`).
- **`asix-backup-runner`** (new Deployment in `k8s/32-backup.yaml`, one replica, same image and same secrets and folder as the old job) looks at that row every 15 seconds. When a request is waiting, or a scheduled time is owed, it starts `node src/backup/backup.js` as a child process (the same job as before, which records its own rows in `backup_runs`). One job at a time.
- A scheduled time missed while the VM was off runs **once** when the runner is back (it does not run once per missed day). Saving new schedule settings starts counting from that moment: a time earlier today does not fire.
- On the first look after this deploy no scheduled run has ever been recorded, so the runner starts one straight away. That is the catch-up for the stale backup.
- The CronJob `asix-backup` is now **suspended**. It stays only as the template for `k3s kubectl -n asix-platform create job --from=cronjob/asix-backup backup-now-$(date +%s)` (which `scripts/restore-backup.sh` and the docs use). Changing the schedule in the portal does not touch it.
- If the runner restarts while a job is running, that job dies with the pod; the runner closes its `backup_runs` row as failed ("interrupted") when it starts again.
- Files: `src/backup/schedule.js` (rules), `src/backup/control.js` (database side), `src/backup/runner.js`, `src/backup/backup.js` (`pruneSets`), `src/gateway/routes/storage.js` (`PUT /v1/storage/backup/settings`, `POST /v1/storage/backup/run`, permission `storage:write`; both are in the audit log), `src/storage/safety.js` (the report's `control` section and findings), `src/portal/index.html` (the card).

## New findings on the Data safety page
- **Scheduled backups are switched off** (warning).
- **A backup was requested but nothing has started it** (critical): a request waited over 2 minutes, so the runner is probably down.
- **A scheduled backup is overdue and nothing has started it** (critical): the time passed more than 10 minutes ago and no run began.
- The "last good backup is old" findings now follow the schedule: 36 hours / 72 hours on a daily schedule, longer on a schedule with gaps (limit = longest gap + 12 hours, critical at twice the gap + 24 hours). The "no backup yet" and "failed" fixes now say "press Back up now".

## If something looks wrong
```bash
k3s kubectl -n asix-platform get deploy asix-backup-runner
k3s kubectl -n asix-platform logs deploy/asix-backup-runner --tail=50
k3s kubectl -n asix-platform apply -f k8s/32-backup.yaml     # if the deployment is missing (deploy.sh does this)
```
Backups in the folder: `sudo scripts/restore-backup.sh list`.

## Checked
- `tests/backup-schedule.test.js` (rules: what a settings change may contain, last/next slot across weekdays, month and year ends, owed / not owed, a missed slot runs once, longest gap), `tests/backup-runner.test.js` (what starts a job and with which trigger: manual, scheduled, both at once, off, one at a time, a failing job, a job that cannot start, the database down), `tests/backup-prune.test.js` (a real temporary folder: whole sets removed, exactly 48 hours stays, the newest complete set kept, dead left-overs, young incomplete sets kept, other files and the ClickHouse folder untouched), `tests/portal-backup-control.test.js` (the card cut out of the page: values shown, Back up now, disabled states, a refused request, Save sends the form, bad forms refused before the server is called). All in `npm test`.
- `tests/backup-control-db.test.js` (gated, real PostgreSQL 16 with the schema applied twice, real `pg_dump`; added to the CI `postgres` job): the settings row and its constraints, a request taken once even by two claimers, a running or dead run, the upsert of the schedule marker with no row, both routes through real HTTP (valid, refused, 202, 409), the Data safety report (schedule text, next run, the three new findings, thresholds following the schedule), and the real job: old sets removed before the run, the 5-day-old-only case (kept through a failing run, removed after the next good one), `BACKUP_RETAIN_DAYS` winning.
- The real runner against a real PostgreSQL 16 and real child process: idle, a request, one manual backup completed and verified (recorded as `manual`), idle again.
- `scripts/ci/validate-k8s.py`: 0 failures (both objects in `k8s/32-backup.yaml` and the schema job).
- **Not run on the k3s box**, the card has not been seen in a browser, and the runner pod has not run in a cluster. The first deploy starts one catch-up backup.

## Not built
- A time zone other than UTC for the schedule; several schedules; per-database retention; retention by count instead of days in the portal (`BACKUP_KEEP` is still an upper bound of 14 sets).
- Pruning ClickHouse day files by age (see above, on purpose).
- Restoring from the portal (restores stay on the command line so a click cannot overwrite live data).
