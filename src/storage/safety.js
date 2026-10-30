'use strict';
// Data safety report (Settings > Storage & retention > Data safety): can the data survive
// a deleted pod, a deleted volume claim, an upgrade, a dead disk? Reads the real volume settings
// from the cluster and the backup history from backup_runs, and says what to do about gaps.

const db = require('../db');
const kube = require('../capacity/kube');
const control = require('../backup/control');
const schedule = require('../backup/schedule');

const BACKUP_DIR = '/var/backups/asix/scheduled';
const HOUR = 3600000;
const asUtc = (v) => (v ? new Date(String(v).endsWith('Z') ? v : v + 'Z').getTime() : null);
const ageH = (t, now) => (t == null ? null : Math.max(0, (now - t) / HOUR));
const DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const describeSchedule = (c) => (!c.enabled ? 'switched off' : (c.days.length === 7 ? 'daily' : c.days.map((d) => DAY_NAMES[d]).join(', ')) + ' at ' + c.time_utc + ' UTC');

async function report(now = Date.now()) {
  const runs = (await db.query(
    `SELECT id, trigger, set_name, status, started_at, finished_at, bytes::bigint AS bytes, databases, verified, verified_at, error
     FROM backup_runs WHERE kind = 'postgres' ORDER BY started_at DESC LIMIT 15`)).rows.map((r) => ({ ...r, bytes: r.bytes == null ? null : Number(r.bytes) }));
  const lastOk = runs.find((r) => r.status === 'completed') || null, lastVerified = runs.find((r) => r.status === 'completed' && r.verified) || null, latest = runs[0] || null;
  // The backup's own settings (Backup control card): schedule, retention, a waiting "Back up now". The age limits below follow the schedule: a backup that is meant to run weekly is not "old" after 36 hours.
  const ctl = await control.load(db).catch(() => control.shape(null));
  const running = await control.running(db, now).catch(() => null);
  const gap = (ctl.enabled && schedule.longestGapDays(ctl.days)) || 1, warnH = gap * 24 + 12, critH = gap * 48 + 24;
  const slot = ctl.enabled ? schedule.lastSlot(ctl, now) : null, lastSched = ctl.last_scheduled_at ? Date.parse(ctl.last_scheduled_at) : null;
  const k = await kube.snapshot().catch((e) => ({ available: false, error: e.message }));
  const volumes = k.available && k.pvs ? k.pvs : null;
  const w = [], add = (id, severity, title, detail, fix) => w.push({ id, severity, title, detail, fix: fix || null });

  if (!latest) add('no_backup', 'warning', 'No backup has run yet', 'Until one has, a lost disk means lost data.', 'Press "Back up now" in Backup control above (or, on the VM: k3s kubectl -n asix-platform create job --from=cronjob/asix-backup backup-now-$(date +%s)).');
  else {
    if (latest.status === 'failed') add('last_failed', 'critical', 'The most recent backup failed', latest.error || 'No error text was recorded.', 'See the job log: k3s kubectl -n asix-platform logs job/<name>. Common causes: the backup folder is not writable, or the passphrase secret is missing.');
    const a = lastOk ? ageH(asUtc(lastOk.finished_at), now) : null;
    const staleFix = 'Press "Back up now" in Backup control above, then check the runner: k3s kubectl -n asix-platform logs deploy/asix-backup-runner --tail=50';
    if (lastOk && a > critH) add('stale', 'critical', `The last good backup is ${Math.round(a / 24)} days old`, 'Backups are expected ' + describeSchedule(ctl) + '.', staleFix);
    else if (lastOk && a > warnH) add('stale', 'warning', `The last good backup is ${Math.round(a)} hours old`, 'Backups are expected ' + describeSchedule(ctl) + '.', staleFix);
    if (lastOk && !lastVerified) add('never_verified', 'warning', 'No backup has been test-restored yet', 'The job restores a backup into a scratch database about once a week to prove it works.', 'Run: sudo scripts/restore-backup.sh verify <set>');
    else if (lastVerified && ageH(asUtc(lastVerified.verified_at), now) > 14 * 24) add('verify_old', 'warning', 'The last restore test is over two weeks old', 'A backup that was never restored is only a hope.', 'Run: sudo scripts/restore-backup.sh verify <set>');
  }
  // Events held in ClickHouse (src/backup/clickhouse-backup.js). Serious only when ClickHouse is where the events go (ASIX_EVENT_STORE=clickhouse).
  const chRuns = (await db.query(
    `SELECT id, trigger, set_name, status, started_at, finished_at, bytes::bigint AS bytes, verified, verified_at, error
     FROM backup_runs WHERE kind = 'clickhouse' ORDER BY started_at DESC LIMIT 15`)).rows.map((r) => ({ ...r, bytes: r.bytes == null ? null : Number(r.bytes) }));
  const chActive = String(process.env.ASIX_EVENT_STORE || '').toLowerCase() === 'clickhouse';
  const chOk = chRuns.find((r) => r.status === 'completed') || null, chVerified = chRuns.find((r) => r.status === 'completed' && r.verified) || null, chLatest = chRuns[0] || null;
  const chSev = chActive ? 'critical' : 'warning';
  if (chActive && !chLatest) add('ch_no_backup', 'critical', 'Events are in ClickHouse and it has never been backed up', 'The backup job backs up ClickHouse too, but no ClickHouse backup has run. A lost volume would lose every event written since the switch.', 'Check that the secret clickhouse-secret exists, then press "Back up now" in Backup control above.');
  if (chLatest) {
    if (chLatest.status === 'failed') add('ch_last_failed', chSev, 'The most recent ClickHouse backup failed', chLatest.error || 'No error text was recorded.', 'See the job log: k3s kubectl -n asix-platform logs job/<n>. Common causes: ClickHouse is not reachable, or the backup passphrase secret is missing.');
    const a = chOk ? ageH(asUtc(chOk.finished_at), now) : null;
    if (chOk && a > critH) add('ch_stale', chSev, `The last good ClickHouse backup is ${Math.round(a / 24)} days old`, 'It is expected ' + describeSchedule(ctl) + '.', 'Press "Back up now" in Backup control above, then check the runner: k3s kubectl -n asix-platform logs deploy/asix-backup-runner --tail=50');
    else if (chOk && a > warnH) add('ch_stale', 'warning', `The last good ClickHouse backup is ${Math.round(a)} hours old`, 'It is expected ' + describeSchedule(ctl) + '.', 'Press "Back up now" in Backup control above, then check the runner: k3s kubectl -n asix-platform logs deploy/asix-backup-runner --tail=50');
    if (chOk && !chVerified) add('ch_never_verified', 'warning', 'The ClickHouse backup has not been test-restored yet', 'The job loads the whole backup into a scratch table about once a week and compares it with what was exported.', 'Run: sudo scripts/restore-backup.sh ch-verify');
    else if (chVerified && ageH(asUtc(chVerified.verified_at), now) > 14 * 24) add('ch_verify_old', 'warning', 'The last ClickHouse restore test is over two weeks old', 'A backup that was never restored is only a hope.', 'Run: sudo scripts/restore-backup.sh ch-verify');
  }
  if (!ctl.enabled) add('schedule_off', 'warning', 'Scheduled backups are switched off', 'Nothing starts a backup by itself; only "Back up now" does.', 'Switch the schedule on in Backup control above.');
  if (ctl.run_requested_at && now - Date.parse(ctl.run_requested_at) > 2 * 60000 && !running) add('runner_stalled', 'critical', 'A backup was requested but nothing has started it', `Requested ${Math.round((now - Date.parse(ctl.run_requested_at)) / 60000)} minutes ago. The backup runner picks requests up within seconds, so it is probably not running.`, 'On the VM: k3s kubectl -n asix-platform get deploy asix-backup-runner, and its log: k3s kubectl -n asix-platform logs deploy/asix-backup-runner --tail=50 (apply k8s/32-backup.yaml if the deployment is missing).');
  else if (ctl.configured && slot !== null && now - slot > 10 * 60000 && (lastSched === null || lastSched < slot) && !running && !ctl.run_requested_at) add('runner_stalled', 'critical', 'A scheduled backup is overdue and nothing has started it', 'The backup runner starts scheduled backups within seconds of their time, so it is probably not running.', 'On the VM: k3s kubectl -n asix-platform get deploy asix-backup-runner, and its log: k3s kubectl -n asix-platform logs deploy/asix-backup-runner --tail=50 (apply k8s/32-backup.yaml if the deployment is missing).');
  if (volumes === null) add('volumes_unknown', 'info', 'Volume settings could not be read from the cluster', (k && k.error) || 'The Kubernetes API did not return volumes.', 'Apply k8s/31-capacity-rbac.yaml (deploy.sh does this).');
  else {
    for (const v of volumes.filter((x) => x.phase !== 'Released' && x.reclaim_policy !== 'Retain')) add('volume_delete_' + v.name, 'warning', `Volume ${v.claim} would be deleted with its claim`, `Its reclaim policy is ${v.reclaim_policy}: deleting the claim or the namespace deletes the data folder (${v.path || 'on this VM'}).`, 'Run: sudo scripts/deploy/protect-volumes.sh');
    const released = volumes.filter((x) => x.phase === 'Released');
    if (released.length) add('released', 'info', `${released.length} retained volume(s) from a deleted claim still hold data`, released.map((x) => `${x.claim} (${x.path || x.name})`).join(', '), 'See: sudo scripts/recover-volume.sh list');
    if (!volumes.length) add('no_volumes', 'info', 'No data volumes found for this namespace', 'Nothing to protect yet.');
  }
  // Copies sent to another machine by scripts/offsite-backup.sh (rows of kind 'offsite'). Until a recent one exists the backups only live on this VM.
  const offRuns = (await db.query(
    `SELECT id, trigger, status, started_at, finished_at, bytes::bigint AS bytes, databases, verified, verified_at, error
     FROM backup_runs WHERE kind = 'offsite' ORDER BY started_at DESC LIMIT 15`)).rows.map((r) => ({ ...r, bytes: r.bytes == null ? null : Number(r.bytes) }));
  const offOk = offRuns.find((r) => r.status === 'completed') || null, offLatest = offRuns[0] || null;
  const offAge = offOk ? ageH(asUtc(offOk.finished_at), now) : null;
  const offFresh = !!offOk && offAge <= 36;
  if (offLatest && offLatest.status === 'failed') add('offsite_failed', 'warning', 'The most recent off-VM copy of the backups failed', offLatest.error || 'No error text was recorded.', 'Test the connection: sudo bash scripts/offsite-backup.sh --check (it uses the saved settings), then copy again: sudo bash scripts/offsite-backup.sh');
  if (offOk && offAge > 72) add('offsite_stale', 'critical', `The last good off-VM copy is ${Math.round(offAge / 24)} days old`, 'The copy runs every night after the backup (03:30).', 'Check the timer: systemctl status asix-offsite-backup.timer, and the last run: journalctl -u asix-offsite-backup -n 30');
  else if (offOk && offAge > 36) add('offsite_stale', 'warning', `The last good off-VM copy is ${Math.round(offAge)} hours old`, 'The copy runs every night after the backup (03:30).', 'Check the timer: systemctl status asix-offsite-backup.timer, and the last run: journalctl -u asix-offsite-backup -n 30');
  if (!offFresh) add('same_disk', 'info', 'Backups are stored on this VM', `They are in ${BACKUP_DIR} on the same disk as the database, so they protect against mistakes and bad upgrades but not against losing the VM. Copy them to another machine every night.`, 'Set it up once: sudo bash scripts/offsite-backup.sh --install-timer --target user@host:/path (see docs/offsite-backup.md). Keep a copy of the passphrase (/root/asix-backup-key.txt) outside the VM too: without it the backups cannot be read.');
  const order = { critical: 0, warning: 1, info: 2 }; w.sort((x, y) => order[x.severity] - order[y.severity]);
  const nextAt = ctl.enabled ? schedule.nextSlot(ctl, now) : null;
  return { schedule: describeSchedule(ctl), backup_dir: BACKUP_DIR, retain_days: ctl.retain_days,
    control: { enabled: ctl.enabled, time_utc: ctl.time_utc, days: ctl.days, retain_days: ctl.retain_days, next_run: nextAt === null ? null : new Date(nextAt).toISOString(),
      run_requested_at: ctl.run_requested_at, run_requested_by: ctl.run_requested_by, running: running ? { trigger: running.trigger, started_at: running.started_at } : null, updated_at: ctl.updated_at, updated_by: ctl.updated_by },
    last_success: lastOk, last_verified: lastVerified, runs, volumes,
    clickhouse: { active: chActive, last_success: chOk, last_verified: chVerified, runs: chRuns },
    offsite: { configured: offRuns.length > 0, fresh: offFresh, last_success: offOk, runs: offRuns },
    verdict: w.some((x) => x.severity === 'critical') ? 'critical' : w.some((x) => x.severity === 'warning') ? 'attention' : 'ok', warnings: w };
}

module.exports = { report, describeSchedule };
