'use strict';
// Data safety report (Settings > Storage & retention > Data safety): can the data survive
// a deleted pod, a deleted volume claim, an upgrade, a dead disk? Reads the real volume settings
// from the cluster and the backup history from backup_runs, and says what to do about gaps.

const db = require('../db');
const kube = require('../capacity/kube');

const BACKUP_DIR = '/var/backups/asix/scheduled';
const HOUR = 3600000;
const asUtc = (v) => (v ? new Date(String(v).endsWith('Z') ? v : v + 'Z').getTime() : null);
const ageH = (t, now) => (t == null ? null : Math.max(0, (now - t) / HOUR));

async function report(now = Date.now()) {
  const runs = (await db.query(
    `SELECT id, trigger, set_name, status, started_at, finished_at, bytes::bigint AS bytes, databases, verified, verified_at, error
     FROM backup_runs ORDER BY started_at DESC LIMIT 15`)).rows.map((r) => ({ ...r, bytes: r.bytes == null ? null : Number(r.bytes) }));
  const lastOk = runs.find((r) => r.status === 'completed') || null, lastVerified = runs.find((r) => r.status === 'completed' && r.verified) || null, latest = runs[0] || null;
  const k = await kube.snapshot().catch((e) => ({ available: false, error: e.message }));
  const volumes = k.available && k.pvs ? k.pvs : null;
  const w = [], add = (id, severity, title, detail, fix) => w.push({ id, severity, title, detail, fix: fix || null });

  if (!latest) add('no_backup', 'warning', 'No backup has run yet', 'The nightly job runs at 02:17 server time. Until it has, a lost disk means lost data.', 'Run one now: k3s kubectl -n asix-platform create job --from=cronjob/asix-backup backup-now-$(date +%s)');
  else {
    if (latest.status === 'failed') add('last_failed', 'critical', 'The most recent backup failed', latest.error || 'No error text was recorded.', 'See the job log: k3s kubectl -n asix-platform logs job/<name>. Common causes: the backup folder is not writable, or the passphrase secret is missing.');
    const a = lastOk ? ageH(asUtc(lastOk.finished_at), now) : null;
    if (lastOk && a > 72) add('stale', 'critical', `The last good backup is ${Math.round(a / 24)} days old`, 'Backups are expected every night.', 'Check the CronJob: k3s kubectl -n asix-platform get cronjob asix-backup');
    else if (lastOk && a > 36) add('stale', 'warning', `The last good backup is ${Math.round(a)} hours old`, 'Backups are expected every night.', 'Check the CronJob: k3s kubectl -n asix-platform get cronjob asix-backup');
    if (lastOk && !lastVerified) add('never_verified', 'warning', 'No backup has been test-restored yet', 'The job restores a backup into a scratch database about once a week to prove it works.', 'Run: sudo scripts/restore-backup.sh verify <set>');
    else if (lastVerified && ageH(asUtc(lastVerified.verified_at), now) > 14 * 24) add('verify_old', 'warning', 'The last restore test is over two weeks old', 'A backup that was never restored is only a hope.', 'Run: sudo scripts/restore-backup.sh verify <set>');
  }
  if (volumes === null) add('volumes_unknown', 'info', 'Volume settings could not be read from the cluster', (k && k.error) || 'The Kubernetes API did not return volumes.', 'Apply k8s/31-capacity-rbac.yaml (deploy.sh does this).');
  else {
    for (const v of volumes.filter((x) => x.phase !== 'Released' && x.reclaim_policy !== 'Retain')) add('volume_delete_' + v.name, 'warning', `Volume ${v.claim} would be deleted with its claim`, `Its reclaim policy is ${v.reclaim_policy}: deleting the claim or the namespace deletes the data folder (${v.path || 'on this VM'}).`, 'Run: sudo scripts/deploy/protect-volumes.sh');
    const released = volumes.filter((x) => x.phase === 'Released');
    if (released.length) add('released', 'info', `${released.length} retained volume(s) from a deleted claim still hold data`, released.map((x) => `${x.claim} (${x.path || x.name})`).join(', '), 'See: sudo scripts/recover-volume.sh list');
    if (!volumes.length) add('no_volumes', 'info', 'No data volumes found for this namespace', 'Nothing to protect yet.');
  }
  add('same_disk', 'info', 'Backups are stored on this VM', `They are in ${BACKUP_DIR} on the same disk as the database, so they protect against mistakes and bad upgrades but not against losing the VM. Copy them somewhere else regularly (rsync, a NAS, cloud storage).`, 'Keep a copy of the passphrase (/root/asix-backup-key.txt) outside the VM too: without it the backups cannot be read.');
  const order = { critical: 0, warning: 1, info: 2 }; w.sort((x, y) => order[x.severity] - order[y.severity]);
  return { schedule: 'daily at 02:17 (server time)', backup_dir: BACKUP_DIR, keep: 14, last_success: lastOk, last_verified: lastVerified, runs, volumes,
    verdict: w.some((x) => x.severity === 'critical') ? 'critical' : w.some((x) => x.severity === 'warning') ? 'attention' : 'ok', warnings: w };
}

module.exports = { report };
