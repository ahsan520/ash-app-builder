'use strict';
// The backup runner: a small always-on process (k8s/32-backup.yaml, Deployment asix-backup-runner) that starts the backup job.
//
//   node src/backup/runner.js
//
// Every few seconds it reads the backup settings (src/backup/control.js) and starts `node src/backup/backup.js` (the same job the nightly CronJob used to start) when
//   * someone pressed "Back up now" in the portal (trigger 'manual'), or
//   * the schedule says a run is owed (trigger 'scheduled'): the latest scheduled time has not been run yet. A time missed while the VM was off runs once, as soon as
//     the runner is back.
// One job at a time. The runner needs no Kubernetes permissions: the portal only writes a row, this process reads it. The job itself is unchanged
// (PostgreSQL first, then ClickHouse; it records its own rows in backup_runs, and prunes old sets first, see backup.js).
const { spawn } = require('child_process');
const control = require('./control');
const schedule = require('./schedule');

const toMs = (v) => (v ? new Date(v).getTime() : null);

function createRunner({ db, spawnJob, now = () => Date.now(), log = console.log }) {
  let busy = false;
  // One look at the settings; starts a job when one is wanted and waits for it. Returns what it did.
  async function tick() {
    if (busy) return { did: 'busy' };
    let trigger = null, slot = null;
    try {
      const s = await control.load(db), at = now();
      slot = s.enabled ? schedule.lastSlot(s, at) : null;
      const scheduledDue = schedule.due(s, toMs(s.last_scheduled_at), at);
      const req = await control.claimRequest(db);
      if (req) { trigger = 'manual'; if (scheduledDue) await control.markScheduled(db, slot); }          // a manual run also covers a slot that was owed
      else if (scheduledDue) { trigger = 'scheduled'; await control.markScheduled(db, slot); }
    } catch (e) { log('[runner] could not read the backup settings:', e.message); return { did: 'error', error: e.message }; }
    if (!trigger) return { did: 'idle' };
    busy = true;
    try { log(`[runner] starting a ${trigger} backup`); const code = await spawnJob(trigger); log(`[runner] ${trigger} backup finished (exit ${code})`); return { did: trigger, code }; }
    catch (e) { log(`[runner] ${trigger} backup could not start:`, e.message); return { did: trigger, error: e.message }; }
    finally { busy = false; }
  }
  return { tick, isBusy: () => busy };
}

// Runs the job as a child process, so a crash or an out-of-memory kill of the job cannot take the runner down. Resolves with its exit code.
function spawnBackup(trigger, { env = process.env, cwd } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['src/backup/backup.js'], { env: { ...env, BACKUP_TRIGGER: trigger }, cwd, stdio: 'inherit' });
    spawnBackup.child = child;
    child.on('error', reject);
    child.on('exit', (code, sig) => { spawnBackup.child = null; resolve(code === null ? 'signal ' + sig : code); });
  });
}

// A 'running' row left by a job that was killed with the pod can never finish: close it, so the portal does not say "running" for two hours.
async function closeDeadRuns(db) {
  await db.query("UPDATE backup_runs SET status = 'failed', finished_at = localtimestamp, error = 'interrupted: the backup runner restarted while this was running' WHERE status = 'running' AND kind IN ('postgres','clickhouse')");
}

module.exports = { createRunner, spawnBackup, closeDeadRuns };

if (require.main === module) {
  const db = require('../db');
  const every = Math.max(5, Number(process.env.RUNNER_INTERVAL_SECONDS || 15)) * 1000;
  const runner = createRunner({ db, spawnJob: (t) => spawnBackup(t) });
  let stopping = false;
  const stop = () => { stopping = true; if (spawnBackup.child) spawnBackup.child.kill('SIGTERM'); setTimeout(() => process.exit(0), 20000).unref(); };
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
  (async () => {
    console.log(`[runner] up; looking for work every ${every / 1000}s`);
    await closeDeadRuns(db).catch((e) => console.error('[runner] could not close old running rows:', e.message));
    while (!stopping) { await runner.tick(); await new Promise((r) => setTimeout(r, every)); }
    process.exit(0);
  })();
}
