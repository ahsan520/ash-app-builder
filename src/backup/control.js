'use strict';
// The backup's settings and the "back up now" request, kept in the one-row table backup_settings (k8s/12-schema-init.yaml).
// The portal route (src/gateway/routes/storage.js) and the Data safety report read and write it here; the runner (src/backup/runner.js)
// reads it every few seconds, claims a request and starts the job. Nothing here talks to Kubernetes.
const schedule = require('./schedule');

const COLUMNS = 'enabled, time_utc, days, retain_days, last_scheduled_at, run_requested_at, run_requested_by, updated_at, updated_by';
const toMs = (v) => (v ? new Date(v).getTime() : null);
const shape = (r) => (r && r.time_utc ? {
  configured: true, enabled: r.enabled, time_utc: r.time_utc, days: Array.isArray(r.days) ? r.days : JSON.parse(r.days || '[]'), retain_days: r.retain_days,
  last_scheduled_at: r.last_scheduled_at ? new Date(r.last_scheduled_at).toISOString() : null,
  run_requested_at: r.run_requested_at ? new Date(r.run_requested_at).toISOString() : null, run_requested_by: r.run_requested_by || null,
  updated_at: r.updated_at ? new Date(r.updated_at).toISOString() : null, updated_by: r.updated_by || null,
} : { ...schedule.DEFAULTS, configured: false, last_scheduled_at: null, run_requested_at: null, run_requested_by: null, updated_at: null, updated_by: null });

// The settings; the defaults when the table is empty or does not exist yet (an install that has not run the new schema).
async function load(db) {
  try { return shape((await db.query(`SELECT ${COLUMNS} FROM backup_settings WHERE id = 1`)).rows[0]); }
  catch (e) { if (/backup_settings/.test(String(e.message))) return shape(null); throw e; }
}

// Applies a checked change (see schedule.check). Saving moves last_scheduled_at to now: a time earlier today must not run at once, only the next one.
async function save(db, fields, who, now = Date.now()) {
  const f = fields || {};
  const r = await db.query(
    `INSERT INTO backup_settings (id, enabled, time_utc, days, retain_days, last_scheduled_at, updated_at, updated_by)
     VALUES (1, COALESCE($1::boolean, $8::boolean), COALESCE($2::text, $9::text), COALESCE($3::jsonb, $10::jsonb), COALESCE($4::int, $11::int), $5::timestamptz, now(), $6::text)
     ON CONFLICT (id) DO UPDATE SET enabled = COALESCE($1::boolean, backup_settings.enabled), time_utc = COALESCE($2::text, backup_settings.time_utc),
       days = COALESCE($3::jsonb, backup_settings.days), retain_days = COALESCE($4::int, backup_settings.retain_days),
       last_scheduled_at = CASE WHEN $7::boolean THEN $5::timestamptz ELSE backup_settings.last_scheduled_at END, updated_at = now(), updated_by = $6::text
     RETURNING ${COLUMNS}`,
    [f.enabled ?? null, f.time_utc ?? null, f.days ? JSON.stringify(f.days) : null, f.retain_days ?? null, new Date(now).toISOString(), who || null,
      f.enabled !== undefined || f.time_utc !== undefined || f.days !== undefined,
      schedule.DEFAULTS.enabled, schedule.DEFAULTS.time_utc, JSON.stringify(schedule.DEFAULTS.days), schedule.DEFAULTS.retain_days]);
  return shape(r.rows[0]);
}

// Is a backup running right now? A 'running' row older than the job's own 2-hour limit is a dead run, not a live one.
async function running(db, now = Date.now()) {
  const rows = (await db.query("SELECT kind, trigger, status, started_at FROM backup_runs WHERE status = 'running' AND kind IN ('postgres','clickhouse') ORDER BY started_at DESC LIMIT 5")).rows;
  const live = rows.filter((r) => r.status === 'running' && now - asUtc(r.started_at) < 2 * 3600000 + 600000);
  return live.length ? { trigger: live[0].trigger, started_at: live[0].started_at } : null;
}
const asUtc = (v) => (v instanceof Date ? v.getTime() : new Date(String(v).endsWith('Z') ? v : v + 'Z').getTime());

// "Back up now". One request waits at a time; asking again while one waits or one runs is refused (the portal shows why).
async function request(db, who, now = Date.now()) {
  const live = await running(db, now); if (live) return { busy: 'running', since: live.started_at };
  const r = await db.query(
    `INSERT INTO backup_settings (id, run_requested_at, run_requested_by) VALUES (1, now(), $1::text)
     ON CONFLICT (id) DO UPDATE SET run_requested_at = now(), run_requested_by = $1::text WHERE backup_settings.run_requested_at IS NULL
     RETURNING run_requested_at`, [who || null]);
  if (!r.rows.length) return { busy: 'requested' };
  return { requested_at: new Date(r.rows[0].run_requested_at).toISOString() };
}

// Runner side: take the waiting request (if any). Returns who asked, or null. Atomic: only one caller gets it.
async function claimRequest(db) {
  const r = await db.query("UPDATE backup_settings SET run_requested_at = NULL WHERE id = 1 AND run_requested_at IS NOT NULL RETURNING run_requested_by");
  return r.rows.length ? { by: r.rows[0].run_requested_by || null } : null;
}
// Runner side: note that the scheduled slot `slotMs` has been handed to a job.
async function markScheduled(db, slotMs) {
  await db.query('INSERT INTO backup_settings (id, last_scheduled_at) VALUES (1, $1::timestamptz) ON CONFLICT (id) DO UPDATE SET last_scheduled_at = $1::timestamptz', [new Date(slotMs).toISOString()]);   // an upsert: with no row yet, an update would change nothing and the same slot would be owed again on the next look
}
// The retention in days that the job should use; null when the table is missing (the job then keeps its older count-based rule).
async function retainDays(db) {
  try { const r = (await db.query('SELECT retain_days FROM backup_settings WHERE id = 1')).rows[0]; return r ? r.retain_days : schedule.DEFAULTS.retain_days; }
  catch { return null; }
}

module.exports = { load, save, running, request, claimRequest, markScheduled, retainDays, shape };
