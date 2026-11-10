'use strict';
// The identity of this installation (docs/licensing.md): one random id made by the schema job the first time the database is created, and kept with it. A license is signed for one id,
// so a copy of the token on another installation, or on a reinstall with a fresh database, does not work; a restore from backup keeps the id. Also keeps the latest time the platform
// has seen, so a clock set back to stretch an expired license is noticed.
const DAY_MS = 24 * 60 * 60 * 1000;
const ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
let cachedId = null;

// db: { query(sql, params) }. Returns { id, clock_back } or { id: null } when the table or row is not there.
async function read(db, now = new Date()) {
  const r = await db.query('SELECT id::text AS id, last_seen_at FROM installation LIMIT 1');
  const row = r.rows[0]; if (!row || !ID_RE.test(row.id)) return { id: null, clock_back: false };
  const last = row.last_seen_at ? new Date(row.last_seen_at).getTime() : null;
  const clockBack = last !== null && last - now.getTime() > DAY_MS;
  if (!clockBack) await db.query('UPDATE installation SET last_seen_at = GREATEST(COALESCE(last_seen_at, $1::timestamp), $1::timestamp)', [now.toISOString()]);
  cachedId = row.id;
  return { id: row.id, clock_back: clockBack };
}
const lastKnownId = () => cachedId;
const reset = () => { cachedId = null; };
module.exports = { read, lastKnownId, reset, DAY_MS, ID_RE };
