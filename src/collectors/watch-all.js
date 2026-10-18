'use strict';
// "Watch everything": a tenant-wide switch for the two collector alerts, so a new collector or broker is covered the moment it
// appears, without pressing "Alert if down" on every row.
//
//   disconnect  true  -> every collector gets the "Collector disconnected" alert (src/collectors/watchdog.js), and every broker the
//                        "Broker installer key unusable" alert (src/collectors/key-watch.js), as if "Alert if down" were on.
//   silent_min  5..4320 -> every collector that has no limit of its own gets the "Collector sending no events" alert
//                        (src/collectors/silence.js) after that many minutes. A collector's own "Alert if silent" limit always wins.
//
// It only ADDS to the per-collector settings: a collector that was switched on by hand stays on when this is off, and this switch
// can be told to leave one collector out (collectors.watch_exclude, "Leave out of all" on the Collectors page; it does not turn off
// what was switched on by hand for that collector). Settings live in collector_watch_defaults (one row per tenant); no row means everything is off, so
// deploying this changes nothing by itself.
//
// Retired collectors are left out: a collector not seen for more than ASIX_WATCH_ALL_MAX_AGE_DAYS (default 7) is treated as gone, or
// turning the switch on would raise one alert for every machine that was ever decommissioned. A collector you switched on by hand is
// never left out. An alert already open for a collector that ages out is closed by the watchdog ("no longer watched").
//
// The rules exist twice on purpose: whereSql() is what the watchdogs send to PostgreSQL (so the filtering happens in the database),
// watchesDisconnect()/silentMinutes() are the same rules in plain code for the Collectors page and for tests. The database test
// (tests/collector-watch-all-db.test.js) runs both against the same rows.

const db = require('../db');
const { tsMs } = require('./status');

const DEFAULT_MAX_AGE_DAYS = 7;
const OFF = Object.freeze({ disconnect: false, silent_min: null });

function maxAgeDays(env = process.env) {
  const n = Number(env.ASIX_WATCH_ALL_MAX_AGE_DAYS);
  return Number.isInteger(n) && n >= 1 && n <= 90 ? n : DEFAULT_MAX_AGE_DAYS;
}

// Stored row -> settings. No row, or anything unusable, means off.
function fromRow(row) {
  if (!row) return { ...OFF };
  return { disconnect: row.watch_disconnect === true, silent_min: Number.isInteger(row.watch_silent_min) ? row.watch_silent_min : null };
}

// A timestamp for a `timestamp` (no zone) column, in the UTC convention the rest of the app uses (see tsMs).
const cutoffOf = (now, days = maxAgeDays()) => new Date(now - days * 86400000).toISOString().slice(0, 23);

// Not seen for longer than the age limit (or never): left out of the switch.
const retired = (lastSeen, now, days = maxAgeDays()) => {
  const ms = tsMs(lastSeen);
  return !Number.isFinite(ms) || ms < now - days * 86400000;
};

// The rules in plain code. c: { watch_disconnect, watch_silent_min, last_seen }; s: settings (fromRow shape).
const watchesDisconnect = (c, s, now = Date.now(), days = maxAgeDays()) =>
  c.watch_disconnect === true || (s.disconnect === true && c.watch_exclude !== true && !retired(c.last_seen, now, days));
const silentMinutes = (c, s, now = Date.now(), days = maxAgeDays()) => {
  if (Number.isInteger(c.watch_silent_min)) return c.watch_silent_min;
  return Number.isInteger(s.silent_min) && c.watch_exclude !== true && !retired(c.last_seen, now, days) ? s.silent_min : null;
};
// True when the switch, not the collector's own setting, is what covers it (the Collectors page says so).
const disconnectByDefault = (c, s, now, days) => c.watch_disconnect !== true && watchesDisconnect(c, s, now, days);
const silentByDefault = (c, s, now, days) => !Number.isInteger(c.watch_silent_min) && silentMinutes(c, s, now, days) !== null;

// The same rules as SQL. Parameters (after the tenant id): disconnect flag, silent minutes (or NULL), cutoff timestamp.
const WHERE_DISCONNECT = '(watch_disconnect OR ($2::boolean AND NOT watch_exclude AND last_seen >= $3::timestamp))';
const SILENT_MIN_SQL = 'COALESCE(watch_silent_min, CASE WHEN NOT watch_exclude AND last_seen >= $3::timestamp THEN $2::integer END)';

async function read(client, tenantId) {
  const r = await client.query('SELECT watch_disconnect, watch_silent_min FROM collector_watch_defaults WHERE tenant_id = $1', [tenantId]);
  return fromRow(r.rows[0]);
}

// patch: { disconnect?: boolean, silent_min?: integer|null }; what it leaves out is kept as it is.
async function write(client, tenantId, patch, userId = null) {
  const cur = await read(client, tenantId);
  const next = {
    disconnect: Object.prototype.hasOwnProperty.call(patch, 'disconnect') ? patch.disconnect === true : cur.disconnect,
    silent_min: Object.prototype.hasOwnProperty.call(patch, 'silent_min') ? patch.silent_min : cur.silent_min,
  };
  await client.query(
    `INSERT INTO collector_watch_defaults (tenant_id, watch_disconnect, watch_silent_min, updated_by)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (tenant_id) DO UPDATE SET watch_disconnect = EXCLUDED.watch_disconnect, watch_silent_min = EXCLUDED.watch_silent_min,
       updated_at = localtimestamp, updated_by = EXCLUDED.updated_by`,
    [tenantId, next.disconnect, next.silent_min, userId ? String(userId) : null]);
  return next;
}

// How many collectors the switch leaves out because they were not seen for a long time (shown next to the switch).
async function retiredCount(client, tenantId, now = Date.now(), days = maxAgeDays()) {
  const r = await client.query(
    `SELECT count(*)::int AS total, (count(*) FILTER (WHERE last_seen IS NULL OR last_seen < $2::timestamp))::int AS retired
       FROM collectors WHERE tenant_id = $1`, [tenantId, cutoffOf(now, days)]);
  return { total: r.rows[0].total, retired: r.rows[0].retired };
}

module.exports = {
  DEFAULT_MAX_AGE_DAYS, OFF, maxAgeDays, fromRow, cutoffOf, retired,
  watchesDisconnect, silentMinutes, disconnectByDefault, silentByDefault,
  WHERE_DISCONNECT, SILENT_MIN_SQL, read, write, retiredCount,
};
