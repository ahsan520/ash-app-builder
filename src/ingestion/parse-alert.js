'use strict';
// Unparsed-events alert limit, chosen from the portal (Settings, Parser pool) instead of only from the API's environment.
// Pure rules plus three small database helpers; the alert itself is src/ingestion/parse-watch.js.
//
// Where the limit comes from, per tenant:
//   a row in parse_alert_settings  -> that row wins (min_events 0 = the alert is OFF for this tenant, even if the server setting is on)
//   no row                         -> the server settings ASIX_PARSE_ALERT_MIN_EVENTS / ASIX_PARSE_ALERT_WINDOW_MIN, as before
// "Follow the server setting" in the portal deletes the row. Nothing about the alert's own rules changes (one alert at a time, the
// 60 minute cooldown after a hand close, the ASIX closing note); the watchdog just reads the effective limit each cycle (every 60 s).

const LIMITS = { MAX_EVENTS: 1000000, MIN_WINDOW: 5, MAX_WINDOW: 1440, DEFAULT_WINDOW: 15 };

// A whole number, as a number or a string of digits. Returns { value } or { error }.
function whole(v, label, lo, hi) {
  const s = typeof v === 'number' ? (Number.isInteger(v) ? String(v) : '') : (typeof v === 'string' ? v.trim() : '');
  if (!/^(0|[1-9][0-9]{0,9})$/.test(s)) return { error: `${label} must be a whole number from ${lo} to ${hi}` };
  const n = Number(s);
  if (n < lo || n > hi) return { error: `${label} must be a whole number from ${lo} to ${hi}` };
  return { value: n };
}

const checkMinEvents = (v) => whole(v, 'Limit (events)', 0, LIMITS.MAX_EVENTS);
const checkWindow = (v) => whole(v, 'Window (minutes)', LIMITS.MIN_WINDOW, LIMITS.MAX_WINDOW);

// Request body of PUT /v1/parser/alert. Two shapes:
//   { follow_server: true }                       go back to the server settings (deletes the tenant's row)
//   { min_events: N, window_min?: M }             N = 0 turns the alert off for this tenant; window_min left out keeps the current window
// Returns { follow: true } | { min_events, window_min | null } | { error }.
function parseBody(body) {
  const b = body && typeof body === 'object' && !Array.isArray(body) ? body : null;
  if (!b) return { error: 'Send { "min_events": N } or { "follow_server": true }' };
  const has = (k) => Object.prototype.hasOwnProperty.call(b, k);
  if (has('follow_server')) {
    if (b.follow_server !== true) return { error: 'follow_server can only be true' };
    if (has('min_events') || has('window_min')) return { error: 'Send follow_server on its own, not together with a limit' };
    return { follow: true };
  }
  if (!has('min_events')) return { error: 'Send { "min_events": N } or { "follow_server": true }' };
  const m = checkMinEvents(b.min_events); if (m.error) return { error: m.error };
  let window = null;
  if (has('window_min') && b.window_min !== null && b.window_min !== undefined && b.window_min !== '') {
    const w = checkWindow(b.window_min); if (w.error) return { error: w.error }; window = w.value;
  }
  return { min_events: m.value, window_min: window };
}

// row: { min_events, window_min } or null; server: { threshold, windowMin } as parse-watch.config() reads the environment.
// Returns the limit the alert uses: { threshold, windowMin, source: 'tenant' | 'server' }.
function resolve(row, server) {
  if (row && Number.isInteger(row.min_events) && Number.isInteger(row.window_min)) return { threshold: row.min_events, windowMin: row.window_min, source: 'tenant' };
  return { threshold: server.threshold, windowMin: server.windowMin, source: 'server' };
}

// What GET /v1/parser/alert returns.
function view(row, server, tableMissing = false) {
  const eff = resolve(row, server);
  return {
    available: !tableMissing,
    source: eff.source,
    min_events: eff.threshold,
    window_min: eff.windowMin,
    enabled: eff.threshold > 0,
    updated_at: row && row.updated_at ? new Date(row.updated_at).toISOString() : null,
    server: { min_events: server.threshold, window_min: server.windowMin, enabled: server.threshold > 0 },
    limits: { min_events: [0, LIMITS.MAX_EVENTS], window_min: [LIMITS.MIN_WINDOW, LIMITS.MAX_WINDOW] },
  };
}

const isMissingTable = (e) => !!e && e.code === '42P01';   // undefined_table: the schema job has not run yet

async function readRow(client, tenantId) {
  const r = await client.query('SELECT min_events, window_min, updated_at FROM parse_alert_settings WHERE tenant_id = $1', [tenantId]);
  return r.rows[0] || null;
}

async function writeRow(client, tenantId, minEvents, windowMin, userId = null) {
  await client.query(
    `INSERT INTO parse_alert_settings (tenant_id, min_events, window_min, updated_by) VALUES ($1, $2, $3, $4)
     ON CONFLICT (tenant_id) DO UPDATE SET min_events = EXCLUDED.min_events, window_min = EXCLUDED.window_min, updated_at = localtimestamp, updated_by = EXCLUDED.updated_by`,
    [tenantId, minEvents, windowMin, userId ? String(userId) : null]);
}

async function clearRow(client, tenantId) {
  await client.query('DELETE FROM parse_alert_settings WHERE tenant_id = $1', [tenantId]);
}

module.exports = { LIMITS, checkMinEvents, checkWindow, parseBody, resolve, view, isMissingTable, readRow, writeRow, clearRow };
