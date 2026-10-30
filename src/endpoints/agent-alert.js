'use strict';
// E4m: the "Endpoint agent disconnected" alert (src/endpoints/agent-watch.js) chosen from the portal instead of only from the API's environment, and a list of
// machines that are NOT watched (a laptop that is meant to sleep). Pure rules plus small database helpers, the same pattern as src/ingestion/parse-alert.js.
//
// Where the limit comes from, per tenant:
//   a row with minutes set      -> that wins (0 = the alert is OFF for this tenant, even if the server setting is on)
//   no row, or minutes NULL     -> the server setting ASIX_AGENT_WATCH_MIN, as before
// "Follow the server setting" sets minutes back to NULL; it never touches the list of machines that are not watched.
// The list (skip_agents) is agent ids as the manager writes them (3 to 8 digits). It applies whatever the limit's source is. At most 200 ids.

const LIMITS = { MIN: 5, MAX: 10080, MAX_SKIP: 200 };
const AGENT_ID_RE = /^[0-9]{3,8}$/;

function whole(v) {
  const s = typeof v === 'number' ? (Number.isInteger(v) ? String(v) : '') : (typeof v === 'string' ? v.trim() : '');
  return /^(0|[1-9][0-9]{0,9})$/.test(s) ? Number(s) : null;
}
// 0 (off) or LIMITS.MIN to LIMITS.MAX minutes. Returns { value } or { error }.
function checkMinutes(v) {
  const n = whole(v);
  if (n === null || (n !== 0 && (n < LIMITS.MIN || n > LIMITS.MAX))) return { error: `Limit (minutes) must be 0 (off) or a whole number from ${LIMITS.MIN} to ${LIMITS.MAX}` };
  return { value: n };
}

// Request body of PUT /v1/endpoints/agent-alert. Exactly one of three shapes:
//   { minutes: N }                        N = 0 turns the alert off for this tenant
//   { follow_server: true }               go back to the server setting
//   { skip_agent: "002", skip: true|false }   do not watch (true) or watch again (false) one agent
// Returns { minutes } | { follow: true } | { agent, skip } | { error }.
function parseBody(body) {
  const b = body && typeof body === 'object' && !Array.isArray(body) ? body : null;
  const usage = 'Send { "minutes": N }, { "follow_server": true } or { "skip_agent": "002", "skip": true }';
  if (!b) return { error: usage };
  const has = (k) => Object.prototype.hasOwnProperty.call(b, k);
  const keys = ['minutes', 'follow_server', 'skip_agent', 'skip'].filter(has);
  if (has('follow_server')) {
    if (b.follow_server !== true) return { error: 'follow_server can only be true' };
    if (keys.length > 1) return { error: 'Send follow_server on its own' };
    return { follow: true };
  }
  if (has('minutes')) {
    if (keys.length > 1) return { error: 'Send minutes on its own' };
    const m = checkMinutes(b.minutes); if (m.error) return { error: m.error };
    return { minutes: m.value };
  }
  if (has('skip_agent')) {
    if (typeof b.skip_agent !== 'string' || !AGENT_ID_RE.test(b.skip_agent)) return { error: 'skip_agent must be an agent id of 3 to 8 digits' };
    if (typeof b.skip !== 'boolean') return { error: 'skip must be true or false' };
    return { agent: b.skip_agent, skip: b.skip };
  }
  return { error: usage };
}

// row: { minutes | null, skip_agents } or null; server: { minutes } as agent-watch.config() reads the environment.
// Returns { minutes, source: 'tenant' | 'server', skip: [ids] }.
function resolve(row, server) {
  const skip = row && Array.isArray(row.skip_agents) ? row.skip_agents.filter((x) => AGENT_ID_RE.test(String(x))).map(String) : [];
  if (row && Number.isInteger(row.minutes)) return { minutes: row.minutes, source: 'tenant', skip };
  return { minutes: server.minutes, source: 'server', skip };
}

// What GET /v1/endpoints/agent-alert returns.
function view(row, server, tableMissing = false) {
  const eff = resolve(row, server);
  return {
    available: !tableMissing,
    source: eff.source,
    minutes: eff.minutes,
    enabled: eff.minutes > 0,
    skip_agents: eff.skip,
    updated_at: row && row.updated_at ? new Date(row.updated_at).toISOString() : null,
    server: { minutes: server.minutes, enabled: server.minutes > 0 },
    limits: { minutes: [LIMITS.MIN, LIMITS.MAX], max_skip: LIMITS.MAX_SKIP },
  };
}

const isMissingTable = (e) => !!e && e.code === '42P01';   // undefined_table: the schema job has not run yet

async function readRow(client, tenantId) {
  const r = await client.query('SELECT minutes, skip_agents, updated_at FROM agent_watch_settings WHERE tenant_id = $1', [tenantId]);
  return r.rows[0] || null;
}

async function tidy(client, tenantId) {   // a row that follows the server and skips nobody holds nothing
  await client.query('DELETE FROM agent_watch_settings WHERE tenant_id = $1 AND minutes IS NULL AND cardinality(skip_agents) = 0', [tenantId]);
}

async function writeMinutes(client, tenantId, minutes, userId = null) {
  await client.query(
    `INSERT INTO agent_watch_settings (tenant_id, minutes, updated_by) VALUES ($1, $2, $3)
     ON CONFLICT (tenant_id) DO UPDATE SET minutes = EXCLUDED.minutes, updated_at = localtimestamp, updated_by = EXCLUDED.updated_by`,
    [tenantId, minutes, userId ? String(userId) : null]);
}

async function clearMinutes(client, tenantId, userId = null) {
  await client.query('UPDATE agent_watch_settings SET minutes = NULL, updated_at = localtimestamp, updated_by = $2 WHERE tenant_id = $1', [tenantId, userId ? String(userId) : null]);
  await tidy(client, tenantId);
}

// Add or remove one agent id in one statement (no read-then-write, so two people saving at once both stay). Returns { ok: true } or { full: true } when adding to a full list.
async function setSkip(client, tenantId, agent, skip, userId = null) {
  const by = userId ? String(userId) : null;
  if (skip) {
    const r = await client.query(
      `INSERT INTO agent_watch_settings (tenant_id, skip_agents, updated_by) VALUES ($1, ARRAY[$2]::text[], $3)
       ON CONFLICT (tenant_id) DO UPDATE
         SET skip_agents = CASE WHEN $2 = ANY(agent_watch_settings.skip_agents) THEN agent_watch_settings.skip_agents ELSE array_append(agent_watch_settings.skip_agents, $2) END,
             updated_at = localtimestamp, updated_by = EXCLUDED.updated_by
         WHERE $2 = ANY(agent_watch_settings.skip_agents) OR cardinality(agent_watch_settings.skip_agents) < $4`,
      [tenantId, agent, by, LIMITS.MAX_SKIP]);
    return r.rowCount ? { ok: true } : { full: true };
  }
  await client.query('UPDATE agent_watch_settings SET skip_agents = array_remove(skip_agents, $2), updated_at = localtimestamp, updated_by = $3 WHERE tenant_id = $1', [tenantId, agent, by]);
  await tidy(client, tenantId);
  return { ok: true };
}

module.exports = { LIMITS, AGENT_ID_RE, checkMinutes, parseBody, resolve, view, isMissingTable, readRow, writeMinutes, clearMinutes, setSkip };
