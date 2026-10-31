'use strict';
// E4o: the limit of the "Endpoint configuration check score low" rule (E4n) chosen from the Endpoints page (Configuration checks tab) instead of by editing the rule's
// query on the Detections page. No new table: the limit IS the number in the built-in rule's own query, `sca_score != null and sca_score < N`, so the Detections page and
// the Endpoints page can never disagree. Pure rules plus small database helpers, the same pattern as src/endpoints/agent-alert.js.
//
//   limit N (1 to 100)  -> the query becomes `sca_score != null and sca_score < N` and the rule is switched ON
//   off                 -> the rule is switched OFF; its query (and so its limit) is kept, so a later Save of any limit switches it on again
// If someone edited the query by hand into anything else (another condition, another field) the limit is not guessed: the card says so, a new limit is refused (409), and the
// way back is Reset on the Detections page. Turning the rule off is always allowed. Severity, window and suppression stay what the Detections page says.

const RULE_KEY = 'endpoint-config-score-low';
const DEFAULT_LIMIT = 50;
const LIMITS = { MIN: 1, MAX: 100 };
const XQL_RE = /^sca_score != null and sca_score < (0|[1-9][0-9]{0,2})$/;
// The same shape for PostgreSQL's ~ (used so the write only happens while the stored query still has it: no read-then-write gap).
const XQL_SQL_RE = '^sca_score != null and sca_score < [0-9]{1,3}$';

const queryFor = (n) => `sca_score != null and sca_score < ${n}`;
// The limit in a stored query, or null when the query is not exactly the shape this page writes.
function limitFromQuery(xql) {
  const m = typeof xql === 'string' ? XQL_RE.exec(xql) : null;
  return m ? Number(m[1]) : null;
}

// The rule's description as shipped since E4o. It does not name the limit (it changes), so nothing has to be rewritten when the limit does.
const DESCRIPTION = 'A configuration check scan of one machine finished with a score under the limit (the manager\'s scan summary; 50% as shipped, changed on the Endpoints page, Configuration checks tab, or in the query). One alert per policy and machine, at most one a day. Switch the rule off here or on the Endpoints page.';
// The description E4n shipped. ensureBuiltinRules replaces it with DESCRIPTION only while it is still exactly this text (nobody edited it).
const E4N_DESCRIPTION = 'A configuration check scan of one machine finished with a score under 50% (the manager\'s scan summary). One alert per policy and machine, at most one a day. Raise or lower the 50 in the query, or switch the rule off, on this page.';

function whole(v) {
  const s = typeof v === 'number' ? (Number.isInteger(v) ? String(v) : '') : (typeof v === 'string' ? v.trim() : '');
  return /^(0|[1-9][0-9]{0,9})$/.test(s) ? Number(s) : null;
}
// A limit of LIMITS.MIN to LIMITS.MAX (whole percent). Returns { value } or { error }. 0 is not a limit: use { off: true }.
function checkLimit(v) {
  const n = whole(v);
  if (n === null || n < LIMITS.MIN || n > LIMITS.MAX) return { error: `Limit must be a whole number from ${LIMITS.MIN} to ${LIMITS.MAX} (percent); to stop the alert send { "off": true }` };
  return { value: n };
}

// Request body of PUT /v1/endpoints/score-alert. Exactly one of two shapes: { limit: N } or { off: true }. Returns { limit } | { off: true } | { error }.
function parseBody(body) {
  const b = body && typeof body === 'object' && !Array.isArray(body) ? body : null;
  const usage = 'Send { "limit": N } (1 to 100) or { "off": true }';
  if (!b) return { error: usage };
  const has = (k) => Object.prototype.hasOwnProperty.call(b, k);
  const keys = ['limit', 'off'].filter(has);
  if (keys.length !== 1 || Object.keys(b).length !== 1) return { error: usage };
  if (has('off')) return b.off === true ? { off: true } : { error: 'off can only be true' };
  const l = checkLimit(b.limit);
  return l.error ? { error: l.error } : { limit: l.value };
}

// row: { id, enabled, severity, xql, updated_at } of the tenant's built-in rule, or null when the rule does not exist yet (the rule runner inserts it within a minute of the
// API starting). Returns what GET /v1/endpoints/score-alert answers.
function view(row) {
  const limit = row ? limitFromQuery(row.xql) : null;
  return {
    available: !!row,
    rule_id: row ? row.id : null,
    enabled: !!(row && row.enabled),
    limit,                                       // null when the query was edited into another shape
    edited: !!row && limit === null,
    severity: row ? row.severity : null,
    default_limit: DEFAULT_LIMIT,
    limits: [LIMITS.MIN, LIMITS.MAX],
    updated_at: row && row.updated_at ? new Date(row.updated_at).toISOString() : null,
  };
}

async function readRow(client, tenantId) {
  const r = await client.query(
    `SELECT id, enabled, severity, definition->>'xql' AS xql, updated_at FROM detection_rules WHERE tenant_id = $1 AND builtin_key = $2`,
    [tenantId, RULE_KEY]);
  return r.rows[0] || null;
}

// Sets the limit and switches the rule on, but only while the stored query still has the shape this page writes. Returns true when a row was written.
async function writeLimit(client, tenantId, n) {
  const r = await client.query(
    `UPDATE detection_rules
        SET definition = jsonb_set(definition, '{xql}', to_jsonb($3::text)), enabled = true, last_error = NULL, updated_at = localtimestamp
      WHERE tenant_id = $1 AND builtin_key = $2 AND definition->>'xql' ~ $4`,
    [tenantId, RULE_KEY, queryFor(n), XQL_SQL_RE]);
  return r.rowCount > 0;
}

// Switches the rule off whatever its query says. Returns true when the rule exists.
async function writeOff(client, tenantId) {
  const r = await client.query(
    'UPDATE detection_rules SET enabled = false, updated_at = localtimestamp WHERE tenant_id = $1 AND builtin_key = $2',
    [tenantId, RULE_KEY]);
  return r.rowCount > 0;
}

module.exports = { RULE_KEY, DEFAULT_LIMIT, LIMITS, DESCRIPTION, E4N_DESCRIPTION, XQL_SQL_RE, queryFor, limitFromQuery, checkLimit, parseBody, view, readRow, writeLimit, writeOff };
