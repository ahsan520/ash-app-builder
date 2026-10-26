'use strict';
// Pausing an optional input on ONE broker from the Brokers page. A broker VM can run log files, HTTP/JSON and the systemd journal next to syslog
// (docs/broker-vm.md). Each has its own Vector config file, listed in VECTOR_CONFIG in broker.env. "Pause" asks the broker to take that file out of the list
// and restart Vector; "resume" asks it to put it back. ASIX runs nothing on the broker: a broker that opted in (bootstrap-broker.sh --accept-config) pulls the
// list with its own key and applies it after its own checks (validate, restart, health, way back), exactly like the syslog port.
// Only these optional inputs can be paused. Syslog and syslog over TLS cannot: they are what the broker is for, and a broker with both off could not be reached
// by the senders it was installed for. Pure rules plus small database helpers.
const { tsMs } = require('../collectors/status');

const KINDS = ['file', 'http', 'journald', 'wazuh', 'wazuhalerts'];   // the fixed order everything is stored and sent in; names are letters only (the database checks ^[a-z,]+$)
const MAX_TEXT = 40;                           // 'file,http,journald,wazuh,wazuhalerts' is 36 characters (the database allows 40)

const order = (set) => KINDS.filter((k) => set.has(k));

// How long a pause (or resume) may stay unapplied before it counts as overdue. A broker asks every 5 minutes and applies in seconds, so 30 minutes means six
// asks went by. ASIX_PAUSE_OVERDUE_MIN: 0 = never overdue (no flag on the page, no alert for it); 5 to 1440 minutes; anything else means the default.
const OVERDUE_DEFAULT_MIN = 30, OVERDUE_MIN_MIN = 5, OVERDUE_MAX_MIN = 1440;
function overdueMinutes(env = process.env) {
  const raw = env.ASIX_PAUSE_OVERDUE_MIN;
  if (raw === undefined || String(raw).trim() === '') return OVERDUE_DEFAULT_MIN;
  const n = Number(raw);
  if (n === 0) return 0;
  return Number.isInteger(n) && n >= OVERDUE_MIN_MIN && n <= OVERDUE_MAX_MIN ? n : OVERDUE_DEFAULT_MIN;
}

// What the operator sent: null / '' / [] clear the list; an array or a comma separated string of known names sets it. Returns { value: [...] } (in the fixed order, each once) or { error }.
function checkPaused(v) {
  if (v === null || v === undefined || v === '') return { value: [] };
  const raw = Array.isArray(v) ? v : typeof v === 'string' ? v.split(',') : null;
  if (!raw) return { error: 'paused must be a list of inputs: ' + KINDS.join(', ') };
  const set = new Set();
  for (const t of raw) {
    if (typeof t !== 'string') return { error: 'paused must be a list of names: ' + KINDS.join(', ') };
    const k = t.trim().toLowerCase();
    if (k === '') continue;
    if (!KINDS.includes(k)) return { error: `"${String(t).slice(0, 30)}" cannot be paused. Inputs that can be paused: ${KINDS.join(', ')} (syslog cannot)` };
    set.add(k);
  }
  return { value: order(set) };
}

// Stored or reported text -> array in the fixed order; unknown names are dropped. null when it is not text (never said).
function parseText(t) {
  if (typeof t !== 'string') return null;
  return order(new Set(t.split(',').map((x) => x.trim().toLowerCase()).filter((x) => KINDS.includes(x))));
}
const toText = (list) => order(new Set(list)).join(',');

// A broker's report field: '' (nothing paused) or a comma list of known names, each once. Anything else is refused (the broker's script sends only these).
function checkReportText(v) {
  if (typeof v !== 'string' || v.length > MAX_TEXT || !/^[a-z,]*$/.test(v)) return { error: true };
  const parts = v === '' ? [] : v.split(',');
  if (new Set(parts).size !== parts.length || parts.some((p) => !KINDS.includes(p))) return { error: true };
  return { value: toText(parts) };
}

// ---- What the pull answers --------------------------------------------------------------------------------------------------
// Read by key AND name (one key cannot read another broker's list), in its own transaction by the caller: a database without the new columns throws and
// the pull then simply leaves the field out. Returns the text to put in the answer ('file,journald' to pause, '' to resume everything), or undefined for
// "no opinion": nothing is asked AND the broker has not reported anything paused, so there is nothing to say (the answer stays as it was before this existed).
async function readForPull(client, tenantId, keyId, name) {
  const r = await client.query('SELECT inputs_paused, config_paused_inputs FROM collectors WHERE tenant_id = $1 AND key_id = $2 AND name = $3', [tenantId, keyId, name]);
  const row = r.rows[0];
  if (!row) return undefined;
  const asked = parseText(row.inputs_paused) || [];
  const has = parseText(row.config_paused_inputs) || [];
  if (!asked.length && !has.length) return undefined;
  return toText(asked);
}

// Sets or clears the list on one broker (a collector whose version reads vector-<version>). Returns { id, name, paused } or null if there is no such broker.
async function writePaused(client, tenantId, brokerId, list) {
  const text = list.length ? toText(list) : null;
  // inputs_paused_at is when the ask last CHANGED (saving the same list again keeps it), so "asked 40 minutes ago" cannot be reset by pressing Save twice.
  const r = await client.query(`UPDATE collectors
       SET inputs_paused_at = CASE WHEN inputs_paused IS DISTINCT FROM $3::text THEN localtimestamp ELSE inputs_paused_at END,
           inputs_paused = $3::text
     WHERE id = $1 AND tenant_id = $2 AND version ILIKE 'vector-%' RETURNING id, name, inputs_paused`, [brokerId, tenantId, text]);
  return r.rows[0] ? { id: r.rows[0].id, name: r.rows[0].name, paused: parseText(r.rows[0].inputs_paused) || [] } : null;
}

// The report: what the broker has paused now, and the list it rejected. Lands on the broker's own row (key AND name). Own statement: a database without the columns throws.
async function recordReport(client, tenantId, keyId, name, paused, rejected) {
  const r = await client.query('UPDATE collectors SET config_paused_inputs = $4, config_rejected_paused = $5 WHERE tenant_id = $1 AND key_id = $2 AND name = $3',
    [tenantId, keyId, name, paused, rejected === undefined || rejected === '' ? null : rejected]);
  return r.rowCount > 0;
}

// The state of one broker against the list ASIX asks for. `row` carries inputs_paused (asked), config_paused_inputs (reported; NULL = never said, '' = nothing paused),
// config_rejected_paused and config_reported_at. Information only: never a "needs attention" problem and never an alert.
//   none      nothing asked, and the broker does not say anything is paused
//   unknown   something is asked but this broker never reported: it did not opt in, or its config script is older than this
//   applied   the broker reports exactly the asked list (also when the list is empty and it has resumed)
//   rejected  the broker reports it tried the asked list and put its old settings back
//   pending   it reports another list and has not rejected this one
//   stale     as pending, but its last report is older than 15 minutes
// `overdue` is a flag next to the state, not a state: the list was asked longer ago than overdueMinutes() (collectors.inputs_paused_at, when the ask last changed)
// and the broker is `unknown` or `pending` (it never reported, or it reports another list without rejecting this one). `rejected` has its own alert and `stale` is
// the disconnect alert's business. An ask made before inputs_paused_at existed has no time, so it is never overdue (there is nothing to measure from).
const REPORT_FRESH_MS = 15 * 60 * 1000;
function pausedState(row, now = Date.now(), overdueMin = overdueMinutes()) {
  const asked = parseText(row && row.inputs_paused) || [];
  const reported = row && row.config_paused_inputs != null ? parseText(row.config_paused_inputs) : null;
  const rejected = row && row.config_rejected_paused ? toText(parseText(row.config_rejected_paused) || []) : '';
  const at = row && row.config_reported_at ? tsMs(row.config_reported_at) : NaN;
  const askedAtMs = row && row.inputs_paused_at ? tsMs(row.inputs_paused_at) : NaN;
  const out = { state: 'none', asked, reported, rejected: rejected ? rejected.split(',') : [], reported_at: row && row.config_reported_at ? row.config_reported_at : null,
    asked_at: Number.isFinite(askedAtMs) ? new Date(askedAtMs).toISOString() : null, overdue: false };
  if (!asked.length && (reported === null || !reported.length)) return out;
  const late = (state) => ({ ...out, state, overdue: ['unknown', 'pending'].includes(state) && overdueMin > 0 && Number.isFinite(askedAtMs) && now - askedAtMs > overdueMin * 60000 });
  if (reported === null) return late('unknown');
  if (toText(reported) === toText(asked)) return { ...out, state: 'applied' };
  if (rejected && rejected === toText(asked)) return { ...out, state: 'rejected' };
  return late(Number.isFinite(at) && now - at > REPORT_FRESH_MS ? 'stale' : 'pending');
}

module.exports = { KINDS, MAX_TEXT, OVERDUE_DEFAULT_MIN, overdueMinutes, checkPaused, parseText, toText, checkReportText, readForPull, writePaused, recordReport, pausedState };
