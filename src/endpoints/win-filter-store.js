'use strict';
// The Windows event filter policy saved per tenant (docs/endpoints.md, task E2): the request rules, the view the portal reads, a preview that checks a policy against
// sample events without saving it, and three small database helpers. The policy itself, its validation and its output for Vector and Wazuh are in win-filter.js.
//
// One row per tenant in win_filter_policy; NO ROW = no policy = every event is kept, as before. `revision` goes up by one on every save so a second person (or a broker, later,
// E3) can tell the policy changed, and a save can say which revision it was based on (if_revision) and is refused with 409 if someone saved in between. Nothing is pushed
// anywhere by saving: the broker applying it is E3.
const wf = require('./win-filter');

const DEFAULT_CHANNELS = ['Security', 'System', 'Application'];
const MAX_EVENTS = 50, MAX_FIELDS = 50, MAX_MESSAGE = 20000;
const PROGRAM_HEADER_ALLOWANCE = 300;   // the comment lines win-filter-broker.js puts in front of the program

const fail = (error) => ({ error });
const whole = (v) => (typeof v === 'number' ? Number.isInteger(v) && v >= 0 && v <= 2147483647 : typeof v === 'string' && /^(0|[1-9][0-9]{0,9})$/.test(v.trim()) && Number(v) <= 2147483647);
const errText = (errors) => errors.slice(0, 5).join('; ') + (errors.length > 5 ? ' (and ' + (errors.length - 5) + ' more)' : '');

// Request body of PUT /v1/endpoints/win-filter. Two shapes:
//   { clear: true }                          remove the tenant's policy (back to keeping every event)
//   { policy: {...}, if_revision?: N }       save this policy; N = the revision it was edited from (0 = none saved yet)
// Returns { clear: true } | { policy (normalised), canonical (as stored), if_revision | null } | { error }.
function parseBody(body) {
  const b = body && typeof body === 'object' && !Array.isArray(body) ? body : null, has = (k) => b && Object.prototype.hasOwnProperty.call(b, k);
  if (!b || (!has('clear') && !has('policy'))) return fail('Send { "policy": {...} } or { "clear": true }');
  if (has('clear')) {
    if (b.clear !== true) return fail('clear can only be true');
    if (has('policy') || has('if_revision')) return fail('Send clear on its own');
    return { clear: true };
  }
  let ifRevision = null;
  if (has('if_revision') && b.if_revision !== null && b.if_revision !== undefined && b.if_revision !== '') {
    if (!whole(b.if_revision)) return fail('if_revision must be a whole number');
    ifRevision = Number(b.if_revision);
  }
  const v = wf.validate(b.policy);
  if (!v.ok) return fail(errText(v.errors));
  // A broker downloads the program this policy makes (win-filter-broker.js): refuse now what could never be delivered, rather than save it and have no broker take it.
  const bytes = Buffer.byteLength(wf.toVrl(v.policy), 'utf8') + PROGRAM_HEADER_ALLOWANCE;
  if (bytes > wf.MAX_PROGRAM_BYTES) return fail('The policy is too large to send to a broker (its program would be about ' + Math.round(bytes / 1024) + ' kB, the limit is ' + Math.round(wf.MAX_PROGRAM_BYTES / 1024) + ' kB): remove rules or event IDs');
  return { policy: v.policy, canonical: wf.toInput(v.policy), if_revision: ifRevision };
}

// Sample events for the preview: [{ channel, event_id, fields?: { Name: text }, message?: text }]. Returns { events } | { error }.
function parseEvents(list) {
  if (list === undefined || list === null) return { events: [] };
  if (!Array.isArray(list) || list.length > MAX_EVENTS) return fail('events must be a list of at most ' + MAX_EVENTS + ' sample events');
  const events = [];
  for (let i = 0; i < list.length; i++) {
    const e = list[i], where = 'event ' + (i + 1);
    if (!e || typeof e !== 'object' || Array.isArray(e)) return fail(where + ' must be an object');
    if (typeof e.channel !== 'string' || e.channel.length > 64) return fail(where + ': channel must be text of at most 64 characters');
    if (!Number.isInteger(e.event_id) || e.event_id < 0 || e.event_id > 65535) return fail(where + ': event_id must be a whole number from 0 to 65535');
    let fields = {};
    if (e.fields !== undefined) {
      if (!e.fields || typeof e.fields !== 'object' || Array.isArray(e.fields) || Object.keys(e.fields).length > MAX_FIELDS) return fail(where + ': fields must be an object of at most ' + MAX_FIELDS + ' names');
      for (const [k, val] of Object.entries(e.fields)) { if (typeof val !== 'string' && typeof val !== 'number') return fail(where + ': field ' + k + ' must be text or a number'); }
      fields = e.fields;
    }
    if (e.message !== undefined && (typeof e.message !== 'string' || e.message.length > MAX_MESSAGE)) return fail(where + ': message must be text of at most ' + MAX_MESSAGE + ' characters');
    events.push({ channel: e.channel, event_id: e.event_id, fields, message: e.message });
  }
  return { events };
}

// The channels the agent.conf blocks are written for: the usual three plus every channel the policy names.
function channelsOf(policy) {
  const out = [...DEFAULT_CHANNELS];
  for (const c of [...Object.keys(policy.channels), ...policy.rules.map((r) => r.channel), ...policy.message_strip.map((m) => m.channel)]) if (c && !out.some((x) => x.toLowerCase() === c.toLowerCase())) out.push(c);
  return out;
}

// What the policy turns into: the Vector transform for the broker, the Wazuh agent group blocks, and per channel the XPath (or why there is none).
function outputs(policy) {
  const channels = channelsOf(policy), xpath = {};
  for (const c of channels) xpath[c] = wf.toXPath(policy, c);
  return { vector: wf.toVectorTransform(policy), agent_conf: wf.toAgentConf(policy, channels), xpath };
}

// What POST /v1/endpoints/win-filter/preview returns for a validated policy and sample events; nothing is saved.
function preview(policy, events) {
  return { ok: true, policy: wf.toInput(policy), outputs: outputs(policy), results: events.map((e) => { const r = wf.evaluate(policy, e); return { channel: e.channel, event_id: e.event_id, keep: r.keep, rule_id: r.rule_id, message: r.message }; }) };
}

// What GET /v1/endpoints/win-filter returns. row: { policy, revision, updated_at } or null.
function view(row, tableMissing = false) {
  const empty = wf.toInput(wf.validate({}).policy);
  let policy = empty, invalid = false;
  if (row) { const v = wf.validate(row.policy); if (v.ok) policy = wf.toInput(v.policy); else invalid = true; }
  return { available: !tableMissing, configured: !!row, invalid, revision: row ? row.revision : 0, updated_at: row && row.updated_at ? new Date(row.updated_at).toISOString() : null, policy,
    preset: wf.toInput(wf.validate(wf.presetNoisySecurity()).policy), limits: { rules: wf.MAX_RULES, message_strip: wf.MAX_STRIPS, regex_length: wf.MAX_REGEX, sample_events: MAX_EVENTS } };
}

const isMissingTable = (e) => !!e && e.code === '42P01';   // undefined_table: the schema job has not run yet

async function readRow(client, tenantId, lock = false) {
  const r = await client.query('SELECT policy, revision, updated_at FROM win_filter_policy WHERE tenant_id = $1' + (lock ? ' FOR UPDATE' : ''), [tenantId]);
  return r.rows[0] || null;
}
async function writeRow(client, tenantId, canonical, userId = null) {
  await client.query(
    `INSERT INTO win_filter_policy (tenant_id, policy, revision, updated_by) VALUES ($1, $2::jsonb, 1, $3)
     ON CONFLICT (tenant_id) DO UPDATE SET policy = EXCLUDED.policy, revision = win_filter_policy.revision + 1, updated_at = localtimestamp, updated_by = EXCLUDED.updated_by`,
    [tenantId, JSON.stringify(canonical), userId ? String(userId) : null]);
}
async function clearRow(client, tenantId) {
  await client.query('DELETE FROM win_filter_policy WHERE tenant_id = $1', [tenantId]);
}

module.exports = { DEFAULT_CHANNELS, MAX_EVENTS, parseBody, parseEvents, channelsOf, outputs, preview, view, isMissingTable, readRow, writeRow, clearRow };
