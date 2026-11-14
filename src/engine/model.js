'use strict';
// The automation engine's side of ASIX (task SR3, docs/engine-callback.md): pure rules, no database and no network.
// What an engine run is: ASIX starts a workflow on the engine through its webhook and hands it a one-run token. The workflow may then only ASK ASIX
// to run actions (`POST /v1/engine/callback/actions/<id>`), and ASIX decides (enabled for the tenant, autonomy level, approval, audit), as it does for a person.
// The token is bound to ONE tenant, ONE run and a list of allowed actions, all chosen by ASIX when the run is started and never by the engine or a caller.
const crypto = require('crypto');
const catalog = require('../actions/catalog');

const LIMITS = { playbookMax: 80, allowedMax: 20, inputBytes: 8192, ttlDefault: 900, ttlMin: 30, ttlMax: 86400, callsDefault: 20, callsMax: 100, summaryMax: 500, webhookMax: 2048 };
const PLAYBOOK_RE = /^[a-z0-9][a-z0-9._-]{0,79}$/;
const ACTION_ID_RE = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/;
const TOKEN_RE = /^aet_[A-Za-z0-9_-]{43}$/;
const FINISH_STATUSES = ['succeeded', 'failed'];

const err = (code, message) => ({ error: { code, message } });
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// A run token: 32 random bytes. Only its SHA-256 is stored (like list feed tokens and ingestion keys), so a database read cannot be replayed against the API.
const newToken = () => 'aet_' + crypto.randomBytes(32).toString('base64url');
const tokenShape = (t) => typeof t === 'string' && TOKEN_RE.test(t);
const hashToken = (t) => crypto.createHash('sha256').update(String(t)).digest('hex');

// body of POST /v1/engine/runs. A body that names a tenant (or anything else not listed) is refused: the tenant of a run is the caller's own, never a field.
function parseStart(body) {
  if (!isObj(body)) return err('INVALID_BODY', 'The body must be a JSON object');
  const known = ['playbook', 'webhook_url', 'allowed_actions', 'input', 'ttl_seconds', 'max_calls'];
  const extra = Object.keys(body).filter((k) => !known.includes(k));
  if (extra.length) return err('INVALID_BODY', `Unknown field: ${extra[0].slice(0, 40)}. Allowed: ${known.join(', ')}`);
  if (typeof body.playbook !== 'string' || !PLAYBOOK_RE.test(body.playbook)) return err('INVALID_PLAYBOOK', 'playbook must be 1 to 80 characters: lower-case letters, digits, dot, dash, underscore');
  if (typeof body.webhook_url !== 'string' || !body.webhook_url || body.webhook_url.length > LIMITS.webhookMax) return err('INVALID_WEBHOOK_URL', 'webhook_url must be the engine webhook address (a string)');
  const a = body.allowed_actions;
  if (!Array.isArray(a) || a.length < 1 || a.length > LIMITS.allowedMax) return err('INVALID_ALLOWED_ACTIONS', `allowed_actions must list 1 to ${LIMITS.allowedMax} action ids`);
  for (const id of a) {
    if (typeof id !== 'string' || !ACTION_ID_RE.test(id)) return err('INVALID_ALLOWED_ACTIONS', 'allowed_actions holds an invalid action id');
    if (!catalog.get(id)) return err('INVALID_ALLOWED_ACTIONS', 'allowed_actions names an action ASIX does not know');
  }
  if (new Set(a).size !== a.length) return err('INVALID_ALLOWED_ACTIONS', 'allowed_actions lists an action twice');
  const input = body.input === undefined ? {} : body.input;
  if (!isObj(input)) return err('INVALID_INPUT', 'input must be a JSON object');
  if (Buffer.byteLength(JSON.stringify(input)) > LIMITS.inputBytes) return err('INVALID_INPUT', `input is larger than ${LIMITS.inputBytes} bytes`);
  const int = (v, d, lo, hi, name) => {
    if (v === undefined) return { value: d };
    if (!Number.isInteger(v) || v < lo || v > hi) return err('INVALID_' + name.toUpperCase(), `${name} must be a whole number from ${lo} to ${hi}`);
    return { value: v };
  };
  const ttl = int(body.ttl_seconds, LIMITS.ttlDefault, LIMITS.ttlMin, LIMITS.ttlMax, 'ttl_seconds'); if (ttl.error) return ttl;
  const calls = int(body.max_calls, LIMITS.callsDefault, 1, LIMITS.callsMax, 'max_calls'); if (calls.error) return calls;
  return { value: { playbook: body.playbook, webhook_url: body.webhook_url, allowed_actions: a.slice(), input, ttl_seconds: ttl.value, max_calls: calls.value } };
}

// body of POST /v1/engine/callback/finish
function parseFinish(body) {
  if (body === undefined || body === null) return err('INVALID_BODY', 'The body must be a JSON object');
  if (!isObj(body)) return err('INVALID_BODY', 'The body must be a JSON object');
  const extra = Object.keys(body).filter((k) => k !== 'status' && k !== 'summary');
  if (extra.length) return err('INVALID_BODY', 'Only status and summary are accepted');
  if (!FINISH_STATUSES.includes(body.status)) return err('INVALID_STATUS', `status must be one of: ${FINISH_STATUSES.join(', ')}`);
  if (body.summary !== undefined && (typeof body.summary !== 'string' || body.summary.length > LIMITS.summaryMax)) return err('INVALID_SUMMARY', `summary must be text of at most ${LIMITS.summaryMax} characters`);
  return { value: { status: body.status, summary: body.summary === undefined ? null : body.summary.trim() || null } };
}

// body of POST /v1/engine/callback/actions/<id>: { parameters? } only. Anything else (an origin, a tenant) is refused.
function parseCall(body) {
  if (body === undefined || body === null) return { value: { parameters: {} } };
  if (!isObj(body)) return err('INVALID_BODY', 'The body must be a JSON object');
  const extra = Object.keys(body).filter((k) => k !== 'parameters');
  if (extra.length) return err('INVALID_BODY', 'Only parameters is accepted');
  if (body.parameters !== undefined && !isObj(body.parameters)) return err('INVALID_BODY', 'parameters must be a JSON object');
  return { value: { parameters: body.parameters || {} } };
}

// What the engine is told about a request, in one word. A refusal is an answer, not an error: the workflow should see it and finish, not crash.
const OUTCOME = { succeeded: 'executed', awaiting_approval: 'awaiting_approval', recommended: 'recommended', refused: 'refused', failed: 'failed', rejected: 'rejected' };
const outcomeOf = (run) => OUTCOME[run.status] || run.status;

// The part of an action run the engine may see (never the parameters of another request, the undo or who decided).
const callView = (run) => ({ id: run.id, action: run.action_id, status: run.status, outcome: outcomeOf(run), result: run.status === 'succeeded' ? run.result : null,
  error_code: run.error_code || null, error_message: run.error_message || null });

// The callback address the engine is given. HTTPS only: the token travels in a header.
function callbackBase(env) {
  const raw = (env && (env.ASIX_ENGINE_CALLBACK_BASE || env.ASIX_PUBLIC_URL)) || '';
  if (!raw || raw.startsWith('__')) return err('ENGINE_NOT_CONFIGURED', 'ASIX_ENGINE_CALLBACK_BASE (the address the engine uses to reach this API) is not set');
  let u; try { u = new URL(raw); } catch (_) { return err('ENGINE_NOT_CONFIGURED', 'ASIX_ENGINE_CALLBACK_BASE is not a valid address'); }
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash) return err('ENGINE_NOT_CONFIGURED', 'ASIX_ENGINE_CALLBACK_BASE must be an https:// address with no credentials or query');
  return { value: u.origin + u.pathname.replace(/\/+$/, '') + '/v1/engine/callback' };
}

// The body of the webhook call: everything the workflow needs and nothing it should not hold (no webhook address, no credential of any tenant).
const hookBody = ({ runId, tenantId, token, callbackUrl, playbook, input }) => ({ run_id: runId, tenant_id: tenantId, token, callback_base: callbackUrl, playbook, input });

module.exports = { LIMITS, newToken, tokenShape, hashToken, parseStart, parseFinish, parseCall, outcomeOf, callView, callbackBase, hookBody, PLAYBOOK_RE, ACTION_ID_RE };
