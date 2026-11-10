'use strict';
// Action registry (task SR2, docs/actions.md): the rules that need no database. What an action definition must look like, how its parameters are
// checked, what a tenant's setting may be, and the one decision that matters: given an action, the tenant's setting and who is asking, does the
// request run now, wait for approval, only produce a recommendation, or get refused. src/actions/catalog.js holds the definitions,
// src/actions/service.js does the SQL, src/gateway/routes/actions.js does the HTTP.
// Every parse/validate function returns { value } or { error: { code, message } } and never throws.
// Autonomy levels are the ones of docs/automation.md.

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ID_RE = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;         // case.add_note, firewall.block_ip: lowercase words joined by dots
const RISKS = ['low', 'medium', 'high'];
const LEVELS = [0, 1, 2, 3, 4];
const LEVEL_LABEL = { 0: 'Observe only', 1: 'Recommend only', 2: 'Ask for approval', 3: 'Run low-risk actions by itself', 4: 'Run by itself (approved class)' };
const ORIGINS = ['user', 'automation', 'undo'];
const STATUSES = ['recommended', 'awaiting_approval', 'rejected', 'succeeded', 'failed', 'refused'];
const KINDS = ['builtin', 'integration', 'endpoint'];           // integration and endpoint arrive with SR1 and SR5; only builtin has definitions today
const PARAM_TYPES = ['uuid', 'uuid_list', 'string', 'enum'];
const LIMITS = { listMax: 50, stringMax: 5000, pageMax: 200, pageDefault: 50, offsetMax: 100000 };
// The highest level a tenant may give an action, by risk class: high-risk actions never run by themselves; medium ones may at most run low-risk-style (3)
// only when they can be undone; low-risk ones may be a level 4 class.
const CEILING = { low: 4, medium: 3, high: 2 };

const bad = (message, code = 'INVALID_BODY') => ({ error: { code, message } });
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// ---- the definition of an action ---------------------------------------------------------------------------------------------------
// { id, name, description, publisher, kind, source, risk, reversible, append_only?, max_autonomy, default_autonomy, parameters: [...], execute(ctx, params) }
// `reversible: true` is a promise that execute returns, for a run that changed something, an `undo` ({ action, params }) that puts it back (the database test checks it for every built-in).
// parameters: [{ name, type, required?, nullable?, max?, values?, description }]. A parameter is never a secret: it is stored with the run (that is how a run
// that waits for approval keeps what was asked). Credentials are passed by reference to an integration instance (SR1), never as a parameter.
// Returns a list of problems (empty = fine). Used when a definition is registered and by the tests, so a bad definition stops at start, never at a request.
function checkDefinition(def) {
  const p = [];
  if (!isObj(def)) return ['an action definition must be an object'];
  if (typeof def.id !== 'string' || !ID_RE.test(def.id) || def.id.length > 100) p.push('id must be lowercase words joined by dots, such as case.add_note');
  for (const f of ['name', 'description', 'publisher', 'source']) if (typeof def[f] !== 'string' || !def[f].trim()) p.push(`${f} is required`);
  if (!KINDS.includes(def.kind)) p.push(`kind must be one of ${KINDS.join(', ')}`);
  if (!RISKS.includes(def.risk)) p.push(`risk must be one of ${RISKS.join(', ')}`);
  if (typeof def.reversible !== 'boolean') p.push('reversible must be true or false');
  if (def.undo !== undefined) p.push('undo is not a field of a definition: execute returns the undo of each run');
  if (typeof def.execute !== 'function') p.push('execute must be a function');
  if (!LEVELS.includes(def.max_autonomy)) p.push('max_autonomy must be 0 to 4');
  if (!LEVELS.includes(def.default_autonomy)) p.push('default_autonomy must be 0 to 4');
  if (LEVELS.includes(def.max_autonomy) && RISKS.includes(def.risk)) {
    if (def.max_autonomy > CEILING[def.risk]) p.push(`a ${def.risk}-risk action cannot have max_autonomy above ${CEILING[def.risk]}`);
    // Level 3 and 4 mean "runs without a person": only for what can be undone or can only add information.
    if (def.max_autonomy >= 3 && !def.reversible && !def.append_only) p.push('an action that is neither reversible nor append-only cannot have max_autonomy above 2');
    if (def.default_autonomy > def.max_autonomy) p.push('default_autonomy cannot be above max_autonomy');
  }
  if (def.risk === 'low' && !def.reversible && !def.append_only) p.push('a low-risk action must be reversible or append-only');
  if (!Array.isArray(def.parameters)) p.push('parameters must be a list');
  else {
    const seen = new Set();
    for (const q of def.parameters) {
      if (!isObj(q) || typeof q.name !== 'string' || !/^[a-z][a-z0-9_]*$/.test(q.name)) { p.push('every parameter needs a name of lowercase letters, digits and underscores'); continue; }
      if (seen.has(q.name)) p.push(`parameter ${q.name} is listed twice`); seen.add(q.name);
      if (!PARAM_TYPES.includes(q.type)) p.push(`parameter ${q.name}: type must be one of ${PARAM_TYPES.join(', ')}`);
      if (q.type === 'enum' && (!Array.isArray(q.values) || !q.values.length)) p.push(`parameter ${q.name}: an enum needs values`);
      if (typeof q.description !== 'string' || !q.description.trim()) p.push(`parameter ${q.name}: description is required`);
    }
  }
  return p;
}

// ---- parameters --------------------------------------------------------------------------------------------------------------------
function oneParam(q, v) {
  if (v === null) return q.nullable ? { value: null } : bad(`${q.name} cannot be null`, 'INVALID_PARAMETER');
  switch (q.type) {
    case 'uuid': return typeof v === 'string' && UUID_RE.test(v) ? { value: v.toLowerCase() } : bad(`${q.name} must be an id`, 'INVALID_PARAMETER');
    case 'uuid_list': {
      const max = q.max || LIMITS.listMax;
      if (!Array.isArray(v) || !v.length || v.length > max || v.some((x) => typeof x !== 'string' || !UUID_RE.test(x))) return bad(`${q.name} must be a list of 1 to ${max} ids`, 'INVALID_PARAMETER');
      return { value: [...new Set(v.map((x) => x.toLowerCase()))] };
    }
    case 'string': {
      const max = Math.min(q.max || LIMITS.stringMax, LIMITS.stringMax);
      if (typeof v !== 'string' || !v.trim() || v.trim().length > max) return bad(`${q.name} must be text of 1 to ${max} characters`, 'INVALID_PARAMETER');
      return { value: v.trim() };
    }
    case 'enum': return q.values.includes(v) ? { value: v } : bad(`${q.name} must be one of ${q.values.join(', ')}`, 'INVALID_PARAMETER');
    default: return bad(`${q.name}: unsupported type`, 'INVALID_PARAMETER');
  }
}

// params: the object a caller sent. Unknown names are refused; required ones must be there; the answer holds only what the definition lists.
function validateParams(def, params) {
  const input = params === undefined ? {} : params;
  if (!isObj(input)) return bad('parameters must be a JSON object', 'INVALID_PARAMETERS');
  const known = new Set(def.parameters.map((q) => q.name));
  const extra = Object.keys(input).filter((k) => !known.has(k));
  if (extra.length) return bad(`unknown parameter: ${extra.join(', ')}`, 'INVALID_PARAMETERS');
  const out = {};
  for (const q of def.parameters) {
    if (!has(input, q.name) || input[q.name] === undefined) {
      if (q.required) return bad(`${q.name} is required`, 'INVALID_PARAMETERS');
      continue;
    }
    const r = oneParam(q, input[q.name]);
    if (r.error) return r;
    out[q.name] = r.value;
  }
  return { value: out };
}

// ---- a tenant's setting ------------------------------------------------------------------------------------------------------------
// body: { enabled?: boolean, autonomy?: 0..4 }. Enabling without a level uses the action's default. The level may not pass the action's own ceiling.
// `current`: the stored setting ({ enabled, autonomy_level }) or null (never enabled).
function parseSetting(def, body, current) {
  if (!isObj(body)) return bad('send a JSON object');
  const extra = Object.keys(body).filter((k) => k !== 'enabled' && k !== 'autonomy');
  if (extra.length) return bad(`unknown field: ${extra.join(', ')}`);
  if (!has(body, 'enabled') && !has(body, 'autonomy')) return bad('send enabled, autonomy or both');
  if (has(body, 'enabled') && typeof body.enabled !== 'boolean') return bad('enabled must be true or false');
  if (has(body, 'autonomy') && !(Number.isInteger(body.autonomy) && LEVELS.includes(body.autonomy))) return bad('autonomy must be a whole number from 0 to 4');
  if (has(body, 'autonomy') && body.autonomy > def.max_autonomy) {
    return bad(`${def.name} cannot be given a level above ${def.max_autonomy} (${LEVEL_LABEL[def.max_autonomy]}): it is ${def.risk}-risk${def.reversible || def.append_only ? '' : ' and cannot be undone'}`, 'AUTONOMY_TOO_HIGH');
  }
  const enabled = has(body, 'enabled') ? body.enabled : !!(current && current.enabled);
  const autonomy = has(body, 'autonomy') ? body.autonomy : (current ? current.autonomy_level : def.default_autonomy);
  return { value: { enabled, autonomy: Math.min(autonomy, def.max_autonomy) } };
}

// ---- the decision ------------------------------------------------------------------------------------------------------------------
// setting: { enabled, autonomy_level } or null. origin: 'user' (a person pressing Run: that press is the approval) or 'automation' (a playbook, SR3).
// Returns { outcome: 'refuse' | 'recommend' | 'approval' | 'execute', level, code?, reason }.
//   refuse     the request is recorded as refused and nothing runs
//   recommend  nothing runs; the run record says what would have been done (a dry run)
//   approval   the request waits for a person; running it is that person's decision
//   execute    runs now
function decide(def, setting, origin) {
  if (!setting || !setting.enabled) return { outcome: 'refuse', level: 0, code: 'ACTION_DISABLED', reason: 'This action is not enabled for this tenant. An administrator enables it first.' };
  const level = Math.min(setting.autonomy_level, def.max_autonomy);   // a ceiling lowered after the setting was saved still wins
  if (level === 0) return { outcome: 'refuse', level, code: 'OBSERVE_ONLY', reason: 'This action is set to Observe only: nothing may be requested.' };
  if (level === 1) return { outcome: 'recommend', level, reason: 'This action is set to Recommend only: the request is recorded and nothing is done.' };
  if (origin === 'user') return { outcome: 'execute', level, reason: 'Run by a person.' };
  if (level === 2) return { outcome: 'approval', level, reason: 'Waiting for a person to approve.' };
  if (level === 3) {
    return def.risk === 'low' ? { outcome: 'execute', level, reason: 'Low-risk action at level 3.' }
      : { outcome: 'approval', level, reason: `Level 3 runs only low-risk actions by itself; this one is ${def.risk}-risk, so it waits for a person.` };
  }
  return { outcome: 'execute', level, reason: 'Approved action class at level 4.' };
}

// A high-risk action needs a second person: the one who approves is not the one who asked.
function approvalRefusal(def, run, approverId) {
  if (def.risk === 'high' && run.requested_by_id && approverId && run.requested_by_id === approverId) {
    return { code: 'SELF_APPROVAL', message: 'A high-risk action must be approved by someone other than the person who requested it.' };
  }
  return null;
}

// Audit wording: what is written to audit_events.result for a run status.
const AUDIT_RESULT = { succeeded: 'success', failed: 'failed', refused: 'denied', recommended: 'recommended', awaiting_approval: 'pending', rejected: 'rejected' };

// The query of the list of runs.
function parseRunsQuery(q) {
  const out = { status: null, action: null, limit: LIMITS.pageDefault, offset: 0 };
  if (q.status !== undefined) { if (!STATUSES.includes(String(q.status))) return bad(`status must be one of ${STATUSES.join(', ')}`, 'INVALID_STATUS'); out.status = String(q.status); }
  if (q.action !== undefined) { if (!ID_RE.test(String(q.action))) return bad('action must be an action id', 'INVALID_ACTION'); out.action = String(q.action); }
  const num = (v, min, max) => { const n = Number(v); return Number.isInteger(n) && n >= min && n <= max ? n : null; };
  if (q.limit !== undefined) { out.limit = num(q.limit, 1, LIMITS.pageMax); if (out.limit === null) return bad(`limit must be a whole number from 1 to ${LIMITS.pageMax}`, 'INVALID_PAGE'); }
  if (q.offset !== undefined) { out.offset = num(q.offset, 0, LIMITS.offsetMax); if (out.offset === null) return bad(`offset must be a whole number from 0 to ${LIMITS.offsetMax}`, 'INVALID_PAGE'); }
  return { value: out };
}

// The body of a request to run: { parameters?: {...} }. Nothing else (the origin is never taken from a caller; the routes always say 'user').
function parseRunBody(body) {
  if (body === undefined) return { value: { parameters: {} } };
  if (!isObj(body)) return bad('send a JSON object');
  const extra = Object.keys(body).filter((k) => k !== 'parameters');
  if (extra.length) return bad(`unknown field: ${extra.join(', ')}`);
  return { value: { parameters: body.parameters === undefined ? {} : body.parameters } };
}

module.exports = {
  UUID_RE, ID_RE, RISKS, LEVELS, LEVEL_LABEL, ORIGINS, STATUSES, KINDS, PARAM_TYPES, LIMITS, CEILING, AUDIT_RESULT,
  checkDefinition, validateParams, parseSetting, decide, approvalRefusal, parseRunsQuery, parseRunBody,
};
