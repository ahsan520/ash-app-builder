'use strict';
// Integrations (task SR1, docs/integrations.md): the checks that need no database. An integration is a tenant's account for a product described by a definition
// (src/integrations/catalog.js). Settings that are not secret are `config`; secrets are `credentials`, which go in but never come out.
// Every parse function returns { value } or { error: { code, message } } and never throws.
const catalog = require('./catalog');

const LIMITS = { nameMax: 100, perTenant: 50, valueMax: catalog.LIMITS.credentialMax };
const STATUSES = ['not_configured', 'configured', 'disabled'];
const bad = (message, code = 'INVALID_BODY') => ({ error: { code, message } });
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

function parseName(v) {
  if (typeof v !== 'string' || !v.trim() || v.trim().length > LIMITS.nameMax || /[\x00-\x1f\x7f]/.test(v)) return bad(`The name must be 1 to ${LIMITS.nameMax} characters on one line`);
  return { value: v.trim() };
}

// One setting, checked against its field. -> { value } (the stored form) or an error.
function parseConfigValue(f, v) {
  const max = f.max || catalog.LIMITS.configString;
  switch (f.type) {
    case 'boolean': return typeof v === 'boolean' ? { value: v } : bad(`${f.label} must be true or false`);
    case 'enum': return typeof v === 'string' && f.values.includes(v) ? { value: v } : bad(`${f.label} must be one of ${f.values.join(', ')}`);
    case 'url': {
      if (typeof v !== 'string' || !/^https?:\/\//i.test(v.trim()) || /[\s\x00-\x1f\x7f]/.test(v.trim())) return bad(`${f.label} must be an address starting with http:// or https://`);
      let u; try { u = new URL(v.trim()); } catch { return bad(`${f.label} is not a valid address`); }
      if (u.username || u.password) return bad(`${f.label} must not contain a user name or password (use the credentials)`);
      if (!u.hostname) return bad(`${f.label} has no host name`);
      u.hash = '';
      const text = u.href.replace(/\/$/, '');
      return text.length > 2048 ? bad(`${f.label} is too long`) : { value: text };
    }
    default: {
      if (typeof v !== 'string' || !v.trim() || v.trim().length > max || /[\x00-\x1f\x7f]/.test(v)) return bad(`${f.label} must be 1 to ${max} characters on one line`);
      return { value: v.trim() };
    }
  }
}
// body: an object of settings. `create` means every required setting must be there; otherwise only the given ones are checked, `null` removes an optional one.
function parseConfig(def, body, create) {
  if (body === undefined || body === null) body = {};
  if (!isObj(body)) return bad('config must be an object');
  const fields = new Map(def.config.map((f) => [f.name, f]));
  const out = {};
  for (const k of Object.keys(body)) if (!fields.has(k)) return bad(`${k.slice(0, 40)} is not a setting of ${def.name}`);
  for (const [name, f] of fields) {
    if (!has(body, name)) { if (create && f.required) return bad(`${f.label} is required`); continue; }
    if (body[name] === null) { if (f.required) return bad(`${f.label} is required and cannot be removed`); out[name] = null; continue; }
    const r = parseConfigValue(f, body[name]); if (r.error) return r;
    out[name] = r.value;
  }
  return { value: out };
}
function parseCreate(def, body) {
  if (!isObj(body)) return bad('The body must be a JSON object');
  const extra = Object.keys(body).find((k) => !['definition_id', 'name', 'config'].includes(k));
  if (extra) return bad(`Unknown field: ${extra.slice(0, 40)}`);
  const name = parseName(body.name); if (name.error) return name;
  const config = parseConfig(def, body.config, true); if (config.error) return config;
  const stored = Object.fromEntries(Object.entries(config.value).filter(([, v]) => v !== null));
  return { value: { name: name.value, config: stored } };
}
function parsePatch(def, body) {
  if (!isObj(body)) return bad('The body must be a JSON object');
  const extra = Object.keys(body).find((k) => !['name', 'config', 'enabled'].includes(k));
  if (extra) return bad(`${extra.slice(0, 40)} cannot be changed here`);
  const out = {};
  if (has(body, 'name')) { const r = parseName(body.name); if (r.error) return r; out.name = r.value; }
  if (has(body, 'config')) { const r = parseConfig(def, body.config, false); if (r.error) return r; if (Object.keys(r.value).length) out.config = r.value; }
  if (has(body, 'enabled')) { if (typeof body.enabled !== 'boolean') return bad('enabled must be true or false'); out.enabled = body.enabled; }
  return Object.keys(out).length ? { value: out } : bad('Nothing to change');
}

// body: { values: { field: "secret" }, clear: ["field"] }. Secrets are text on one line (a token, a key), trimmed, never echoed in an error.
function parseCredentials(def, body) {
  if (!isObj(body)) return bad('The body must be a JSON object');
  const extra = Object.keys(body).find((k) => !['values', 'clear'].includes(k));
  if (extra) return bad(`Unknown field: ${extra.slice(0, 40)}`);
  const fields = new Map(def.credentials.map((f) => [f.name, f]));
  const values = {}; const clear = [];
  if (has(body, 'values')) {
    if (!isObj(body.values)) return bad('values must be an object');
    for (const [k, v] of Object.entries(body.values)) {
      const f = fields.get(k); if (!f) return bad(`${k.slice(0, 40)} is not a credential of ${def.name}`);
      const max = f.max || catalog.LIMITS.credentialMax;
      if (typeof v !== 'string' || !v.trim() || v.trim().length > max || /[\x00-\x1f\x7f]/.test(v)) return bad(`${f.label} must be 1 to ${max} characters on one line`);   // the value itself is never in the message
      values[k] = v.trim();
    }
  }
  if (has(body, 'clear')) {
    if (!Array.isArray(body.clear) || body.clear.some((k) => typeof k !== 'string' || !fields.has(k))) return bad('clear must be a list of credential names of this integration');
    clear.push(...new Set(body.clear));
  }
  if (!Object.keys(values).length && !clear.length) return bad('Send values to set or clear to remove');
  if (clear.some((k) => has(values, k))) return bad('A credential cannot be set and cleared in the same request');
  return { value: { values, clear } };
}

// not_configured until every required credential is set (and, for a definition that is gone, always); disabled when the owner switched it off.
function statusOf(def, row) {
  if (!row.enabled) return 'disabled';
  if (!def) return 'not_configured';
  const set = new Set(row.credential_fields || []);
  return def.credentials.every((f) => !f.required || set.has(f.name)) ? 'configured' : 'not_configured';
}

module.exports = { LIMITS, STATUSES, parseName, parseConfig, parseCreate, parsePatch, parseCredentials, statusOf };
