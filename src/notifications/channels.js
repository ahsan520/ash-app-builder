'use strict';
// Channel configuration: validation, secret handling and the public (masked) view.
const net = require('net');
const { checkUrl, addressAllowed } = require('./net-guard');

const TYPES = ['email', 'slack', 'webhook'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const FORMATS = ['json', 'teams', 'pagerduty'];
const SECRET_FIELDS = { email: ['password'], slack: ['webhook_url'], webhook: ['url', 'signing_secret', 'routing_key'] };
const FORBIDDEN_HEADERS = new Set(['host', 'content-length', 'content-type', 'connection', 'transfer-encoding', 'x-asix-signature', 'x-asix-timestamp']);
const EMAIL_RE = /^[^\s@<>()",;:]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
const HOST_RE = /^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const bad = (message) => Object.assign(new Error(message), { code: 'INVALID_CONFIG' });
const str = (v, max = 500) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

function normalizeHeaders(h, existing = {}) {
  if (h === undefined) return existing;
  if (!h || typeof h !== 'object' || Array.isArray(h)) throw bad('headers must be an object of name: value');
  const out = {};
  for (const [k, v] of Object.entries(h)) {
    if (!/^[A-Za-z0-9-]{1,60}$/.test(k)) throw bad(`Invalid header name "${k}"`);
    if (FORBIDDEN_HEADERS.has(k.toLowerCase())) throw bad(`Header "${k}" is set by ASIX and cannot be overridden`);
    const val = v === '' && existing[k] !== undefined ? existing[k] : String(v);   // blank = keep stored value
    if (/[\r\n]/.test(val) || val.length > 1000) throw bad(`Invalid value for header "${k}"`);
    out[k] = val;
  }
  if (Object.keys(out).length > 10) throw bad('At most 10 custom headers');
  return out;
}

// merged = previous config overlaid with the request; blank/absent secrets keep their stored value.
function normalizeConfig(type, input, previous = {}) {
  if (!TYPES.includes(type)) throw bad('type must be one of ' + TYPES.join(', '));
  const c = input && typeof input === 'object' ? input : {};
  const pick = (name, fallback = '') => (c[name] === undefined ? previous[name] ?? fallback : c[name]);
  const secret = (name) => (str(c[name], 2000) !== '' ? str(c[name], 2000) : previous[name] || '');

  if (type === 'email') {
    const host = str(pick('host'), 253), port = Number(pick('port', 587)), security = str(pick('security', 'starttls'), 10);
    if (!HOST_RE.test(host) && !net.isIP(host)) throw bad('SMTP host is required');
    if (net.isIP(host) && !addressAllowed(host)) throw bad('SMTP host is a blocked (internal/loopback/link-local) address');
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw bad('SMTP port must be 1-65535');
    if (!['starttls', 'tls', 'none'].includes(security)) throw bad('security must be starttls, tls or none');
    const from = str(pick('from'), 254);
    if (!EMAIL_RE.test(from)) throw bad('From must be a valid email address');
    const toRaw = pick('to', []);
    const to = (Array.isArray(toRaw) ? toRaw : String(toRaw).split(/[,;\s]+/)).map((x) => String(x).trim()).filter(Boolean);
    if (!to.length || to.length > 20 || !to.every((x) => EMAIL_RE.test(x))) throw bad('To must be 1-20 valid email addresses');
    const username = str(pick('username'), 200), password = secret('password');
    return { host, port, security, from, to, username, password, allow_self_signed: pick('allow_self_signed', false) === true };
  }
  if (type === 'slack') {
    const webhook_url = secret('webhook_url');
    if (!webhook_url) throw bad('Slack webhook URL is required');
    try { checkUrl(webhook_url); } catch (e) { throw bad('Webhook URL: ' + e.message); }
    return { webhook_url };
  }
  const url = secret('url'), format = str(pick('format', 'json'), 12);
  if (!url) throw bad('Webhook URL is required');
  if (!FORMATS.includes(format)) throw bad('format must be one of ' + FORMATS.join(', '));
  try { checkUrl(url); } catch (e) { throw bad('Webhook URL: ' + e.message); }
  const routing_key = secret('routing_key');
  if (format === 'pagerduty' && !routing_key) throw bad('PagerDuty needs a routing (integration) key');
  return { url, format, headers: normalizeHeaders(c.headers, previous.headers), signing_secret: secret('signing_secret'), routing_key };
}

function validateCommon(b, previous = {}) {
  const name = b.name === undefined ? previous.name : str(b.name, 100);
  if (!/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,99}$/.test(name || '')) throw bad('Name: 1-100 chars, letters, digits, space . _ -');
  const min_severity = b.min_severity === undefined ? previous.min_severity || 'high' : b.min_severity;
  if (!SEVERITIES.includes(min_severity)) throw bad('min_severity must be one of ' + SEVERITIES.join(', '));
  const rf = b.rule_filter === undefined ? previous.rule_filter : b.rule_filter;
  const rule_filter = rf ? str(rf, 100) : null;
  const enabled = b.enabled === undefined ? previous.enabled ?? true : b.enabled === true;
  return { name, min_severity, rule_filter, enabled };
}

// What the API returns: no secret values, only which ones are set, and a safe target summary.
function toPublic(row, config) {
  const secrets = SECRET_FIELDS[row.type] || [];
  const cfg = { ...config };
  const set = secrets.filter((s) => cfg[s]);
  secrets.forEach((s) => delete cfg[s]);
  if (row.type === 'webhook') { cfg.headers = Object.fromEntries(Object.keys(config.headers || {}).map((k) => [k, ''])); }
  let target = '';
  try {
    if (row.type === 'email') target = `${config.to.join(', ')} via ${config.host}:${config.port}`;
    if (row.type === 'slack') target = new URL(config.webhook_url).hostname;
    if (row.type === 'webhook') target = `${new URL(config.url).hostname} (${config.format})`;
  } catch { target = '(unreadable)'; }
  return { id: row.id, name: row.name, type: row.type, enabled: row.enabled, min_severity: row.min_severity, rule_filter: row.rule_filter,
    created_at: row.created_at, updated_at: row.updated_at, config: cfg, secrets_set: set, target,
    last_delivery_status: row.last_delivery_status || null, last_delivery_at: row.last_delivery_at || null };
}

module.exports = { TYPES, SEVERITIES, FORMATS, normalizeConfig, validateCommon, toPublic };
