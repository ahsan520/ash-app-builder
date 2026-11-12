'use strict';
// IOC feeds (docs/ioc-feeds.md): the checks that need no database. Every parse function returns { value } or { error: { code, message } }.
const bad = (message, code = 'INVALID_BODY') => ({ error: { code, message } });
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

const SEVERITIES = ['low', 'medium', 'high', 'critical'];   // the same words as src/gateway/routes/threat-intel.js
const INTERVALS = [1, 6, 12, 24];
const LIMITS = { nameMax: 100, perTenant: 20, ttlMin: 1, ttlMax: 365, runsKept: 100, leaseMinutes: 15, shrinkFloor: 20, shrinkRatio: 0.2, runsPage: 100 };

const parseName = (v) => (typeof v !== 'string' || !v.trim() || v.trim().length > LIMITS.nameMax || /[\x00-\x1f\x7f]/.test(v) ? bad(`The name must be 1 to ${LIMITS.nameMax} characters on one line`) : { value: v.trim() });
const parseSeverity = (v) => (SEVERITIES.includes(v) ? { value: v } : bad(`severity must be one of ${SEVERITIES.join(', ')}`));
const parseTtl = (v) => (Number.isInteger(v) && v >= LIMITS.ttlMin && v <= LIMITS.ttlMax ? { value: v } : bad(`ttl_days must be a whole number from ${LIMITS.ttlMin} to ${LIMITS.ttlMax}`));
const parseInterval = (v) => (INTERVALS.includes(v) ? { value: v } : bad(`interval_hours must be one of ${INTERVALS.join(', ')}`));

function parseCreate(body, uuidRe) {
  if (!isObj(body)) return bad('The body must be a JSON object');
  const extra = Object.keys(body).find((k) => !['integration_id', 'name', 'severity', 'ttl_days', 'interval_hours'].includes(k));
  if (extra) return bad(`Unknown field: ${extra.slice(0, 40)}`);
  if (typeof body.integration_id !== 'string' || !uuidRe.test(body.integration_id)) return bad('integration_id must be the id of a threat feed integration');
  const name = parseName(body.name); if (name.error) return name;
  const sev = parseSeverity(has(body, 'severity') ? body.severity : 'medium'); if (sev.error) return sev;
  const ttl = parseTtl(has(body, 'ttl_days') ? body.ttl_days : 30); if (ttl.error) return ttl;
  const iv = parseInterval(has(body, 'interval_hours') ? body.interval_hours : 24); if (iv.error) return iv;
  return { value: { integration_id: body.integration_id, name: name.value, severity: sev.value, ttl_days: ttl.value, interval_hours: iv.value } };
}
function parsePatch(body) {
  if (!isObj(body)) return bad('The body must be a JSON object');
  const extra = Object.keys(body).find((k) => !['name', 'severity', 'ttl_days', 'interval_hours', 'enabled'].includes(k));
  if (extra) return bad(`${extra.slice(0, 40)} cannot be changed`);
  const out = {};
  for (const [k, fn] of [['name', parseName], ['severity', parseSeverity], ['ttl_days', parseTtl], ['interval_hours', parseInterval]]) if (has(body, k)) { const r = fn(body[k]); if (r.error) return r; out[k] = r.value; }
  if (has(body, 'enabled')) { if (typeof body.enabled !== 'boolean') return bad('enabled must be true or false'); out.enabled = body.enabled; }
  return Object.keys(out).length ? { value: out } : bad('Nothing to change');
}
function parseRun(body) {
  if (body === undefined || body === null) return { value: { force: false } };
  if (!isObj(body) || Object.keys(body).some((k) => k !== 'force')) return bad('Only force can be sent');
  if (has(body, 'force') && typeof body.force !== 'boolean') return bad('force must be true or false');
  return { value: { force: !!body.force } };
}
// A feed that suddenly lists far fewer indicators than last time is more likely broken (an error page, an empty file) than truly emptied.
const shrank = (previous, now) => previous != null && previous >= LIMITS.shrinkFloor && now < previous * LIMITS.shrinkRatio;

module.exports = { SEVERITIES, INTERVALS, LIMITS, parseName, parseCreate, parsePatch, parseRun, shrank };
