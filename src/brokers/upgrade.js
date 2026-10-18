'use strict';
// Broker upgrades, first slice: a target Vector version for the tenant, and which brokers are behind it.
// Pure functions plus two small database helpers. ASIX never runs anything on a broker: the operator runs
// scripts/deploy/upgrade-broker.sh on the VM (the Brokers page gives the command). Nothing here changes a broker.

const VERSION_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

// "0.59.0" -> [0, 59, 0]; anything else (a pre-release, "unknown", empty) -> null.
function parseVersion(v) {
  const m = VERSION_RE.exec(String(v == null ? '' : v).trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

// -1, 0 or 1; null when either side is not a plain x.y.z version.
function compareVersions(a, b) {
  const x = parseVersion(a); const y = parseVersion(b);
  if (!x || !y) return null;
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}

// Validates what the operator typed. Empty or null clears the target. Returns { value } or { error }.
function checkTarget(v) {
  if (v === null || v === undefined || (typeof v === 'string' && v.trim() === '')) return { value: null };
  if (typeof v !== 'string' || !parseVersion(v)) return { error: 'Target version must look like 0.59.0 (three numbers separated by dots), or be empty to clear it' };
  return { value: v.trim() };
}

// current: the Vector version a broker reports (or null); target: the tenant's target (or null).
//   none     no target set, nothing to compare
//   unknown  the broker's version, or the target, is not a plain x.y.z version, so no judgement is made
//   current  same as the target
//   behind   older than the target: needs an upgrade
//   ahead    newer than the target (the target is behind the fleet; not a problem)
function upgradeState(current, target) {
  if (!target) return 'none';
  const c = compareVersions(current, target);
  if (c === null) return 'unknown';
  return c === 0 ? 'current' : c < 0 ? 'behind' : 'ahead';
}

// What to run on the broker VM, as root, from the repo checkout.
const upgradeCommand = (target) => (target
  ? `sudo ./scripts/deploy/upgrade-broker.sh --version ${target}`
  : 'sudo ./scripts/deploy/upgrade-broker.sh   # upgrades to the newest Vector the package repository offers');

async function readTarget(client, tenantId) {
  const r = await client.query('SELECT vector_target FROM broker_settings WHERE tenant_id = $1', [tenantId]);
  return r.rows[0] ? r.rows[0].vector_target || null : null;
}

async function writeTarget(client, tenantId, target, userId = null) {
  await client.query(
    `INSERT INTO broker_settings (tenant_id, vector_target, updated_by) VALUES ($1, $2, $3)
     ON CONFLICT (tenant_id) DO UPDATE SET vector_target = EXCLUDED.vector_target, updated_at = localtimestamp, updated_by = EXCLUDED.updated_by`,
    [tenantId, target, userId ? String(userId) : null]);
  return target;
}

module.exports = { parseVersion, compareVersions, checkTarget, upgradeState, upgradeCommand, readTarget, writeTarget };
