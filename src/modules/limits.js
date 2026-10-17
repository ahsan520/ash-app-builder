'use strict';
// Enforcing the numeric limits of the license (or the profile defaults when there is no valid license):
//   tenants             how many tenants may exist (null = unlimited)
//   retention_days_max  the longest time events may be kept, in days (null = unlimited)
// Pure functions, no I/O, so they are easy to test. Rules that keep this safe:
//   * Enforcement happens when someone SAVES something. An expired or removed license never deletes or
//     hides data, and never changes a setting that is already stored; the portal and API report it instead
//     ("over limit") so a person decides.
//   * "Keep forever" counts as longer than any cap, so it needs `retention_days_max: null`.
//   * A missing or unknown limit means unlimited (fail open for a limit key this code does not know about).
const profiles = require('./profiles');

const isCap = (v) => Number.isInteger(v) && v > 0;

// The limits to enforce right now. Never throws: if the module snapshot cannot be built (for example a
// bad ASIX_PROFILE) the Home defaults apply, which are the strictest.
async function currentLimits(snapshotFn) {
  try {
    const s = await (snapshotFn || (() => require('./index').snapshot()))();
    if (s && s.limits) return s.limits;
  } catch { /* fall through to the Home defaults */ }
  return { ...profiles.get('home').default_limits };
}

// body: the retention PUT body, already shape-checked. Returns null when allowed, else { code, message, limit }.
function checkRetentionChange(body, limits) {
  const cap = limits && limits.retention_days_max;
  if (!isCap(cap)) return null;
  const msg = (what) => `${what} is longer than this installation's retention limit of ${cap} days. A license that raises the limit is needed to keep events longer.`;
  const b = body || {};
  if (b.default_days !== undefined && b.default_days > cap) return { code: 'LICENSE_LIMIT', limit: 'retention_days_max', message: msg('The default retention of ' + b.default_days + ' days') };
  if (Array.isArray(b.overrides)) {
    for (const o of b.overrides) {
      if (o.retention_days === null) return { code: 'LICENSE_LIMIT', limit: 'retention_days_max', message: `Keeping "${o.source_type}" forever is not allowed: this installation's retention limit is ${cap} days. A license that raises the limit is needed.` };
      if (o.retention_days > cap) return { code: 'LICENSE_LIMIT', limit: 'retention_days_max', message: msg(`Retention of ${o.retention_days} days for "${o.source_type}"`) };
    }
  }
  return null;
}

// What is already stored and above the cap (so the portal can say so). policy is storage.loadPolicy()'s result.
function retentionOverLimit(policy, limits) {
  const cap = limits && limits.retention_days_max;
  if (!isCap(cap) || !policy) return [];
  const out = [];
  if (policy.default_days > cap) out.push({ scope: 'default', days: policy.default_days, limit: cap });
  for (const o of policy.overrides || []) {
    if (o.retention_days === null || o.retention_days > cap) out.push({ scope: o.source_type, days: o.retention_days, limit: cap });
  }
  return out;
}

// Creating one more tenant when `count` exist. For the tenant-creation code to call before it inserts.
function checkTenantCreate(count, limits) {
  const cap = limits && limits.tenants;
  if (!isCap(cap) || count < cap) return null;
  return { code: 'LICENSE_LIMIT', limit: 'tenants', message: `This installation is limited to ${cap} tenant${cap === 1 ? '' : 's'} and ${count} already exist${count === 1 ? 's' : ''}. A license that raises the limit is needed to add another.` };
}

// Usage next to the limits, for the Modules page. usage: { tenants }.
function usageReport(limits, usage) {
  const rows = [];
  const cap = limits && limits.tenants;
  if (isCap(cap) && usage && Number.isInteger(usage.tenants) && usage.tenants > cap) rows.push({ limit: 'tenants', used: usage.tenants, allowed: cap });
  return rows;
}

module.exports = { currentLimits, checkRetentionChange, retentionOverLimit, checkTenantCreate, usageReport };
