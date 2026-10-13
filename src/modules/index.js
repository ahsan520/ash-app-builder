'use strict';
// Resolves which modules are on for this deployment: profile (deployment shape) + license (entitlements).
// A module is `enabled` only if: its tier is in the profile, its license feature (if any) is granted,
// and every module it requires is enabled. `planned` modules have no backend yet and are never enabled.
const registry = require('./registry');
const profiles = require('./profiles');
const license = require('./license');

// Pure and synchronous, so it is easy to test: no I/O.
function resolve(manifests, profile, lic) {
  const features = new Set((lic && lic.features) || []);
  const byId = new Map();
  const out = [];
  for (const m of manifests) { // manifests are already in dependency order
    let state; let reason = null;
    const tierOk = profile.tiers.includes(m.tier);
    const entitled = !m.entitlement || features.has(m.entitlement);
    if (m.status === 'planned') { state = 'planned'; }
    else if (!tierOk) { state = 'locked'; reason = 'profile'; }
    else if (!entitled) { state = 'locked'; reason = 'license'; }
    else {
      const blocker = m.requires.find((r) => byId.get(r) !== 'enabled');
      if (blocker) { state = 'locked'; reason = 'dependency:' + blocker; } else state = 'enabled';
    }
    byId.set(m.id, state);
    out.push({
      id: m.id, name: m.name, description: m.description, tier: m.tier, status: m.status,
      requires: m.requires, entitlement: m.entitlement, portal_area: m.portal_area,
      state, reason, included_in_profile: tierOk, entitled,
    });
  }
  return out;
}

function effectiveLimits(profile, lic) {
  return { ...profile.default_limits, ...((lic && lic.limits) || {}) };
}

let manifestsCache = null;
let licCache = null;
const TTL_MS = 60 * 1000;

async function snapshot(env = process.env) {
  if (!manifestsCache) manifestsCache = registry.loadDir();
  const profile = profiles.get(env.ASIX_PROFILE);
  if (!profile) throw new Error('ASIX_PROFILE must be one of: ' + Object.keys(profiles.PROFILES).join(', '));
  if (!licCache || Date.now() - licCache.at > TTL_MS) licCache = { at: Date.now(), value: await license.load(env) };
  const lic = licCache.value;
  const modules = resolve(manifestsCache, profile, lic);
  return {
    profile: { id: profile.id, label: profile.label, deployment: profile.deployment },
    license: { status: lic.status, customer: lic.customer || null, expires_at: lic.expires_at || null, features: lic.features, reason: lic.reason || null },
    limits: effectiveLimits(profile, lic),
    modules,
  };
}

async function isEnabled(id, env = process.env) {
  const s = await snapshot(env);
  const m = s.modules.find((x) => x.id === id);
  return !!m && m.state === 'enabled';
}

function resetCache() { manifestsCache = null; licCache = null; }

module.exports = { resolve, effectiveLimits, snapshot, isEnabled, resetCache };
