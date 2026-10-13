'use strict';
// Deployment profiles. Same codebase, different shape. "deployment" is descriptive in this step
// (it tells the portal and docs what the profile is for); the data-plane work in Phase 2/3 reads it.
// default_limits apply when no valid license is present. null means unlimited.
const PROFILES = {
  home: {
    id: 'home', label: 'Home', tiers: ['home'],
    deployment: { storage: 'postgres', queue: 'none', archive: 'local disk', ingest: 'direct', ha: false },
    // ASSUMPTION: retention cap value is a placeholder until the licensing decision is made (docs/product-plan.md).
    default_limits: { tenants: 1, retention_days_max: 90 },
  },
  enterprise: {
    id: 'enterprise', label: 'Enterprise', tiers: ['home', 'enterprise'],
    deployment: { storage: 'clickhouse cluster', queue: 'kafka', archive: 's3', ingest: 'broker vms', ha: true },
    default_limits: { tenants: 1, retention_days_max: 90 },
  },
};

function get(id) {
  const p = PROFILES[String(id || 'home').toLowerCase()];
  return p || null;
}

module.exports = { PROFILES, get };
