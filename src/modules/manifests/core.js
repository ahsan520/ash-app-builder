'use strict';
// Module manifest. Copy this file to add a module; the registry loads every file in this folder.
module.exports = {
  id: "core",
  name: "Core platform",
  description: "Login, tenants, roles, audit, settings and platform status.",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",         // 'available' = backend exists, 'planned' = not built yet
  requires: [],
  permissions: ["auth:identity:read", "settings:access:read"],
  portal_area: "Settings",
};
