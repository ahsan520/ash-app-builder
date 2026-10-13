'use strict';
// Module manifest. Copy this file to add a module; the registry loads every file in this folder.
module.exports = {
  id: "dashboards",
  name: "Dashboards & reports",
  description: "Command Center dashboards over ingested events and alerts.",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["core", "search"],
  permissions: ["search:events:read"],
  portal_area: "Dashboards & Reports",
};
