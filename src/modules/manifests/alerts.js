'use strict';
// Module manifest. Copy this file to add a module; the registry loads every file in this folder.
module.exports = {
  id: "alerts",
  name: "Alerts",
  description: "Alert list, detail and status handling.",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["detections"],
  permissions: ["alerts:read", "alerts:write"],
  portal_area: "Cases & Issues",
};
