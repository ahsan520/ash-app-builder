'use strict';
// Module manifest. Copy this file to add a module; the registry loads every file in this folder.
module.exports = {
  id: "threat-intel",
  name: "Threat intelligence",
  description: "Indicator library and IOC matching against new events.",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["detections"],
  permissions: ["threatintel:read", "threatintel:write"],
  portal_area: "Threat Management",
};
