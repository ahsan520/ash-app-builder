'use strict';
// Module manifest. Copy this file to add a module; the registry loads every file in this folder.
module.exports = {
  id: "detections",
  name: "Detections",
  description: "BIOC and correlation rules that raise alerts.",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["core", "search"],
  permissions: ["detections:rules:read", "detections:rules:write"],
  portal_area: "Threat Management",
};
