'use strict';
// Module manifest. Copy this file to add a module; the registry loads every file in this folder.
module.exports = {
  id: "compliance",
  name: "Compliance",
  description: "Compliance reporting and audit export.",
  tier: "enterprise",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: "compliance",        // license feature that unlocks it; null = no license needed
  status: "planned",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["core"],
  permissions: [],
  portal_area: "Settings",
};
