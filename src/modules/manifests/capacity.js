'use strict';
// Module manifest. Copy this file to add a module; the registry loads every file in this folder.
module.exports = {
  id: "capacity",
  name: "Capacity & scaling",
  description: "Capacity history and scaling recommendations.",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["core"],
  permissions: ["capacity:read"],
  portal_area: "Settings",
};
