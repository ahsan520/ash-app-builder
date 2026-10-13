'use strict';
// Module manifest. Copy this file to add a module; the registry loads every file in this folder.
module.exports = {
  id: "search",
  name: "Log search",
  description: "XQL log search over stored events.",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["core"],
  permissions: ["search:events:read"],
  portal_area: "Investigation & Response",
};
