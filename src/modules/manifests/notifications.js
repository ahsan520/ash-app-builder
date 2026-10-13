'use strict';
// Module manifest. Copy this file to add a module; the registry loads every file in this folder.
module.exports = {
  id: "notifications",
  name: "Notifications",
  description: "Email, Slack and webhook delivery of new alerts.",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["alerts"],
  permissions: ["notify:read", "notify:write"],
  portal_area: "Settings",
};
