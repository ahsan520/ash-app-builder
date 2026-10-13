'use strict';
// Module manifest. Copy this file to add a module; the registry loads every file in this folder.
module.exports = {
  id: "ai-assistant",
  name: "AI assistant",
  description: "Assistant for investigation and rule authoring.",
  tier: "enterprise",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: "ai",        // license feature that unlocks it; null = no license needed
  status: "planned",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["search"],
  permissions: [],
  portal_area: "Settings",
};
