'use strict';
// Module manifest. Copy this file to add a module; the registry loads every file in this folder.
module.exports = {
  id: "soar",
  name: "SOAR playbooks",
  description: "Automated, approval-gated response playbooks.",
  tier: "enterprise",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: "soar",        // license feature that unlocks it; null = no license needed
  status: "planned",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["alerts"],
  permissions: [],
  portal_area: "Investigation & Response",
};
