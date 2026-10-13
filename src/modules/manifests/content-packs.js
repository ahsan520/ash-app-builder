'use strict';
// Module manifest. Copy this file to add a module; the registry loads every file in this folder.
module.exports = {
  id: "content-packs",
  name: "Content packs",
  description: "Installable bundles of rules, parsers and dashboards (residential packs first).",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "planned",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["detections", "ingestion"],
  permissions: [],
  portal_area: "Modules",
};
