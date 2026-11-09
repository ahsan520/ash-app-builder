'use strict';
// Module manifest. Copy this file to add a module; the registry loads every file in this folder.
module.exports = {
  id: "content-packs",
  name: "Content packs",
  description: "Installable bundles of detection rules (residential packs first; parsers and dashboards come later).",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["detections", "ingestion"],
  permissions: ["detections:rules:read", "detections:rules:write"],
  portal_area: "Modules",
  // The Marketplace page (task MK2, docs/portal-shell.md): the first page a module brings itself. The older "Content packs" page
  // in the main menu stays until the Marketplace has been seen working in a real browser.
  ui: {
    kind: "native",
    entries: [
      { id: "marketplace", label: "Marketplace", area: "Main", permission: "detections:rules:read", order: 60, page: "marketplace.js" },
    ],
  },
};
