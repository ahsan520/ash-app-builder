'use strict';
module.exports = {
  id: "cases",
  name: "Cases",
  description: "Group alerts into a case with an owner, a status, notes and a timeline.",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["alerts"],
  permissions: ["alerts:read", "alerts:write"],   // the same two as Alerts: no role changes are needed
  portal_area: "Cases & Issues",
  // The Cases page (task CS1, docs/cases.md), a page the module brings itself (docs/portal-shell.md).
  ui: {
    kind: "native",
    entries: [
      { id: "cases", label: "Cases", area: "Main", permission: "alerts:read", order: 30, page: "cases.js" },
    ],
  },
};
