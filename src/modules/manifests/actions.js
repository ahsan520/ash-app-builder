'use strict';
module.exports = {
  id: "actions",
  name: "Action registry",
  description: "The allow-list of things ASIX may do: each action is off until an administrator enables it for a tenant, has a risk class and an autonomy level, and every run is audited.",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["cases"],      // the built-in actions act on cases (docs/actions.md)
  permissions: ["soar:actions:read", "soar:actions:write"],
  portal_area: "Investigation & Response",
  // The Actions page (task SR2, docs/actions.md), a page the module brings itself (docs/portal-shell.md).
  ui: {
    kind: "native",
    entries: [
      { id: "actions", label: "Actions", area: "Settings", group: "Automation", permission: "soar:actions:read", order: 40, page: "actions.js" },
    ],
  },
};
