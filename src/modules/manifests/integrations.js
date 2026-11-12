'use strict';
module.exports = {
  id: "integrations",
  name: "Integrations",
  description: "A tenant's accounts for other products (firewalls, threat feeds, enrichment): settings and write-only credentials, status Not configured until an account is added.",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",         // 'available' = backend exists, 'planned' = not built yet
  requires: [],
  permissions: ["soar:integrations:read", "soar:integrations:write"],
  portal_area: "Settings",
  // The Integrations page (task SR1, docs/integrations.md), a page the module brings itself (docs/portal-shell.md).
  ui: {
    kind: "native",
    entries: [
      { id: "integrations", label: "Integrations", area: "Settings", group: "Integrations", permission: "soar:integrations:read", order: 40, page: "integrations.js" },
    ],
  },
};
