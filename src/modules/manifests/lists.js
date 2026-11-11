'use strict';
module.exports = {
  id: "lists",
  name: "Lists",
  description: "Block, allow and watch lists of addresses, domain names, URLs and file hashes, with an address a firewall can poll.",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",         // 'available' = backend exists, 'planned' = not built yet
  requires: [],
  permissions: ["soar:lists:read", "soar:lists:write"],
  portal_area: "Investigation & Response",
  // The Lists page (task L1, docs/lists.md), a page the module brings itself (docs/portal-shell.md).
  ui: {
    kind: "native",
    entries: [
      { id: "lists", label: "Lists", area: "Threat Management", group: "Lists", permission: "soar:lists:read", order: 30, page: "lists.js" },
    ],
  },
};
