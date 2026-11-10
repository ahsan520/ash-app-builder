'use strict';
// Module manifest. Licensing is a module like any other: its code is in src/licensing/, its page is src/portal/modules/licensing/license.js, and nothing else in the platform depends on it.
// It needs no license itself (the License page must always open), and it can be OFF: a development build is off until an admin switches it on (docs/licensing.md).
module.exports = {
  id: "licensing",
  name: "License",
  description: "Installation id, stored licenses and what the active license unlocks. Off on a development build until switched on; always on in a release build.",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",      // 'available' = backend exists, 'planned' = not built yet
  requires: [],
  permissions: ["license:read", "license:write"],
  portal_area: "Settings",
  ui: {
    kind: "native",
    entries: [
      { id: "license", label: "License", area: "Settings", group: "General", permission: "license:read", order: 90, page: "license.js" },
    ],
  },
};
