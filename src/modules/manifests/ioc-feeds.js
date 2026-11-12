'use strict';
module.exports = {
  id: "ioc-feeds",
  name: "IOC feeds",
  description: "Scheduled import of an indicator feed (address list, CSV or JSON) into the IOC store: normalise, score, expire what the feed no longer lists, and record what changed.",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["threat-intel", "integrations"],
  permissions: ["threatintel:feeds:read", "threatintel:feeds:write"],
  portal_area: "Threat Management",
  // The IOC feeds page (docs/ioc-feeds.md), a page the module brings itself (docs/portal-shell.md).
  ui: {
    kind: "native",
    entries: [
      { id: "ioc-feeds", label: "IOC feeds", area: "Threat Management", group: "Feeds", permission: "threatintel:feeds:read", order: 40, page: "feeds.js" },
    ],
  },
};
