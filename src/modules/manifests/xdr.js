'use strict';
// Module manifest. Copy this file to add a module; the registry loads every file in this folder.
module.exports = {
  id: "xdr",
  name: "XDR",
  description: "Endpoint, identity and cloud telemetry with behavioural analytics.",
  tier: "enterprise",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: "xdr",        // license feature that unlocks it; null = no license needed
  status: "planned",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["ingestion"],
  permissions: [],
  portal_area: "Investigation & Response",
};
