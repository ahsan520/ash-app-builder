'use strict';
// Module manifest. Endpoint protection and monitoring: agents on Windows and Linux machines, their alerts, vulnerabilities, file integrity, group settings (docs/endpoints.md).
module.exports = {
  id: "endpoints",
  name: "Endpoints",
  description: "Agents on Windows and Linux machines: alerts, vulnerabilities, file integrity, log collection settings and group configuration.",
  tier: "enterprise",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: "endpoints",       // license feature that unlocks it; null = no license needed
  status: "available",            // 'available' = backend exists, 'planned' = not built yet
  requires: ["ingestion"],
  permissions: [],
  portal_area: "Investigation & Response",
};
