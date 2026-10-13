'use strict';
// Module manifest. Copy this file to add a module; the registry loads every file in this folder.
module.exports = {
  id: "ingestion",
  name: "Data collection",
  description: "Collectors, data sources, parsing rules and data model rules.",
  tier: "home",             // lowest edition that includes it: 'home' or 'enterprise'
  entitlement: null,        // license feature that unlocks it; null = no license needed
  status: "available",         // 'available' = backend exists, 'planned' = not built yet
  requires: ["core"],
  permissions: ["collectors:read", "collectors:write", "parsing:rules:read", "parsing:rules:write", "datamodel:rules:read", "datamodel:rules:write"],
  portal_area: "Settings",
};
