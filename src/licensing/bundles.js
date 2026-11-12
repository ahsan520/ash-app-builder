'use strict';
// The license feature names, grouped into the two products a license is sold as (docs/licensing.md). A manifest's `entitlement` is one of these names; null means the BASELINE:
// the modules every installation has with no license at all (core, ingestion, search, retention, capacity). `scripts/license-tool.js sign ... @residential` expands to RESIDENTIAL.
const RESIDENTIAL = ['search', 'detections', 'alerts', 'cases', 'actions', 'lists', 'integrations', 'ioc-feeds', 'content-packs', 'dashboards', 'notifications', 'threat-intel'];
const ENTERPRISE_ONLY = ['endpoints', 'xdr', 'soar', 'posture', 'compliance', 'ai', 'multi-tenant'];
const BUNDLES = { '@residential': RESIDENTIAL, '@enterprise': [...RESIDENTIAL, ...ENTERPRISE_ONLY] };
const ALL = [...RESIDENTIAL, ...ENTERPRISE_ONLY];
// Which module a residential feature unlocks. The module manifests do NOT know about licensing: this table is the only place a home-tier module is tied to a license feature, so a
// module can be built, renamed or removed without touching licensing, and licensing can be off without any module noticing. A manifest that names its own `entitlement` (the
// enterprise modules do) wins over this table. A module in neither place is baseline (core, ingestion, retention, capacity) and needs no license.
const FEATURE_OF = { search: 'search', detections: 'detections', alerts: 'alerts', cases: 'cases', actions: 'actions', lists: 'lists', integrations: 'integrations', 'ioc-feeds': 'ioc-feeds', 'content-packs': 'content-packs', dashboards: 'dashboards', notifications: 'notifications', 'threat-intel': 'threat-intel' };
const featureFor = (m) => m.entitlement || FEATURE_OF[m.id] || null;
module.exports = { RESIDENTIAL, ENTERPRISE_ONLY, BUNDLES, ALL, FEATURE_OF, featureFor };
