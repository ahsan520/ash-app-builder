// Phase 4 — Normalization / Enrichment / Parser (ECS/OCSF target)
class NormalizationEngine {
  parse(event, parserProfile) { return { normalized: true, schema: 'ECS/OCSF', fields: event, parser: parserProfile }; }
  enrich(event, context) { return { enriched: true, asset_context: context.asset, user_context: context.user, threat_context: context.ioc, geo: context.geo }; }
  route(event, rules) { return { routed: true, target: rules.target || 'open/search' }; }
}
module.exports = { NormalizationEngine };
