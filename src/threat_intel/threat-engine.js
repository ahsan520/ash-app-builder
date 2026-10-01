// Phase 9 — Threat Intelligence / IOC / Watchlists / Reputation / Feeds (MISP / OpenCTI — API-only / external)
// Level 0 — framework; MISP/OpenCTI handled externally (AGPL — docs/open-source-stack.md); AI never gets unrestricted feed access
class ThreatIntelligence {
  ingestIOC(ioc = {}, source = 'misp', user = 'unknown', tenant = 'unknown') {
    return {
      ingested: true,
      ioc_type: ioc.type || 'unknown',
      value: ioc.value || 'unknown',
      reputation: ioc.reputation || 'unknown',
      source,
      feed_ref: source,
      user,
      tenant,
      ingested_at: new Date().toISOString(),
      audit_event: 'threat:ioc:ingest',
      external_integration: source === 'misp' || source === 'opencti'
    };
  }
  queryReputation(query = '', feed = 'opencti', user = 'unknown', tenant = 'unknown') {
    return {
      reputation: 'unknown',
      threat_actor: null,
      feed,
      query,
      user,
      tenant,
      queried_at: new Date().toISOString(),
      audit_event: 'threat:reputation:query',
      external_integration: true,
      note: 'Result requires external feed (MISP / OpenCTI API) — not stored in local DB for licensing/AGPL separation'
    };
  }
  addWatchlist(ioc = {}, user = 'unknown', tenant = 'unknown') {
    return {
      watchlisted: true,
      alert_on_match: true,
      ioc_ref: ioc.value || ioc.type || 'unknown',
      user,
      tenant,
      added_at: new Date().toISOString(),
      audit_event: 'threat:watchlist:add'
    };
  }
  removeWatchlist(iocRef = '') {
    return { removed: true, ioc_ref: iocRef, audit_event: 'threat:watchlist:remove' };
  }
  listWatchlists(tenant = 'unknown') {
    return { watchlists: [], tenant, audit_event: 'threat:watchlist:list' };
  }
}

class ThreatFeed {
  subscribe(feedName = 'misp', user = 'unknown', tenant = 'unknown') {
    return { subscribed: true, feed: feedName, user, tenant, audit_event: 'threat:feed:subscribe', external_agpl_note: 'MISP/OpenCTI API-only; no local replication required' };
  }
  sync(feedName = 'misp') {
    return { sync_started: true, feed: feedName, audit_event: 'threat:feed:sync', status: 'pending_external' };
  }
}

module.exports = { ThreatIntelligence, ThreatFeed };
