'use strict';
// ATT&CK per alert for lists (E4g, shared with "My open alerts" in E4i): what is stored on the alert (E4f) through the safe view; an alert with none stored takes it from its
// sample events, read in batches of 500 through the event store (the same rule as the alert page). A failed read means "none", never a failed list. The raw columns are not returned.
// rows need `mitre_stored` (details->'mitre') and `sample_ids` (details->'sample_event_ids'); both are removed from what comes back and `mitre` is added.
const { getEventStore } = require('../events');
const { mitreOfEvents, mitreView } = require('../endpoints/endpoint-alerts');
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function withMitre(tenantId, rows) {
  const lacking = rows.filter((r) => { const m = mitreView(r.mitre_stored); return !m.techniques.length && !m.tactics.length; });
  const ids = [...new Set(lacking.flatMap((r) => (Array.isArray(r.sample_ids) ? r.sample_ids : []).filter((i) => typeof i === 'string' && UUID_RE.test(i))))];
  const byId = new Map();
  try {
    for (let i = 0; i < ids.length; i += 500) for (const e of await getEventStore().getByIds(tenantId, ids.slice(i, i + 500))) byId.set(e.id, e);
  } catch (error) { console.error('Alert list ATT&CK lookup failed:', error.message); }
  return rows.map(({ mitre_stored: stored, sample_ids: sample, ...row }) => {
    let m = mitreView(stored);
    if (!m.techniques.length && !m.tactics.length) m = mitreView(mitreOfEvents((Array.isArray(sample) ? sample : []).map((i) => byId.get(i)).filter(Boolean)));
    return { ...row, mitre: m };
  });
}

module.exports = { withMitre };
