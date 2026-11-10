'use strict';
// One place where a locked module is refused on the SERVER (docs/licensing.md). While licensing is OFF it lets everything through, whatever the edition: other modules behave exactly as if licensing did not exist. Until now only the menu followed the license; this makes the API follow it too, so a locked feature
// cannot be reached by calling its routes directly. Which module a path belongs to is the table below; everything not in it is baseline (core, ingestion, search, retention,
// capacity, brokers, collectors, parsing, health, modules, authentication) and is never refused here. The data plane (events in, heartbeats, broker config) is mounted before this
// and cannot be switched off by a license. A locked module's data is untouched: it is just not served until a license unlocks it again.
const modules = require('../modules');

const MAP = [
  ['/v1/search', 'search'],
  ['/v1/detections', 'detections'],
  ['/v1/cases', 'cases'], ['/v1/actions', 'actions'],
  ['/v1/alerts', 'alerts'], ['/v1/alert-duplicates', 'alerts'], ['/v1/alert-assignees', 'alerts'], ['/v1/my-alerts', 'alerts'],
  ['/v1/notifications', 'notifications'],
  ['/v1/threat-intel', 'threat-intel'],
  ['/v1/packs', 'content-packs'],
  ['/v1/endpoints', 'endpoints'],
];
const moduleOf = (p) => { for (const [prefix, id] of MAP) if (p === prefix || p.startsWith(prefix + '/')) return id; return null; };

async function gate(req, res, next) {
  const id = moduleOf(req.path);
  if (!id) return next();
  let snap;
  try { snap = await modules.snapshot(); } catch (e) { console.error('Module gate could not read the module state:', e.message); return res.status(503).json({ success: false, error: { code: 'MODULES_ERROR', message: 'The module state could not be read' } }); }
  if (snap.license.mode === 'off') return next();
  const m = snap.modules.find((x) => x.id === id);
  if (m && m.state === 'enabled') return next();
  const why = m && m.reason === 'profile' ? 'This feature belongs to the ' + m.tier + ' edition and needs a license that includes "' + m.license_feature + '" (license status: ' + snap.license.status + ').' : m && m.reason === 'license' ? 'This feature needs a license that includes "' + m.license_feature + '" (license status: ' + snap.license.status + ').' : 'This feature is not available on this installation (' + (m ? m.reason || m.state : 'unknown module') + ').';
  return res.status(403).json({ success: false, error: { code: 'MODULE_LOCKED', message: why, module: id, reason: m ? m.reason : null, license_status: snap.license.status } });
}

module.exports = { gate, moduleOf, MAP };
