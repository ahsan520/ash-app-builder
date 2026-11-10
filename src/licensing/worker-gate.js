'use strict';
// Background workers that belong to a licensed module (the rule runner and the IOC matcher) ask here before each cycle, so a lapsed license stops detection and alerting for real, not
// only in the menu (docs/licensing.md). Ingestion, retention, backup and capacity never ask: they keep running. If the module state cannot be read, the worker keeps running (an
// error here must never switch protection off silently) and says so once.
const modules = require('../modules');   // the only module-system call this folder makes besides the hook in src/modules/index.js
const said = new Set();
async function enabled(...ids) {
  try { const s = await modules.snapshot(); return ids.every((id) => { const m = s.modules.find((x) => x.id === id); return !!m && m.state === 'enabled'; }); }
  catch (e) { if (!said.has('err')) { said.add('err'); console.error('[license] module state not readable, workers keep running:', e.message); } return true; }
}
function pausedOnce(tag) { if (!said.has(tag)) { said.add(tag); console.warn(tag + ' paused: the license does not include it (or has lapsed). Ingestion continues; nothing is deleted.'); } }
function resumed(tag) { if (said.delete(tag)) console.log(tag + ' resumed: licensed again.'); }
module.exports = { enabled, pausedOnce, resumed };
