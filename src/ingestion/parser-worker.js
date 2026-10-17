'use strict';
// Worker thread entry for the parser pool (src/ingestion/parser-pool.js). Do not require this file.
//
// Messages in:  { id, rulesKey, rules?: { parsing, model }, sourceType, items }
// Messages out: { id, ok: true, kept, dropped, ms }
//               { id, need_rules: true }          the worker has no rules for rulesKey: send them with the job
//               { id, ok: false, error }          the batch failed (the worker itself is fine)
// The worker keeps the compiled rules of the last few rule sets it saw, keyed by rulesKey (a hash of the rule
// text), so the rule text is sent once per worker instead of with every batch.
const { parentPort, workerData } = require('worker_threads');
const { buildSets } = require('./rule-sets');
const { parseItems } = require('./parse-batch');

const MAX_CACHED = Math.max(1, Number((workerData && workerData.maxCachedRulesets) || 32));
const cache = new Map(); // rulesKey -> { parsingSets, modelSets }; insertion order is least recently used first

parentPort.on('message', (m) => {
  try {
    let entry = cache.get(m.rulesKey);
    if (entry) {
      cache.delete(m.rulesKey); cache.set(m.rulesKey, entry);
    } else if (m.rules) {
      entry = buildSets(m.rules);
      cache.set(m.rulesKey, entry);
      while (cache.size > MAX_CACHED) cache.delete(cache.keys().next().value);
    } else {
      parentPort.postMessage({ id: m.id, need_rules: true });
      return;
    }
    const t0 = Date.now();
    const out = parseItems(entry.parsingSets, entry.modelSets, m.sourceType, m.items);
    parentPort.postMessage({ id: m.id, ok: true, kept: out.kept, dropped: out.dropped, ms: Date.now() - t0 });
  } catch (e) {
    parentPort.postMessage({ id: m.id, ok: false, error: String((e && e.message) || e) });
  }
});
