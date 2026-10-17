'use strict';
// The parse step of the HTTP ingest lane as a pure function: parsing rules, then the data model pass.
// The API process (inline mode) and the parser workers (src/ingestion/parser-worker.js) both call this,
// so a batch gives the same result wherever it runs. Nothing here touches the database or the network.
//
//   parseItems(parsingSets, modelSets, sourceType, items) -> { kept, dropped }
//
// items are { raw, time (ISO|null), parsed }. kept are { raw, time, parsed, source_type } (a parsing rule can
// move an event to another dataset). A parsing rule can also drop an event: that only counts in `dropped`.
const parsingRules = require('./parsing-rules');

function parseItems(parsingSets, modelSets, sourceType, items) {
  const kept = [];
  let dropped = 0;
  for (const it of items) {
    const o = parsingRules.apply(parsingSets, { source_type: sourceType, raw: it.raw, time: it.time, parsed: it.parsed });
    if (o.dropped) { dropped++; continue; }
    // Data model pass: maps the parsed fields onto XDM (parsed.xdm.*). It never throws.
    const mo = parsingRules.applyModel(modelSets, { source_type: o.source_type, raw: it.raw, time: o.time, parsed: o.parsed });
    if (mo.xdm) o.parsed.xdm = mo.xdm;
    kept.push({ raw: it.raw, time: o.time, parsed: o.parsed, source_type: o.source_type });
  }
  return { kept, dropped };
}

module.exports = { parseItems };
