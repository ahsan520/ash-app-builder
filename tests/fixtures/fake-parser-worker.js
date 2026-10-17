'use strict';
// A stand-in parser worker for tests/parser-pool.test.js and tests/parse-ingest-db.test.js. It answers like the real
// one, except that the first event's raw text can ask for bad behaviour:
//   'hang'  never answers (the pool must time it out)      'crash'  throws outside the message handler
//   'oom'   allocates until its memory cap is hit          anything else: echoes the events back as kept
const { parentPort } = require('worker_threads');
parentPort.on('message', (m) => {
  const raw = m.items[0] && m.items[0].raw;
  if (raw === 'hang') return;
  if (raw === 'crash') { setImmediate(() => { throw new Error('boom'); }); return; }
  if (raw === 'oom') { const hog = []; for (;;) hog.push(new Array(1e6).fill('x')); }
  parentPort.postMessage({ id: m.id, ok: true, kept: m.items.map((i) => ({ ...i, source_type: m.sourceType })), dropped: 0, ms: 0 });
});
