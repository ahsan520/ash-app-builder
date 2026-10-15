'use strict';
// Regenerates tests/fixtures/xql-search-expected.json: what every engine must return for each query in
// tests/fixtures/xql-golden.json over the dataset in xql-dataset.js. It runs the queries on REAL PostgreSQL
// (the engine the platform ships on) and refuses to write unless the in-memory evaluator agrees, so the file
// pins one meaning for the language. Run it only when the language's meaning is changed on purpose:
//   DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/fixtures/gen-xql-search-expected.js
const fs = require('fs');
const path = require('path');
const { parse } = require('../../src/search/xql');
const { MemoryEventStore } = require('../../src/events/memory-store');
const { PostgresEventStore } = require('../../src/events/postgres-store');
const db = require('../../src/db');
const { buildDataset } = require('./xql-dataset');
const { normalizeResult, WINDOWS } = require('../event-search-conformance');
const G = require('./xql-golden.json');

(async () => {
  const ds = buildDataset();
  const A = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['gen-a-' + Date.now()])).rows[0].id;
  const B = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['gen-b-' + Date.now()])).rows[0].id;
  const pg = new PostgresEventStore(), mem = new MemoryEventStore();
  const out = { cases: [] };
  try {
    for (const s of [pg, mem]) { await s.insertBatch(A, ds.events); await s.insertBatch(B, [ds.other]); }
    const queries = [...new Set(G.compile.filter((c) => c.ok).map((c) => c.query))];
    for (const q of queries) for (const [wi, win] of WINDOWS.entries()) {
      const plan = parse(q, { ...win, limit: 50 });
      const run = async (s) => { try { return normalizeResult(plan, await s.search(A, plan), ds.nOf); } catch (e) { return { error: e.code || e.name }; } };
      const [p, m] = [await run(pg), await run(mem)];
      if (JSON.stringify(p) !== JSON.stringify(m)) throw new Error(`engines disagree on ${JSON.stringify(q)} window ${wi}:\n pg  ${JSON.stringify(p)}\n mem ${JSON.stringify(m)}`);
      out.cases.push({ query: q, window: wi, expect: p });
    }
    fs.writeFileSync(path.join(__dirname, 'xql-search-expected.json'), JSON.stringify(out));
    console.log('wrote', out.cases.length, 'cases');
  } finally {
    for (const t of [A, B]) { await db.withTenant(t, (c) => c.query('DELETE FROM events WHERE tenant_id=$1', [t])); await db.query('DELETE FROM tenants WHERE id=$1', [t]); }
    await db.close();
  }
})().catch((e) => { console.error(e); process.exit(1); });
