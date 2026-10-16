'use strict';
// The rule-match contract against the Postgres adapter and the real events table.
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/event-match-postgres.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const { after } = require('node:test');
const db = require('../src/db');
const { runMatchConformance } = require('./event-match-conformance');
const { PostgresEventStore } = require('../src/events/postgres-store');

runMatchConformance('postgres', async () => {
  const stamp = Date.now();
  const tenants = [];
  for (const n of ['a', 'b']) tenants.push((await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', [`event-match-${n}-${stamp}`])).rows[0].id);
  const store = new PostgresEventStore({ db });
  return {
    store, tenants,
    cleanup: async () => {
      for (const t of tenants) await store.deleteBefore(t, '2999-01-01T00:00:00Z');
      for (const t of tenants) await db.query('DELETE FROM tenants WHERE id = $1', [t]);
    },
  };
});

after(() => db.close());
