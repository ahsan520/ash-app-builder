'use strict';
// Runs the event-store contract against the Postgres adapter and the real events table.
// Needs a Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/event-store-postgres.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const { after } = require('node:test');
const db = require('../src/db');
const { runConformance } = require('./event-store-conformance');
const { PostgresEventStore } = require('../src/events/postgres-store');
const storage = require('../src/storage/retention');

runConformance('postgres', async () => {
  const stamp = Date.now();
  const tenants = [];
  for (const n of ['a', 'b']) tenants.push((await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', [`event-store-${n}-${stamp}`])).rows[0].id);
  const store = new PostgresEventStore({ db });
  return {
    store,
    tenants,
    prepareDay: (day) => storage.ensurePartition(day),            // events for a day go to its own partition once it exists
    // events reference tenants, so remove them first (a far-future cutoff deletes everything of the tenant)
    cleanup: async () => {
      for (const t of tenants) await store.deleteBefore(t, '2999-01-01T00:00:00Z');
      for (const t of tenants) await db.query('DELETE FROM tenants WHERE id = $1', [t]);
    },
  };
});

after(() => db.close());
