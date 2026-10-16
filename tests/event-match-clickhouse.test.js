'use strict';
// The rule-match contract against a real ClickHouse server (same setup as tests/event-store-clickhouse.test.js):
//   ASIX_TEST_DB=1 ASIX_CLICKHOUSE_URL=http://default:pass@127.0.0.1:8123/asix node tests/event-match-clickhouse.test.js
// Skips itself otherwise. Uses a throwaway events_test_<random> table and drops only that.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 and ASIX_CLICKHOUSE_URL to run against ClickHouse)'); process.exit(0); }
if (!process.env.ASIX_CLICKHOUSE_URL) { console.error('ASIX_TEST_DB=1 needs ASIX_CLICKHOUSE_URL, e.g. http://default:pass@127.0.0.1:8123/asix'); process.exit(1); }

const crypto = require('crypto');
const { runMatchConformance } = require('./event-match-conformance');
const { ClickHouseEventStore } = require('../src/events/clickhouse-store');

runMatchConformance('clickhouse', async () => {
  const table = `events_test_${crypto.randomBytes(6).toString('hex')}`;
  const store = new ClickHouseEventStore({ table });
  await store.ensureSchema();
  return {
    store,
    tenants: [crypto.randomUUID(), crypto.randomUUID()],
    cleanup: async () => { await store._exec(`DROP TABLE IF EXISTS ${table}`); await store.close(); },
  };
});
