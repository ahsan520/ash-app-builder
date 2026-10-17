'use strict';
// ClickHouse partition retention without a server: the store talks HTTP through an injected fetch, so the SQL it sends and
// how it reacts to an error from ClickHouse can be checked in CI's plain `test` job. (The real-server version of the same
// behaviour is in tests/event-store-clickhouse.test.js and tests/retention-clickhouse.test.js.)
const { describe, it } = require('node:test');
const assert = require('assert');
const { ClickHouseEventStore } = require('../src/events/clickhouse-store');

// parts: system.parts rows (what `SELECT partition AS p, ...` returns); failOn: partition ids whose DROP ClickHouse refuses
function fakeStore(parts, failOn = []) {
  const sent = [];
  const fetch = async (url, init) => {
    const sql = new URL(url).searchParams.get('query') || String(init.body);
    sent.push(sql);
    if (/FROM system\.parts/.test(sql)) return { ok: true, status: 200, text: async () => parts.map((r) => JSON.stringify(r)).join('\n') };
    const m = /DROP PARTITION ID '(\d+)'/.exec(sql);
    if (m && failOn.includes(m[1])) return { ok: false, status: 500, text: async () => 'Code: 359. DB::Exception: Table or Partition in asix.events was not dropped. Reason: size (60.00 GiB) is greater than max_[partition_]size_to_drop (50.00 GiB)' };
    return { ok: true, status: 200, text: async () => '' };
  };
  return { store: new ClickHouseEventStore({ url: 'http://default:ci@127.0.0.1:8123/asix', table: 'events', fetch }), sent };
}
const parts = [
  { p: '20261016', rows: 5, bytes: 500 }, { p: '20261015', rows: 7, bytes: 700 },
  { p: '20260101', rows: 9, bytes: 900 }, { p: '20250101', rows: 11, bytes: 1100 }, { p: 'tuple()', rows: 1, bytes: 10 },
];

describe('ClickHouse partition retention (stubbed HTTP)', () => {
  it('storageStats turns system.parts into whole UTC days and ignores partitions that are not days', async () => {
    const { store, sent } = fakeStore(parts);
    const st = await store.storageStats();
    assert.deepStrictEqual(st.partitions.map((p) => [p.name, p.from, p.to, p.rows, p.bytes]), [
      ['20261016', '2026-10-16', '2026-10-17', 5, 500], ['20261015', '2026-10-15', '2026-10-16', 7, 700],
      ['20260101', '2026-01-01', '2026-01-02', 9, 900], ['20250101', '2025-01-01', '2025-01-02', 11, 1100]]);
    assert.deepStrictEqual([st.partitioned, st.events_rows, st.events_bytes, st.default_partition_rows], [true, 32, 3200, 0]);
    assert.ok(/database = \{d:String\} AND table = \{tb:String\} AND active/.test(sent[0]), 'only active parts of this table');
  });

  it('dropPartitionsBefore drops the days before the cut-off, oldest first, with ALTER TABLE DROP PARTITION ID', async () => {
    const { store, sent } = fakeStore(parts);
    const r = await store.dropPartitionsBefore('2026-10-16');                 // 2025-01-01, 2026-01-01, 2026-10-15 go; 2026-10-16 stays
    assert.deepStrictEqual(r, { dropped: ['20250101', '20260101', '20261015'], failed: [] });
    assert.deepStrictEqual(sent.filter((q) => /DROP/.test(q)), [
      "ALTER TABLE events DROP PARTITION ID '20250101'", "ALTER TABLE events DROP PARTITION ID '20260101'", "ALTER TABLE events DROP PARTITION ID '20261015'"]);
  });

  it('a partition ClickHouse refuses to drop is reported and the other days still go', async () => {
    const { store } = fakeStore(parts, ['20250101']);
    const r = await store.dropPartitionsBefore('2026-10-16');
    assert.deepStrictEqual(r.dropped, ['20260101', '20261015']);
    assert.strictEqual(r.failed.length, 1);
    assert.strictEqual(r.failed[0].name, '20250101');
    assert.match(r.failed[0].error, /359.*not dropped/);
  });

  it('never builds SQL from a day string that is not a calendar date', async () => {
    const { store, sent } = fakeStore(parts);
    await assert.rejects(store.dropPartitionsBefore("2026-10-16'; DROP TABLE events"), (e) => e.code === 'INVALID_QUERY');
    assert.strictEqual(sent.length, 0);
  });
});
