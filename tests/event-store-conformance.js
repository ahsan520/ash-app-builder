'use strict';
// The event-store contract as a test suite. Every adapter must pass it unchanged:
//
//   const { runConformance } = require('./event-store-conformance');
//   runConformance('my-adapter', async () => ({ store, tenants: [uuidA, uuidB], cleanup: async () => {} }));
//
// `setup` returns a fresh store and two tenant ids the store accepts. See tests/event-store-memory.test.js
// (runs in CI) and tests/event-store-postgres.test.js (needs ASIX_TEST_DB=1). Not named *.test.js on
// purpose: it is a library, not a test file of its own.

const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');

const T0 = Date.parse('2026-10-01T00:00:00.000Z');
const iso = (minutes) => new Date(T0 + minutes * 60000).toISOString();
const uuid = () => crypto.randomUUID();
const instant = (s) => (s === null ? null : Date.parse(s));

// an event with an explicit id + received_at (so ordering and idempotency are deterministic)
const ev = (minutes, over = {}) => ({
  id: uuid(), received_at: iso(minutes), event_time: iso(minutes - 1),
  source_type: 'syslog', collector_id: 'c1', raw: `line at ${minutes}`, parsed: { n: minutes }, ...over,
});

function runConformance(label, setup) {
  describe(`event store conformance: ${label}`, () => {
    let store; let A; let B; let cleanup;
    before(async () => { ({ store, tenants: [A, B], cleanup } = await setup()); });
    after(async () => { if (cleanup) await cleanup(); });

    it('round-trips every envelope field', async () => {
      const e = ev(1, { raw: 'Failed password for root', parsed: { host: 'web01', xdm: { source: { ipv4: '203.0.113.9' } }, tags: ['a', 'b'], n: 1.5, ok: true, none: null } });
      const r = await store.insertBatch(A, [e]);
      assert.deepStrictEqual(r, { inserted: 1, skipped: 0, ids: [e.id] });
      const [got] = await store.getByIds(A, [e.id]);
      assert.strictEqual(got.v, 1);
      assert.strictEqual(got.id, e.id);
      assert.strictEqual(got.tenant_id, A);
      assert.strictEqual(got.source_type, 'syslog');
      assert.strictEqual(got.collector_id, 'c1');
      assert.strictEqual(got.raw, 'Failed password for root');
      assert.strictEqual(instant(got.received_at), instant(e.received_at));
      assert.strictEqual(instant(got.event_time), instant(e.event_time));
      assert.deepStrictEqual(got.parsed, e.parsed);
    });

    it('assigns ids and received_at when missing, ids come back in input order', async () => {
      const before = Date.now();
      const r = await store.insertBatch(A, [{ source_type: 'x-assign', raw: 'one' }, { source_type: 'x-assign', raw: 'two', collector_id: null, event_time: null }]);
      assert.strictEqual(r.inserted, 2);
      assert.strictEqual(r.ids.length, 2);
      assert.notStrictEqual(r.ids[0], r.ids[1]);
      const got = await store.getByIds(A, r.ids);
      assert.deepStrictEqual(got.map((g) => g.raw), ['one', 'two']);
      assert.strictEqual(got[0].collector_id, null);
      assert.strictEqual(got[1].event_time, null);
      assert.deepStrictEqual(got[0].parsed, {});
      // stamped "now" (allow a generous skew for databases whose clock is not this process's)
      assert.ok(Math.abs(instant(got[0].received_at) - before) < 5 * 60000, 'received_at is about now');
    });

    it('is idempotent on (id, received_at)', async () => {
      const e = ev(2, { raw: 'once' });
      assert.strictEqual((await store.insertBatch(A, [e])).inserted, 1);
      const again = await store.insertBatch(A, [e, ev(2, { raw: 'twin' })]);
      assert.strictEqual(again.inserted, 1, 'only the new event is stored');
      assert.strictEqual(again.skipped, 1);
      assert.strictEqual((await store.getByIds(A, [e.id])).length, 1);
    });

    it('rejects bad input and stores nothing from a bad batch', async () => {
      const good = ev(3, { source_type: 'x-atomic' });
      await assert.rejects(store.insertBatch(A, [good, { source_type: 'x-atomic' }]), (e) => e.code === 'INVALID_ENVELOPE' && /event 1/.test(e.message));
      assert.strictEqual(await store.count(A, { source_type: 'x-atomic' }), 0);
      await assert.rejects(store.insertBatch(A, [{ ...ev(3), id: uuid(), received_at: undefined }]), (e) => e.code === 'INVALID_ENVELOPE');
      await assert.rejects(store.insertBatch(A, [{ ...ev(3), event_time: 'yesterday' }]), (e) => e.code === 'INVALID_ENVELOPE');
      await assert.rejects(store.insertBatch(A, [{ ...ev(3), parsed: [1] }]), (e) => e.code === 'INVALID_ENVELOPE');
      await assert.rejects(store.insertBatch(A, [{ ...ev(3), tenant_id: B }]), (e) => e.code === 'INVALID_ENVELOPE', 'cannot write into another tenant');
      await assert.rejects(store.insertBatch('not-a-uuid', [ev(3)]), (e) => e.code === 'INVALID_TENANT');
      await assert.rejects(store.insertBatch(A, 'nope'), (e) => e.code === 'INVALID_BATCH');
      assert.deepStrictEqual(await store.insertBatch(A, []), { inserted: 0, skipped: 0, ids: [] });
    });

    it('strips NUL characters instead of failing the batch', async () => {
      const r = await store.insertBatch(A, [{ source_type: 'x-nul', raw: 'ab\u0000cd', parsed: { k: 'v\u0000w', 'a\u0000b': 1 } }]);
      const [got] = await store.getByIds(A, r.ids);
      assert.strictEqual(got.raw, 'abcd');
      assert.deepStrictEqual(got.parsed, { k: 'vw', ab: 1 });
    });

    it('keeps tenants apart', async () => {
      const mine = ev(10, { source_type: 'x-iso', raw: 'tenant A only' });
      await store.insertBatch(A, [mine]);
      await store.insertBatch(B, [ev(10, { source_type: 'x-iso-b', raw: 'tenant B only' })]);
      assert.deepStrictEqual(await store.getByIds(B, [mine.id]), []);
      assert.strictEqual(await store.count(B, { source_type: 'x-iso' }), 0);
      assert.strictEqual((await store.scan(B, { source_type: 'x-iso' })).events.length, 0);
      assert.ok(!(await store.sourceTypes(B)).includes('x-iso'));
      assert.ok((await store.sourceTypes(A)).includes('x-iso'));
      assert.deepStrictEqual((await store.deleteBefore(B, iso(100000))).deleted >= 1, true);
      assert.strictEqual((await store.getByIds(A, [mine.id])).length, 1, 'deleting B did not touch A');
    });

    describe('scan, count and sourceTypes', () => {
      const DS = 'x-scan';
      const ids = [];
      before(async () => {
        // 10 events, minutes 20..29; minutes 24 and 25 each have TWO events (same received_at, ordered by id)
        const batch = [];
        for (let m = 20; m < 30; m++) batch.push(ev(m, { source_type: DS, collector_id: m % 2 ? 'odd' : 'even' }));
        batch.push(ev(24, { source_type: DS, collector_id: 'even' }), ev(25, { source_type: DS, collector_id: 'odd' }));
        batch.push(ev(26, { source_type: 'x-scan-other', collector_id: 'odd' }));
        await store.insertBatch(A, batch);
        ids.push(...batch.filter((b) => b.source_type === DS).map((b) => b.id));
      });

      const pageAll = async (q) => {
        const seen = []; let after = null; let pages = 0;
        do {
          const r = await store.scan(A, { ...q, after });
          seen.push(...r.events); after = r.next; pages++;
          assert.ok(pages < 50, 'paging terminates');
        } while (after);
        return { seen, pages };
      };
      const inOrder = (events, dir) => events.every((e, i) => i === 0 || (() => {
        const p = events[i - 1];
        const c = instant(p.received_at) - instant(e.received_at) || (p.id < e.id ? -1 : p.id > e.id ? 1 : 0);
        return dir === 'asc' ? c < 0 : c > 0;
      })());

      it('pages through everything exactly once, ascending, including ties', async () => {
        const { seen, pages } = await pageAll({ source_type: DS, limit: 3 });
        assert.strictEqual(seen.length, 12);
        assert.strictEqual(new Set(seen.map((e) => e.id)).size, 12, 'no duplicates across pages');
        assert.deepStrictEqual(new Set(seen.map((e) => e.id)), new Set(ids), 'nothing missing');
        assert.ok(inOrder(seen, 'asc'));
        assert.strictEqual(pages, 4, '12 rows at 3 per page: the last page is full and reports no next');
      });

      it('pages descending', async () => {
        const { seen } = await pageAll({ source_type: DS, limit: 5, order: 'desc' });
        assert.strictEqual(seen.length, 12);
        assert.ok(inOrder(seen, 'desc'));
      });

      it('filters: since is inclusive, until is exclusive, source_type and collector_id', async () => {
        const r = await store.scan(A, { source_type: DS, since: iso(22), until: iso(25), limit: 100 });
        assert.deepStrictEqual(r.events.map((e) => instant(e.received_at)).sort(), [22, 23, 24, 24].map((m) => instant(iso(m))));
        assert.strictEqual(r.next, null);
        assert.strictEqual((await store.scan(A, { source_type: DS, collector_id: 'odd', limit: 100 })).events.length, 6);
        assert.strictEqual(await store.count(A, { source_type: DS }), 12);
        assert.strictEqual(await store.count(A, { source_type: DS, collector_id: 'even' }), 6);
        assert.strictEqual(await store.count(A, { source_type: DS, since: iso(22), until: iso(25) }), 4);
        assert.strictEqual(await store.count(A, { source_type: 'x-does-not-exist' }), 0);
      });

      it('lists distinct source types, sorted, optionally since a time', async () => {
        const all = await store.sourceTypes(A);
        assert.ok(all.includes(DS) && all.includes('x-scan-other'));
        assert.deepStrictEqual([...all].sort(), all);
        assert.strictEqual(new Set(all).size, all.length);
        const recent = await store.sourceTypes(A, { since: iso(26) });
        assert.ok(recent.includes('x-scan-other') && recent.includes(DS));
        assert.ok(!(await store.sourceTypes(A, { since: iso(27) })).includes('x-scan-other'));
      });

      it('validates query arguments', async () => {
        for (const bad of [{ limit: 0 }, { limit: -1 }, { limit: 1.5 }, { limit: '5' }, { order: 'sideways' }, { since: 'soon' }, { after: 'garbage' }, { source_type: 5 }]) {
          await assert.rejects(store.scan(A, bad), (e) => e.code === 'INVALID_QUERY' || e.code === 'INVALID_CURSOR', JSON.stringify(bad));
        }
        await assert.rejects(store.getByIds(A, ['nope']), (e) => e.code === 'INVALID_QUERY');
        assert.strictEqual((await store.scan(A, { limit: 100000 })).events.length <= 1000, true, 'limit above the maximum is clamped');
      });
    });

    describe('groupCounts, timeRange and fieldStats', () => {
      // all in tenant A, in a window (minutes 5000..6500) that no other test uses
      const WIN = { since: iso(5000), until: iso(6501) };
      const day = (m) => iso(m).slice(0, 10);
      before(async () => {
        await store.insertBatch(A, [
          ev(5000, { source_type: 'x-gc1', collector_id: 'gc-a' }), ev(5001, { source_type: 'x-gc1', collector_id: 'gc-a' }), ev(5059, { source_type: 'x-gc1', collector_id: 'gc-a' }),
          ev(5010, { source_type: 'x-gc1', collector_id: 'gc-b' }), ev(5010, { source_type: 'x-gc1', collector_id: 'gc-b' }),   // two with the same time
          ev(5020, { source_type: 'x-gc2', collector_id: null }),                                                                // no collector
          ev(5030, { source_type: 'x-gc2', collector_id: 'gc-a' }),
          ev(6500, { source_type: 'x-gc3', collector_id: 'gc-c' }),                                                              // the next day
        ]);
      });
      const shape = (rows) => rows.map((r) => [r.key, r.events, instant(r.first_seen), instant(r.last_seen)]);

      it('counts per collector, with first and last time; events without a collector are not a group', async () => {
        assert.deepStrictEqual(shape(await store.groupCounts(A, { by: 'collector_id', ...WIN })), [
          ['gc-a', 4, instant(iso(5000)), instant(iso(5059))], ['gc-b', 2, instant(iso(5010)), instant(iso(5010))], ['gc-c', 1, instant(iso(6500)), instant(iso(6500))]]);
      });

      it('counts per source type, most events first', async () => {
        assert.deepStrictEqual(shape(await store.groupCounts(A, { by: 'source_type', ...WIN })), [
          ['x-gc1', 5, instant(iso(5000)), instant(iso(5059))], ['x-gc2', 2, instant(iso(5020)), instant(iso(5030))], ['x-gc3', 1, instant(iso(6500)), instant(iso(6500))]]);
      });

      it('counts per UTC day, oldest day first', async () => {
        const rows = await store.groupCounts(A, { by: 'day', ...WIN });
        assert.deepStrictEqual(rows.map((r) => [r.key, r.events]), [[day(5000), 7], [day(6500), 1]]);
        assert.notStrictEqual(day(5000), day(6500), 'the fixture spans two days');
      });

      it('since is inclusive and until is exclusive', async () => {
        const rows = await store.groupCounts(A, { by: 'collector_id', since: iso(5010), until: iso(5059) });
        assert.deepStrictEqual(rows.map((r) => [r.key, r.events]), [['gc-b', 2], ['gc-a', 1]]);   // 5000 and 5001 are before since, 5059 is not before until
        assert.deepStrictEqual(await store.groupCounts(A, { by: 'source_type', since: iso(9000), until: iso(9001) }), []);
      });

      it('only counts this tenant', async () => {
        assert.deepStrictEqual(await store.groupCounts(B, { by: 'collector_id', ...WIN }), []);
      });

      it('validates its arguments', async () => {
        for (const bad of [{}, { by: 'host' }, { by: 5 }, { by: 'day', since: 'soon' }, null]) {
          await assert.rejects(store.groupCounts(A, bad), (e) => e.code === 'INVALID_QUERY', JSON.stringify(bad));
        }
      });

      it('timeRange: the oldest and newest event, or nulls for a tenant with none', async () => {
        const r = await store.timeRange(A);
        assert.ok(instant(r.oldest) <= instant(iso(5000)) && instant(r.newest) >= instant(iso(6500)));
        assert.match(r.oldest, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
        assert.deepStrictEqual(await store.timeRange(uuid()), { oldest: null, newest: null });
      });

      describe('fieldStats', () => {
        // the newest events of tenant A (far in the future, so nothing else is newer), plus one in tenant B
        const parsed = [
          { host: 'h1', app_name: 'sshd', xdm: { source: { ipv4: '1.1.1.1' }, event: { type: 'authentication' } } },
          { host: 'h2', app_name: 'sshd', xdm: { source: { ipv4: '2.2.2.2' } } },
          { host: 'h3', n: 5 },
          { host: 'h4', tags: ['a', 'b'], xdm: { tags: ['x'], nothing: {} } },     // an array is a leaf, an empty object has none
          { host: 'h5', xdm: 'not an object' },                                      // counts as a field, gives no xdm paths
        ];
        before(async () => {
          await store.insertBatch(A, parsed.map((p, i) => ev(900001 + i, { source_type: 'x-fs', parsed: p })));
          await store.insertBatch(B, [ev(900010, { source_type: 'x-fs', parsed: { only_in_b: 1, xdm: { b: { secret: 1 } } } })]);
        });
        const pairs = (rows) => rows.map((r) => [r.name, r.events]);

        it('counts top-level keys and xdm leaf paths, most events first, ties by name', async () => {
          const r = await store.fieldStats(A, { sample: 5, xdmSample: 3 });   // 3: my three events with an xdm object (older tests left others)
          assert.deepStrictEqual(pairs(r.fields), [['host', 5], ['xdm', 4], ['app_name', 2], ['n', 1], ['tags', 1]]);
          assert.deepStrictEqual(pairs(r.xdm), [['xdm.source.ipv4', 2], ['xdm.event.type', 1], ['xdm.tags', 1]]);
        });

        it('`sample` takes the newest events; `xdmSample` the newest ones that have an xdm object', async () => {
          const r = await store.fieldStats(A, { sample: 3, xdmSample: 2 });
          assert.deepStrictEqual(pairs(r.fields), [['host', 3], ['xdm', 2], ['n', 1], ['tags', 1]]);        // events 3, 4 and 5 only
          assert.deepStrictEqual(pairs(r.xdm), [['xdm.source.ipv4', 1], ['xdm.tags', 1]]);                  // events 4 and 2 (5 has xdm but not an object)
        });

        it('never shows another tenant\'s fields', async () => {
          const r = await store.fieldStats(A, { sample: 10, xdmSample: 10 });
          assert.ok(!r.fields.some((f) => f.name === 'only_in_b') && !r.xdm.some((f) => f.name.startsWith('xdm.b')));
          const b = await store.fieldStats(B, { sample: 1, xdmSample: 1 });
          assert.deepStrictEqual(pairs(b.fields), [['only_in_b', 1], ['xdm', 1]]);
          assert.deepStrictEqual(pairs(b.xdm), [['xdm.b.secret', 1]]);
        });

        it('has defaults and validates its arguments', async () => {
          const d = await store.fieldStats(A);
          assert.ok(Array.isArray(d.fields) && Array.isArray(d.xdm));
          assert.deepStrictEqual(await store.fieldStats(uuid()), { fields: [], xdm: [] });
          for (const bad of [{ sample: 0 }, { sample: '5' }, { sample: 1.5 }, { sample: 10001 }, { xdmSample: -1 }, { xdmSample: 5001 }, null]) {
            await assert.rejects(store.fieldStats(A, bad), (e) => e.code === 'INVALID_QUERY', JSON.stringify(bad));
          }
        });
      });
    });

    it('scan returns a checkpoint cursor that resumes exactly after the last event, however many arrive meanwhile', async () => {
      const mk = (m) => ev(m, { source_type: 'x-ckpt' });
      await store.insertBatch(A, [mk(600), mk(601), mk(602), mk(603)]);
      const first = await store.scan(A, { source_type: 'x-ckpt', limit: 2 });
      assert.strictEqual(first.events.length, 2);
      assert.ok(first.cursor, 'a page with events has a checkpoint');
      await store.insertBatch(A, [mk(604)]);
      const rest = await store.scan(A, { source_type: 'x-ckpt', after: first.cursor, limit: 100 });
      assert.deepStrictEqual(rest.events.map((e) => e.raw), ['line at 602', 'line at 603', 'line at 604'], 'nothing twice, nothing missed');
      assert.strictEqual(rest.cursor && typeof rest.cursor, 'string');
      const empty = await store.scan(A, { source_type: 'x-ckpt', after: rest.cursor });
      assert.deepStrictEqual([empty.events.length, empty.next, empty.cursor], [0, null, null]);
    });

    it('deletes only events older than the cutoff', async () => {
      const mk = (m) => ev(m, { source_type: 'x-del' });
      const [e1, e2, e3] = [mk(40), mk(41), mk(42)];
      await store.insertBatch(A, [e1, e2, e3]);
      const r = await store.deleteBefore(A, iso(41));
      assert.ok(r.deleted >= 1);
      assert.strictEqual(await store.count(A, { source_type: 'x-del' }), 2);
      assert.deepStrictEqual((await store.getByIds(A, [e1.id])), []);
      assert.strictEqual((await store.getByIds(A, [e2.id, e3.id])).length, 2, 'the cutoff itself is kept');
      await assert.rejects(store.deleteBefore(A, undefined), (e) => e.code === 'INVALID_QUERY');
    });
  });
}

module.exports = { runConformance };
