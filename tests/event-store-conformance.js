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
