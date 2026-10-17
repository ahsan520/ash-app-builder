'use strict';
// Copies events from one event store to another, per tenant, and checks every event it wrote.
// Phase 3: this is what makes switching ASIX_EVENT_STORE from postgres to clickhouse (or back) safe for an install that has history.
//
//   node src/events/copy-events.js --from postgres --to clickhouse                  all tenants, all events
//   node src/events/copy-events.js --from postgres --to clickhouse --dry-run        count what would be copied, write nothing
//   ... --tenant <uuid>   one tenant     --since <ISO>  --until <ISO>   only events received in that window (since inclusive)
//   ... --batch 500       events per round trip (1 to 1000)               --no-verify   skip reading the copies back
//
// In the cluster: k3s kubectl -n asix-platform exec deploy/asix-api -- node src/events/copy-events.js --from postgres --to clickhouse
// (the API pods have both databases' settings; the tenant list comes from PostgreSQL). Exit code 0 only if nothing failed or differed.
//
// How it works: events are read from the source with scan() (stable order, cursor), and each batch is
//   1. looked up in the destination BY ID: events already there are left alone, so the tool can be run again and again, also after the API
//      has been switched over (that is how events that arrived during the copy are caught up), and a copy back never duplicates
//      events that came from the other side (ClickHouse keeps received_at to the millisecond, PostgreSQL to the microsecond, so the
//      store's own (id, received_at) idempotency is not enough here);
//   2. inserted into the destination with the same id, received_at and fields;
//   3. read back from the destination and compared (source type, collector, raw, parsed, event time, received time).
// Nothing is deleted from either store.
const { FACTORIES } = require('./index');
const { isDeepStrictEqual } = require('util');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const COMPARED = ['source_type', 'collector_id', 'raw', 'parsed', 'event_time', 'received_at'];
const MAX_EXAMPLES = 5;

// What differs between a source event and its copy, as field names. Times are compared to the millisecond.
function differences(a, b) {
  const out = [];
  for (const f of COMPARED) {
    let x = a[f] ?? null, y = b[f] ?? null;
    if ((f === 'event_time' || f === 'received_at') && x !== null && y !== null) { x = new Date(x).getTime(); y = new Date(y).getTime(); }
    if (!isDeepStrictEqual(x, y)) out.push(f);
  }
  return out;
}

// Copies one tenant. from / to are event stores. Returns { read, copied, already_there, verified, mismatches, missing, examples, ... }.
async function copyTenant(from, to, tenantId, opts = {}) {
  const batch = opts.batch || 500;
  const verify = opts.verify !== false;
  const r = { tenant_id: tenantId, read: 0, copied: 0, already_there: 0, would_copy: 0, verified: 0, missing: 0, mismatches: 0, examples: [], first_received: null, last_received: null };
  let after = null;
  for (;;) {
    const page = await from.scan(tenantId, { since: opts.since, until: opts.until, limit: batch, after, order: 'asc' });
    if (!page.events.length) break;
    const events = page.events;
    r.read += events.length;
    r.first_received = r.first_received || events[0].received_at;
    r.last_received = events[events.length - 1].received_at;

    const there = new Set((await to.getByIds(tenantId, events.map((e) => e.id))).map((e) => e.id));
    const fresh = events.filter((e) => !there.has(e.id));
    r.already_there += events.length - fresh.length;
    if (opts.dryRun) r.would_copy += fresh.length;
    else if (fresh.length) {
      const res = await to.insertBatch(tenantId, fresh.map((e) => ({ ...e })));
      r.copied += res.inserted;
      // inserted < fresh.length only when the destination already held that (id, received_at): same event, nothing lost
      r.already_there += fresh.length - res.inserted;
    }

    if (verify && !opts.dryRun) {
      const copies = new Map((await to.getByIds(tenantId, events.map((e) => e.id))).map((e) => [e.id, e]));
      for (const e of events) {
        const c = copies.get(e.id);
        if (!c) { r.missing++; if (r.examples.length < MAX_EXAMPLES) r.examples.push({ id: e.id, problem: 'not in the destination after the copy' }); continue; }
        // An event that was already there is compared too (it may be a different event with a reused id: say so, do not overwrite it).
        const d = differences(e, c);
        if (d.length) { r.mismatches++; if (r.examples.length < MAX_EXAMPLES) r.examples.push({ id: e.id, problem: 'differs in ' + d.join(', ') }); } else r.verified++;
      }
    }
    if (opts.onProgress) opts.onProgress(r);
    if (!page.next) break;
    after = page.next;
  }
  return r;
}

// tenants: [{ id, name? }]. Returns { tenants: [result...], totals, ok }.
async function copyAll(from, to, tenants, opts = {}) {
  const results = [];
  const totals = { read: 0, copied: 0, already_there: 0, would_copy: 0, verified: 0, missing: 0, mismatches: 0, failed_tenants: 0 };
  for (const t of tenants) {
    let r;
    try { r = await copyTenant(from, to, t.id, opts); }
    catch (e) { r = { tenant_id: t.id, error: `${e.code ? e.code + ': ' : ''}${e.message}`, read: 0, copied: 0, already_there: 0, would_copy: 0, verified: 0, missing: 0, mismatches: 0, examples: [] }; totals.failed_tenants++; }
    r.name = t.name || null;
    results.push(r);
    for (const k of ['read', 'copied', 'already_there', 'would_copy', 'verified', 'missing', 'mismatches']) totals[k] += r[k];
  }
  return { tenants: results, totals, ok: totals.failed_tenants === 0 && totals.missing === 0 && totals.mismatches === 0 };
}

// ---- command line ------------------------------------------------------------------------------------------------
function parseArgs(argv) {
  const a = { batch: 500, verify: true, dryRun: false };
  const need = (i, flag) => { if (i + 1 >= argv.length) throw new Error(`${flag} needs a value`); return argv[i + 1]; };
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    if (f === '--from') a.from = need(i++, f).toLowerCase();
    else if (f === '--to') a.to = need(i++, f).toLowerCase();
    else if (f === '--tenant') a.tenant = need(i++, f).toLowerCase();
    else if (f === '--since') a.since = need(i++, f);
    else if (f === '--until') a.until = need(i++, f);
    else if (f === '--batch') a.batch = Number(need(i++, f));
    else if (f === '--dry-run') a.dryRun = true;
    else if (f === '--no-verify') a.verify = false;
    else if (f === '-h' || f === '--help') a.help = true;
    else throw new Error(`unknown option ${f}`);
  }
  if (a.help) return a;
  const stores = Object.keys(FACTORIES).filter((n) => n !== 'memory');
  for (const [flag, v] of [['--from', a.from], ['--to', a.to]]) if (!stores.includes(v)) throw new Error(`${flag} must be one of: ${stores.join(', ')}`);
  if (a.from === a.to) throw new Error('--from and --to are the same store');
  if (!Number.isInteger(a.batch) || a.batch < 1 || a.batch > 1000) throw new Error('--batch must be a whole number from 1 to 1000');
  if (a.tenant && !UUID_RE.test(a.tenant)) throw new Error('--tenant must be a tenant id (UUID)');
  for (const [flag, v] of [['--since', a.since], ['--until', a.until]]) if (v !== undefined && Number.isNaN(Date.parse(v))) throw new Error(`${flag} must be a date and time, for example 2026-10-17T00:00:00Z`);
  return a;
}

const USAGE = `Usage: node src/events/copy-events.js --from <postgres|clickhouse> --to <postgres|clickhouse> [--tenant <uuid>] [--since <ISO>] [--until <ISO>] [--batch 1-1000] [--dry-run] [--no-verify]`;

async function main(argv, log = console.log) {
  let args;
  try { args = parseArgs(argv); } catch (e) { log(`copy-events: ${e.message}\n${USAGE}`); return 2; }
  if (args.help) { log(USAGE); return 0; }

  const db = require('../db');
  const started = new Date();
  try {
    const from = FACTORIES[args.from](), to = FACTORIES[args.to]();
    await from.init(); await to.init();
    const tenants = args.tenant
      ? (await db.query('SELECT id, name FROM tenants WHERE id = $1', [args.tenant])).rows
      : (await db.query('SELECT id, name FROM tenants ORDER BY created_at, id')).rows;
    if (!tenants.length) { log(args.tenant ? 'copy-events: no such tenant' : 'copy-events: no tenants found'); return 1; }

    log(`${args.dryRun ? 'DRY RUN: ' : ''}copying events ${args.from} -> ${args.to} for ${tenants.length} tenant(s)` +
      `${args.since ? ', received since ' + args.since : ''}${args.until ? ' until ' + args.until : ''}, batches of ${args.batch}${args.verify && !args.dryRun ? ', each copy read back and compared' : ''}`);
    let lastPrint = 0;
    const res = await copyAll(from, to, tenants, {
      batch: args.batch, since: args.since, until: args.until, dryRun: args.dryRun, verify: args.verify,
      onProgress: (r) => { if (r.read - lastPrint >= 10000) { lastPrint = r.read; log(`  ... ${r.read} events read so far for the current tenant`); } if (r.read < lastPrint) lastPrint = 0; },
    });
    for (const r of res.tenants) {
      const label = `${r.name || '(unnamed)'} ${r.tenant_id}`;
      if (r.error) { log(`FAILED   ${label}: ${r.error}`); continue; }
      const bits = args.dryRun ? `would copy ${r.would_copy}, already there ${r.already_there}` : `copied ${r.copied}, already there ${r.already_there}${args.verify ? `, verified ${r.verified}` : ''}`;
      const bad = r.missing || r.mismatches ? `  PROBLEMS: ${r.missing} missing, ${r.mismatches} different` : '';
      log(`${bad ? 'CHECK   ' : 'ok      '} ${label}: read ${r.read}, ${bits}${bad}`);
      for (const x of r.examples) log(`           ${x.id}: ${x.problem}`);
    }
    const t = res.totals;
    log(`total: read ${t.read}, ${args.dryRun ? 'would copy ' + t.would_copy : 'copied ' + t.copied}, already there ${t.already_there}` +
      `${args.verify && !args.dryRun ? ', verified ' + t.verified : ''}${t.failed_tenants ? `, ${t.failed_tenants} tenant(s) FAILED` : ''}`);
    if (!args.dryRun) {
      log(`Events that arrive in the source while this runs, or after it, are not in the copy. After switching ASIX_EVENT_STORE, or to catch up first, run it again with --since ${new Date(started.getTime() - 5 * 60000).toISOString()} (safe to repeat: events already there are skipped).`);
    }
    log(res.ok ? 'RESULT: OK' : 'RESULT: NOT OK - see the lines marked FAILED / CHECK above; nothing was deleted from either store');
    return res.ok ? 0 : 1;
  } catch (e) {
    log(`copy-events: ${e.code ? e.code + ': ' : ''}${e.message}`);
    return 1;
  } finally {
    await db.close().catch(() => {});
  }
}

if (require.main === module) main(process.argv.slice(2)).then((code) => process.exit(code));

module.exports = { copyTenant, copyAll, differences, parseArgs, main };
