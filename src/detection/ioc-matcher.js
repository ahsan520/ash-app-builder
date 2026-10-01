'use strict';
// IOC matcher: checks newly ingested events against the tenant's threat indicators and
// raises (or updates) alerts. Works incrementally: a per-tenant cursor in ioc_scan_state
// (received_at, id) means each event is examined exactly once, even across API restarts
// and several API replicas (a Postgres advisory lock lets one replica run a cycle).

const db = require('../db');
const { extractCandidates } = require('../threat-intel/indicators');

const LOCK_KEY = 7412002;
const BATCH = 5000;
const FIRST_RUN_LOOKBACK = "interval '1 hour'";
const RULE_NAME = 'IOC match';

async function loadIndicators(client, tenantId) {
  const r = await client.query(
    `SELECT id, type, value, source, severity FROM threat_indicators
     WHERE tenant_id = $1 AND enabled = true AND (expires_at IS NULL OR expires_at > localtimestamp)`,
    [tenantId]
  );
  return new Map(r.rows.map((i) => [`${i.type}:${i.value}`, i]));
}

async function raiseAlert(client, tenantId, ind, m) {
  const key = `ioc:${ind.type}:${ind.value}`;
  const sample = { event_ids: m.ids, lines: m.lines };
  const open = await client.query(
    `SELECT id FROM alerts
     WHERE tenant_id = $1 AND rule_name = $2 AND group_key = $3 AND status IN ('open','acknowledged')
     LIMIT 1`,
    [tenantId, RULE_NAME, key]
  );
  const details = JSON.stringify({ indicator_id: ind.id, type: ind.type, value: ind.value, source: ind.source, sample });
  if (open.rows.length) {
    await client.query(
      `UPDATE alerts SET event_count = event_count + $2, last_event_at = $3, details = $4::jsonb,
              updated_at = localtimestamp WHERE id = $1`,
      [open.rows[0].id, m.n, m.last, details]
    );
    return 'updated';
  }
  await client.query(
    `INSERT INTO alerts (tenant_id, rule_id, rule_name, severity, title, summary, group_key,
                         event_count, first_event_at, last_event_at, details)
     VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)`,
    [tenantId, RULE_NAME, ind.severity, `IOC match: ${ind.value} (${ind.type})`,
     `Indicator from "${ind.source}" seen in ${m.n} event${m.n > 1 ? 's' : ''}`, key, m.n, m.first, m.last, details]
  );
  return 'created';
}

async function runTenant(tenantId) {
  return db.withTenant(tenantId, async (client) => {
    await client.query("SET LOCAL statement_timeout = '20s'");
    const out = { scanned: 0, matches: 0, created: 0, updated: 0 };
    const indicators = await loadIndicators(client, tenantId);
    const st = (await client.query('SELECT last_received_at::text AS last_received_at, last_event_id FROM ioc_scan_state WHERE tenant_id = $1', [tenantId])).rows[0];
    let curTs = st ? st.last_received_at : null;
    let curId = st ? st.last_event_id : null;

    const ev = await client.query(
      curTs
        ? `SELECT id, raw, received_at, received_at::text AS received_at_txt FROM events WHERE tenant_id = $1 AND (received_at, id) > ($2::timestamp, $3::uuid)
           ORDER BY received_at, id LIMIT ${BATCH}`
        : `SELECT id, raw, received_at, received_at::text AS received_at_txt FROM events WHERE tenant_id = $1 AND received_at > localtimestamp - ${FIRST_RUN_LOOKBACK}
           ORDER BY received_at, id LIMIT ${BATCH}`,
      curTs ? [tenantId, curTs, curId] : [tenantId]
    );
    const hits = new Map(); // indicator key -> aggregate
    if (indicators.size) {
      for (const e of ev.rows) {
        for (const c of extractCandidates(e.raw)) {
          if (!indicators.has(c)) continue;
          const h = hits.get(c) || { n: 0, first: e.received_at, last: e.received_at, ids: [], lines: [] };
          h.n += 1; h.last = e.received_at;
          if (h.ids.length < 5) { h.ids.push(e.id); h.lines.push(String(e.raw).slice(0, 300)); }
          hits.set(c, h);
        }
      }
    }
    for (const [key, m] of hits) {
      out[await raiseAlert(client, tenantId, indicators.get(key), m)] += 1;
      out.matches += m.n;
    }
    out.scanned = ev.rows.length;
    if (ev.rows.length) { const last = ev.rows[ev.rows.length - 1]; curTs = last.received_at_txt; curId = last.id; }
    await client.query(
      `INSERT INTO ioc_scan_state (tenant_id, last_received_at, last_event_id, last_run_at, last_error, matched_total)
       VALUES ($1, COALESCE($2::timestamp, localtimestamp), $3::uuid, localtimestamp, NULL, $4)
       ON CONFLICT (tenant_id) DO UPDATE SET last_received_at = COALESCE($2::timestamp, ioc_scan_state.last_received_at),
         last_event_id = COALESCE($3::uuid, ioc_scan_state.last_event_id), last_run_at = localtimestamp, last_error = NULL,
         matched_total = ioc_scan_state.matched_total + $4`,
      [tenantId, curTs, curId, out.matches]
    );
    return out;
  });
}

async function recordError(tenantId, err) {
  await db.query(
    `INSERT INTO ioc_scan_state (tenant_id, last_run_at, last_error) VALUES ($1, localtimestamp, $2)
     ON CONFLICT (tenant_id) DO UPDATE SET last_run_at = localtimestamp, last_error = $2`,
    [tenantId, String(err.message).slice(0, 500)]
  ).catch(() => {});
}

async function runOnce() {
  const lock = await db.pool.connect();
  try {
    const got = await lock.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK_KEY]);
    if (!got.rows[0].ok) return { skipped: true };
    const total = { tenants: 0, scanned: 0, created: 0, updated: 0, errors: 0 };
    for (const t of (await lock.query("SELECT id FROM tenants WHERE status = 'active'")).rows) {
      try {
        const r = await runTenant(t.id);
        total.tenants += 1; total.scanned += r.scanned; total.created += r.created; total.updated += r.updated;
      } catch (err) {
        total.errors += 1;
        console.error(`[ioc] tenant ${t.id} failed: ${err.message}`);
        await recordError(t.id, err);
      }
    }
    return total;
  } finally {
    await lock.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]).catch(() => {});
    lock.release();
  }
}

let timer = null;
let running = false;
function start() {
  if (process.env.IOC_MATCHER_ENABLED === 'false' || timer) return;
  const every = Math.max(15, Number(process.env.IOC_INTERVAL_SECONDS || 60)) * 1000;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      const r = await runOnce();
      if (r.created || r.errors) console.log('[ioc] cycle', JSON.stringify(r));
    } catch (err) {
      console.error('[ioc] cycle failed:', err.message);
    } finally { running = false; }
  };
  setTimeout(tick, 25000).unref();
  timer = setInterval(tick, every);
  timer.unref();
  console.log(`[ioc] matcher started (every ${every / 1000}s)`);
}

module.exports = { start, runOnce, runTenant };
