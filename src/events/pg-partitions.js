'use strict';
// PostgreSQL's `events` table can be plain or partitioned by day on received_at (k8s/12-schema-init.yaml).
// These helpers read that layout. They are used by the Postgres adapter (to delete expired rows one partition at
// a time) and by src/storage/retention.js (partition housekeeping, the storage page). Nothing here is for other engines.

const PART_RE = /^events_p\d{8}$/;

// 'p' when events is partitioned, 'r' when it is a plain table. q is anything with query(): the pool or a client.
async function eventsKind(q) {
  return (await q.query("SELECT c.relkind::text AS k FROM pg_class c WHERE c.oid = 'public.events'::regclass")).rows[0].k;
}

async function listPartitions(q) {
  const r = await q.query(
    `SELECT c.relname AS name, pg_get_expr(c.relpartbound, c.oid) AS bound, pg_total_relation_size(c.oid)::bigint AS bytes,
            pg_relation_size(c.oid)::bigint AS heap_bytes, c.reltuples::bigint AS est_rows
     FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
     WHERE i.inhparent = 'public.events'::regclass ORDER BY c.relname`);
  return r.rows.map((p) => {
    const m = /FROM \('(\d{4}-\d{2}-\d{2})[^']*'\) TO \('(\d{4}-\d{2}-\d{2})/.exec(p.bound || '');
    return { name: p.name, bytes: Number(p.bytes), heap_bytes: Number(p.heap_bytes), est_rows: Number(p.est_rows),
      is_default: p.bound === 'DEFAULT', from: m ? m[1] : null, to: m ? m[2] : null };
  });
}

module.exports = { PART_RE, eventsKind, listPartitions };
