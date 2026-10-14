'use strict';
// Alert dedupe: fold repeat alerts (same rule + same group key, still active) into one.
//
// Why repeats exist: the rule runner only merges a new hit into an existing alert while that alert
// has seen events within 2x the rule window. A noisy source that goes quiet for longer and then
// returns raises a second alert for the same rule and group, and so on. Nothing here changes how
// alerts are raised; this is the analyst-side cleanup (and the one-click "merge all").
//
// A merge keeps the OLDEST alert as the primary and closes the others with merged_into_id pointing
// at it. Closed alerts are never touched again by the rule runner or the IOC matcher, so the
// primary simply carries on absorbing new events. Nothing is deleted: the merged alerts stay
// readable (status closed), and their notes move to the primary.

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 }; // lower = worse
const MAX_MERGE = 200;     // duplicates folded per call/transaction chunk
const MAX_GROUPS_LIST = 100;
const MAX_PER_GROUP_LIST = 50;
const MAX_GROUPS_MERGE_ALL = 500;

// Two alerts are repeats of each other when this is equal. IOC alerts have no rule_id, so they fall
// back to the rule name (their group_key already carries the indicator).
const identity = (a) => (a.rule_id ? 'rule:' + a.rule_id : 'name:' + a.rule_name) + '|' + a.group_key;

const worstSeverity = (rows) =>
  rows.reduce((w, r) => (SEVERITY_RANK[r.severity] ?? 9) < (SEVERITY_RANK[w] ?? 9) ? r.severity : w, rows[0].severity);

// An unhandled repeat must not be hidden behind an acknowledged primary, so any open alert wins.
const mergedStatus = (rows) => (rows.some((r) => r.status === 'open') ? 'open' : 'acknowledged');

// Keep the primary's owner; otherwise the owner of the most recently active duplicate that has one.
function mergedAssignee(primary, dups) {
  if (primary.assignee_id) return primary.assignee_id;
  const owned = dups.filter((d) => d.assignee_id)
    .sort((a, b) => new Date(b.last_event_at || 0) - new Date(a.last_event_at || 0));
  return owned.length ? owned[0].assignee_id : null;
}

// What the primary looks like after absorbing dups. event_count and the first/last times are
// aggregated in SQL (microsecond precision), so they are not part of the plan.
function planMerge(primary, dups) {
  const all = [primary, ...dups];
  return {
    severity: worstSeverity(all),
    status: mergedStatus(all),
    assignee_id: mergedAssignee(primary, dups),
    // every absorbed alert counts once, plus whatever it had absorbed before
    merged_count: (primary.merged_count || 0) + dups.reduce((n, d) => n + 1 + (d.merged_count || 0), 0),
  };
}

const ACTIVE_UNMERGED = "a.tenant_id = $1 AND a.status <> 'closed' AND a.merged_into_id IS NULL";
const IDENT_SQL = 'COALESCE(a.rule_id::text, a.rule_name)';

// Groups of repeat alerts, worst/biggest first. Each group lists its alerts oldest first, so
// alerts[0] is the one a merge would keep. Only up to perGroup alerts are returned per group;
// `count` is the true size.
async function findGroups(client, tenantId, { maxGroups = MAX_GROUPS_LIST, perGroup = MAX_PER_GROUP_LIST } = {}) {
  const r = await client.query(
    `WITH active AS (
       SELECT a.id, a.rule_id, a.rule_name, a.severity, a.status, a.title, a.group_key, a.event_count,
              a.first_event_at, a.last_event_at, a.created_at, a.assignee_id, a.merged_count,
              ${IDENT_SQL} AS ident,
              (SELECT u.username FROM users u WHERE u.id = a.assignee_id) AS assignee_name
       FROM alerts a WHERE ${ACTIVE_UNMERGED}),
     dup AS (
       SELECT ident, group_key, COUNT(*)::int AS n, COALESCE(SUM(event_count), 0)::int AS total_events
       FROM active GROUP BY ident, group_key HAVING COUNT(*) > 1
       ORDER BY COUNT(*) DESC, ident, group_key LIMIT $2),
     ranked AS (
       SELECT active.*, d.n, d.total_events,
              ROW_NUMBER() OVER (PARTITION BY active.ident, active.group_key
                                 ORDER BY COALESCE(active.first_event_at, active.created_at), active.id) AS rn
       FROM active JOIN dup d USING (ident, group_key))
     SELECT * FROM ranked WHERE rn <= $3 ORDER BY n DESC, ident, group_key, rn`,
    [tenantId, maxGroups, perGroup]
  );
  const groups = new Map();
  for (const row of r.rows) {
    const k = row.ident + '|' + row.group_key;
    if (!groups.has(k)) {
      groups.set(k, { rule_name: row.rule_name, group_key: row.group_key, count: row.n, total_events: row.total_events, alerts: [] });
    }
    const { ident, n, total_events, rn, ...alert } = row;
    groups.get(k).alerts.push(alert);
  }
  return [...groups.values()];
}

// Fold dupIds into primaryId inside the caller's transaction (db.withTenant). Everything involved is
// locked and re-checked first, so a rule-runner update or another analyst closing an alert at the
// same moment cannot produce a half-merged state. Returns { ok: true, ... } or { error: CODE }.
async function mergeInto(client, tenantId, primaryId, dupIds, actorName) {
  const dups = [...new Set(dupIds)].filter((i) => i !== primaryId);
  if (!dups.length) return { error: 'NOTHING_TO_MERGE' };
  if (dups.length > MAX_MERGE) return { error: 'TOO_MANY' };
  const ids = [primaryId, ...dups];

  const locked = await client.query(
    `SELECT id, rule_id, rule_name, severity, status, group_key, event_count, last_event_at,
            assignee_id, merged_count, merged_into_id
     FROM alerts WHERE tenant_id = $1 AND id = ANY($2::uuid[]) ORDER BY id FOR UPDATE`,
    [tenantId, ids]
  );
  if (locked.rows.length !== ids.length) return { error: 'NOT_FOUND' };
  const byId = new Map(locked.rows.map((r) => [r.id, r]));
  if (locked.rows.some((r) => r.status === 'closed' || r.merged_into_id)) return { error: 'NOT_ACTIVE' };
  const primary = byId.get(primaryId);
  const dupRows = dups.map((i) => byId.get(i));
  if (dupRows.some((d) => identity(d) !== identity(primary))) return { error: 'NOT_DUPLICATES' };

  const plan = planMerge(primary, dupRows);
  const upd = await client.query(
    `UPDATE alerts a SET
       event_count = agg.n, first_event_at = agg.first_at, last_event_at = agg.last_at,
       severity = $3, status = $4, assignee_id = $5, merged_count = $6, updated_at = localtimestamp
     FROM (SELECT COALESCE(SUM(event_count), 0)::int AS n, MIN(first_event_at) AS first_at, MAX(last_event_at) AS last_at
           FROM alerts WHERE tenant_id = $7 AND id = ANY($2::uuid[])) agg
     WHERE a.id = $1 AND a.tenant_id = $7
     RETURNING a.event_count`,
    [primaryId, ids, plan.severity, plan.status, plan.assignee_id, plan.merged_count, tenantId]
  );
  // anything that had been merged into a duplicate now points at the primary
  await client.query('UPDATE alerts SET merged_into_id = $1 WHERE tenant_id = $3 AND merged_into_id = ANY($2::uuid[])', [primaryId, dups, tenantId]);
  await client.query(
    "UPDATE alerts SET status = 'closed', merged_into_id = $1, updated_at = localtimestamp WHERE tenant_id = $3 AND id = ANY($2::uuid[])",
    [primaryId, dups, tenantId]
  );
  await client.query('UPDATE alert_notes SET alert_id = $1 WHERE tenant_id = $3 AND alert_id = ANY($2::uuid[])', [primaryId, dups, tenantId]);
  const who = actorName ? ' by ' + actorName : '';
  await client.query(
    `INSERT INTO alert_notes (tenant_id, alert_id, author_id, author_name, body) VALUES ($1, $2, NULL, 'ASIX', $3)`,
    [tenantId, primaryId, `Merged ${dups.length} repeat alert${dups.length > 1 ? 's' : ''} into this one${who}. It now covers ${upd.rows[0].event_count} events.`]
  );
  return { ok: true, primary_id: primaryId, merged: dups.length, event_count: upd.rows[0].event_count, status: plan.status, severity: plan.severity };
}

// Merge every group of repeats into its oldest alert. Each group is its own savepoint, so one group
// that changed underneath us (closed meanwhile) is skipped, not fatal. Large groups go in chunks.
async function mergeAll(client, tenantId, actorName) {
  const groups = await findGroups(client, tenantId, { maxGroups: MAX_GROUPS_MERGE_ALL, perGroup: 1 });
  const out = { groups: 0, merged: 0, skipped: 0, more: groups.length >= MAX_GROUPS_MERGE_ALL };
  for (const g of groups) {
    const rows = await client.query(
      `SELECT a.id FROM alerts a WHERE ${ACTIVE_UNMERGED} AND ${IDENT_SQL} = $2 AND a.group_key = $3
       ORDER BY COALESCE(a.first_event_at, a.created_at), a.id`,
      [tenantId, g.alerts[0].rule_id ? g.alerts[0].rule_id : g.alerts[0].rule_name, g.group_key]
    );
    const ids = rows.rows.map((r) => r.id);
    if (ids.length < 2) { out.skipped += 1; continue; }
    const [primary, ...rest] = ids;
    await client.query('SAVEPOINT dedupe_group');
    let folded = 0; let failed = false;
    for (let i = 0; i < rest.length && !failed; i += MAX_MERGE) {
      const r = await mergeInto(client, tenantId, primary, rest.slice(i, i + MAX_MERGE), actorName);
      if (r.ok) folded += r.merged; else failed = true;
    }
    if (failed) { await client.query('ROLLBACK TO SAVEPOINT dedupe_group'); out.skipped += 1; }
    else { await client.query('RELEASE SAVEPOINT dedupe_group'); out.groups += 1; out.merged += folded; }
  }
  return out;
}

module.exports = {
  identity, worstSeverity, mergedStatus, mergedAssignee, planMerge, findGroups, mergeInto, mergeAll,
  MAX_MERGE, SEVERITY_RANK,
};
