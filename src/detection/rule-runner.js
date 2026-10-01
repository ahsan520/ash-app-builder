'use strict';
// Detection rule runner: evaluates enabled threshold rules against stored events
// for every active tenant and raises (or updates) alerts.
//
// - Runs inside asix-api on an interval. With several API replicas, a Postgres
//   advisory lock makes sure only one of them runs a cycle at a time.
// - Rule definitions are data (detection_rules.definition). Group-by columns come
//   from the fixed GROUP_EXPR whitelist below, never from user input.

const db = require('../db');

const LOCK_KEY = 7412001; // arbitrary app-wide advisory lock id

// Attacker/source address as written in typical sshd / pam / firewall lines.
const SOURCE_IP_SQL =
  "substring(raw from '(?:from|rhost=|src=)\\s*([0-9]{1,3}(?:\\.[0-9]{1,3}){3})')";

const GROUP_EXPR = {
  none: "'all'",
  host: "COALESCE(parsed->>'host', 'unknown')",
  source_ip: `COALESCE(${SOURCE_IP_SQL}, 'unknown')`,
};

// Shipped with the platform; created per tenant on first run (by builtin_key).
const BUILTIN_RULES = [
  {
    key: 'ssh-brute-force',
    name: 'SSH brute force',
    description: 'Repeated failed SSH logins from one source address.',
    severity: 'high',
    mitre: ['T1110'],
    definition: {
      regex: '(Failed password for|Invalid user |authentication failure)',
      group_by: 'source_ip',
      threshold: 5,
      window_minutes: 5,
    },
  },
  {
    key: 'root-escalation',
    name: 'Privilege escalation to root',
    description: 'sudo command execution or su/session opened as root.',
    severity: 'medium',
    mitre: ['T1548'],
    definition: {
      regex: '(sudo: .*COMMAND=|session opened for user root|su: .*\\(to root\\))',
      group_by: 'host',
      threshold: 1,
      window_minutes: 5,
    },
  },
  {
    key: 'new-user-account',
    name: 'New user account created',
    description: 'useradd/adduser activity on a host.',
    severity: 'medium',
    mitre: ['T1136'],
    definition: {
      regex: '(useradd\\[[0-9]+\\]: new user|adduser\\[[0-9]+\\]: (Adding|New) user|new user: name=)',
      group_by: 'host',
      threshold: 1,
      window_minutes: 5,
    },
  },
];

async function ensureBuiltinRules(client, tenantId) {
  for (const r of BUILTIN_RULES) {
    await client.query(
      `INSERT INTO detection_rules
         (tenant_id, name, description, severity, builtin_key, mitre, definition)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
       ON CONFLICT (tenant_id, builtin_key) DO NOTHING`,
      [tenantId, r.name, r.description, r.severity, r.key, r.mitre, JSON.stringify(r.definition)]
    );
  }
}

async function evaluateRule(client, tenantId, rule) {
  const d = rule.definition;
  const groupExpr = GROUP_EXPR[d.group_by] || GROUP_EXPR.none;
  const hits = await client.query(
    `
    SELECT ${groupExpr} AS gkey,
           COUNT(*)::int AS n,
           MIN(ts) AS first_at,
           MAX(ts) AS last_at,
           (array_agg(id ORDER BY ts DESC))[1:5] AS sample_ids
    FROM (
      SELECT id, raw, parsed, COALESCE(event_time, received_at) AS ts
      FROM events
      WHERE tenant_id = $1
        AND COALESCE(event_time, received_at) > localtimestamp - make_interval(mins => $2::int)
        AND raw ~* $3
    ) e
    GROUP BY 1
    HAVING COUNT(*) >= $4::int
    `,
    [tenantId, d.window_minutes, d.regex, d.threshold]
  );

  let created = 0;
  let updated = 0;
  for (const row of hits.rows) {
    const details = JSON.stringify({
      sample_event_ids: row.sample_ids || [],
      window_minutes: d.window_minutes,
      threshold: d.threshold,
      group_by: d.group_by,
    });
    // Merge into a still-active alert for the same rule + group instead of
    // raising a new alert every cycle.
    const existing = await client.query(
      `SELECT id FROM alerts
       WHERE tenant_id = $1 AND rule_id = $2 AND group_key = $3 AND status <> 'closed'
         AND last_event_at > localtimestamp - make_interval(mins => $4::int)
       ORDER BY last_event_at DESC LIMIT 1`,
      [tenantId, rule.id, row.gkey, d.window_minutes * 2]
    );
    if (existing.rows.length) {
      await client.query(
        `UPDATE alerts
         SET event_count = GREATEST(event_count, $2), last_event_at = $3,
             details = $4::jsonb, updated_at = localtimestamp
         WHERE id = $1`,
        [existing.rows[0].id, row.n, row.last_at, details]
      );
      updated += 1;
    } else {
      const title = row.gkey === 'all' ? rule.name : `${rule.name}: ${row.gkey}`;
      await client.query(
        `INSERT INTO alerts
           (tenant_id, rule_id, rule_name, severity, title, summary, group_key,
            event_count, first_event_at, last_event_at, details)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)`,
        [
          tenantId, rule.id, rule.name, rule.severity, title,
          `${row.n} matching events within ${d.window_minutes} minutes`,
          row.gkey, row.n, row.first_at, row.last_at, details,
        ]
      );
      created += 1;
    }
  }
  return { created, updated };
}

async function runTenant(tenantId) {
  return db.withTenant(tenantId, async (client) => {
    await client.query("SET LOCAL statement_timeout = '15s'");
    await ensureBuiltinRules(client, tenantId);
    const rules = await client.query(
      // Explicit tenant filter: the API connects as the table owner, which bypasses RLS.
      'SELECT id, name, severity, definition FROM detection_rules WHERE enabled = true AND tenant_id = $1',
      [tenantId]
    );
    const out = { rules: rules.rows.length, created: 0, updated: 0, errors: 0 };
    for (const rule of rules.rows) {
      await client.query('SAVEPOINT rule_eval');
      try {
        const r = await evaluateRule(client, tenantId, rule);
        out.created += r.created;
        out.updated += r.updated;
        await client.query('RELEASE SAVEPOINT rule_eval');
        await client.query(
          'UPDATE detection_rules SET last_run_at = localtimestamp, last_error = NULL WHERE id = $1',
          [rule.id]
        );
      } catch (err) {
        await client.query('ROLLBACK TO SAVEPOINT rule_eval');
        await client.query(
          'UPDATE detection_rules SET last_run_at = localtimestamp, last_error = $2 WHERE id = $1',
          [rule.id, String(err.message).slice(0, 500)]
        );
        out.errors += 1;
        console.error(`[detection] rule "${rule.name}" failed: ${err.message}`);
      }
    }
    return out;
  });
}

async function runOnce() {
  const lockClient = await db.pool.connect();
  try {
    const got = await lockClient.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK_KEY]);
    if (!got.rows[0].ok) return { skipped: true };
    const tenants = await lockClient.query("SELECT id FROM tenants WHERE status = 'active'");
    const total = { tenants: 0, created: 0, updated: 0, errors: 0 };
    for (const t of tenants.rows) {
      const r = await runTenant(t.id);
      total.tenants += 1;
      total.created += r.created;
      total.updated += r.updated;
      total.errors += r.errors;
    }
    return total;
  } finally {
    await lockClient.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]).catch(() => {});
    lockClient.release();
  }
}

let timer = null;
let running = false;

function start() {
  if (process.env.DETECTION_RUNNER_ENABLED === 'false' || timer) return;
  const every = Math.max(15, Number(process.env.DETECTION_INTERVAL_SECONDS || 60)) * 1000;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      const r = await runOnce();
      if (r.created || r.errors) console.log('[detection] cycle', JSON.stringify(r));
    } catch (err) {
      console.error('[detection] cycle failed:', err.message);
    } finally {
      running = false;
    }
  };
  setTimeout(tick, 20000).unref();
  timer = setInterval(tick, every);
  timer.unref();
  console.log(`[detection] rule runner started (every ${every / 1000}s)`);
}

module.exports = { start, runOnce, ensureBuiltinRules, BUILTIN_RULES };
