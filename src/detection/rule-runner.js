'use strict';
// Detection rule runner: evaluates enabled threshold rules against stored events
// for every active tenant and raises (or updates) alerts.
//
// - Runs inside asix-api on an interval. With several API replicas, a Postgres
//   advisory lock makes sure only one of them runs a cycle at a time.
// - Rule definitions are data (detection_rules.definition). Group-by columns come
//   from the fixed GROUP_EXPR whitelist below, never from user input.

const db = require('../db');
const { buildMatch } = require('./rule-query');

const LOCK_KEY = 7412001; // arbitrary app-wide advisory lock id

// Shipped with the platform; created per tenant on first run (by builtin_key).
const BUILTIN_RULES = [
  {
    key: 'ssh-brute-force',
    kind: 'correlation',
    category: 'Credential Access',
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
    kind: 'correlation',
    category: 'Privilege Escalation',
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
    kind: 'correlation',
    category: 'Persistence',
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
  {
    key: 'bioc-reverse-shell',
    kind: 'bioc',
    category: 'Execution',
    name: 'Reverse shell one-liner',
    description: 'Command line that opens an interactive shell over a network socket.',
    severity: 'high',
    mitre: ['T1059'],
    definition: {
      regex: '(bash -i >& /dev/tcp/|nc(at)? [^ ]+ [0-9]+ -e /bin/(ba)?sh|socket\\.connect.*(pty\\.spawn|/bin/sh))',
      threshold: 1, window_minutes: 5, run_every_minutes: 1, mode: 'realtime',
    },
  },
  {
    key: 'bioc-log-clearing',
    kind: 'bioc',
    category: 'Defense Evasion',
    name: 'Log or shell history clearing',
    description: 'Deleting system logs or wiping shell history.',
    severity: 'medium',
    mitre: ['T1070'],
    definition: {
      regex: '(rm( -[a-z]+)* [^ ]*(/var/log/|\\.bash_history)|history -c|journalctl --vacuum|truncate -s 0 /var/log)',
      group_by: 'host', threshold: 1, window_minutes: 5, run_every_minutes: 1, mode: 'realtime',
    },
  },
  {
    key: 'bioc-decode-and-exec',
    kind: 'bioc',
    category: 'Execution',
    name: 'Decode and execute payload',
    description: 'Base64-decoded content piped straight into a shell.',
    severity: 'medium',
    mitre: ['T1027', 'T1059'],
    definition: {
      regex: 'base64 (-d|--decode)[^|]*\\|\\s*(ba|z)?sh',
      group_by: 'host', threshold: 1, window_minutes: 5, run_every_minutes: 1, mode: 'realtime',
    },
  },
  // ---- XDM-based BIOC rules: written once against xdm.* fields from the data model ----
  // (XQL strings: a backslash inside quotes is written twice, so \\. means a literal dot.)
  {
    key: 'bioc-xdm-ssh-fail-external', kind: 'bioc', category: 'Credential Access', name: 'SSH login failure from an external IP',
    description: 'Failed authentication from a public source address.', severity: 'medium', mitre: ['T1110'],
    definition: {
      event_type: 'event_log', group_by: 'field:xdm.source.ipv4', threshold: 1, window_minutes: 5, run_every_minutes: 1, mode: 'realtime',
      suppression: { enabled: true, minutes: 60 },
      xql: String.raw`xdm.event.type = "authentication" and xdm.event.outcome = XDM_CONST.OUTCOME_FAILED and xdm.source.ipv4 != null and not xdm.source.ipv4 ~= "^(10\\.|127\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)"`,
    },
  },
  {
    key: 'bioc-xdm-root-login', kind: 'bioc', category: 'Initial Access', name: 'Direct root login',
    description: 'Successful authentication as root, for example over SSH.', severity: 'high', mitre: ['T1078'],
    definition: {
      event_type: 'event_log', group_by: 'field:xdm.target.host.hostname', threshold: 1, window_minutes: 5, run_every_minutes: 1, mode: 'realtime',
      xql: String.raw`xdm.event.type = "authentication" and xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS and xdm.target.user.username = "root"`,
    },
  },
  {
    key: 'bioc-xdm-sudo-shell', kind: 'bioc', category: 'Privilege Escalation', name: 'sudo used to open a shell',
    description: 'sudo launching an interactive shell or su.', severity: 'medium', mitre: ['T1548.003'],
    definition: {
      event_type: 'process', group_by: 'field:xdm.target.host.hostname', threshold: 1, window_minutes: 5, run_every_minutes: 1, mode: 'realtime',
      xql: String.raw`xdm.event.type = "privilege_use" and xdm.target.process.command_line ~= "^(/usr/bin/|/bin/)?((ba|z|da|k|c)?sh|su)( |$)"`,
    },
  },
  {
    key: 'bioc-xdm-sensitive-file-sudo', kind: 'bioc', category: 'Credential Access', name: 'Credential file accessed with sudo',
    description: 'A sudo command that touches /etc/shadow, sudoers or SSH private keys.', severity: 'high', mitre: ['T1003.008'],
    definition: {
      event_type: 'process', group_by: 'field:xdm.target.host.hostname', threshold: 1, window_minutes: 5, run_every_minutes: 1, mode: 'realtime',
      xql: String.raw`xdm.event.type = "privilege_use" and xdm.target.process.command_line ~= "/etc/(shadow|gshadow|sudoers)|\\.ssh/(id_[a-z0-9]+|authorized_keys)"`,
    },
  },
  {
    key: 'bioc-xdm-account-change', kind: 'bioc', category: 'Persistence', name: 'Local account created or modified',
    description: 'useradd, usermod or passwd activity on a host.', severity: 'medium', mitre: ['T1136.001', 'T1098'],
    definition: {
      event_type: 'event_log', group_by: 'field:xdm.target.host.hostname', threshold: 1, window_minutes: 5, run_every_minutes: 1, mode: 'realtime',
      xql: String.raw`xdm.event.type = "account_management" and xdm.event.operation in ("useradd", "usermod", "passwd", "groupadd")`,
    },
  },
  {
    key: 'bioc-xdm-cron-temp', kind: 'bioc', category: 'Persistence', name: 'Cron job running from a temporary or hidden path',
    description: 'A scheduled task whose command lives in /tmp, /dev/shm or a hidden directory.', severity: 'high', mitre: ['T1053.003'],
    definition: {
      event_type: 'process', group_by: 'field:xdm.target.host.hostname', threshold: 1, window_minutes: 5, run_every_minutes: 1, mode: 'realtime',
      xql: String.raw`xdm.event.type = "scheduled_task" and xdm.target.process.command_line ~= "(/tmp/|/var/tmp/|/dev/shm/|/\\.[A-Za-z0-9])"`,
    },
  },
];

async function ensureBuiltinRules(client, tenantId) {
  for (const r of BUILTIN_RULES) {
    await client.query(
      `INSERT INTO detection_rules
         (tenant_id, name, description, severity, builtin_key, mitre, definition, kind, category)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
       ON CONFLICT (tenant_id, builtin_key) DO NOTHING`,
      [tenantId, r.name, r.description, r.severity, r.key, r.mitre, JSON.stringify(r.definition), r.kind, r.category]
    );
  }
}

async function evaluateRule(client, tenantId, rule) {
  const d = rule.definition;
  const q = buildMatch(tenantId, d);
  const hits = await client.query(q.text, q.values);
  const supp = d.suppression && d.suppression.enabled ? d.suppression.minutes : 0;

  let created = 0;
  let updated = 0;
  let suppressed = 0;
  for (const row of hits.rows) {
    const details = JSON.stringify({
      sample_event_ids: row.sample_ids || [],
      window_minutes: d.window_minutes,
      threshold: d.threshold,
      group_by: d.group_by,
      kind: rule.kind,
      category: rule.category || null,
      sample_raw: row.sample_raw ? String(row.sample_raw).slice(0, 500) : null,
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
      if (supp) {
        // Issue suppression: no new alert for this rule + group within the suppression window.
        const recent = await client.query(
          `SELECT 1 FROM alerts WHERE tenant_id = $1 AND rule_id = $2 AND group_key = $3
             AND created_at > localtimestamp - make_interval(mins => $4::int) LIMIT 1`,
          [tenantId, rule.id, row.gkey, supp]
        );
        if (recent.rows.length) { suppressed += 1; continue; }
      }
      const title = row.gkey === 'all' ? rule.name : `${rule.name}: ${row.gkey}`;
      await client.query(
        `INSERT INTO alerts
           (tenant_id, rule_id, rule_name, severity, title, summary, group_key,
            event_count, first_event_at, last_event_at, details)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)`,
        [
          tenantId, rule.id, rule.name, rule.severity, title,
          `${row.n} matching event${row.n > 1 ? 's' : ''} within ${d.window_minutes} minutes` + (rule.description ? ' - ' + rule.description : ''),
          row.gkey, row.n, row.first_at, row.last_at, details,
        ]
      );
      created += 1;
    }
  }
  return { created, updated, suppressed };
}

async function runTenant(tenantId) {
  return db.withTenant(tenantId, async (client) => {
    await client.query("SET LOCAL statement_timeout = '15s'");
    await ensureBuiltinRules(client, tenantId);
    const rules = await client.query(
      // Explicit tenant filter: the API connects as the table owner, which bypasses RLS.
      `SELECT id, name, description, severity, definition, kind, category,
              (last_run_at IS NULL OR last_run_at <= localtimestamp
                 - make_interval(secs => GREATEST(COALESCE((definition->>'run_every_minutes')::int, 1), 1) * 60 - 30)) AS due
       FROM detection_rules WHERE enabled = true AND tenant_id = $1`,
      [tenantId]
    );
    const out = { rules: rules.rows.length, created: 0, updated: 0, errors: 0 };
    for (const rule of rules.rows) {
      if (!rule.due) continue; // scheduled rules run on their own interval
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
