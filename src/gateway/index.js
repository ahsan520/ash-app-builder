const path = require('path');
const express = require('express');
const db = require('../db');

const {
  authMiddleware,
  tenantMiddleware,
  rbacMiddleware,
  auditMiddleware,
  brokerAuthMiddleware,
} = require('./middleware');

const app = express();

app.disable('x-powered-by');

// HTTP ingestion lane (per-key auth). Mounted BEFORE the global JSON parser: it authenticates
// first and then parses with its own, larger body limit.
app.use(require('../ingest/http-ingest').router);

app.use(express.json());

// Central portal (static SPA). Unauthenticated on purpose: it is only HTML/JS;
// every data call it makes goes through the Bearer-token middleware below.
app.use(
  '/portal',
  (req, res, next) => {
    res.set({
      'Content-Security-Policy':
        "default-src 'self'; connect-src 'self' https:; style-src 'self' 'unsafe-inline'; " +
        "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
    });
    next();
  },
  express.static(path.join(__dirname, '..', 'portal'))
);

// Kubernetes / load-balancer health endpoint.
// Intentionally unauthenticated so health checks do not require a JWT.
app.get('/v1/health/status', async (req, res) => {
  try {
    const database = await db.healthCheck();

    res.status(200).json({
      success: true,
      status: 'ok',
      service: 'asix-api',
      version: '0.1.0',
      dependencies: {
        database: database ? 'ok' : 'error',
      },
    });
  } catch (error) {
    console.error('Health check failed:', error.message);

    res.status(503).json({
      success: false,
      status: 'degraded',
      service: 'asix-api',
      version: '0.1.0',
      dependencies: {
        database: 'error',
      },
    });
  }
});

// Authenticated identity test endpoint.
// Full middleware chain:
// JWT authentication -> tenant context -> RBAC -> audit.
app.get(
  '/v1/auth/me',
  (req, res, next) => {
    req.required_permission = 'auth:identity:read';
    next();
  },
  authMiddleware,
  tenantMiddleware,
  rbacMiddleware,
  auditMiddleware,
  async (req, res) => {
    try {
      const result = await db.withTenant(req.tenant_id, (client) =>
        client.query(
          `
          SELECT id, name, status
          FROM tenants
          WHERE id = $1
          `,
          [req.tenant_id]
        )
      );

      if (result.rows.length === 0) {
        return res.status(403).json({
          success: false,
          error: {
            code: 'TENANT_NOT_VISIBLE',
            message: 'Authenticated tenant is not available in the current tenant scope',
          },
        });
      }

      const tenant = result.rows[0];

      res.status(200).json({
        success: true,
        authenticated: true,
        user_id: req.user_id,
        tenant_id: req.tenant_id,
        tenant_name: tenant.name,
        tenant_status: tenant.status,
        session_id: req.session_id,
      });
    } catch (error) {
      console.error('Auth context lookup failed:', error.message);
      return res.status(500).json({
        success: false,
        error: {
          code: 'TENANT_CONTEXT_ERROR',
          message: 'Unable to establish tenant database context',
        },
      });
    }
  }
);

// Broker ingestion — the data node side of the Collector/Broker split
// (architecture.md: Data Source -> Collector -> Broker -> ... -> Storage).
// Brokers (e.g. src/ingestion/syslog-server.js) POST batches here instead
// of writing to Postgres directly. Auth is brokerAuthMiddleware, not the
// Keycloak JWT flow — see its comment in middleware.js for why and for
// the known gap (single shared token, not yet per-broker identity).
app.post('/v1/ingest/events', brokerAuthMiddleware, async (req, res) => {
  try {
    const { tenant_id, tenant_name, source_type, collector_id, events } = req.body || {};

    if (!source_type || !Array.isArray(events) || events.length === 0) {
      return res.status(400).json({
        success: false,
        error: { code: 'INGEST_INVALID_BODY', message: 'source_type and a non-empty events array are required' },
      });
    }

    if (events.length > 1000) {
      return res.status(400).json({
        success: false,
        error: { code: 'INGEST_BATCH_TOO_LARGE', message: 'Max 1000 events per batch' },
      });
    }

    let resolvedTenantId = tenant_id;

    if (!resolvedTenantId) {
      if (!tenant_name) {
        return res.status(400).json({
          success: false,
          error: { code: 'INGEST_NO_TENANT', message: 'tenant_id or tenant_name is required' },
        });
      }

      // No tenant context exists yet — same superuser-bypasses-RLS
      // property used elsewhere pre-tenant-context (see
      // resolve_external_identity). A Phase 2 lower-privileged app role
      // would need this routed through a narrow SECURITY DEFINER
      // function instead.
      const tenantResult = await db.query('SELECT id FROM tenants WHERE name = $1 LIMIT 1', [tenant_name]);
      if (tenantResult.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: { code: 'INGEST_TENANT_NOT_FOUND', message: `No tenant named "${tenant_name}"` },
        });
      }
      resolvedTenantId = tenantResult.rows[0].id;
    }

    await db.withTenant(resolvedTenantId, async (client) => {
      for (const event of events) {
        await client.query(
          `
          INSERT INTO events (tenant_id, source_type, collector_id, event_time, raw, parsed)
          VALUES ($1, $2, $3, $4, $5, $6)
          `,
          [
            resolvedTenantId,
            source_type,
            collector_id || null,
            event.event_time || null,
            event.raw,
            JSON.stringify(event.parsed || {}),
          ]
        );
      }

      // One audit row per batch, not per event — this is high-volume
      // ingestion traffic, not a user action; per-event audit rows would
      // just double the write volume for no real audit value.
      await client.query(
        `
        INSERT INTO audit_events (tenant_id, action, resource, result)
        VALUES ($1, $2, $3, 'success')
        `,
        [resolvedTenantId, 'ingest:events:create', `${source_type}:${collector_id || 'unknown'}`]
      );
    });

    res.status(202).json({ success: true, inserted: events.length });
  } catch (error) {
    console.error('Event ingestion failed:', error.message);
    res.status(500).json({
      success: false,
      error: { code: 'INGEST_ERROR', message: 'Failed to persist events' },
    });
  }
});

// Search — the console/search-head side of the portal. Full
// identity/tenant/RBAC/audit chain, same as /v1/auth/me — a human or
// service identity querying data is a different lane from
// brokerAuthMiddleware's machine-to-machine ingestion.
app.get(
  '/v1/search/events',
  (req, res, next) => {
    req.required_permission = 'search:events:read';
    next();
  },
  authMiddleware,
  tenantMiddleware,
  rbacMiddleware,
  auditMiddleware,
  async (req, res) => {
    try {
      const limit = Math.min(Number(req.query.limit) || 50, 500);
      const offset = Math.max(Number(req.query.offset) || 0, 0);

      const conditions = ['tenant_id = $1'];
      const params = [req.tenant_id];

      if (req.query.source_type) {
        params.push(req.query.source_type);
        conditions.push(`source_type = $${params.length}`);
      }

      if (req.query.collector_id) {
        params.push(req.query.collector_id);
        conditions.push(`collector_id = $${params.length}`);
      }

      if (req.query.from) {
        params.push(req.query.from);
        conditions.push(`COALESCE(event_time, received_at) >= $${params.length}`);
      }

      if (req.query.to) {
        params.push(req.query.to);
        conditions.push(`COALESCE(event_time, received_at) <= $${params.length}`);
      }

      // Free-text: ILIKE over the raw line — a sequential scan, not an
      // indexed search (the parsed JSONB's GIN index only supports
      // containment queries, not substring matching). Fine at today's
      // volume; real full-text search needs a tsvector column or a move
      // to OpenSearch per data-architecture.md's phased plan.
      if (req.query.q) {
        params.push(`%${req.query.q}%`);
        conditions.push(`raw ILIKE $${params.length}`);
      }

      params.push(limit);
      const limitParam = params.length;
      params.push(offset);
      const offsetParam = params.length;

      const result = await db.withTenant(req.tenant_id, (client) =>
        client.query(
          `
          SELECT id, source_type, collector_id, received_at, event_time, raw, parsed
          FROM events
          WHERE ${conditions.join(' AND ')}
          ORDER BY COALESCE(event_time, received_at) DESC
          LIMIT $${limitParam} OFFSET $${offsetParam}
          `,
          params
        )
      );

      res.status(200).json({
        success: true,
        count: result.rows.length,
        limit,
        offset,
        events: result.rows,
      });
    } catch (error) {
      console.error('Event search failed:', error.message);
      res.status(500).json({
        success: false,
        error: { code: 'SEARCH_ERROR', message: 'Failed to search events' },
      });
    }
  }
);

// Data sources: what has actually been ingested, per source type + collector.
// Derived from the events table (there is no separate collector registry yet).
app.get(
  '/v1/data-sources',
  (req, res, next) => {
    req.required_permission = 'search:events:read';
    next();
  },
  authMiddleware,
  tenantMiddleware,
  rbacMiddleware,
  auditMiddleware,
  async (req, res) => {
    try {
      const result = await db.withTenant(req.tenant_id, (client) =>
        client.query(
          `
          SELECT source_type,
                 collector_id,
                 COUNT(*)::int AS events_total,
                 COUNT(*) FILTER (
                   WHERE COALESCE(event_time, received_at) > now() - interval '24 hours'
                 )::int AS events_24h,
                 MAX(received_at) AS last_received
          FROM events
          WHERE tenant_id = $1
          GROUP BY source_type, collector_id
          ORDER BY MAX(received_at) DESC
          `,
          [req.tenant_id]
        )
      );
      res.status(200).json({ success: true, sources: result.rows });
    } catch (error) {
      console.error('Data source listing failed:', error.message);
      res.status(500).json({
        success: false,
        error: { code: 'DATA_SOURCES_ERROR', message: 'Failed to list data sources' },
      });
    }
  }
);

// Settings > Users & roles (read-only): the tenant's users and roles.
app.get(
  '/v1/settings/access',
  (req, res, next) => {
    req.required_permission = 'settings:access:read';
    next();
  },
  authMiddleware,
  tenantMiddleware,
  rbacMiddleware,
  auditMiddleware,
  async (req, res) => {
    try {
      const out = await db.withTenant(req.tenant_id, async (client) => {
        const users = await client.query(
          `
          SELECT u.id, u.username, u.email, u.mfa_enabled, u.created_at,
                 COALESCE(
                   (SELECT array_agg(r.name ORDER BY r.name)
                      FROM roles r WHERE r.id = ANY(u.role_ids)),
                   '{}'
                 ) AS roles
          FROM users u
          WHERE u.tenant_id = $1
          ORDER BY u.username
          `,
          [req.tenant_id]
        );
        const roles = await client.query(
          `SELECT id, name, permissions FROM roles WHERE tenant_id = $1 ORDER BY name`,
          [req.tenant_id]
        );
        return { users: users.rows, roles: roles.rows };
      });
      res.status(200).json({ success: true, ...out });
    } catch (error) {
      console.error('Access listing failed:', error.message);
      res.status(500).json({
        success: false,
        error: { code: 'ACCESS_LIST_ERROR', message: 'Failed to list users and roles' },
      });
    }
  }
);

// Command Center data: ingestion totals, hourly volume and a breakdown by
// source type or collector, all derived from the events table.
app.get(
  '/v1/dashboard/ingestion',
  (req, res, next) => {
    req.required_permission = 'search:events:read';
    next();
  },
  authMiddleware,
  tenantMiddleware,
  rbacMiddleware,
  auditMiddleware,
  async (req, res) => {
    // Column comes from a whitelist, never from user input.
    const col = req.query.by === 'collector' ? 'collector_id' : 'source_type';
    try {
      const out = await db.withTenant(req.tenant_id, async (client) => {
        const totals = await client.query(
          `
          SELECT COUNT(*)::int AS events_24h,
                 COALESCE(SUM(octet_length(raw)), 0)::bigint AS bytes_24h,
                 COUNT(*) FILTER (WHERE received_at > localtimestamp - interval '1 hour')::int AS events_1h,
                 COUNT(DISTINCT source_type)::int AS source_types,
                 COUNT(DISTINCT collector_id)::int AS collectors,
                 MAX(received_at) AS last_received
          FROM events
          WHERE tenant_id = $1
            AND COALESCE(event_time, received_at) > localtimestamp - interval '24 hours'
          `,
          [req.tenant_id]
        );
        const hourly = await client.query(
          `
          SELECT g.h AS hour, COALESCE(c.n, 0)::int AS n
          FROM generate_series(
                 date_trunc('hour', localtimestamp) - interval '23 hours',
                 date_trunc('hour', localtimestamp),
                 interval '1 hour') AS g(h)
          LEFT JOIN (
            SELECT date_trunc('hour', COALESCE(event_time, received_at)) AS h, COUNT(*) AS n
            FROM events
            WHERE tenant_id = $1
              AND COALESCE(event_time, received_at) >= date_trunc('hour', localtimestamp) - interval '23 hours'
            GROUP BY 1
          ) c ON c.h = g.h
          ORDER BY g.h
          `,
          [req.tenant_id]
        );
        const groups = await client.query(
          `
          SELECT COALESCE(${col}, '(none)') AS key,
                 COUNT(*)::int AS events_24h,
                 COALESCE(SUM(octet_length(raw)), 0)::bigint AS bytes_24h
          FROM events
          WHERE tenant_id = $1
            AND COALESCE(event_time, received_at) > localtimestamp - interval '24 hours'
          GROUP BY 1
          ORDER BY 2 DESC
          LIMIT 12
          `,
          [req.tenant_id]
        );
        return { totals: totals.rows[0], hourly: hourly.rows, groups: groups.rows };
      });
      res.status(200).json({ success: true, by: col, ...out });
    } catch (error) {
      console.error('Ingestion summary failed:', error.message);
      res.status(500).json({
        success: false,
        error: { code: 'INGESTION_SUMMARY_ERROR', message: 'Failed to build ingestion summary' },
      });
    }
  }
);

// ---------------------------------------------------------------------------
// Detections and alerts
// ---------------------------------------------------------------------------
const { ensureBuiltinRules, BUILTIN_RULES } = require('../detection/rule-runner');
const { normalizeDefinition, buildMatch } = require('../detection/rule-query');
const xql = require('../search/xql');
const guarded = (permission) => [
  (req, res, next) => {
    req.required_permission = permission;
    next();
  },
  authMiddleware,
  tenantMiddleware,
  rbacMiddleware,
  auditMiddleware,
];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const ALERT_STATUSES = ['open', 'acknowledged', 'closed'];
const apiError = (res, status, code, message) =>
  res.status(status).json({ success: false, error: { code, message } });

app.get('/v1/detections/rules', ...guarded('detections:rules:read'), async (req, res) => {
  try {
    const rules = await db.withTenant(req.tenant_id, async (client) => {
      await ensureBuiltinRules(client, req.tenant_id);
      const r = await client.query(
        `SELECT r.id, r.name, r.description, r.severity, r.enabled, r.builtin_key, r.mitre,
                r.definition, r.last_run_at, r.last_error, r.kind, r.category,
                (r.builtin_key IS NULL) AS custom,
                (SELECT COUNT(*)::int FROM alerts a
                  WHERE a.rule_id = r.id AND a.status <> 'closed') AS open_alerts
         FROM detection_rules r
         WHERE r.tenant_id = $1 AND ($2::text IS NULL OR r.kind = $2)
         ORDER BY CASE r.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, r.name`,
        [req.tenant_id, RULE_KINDS.includes(req.query.kind) ? req.query.kind : null]
      );
      return r.rows;
    });
    res.status(200).json({ success: true, rules });
  } catch (error) {
    console.error('Rule listing failed:', error.message);
    apiError(res, 500, 'RULES_LIST_ERROR', 'Failed to list detection rules');
  }
});

// ---- user-defined correlation / BIOC rules -------------------------------------------
const RULE_KINDS = ['correlation', 'bioc'];
const MITRE_RE = /^T\d{4}(\.\d{3})?$/;

// Validates the rule form; returns { rule } or { error }.
function parseRuleBody(b) {
  b = b || {};
  const name = typeof b.name === 'string' ? b.name.trim() : '';
  if (!name || name.length > 255) return { error: 'Rule name is required (max 255 characters)' };
  if (!RULE_KINDS.includes(b.kind)) return { error: 'kind must be correlation or bioc' };
  if (!SEVERITIES.includes(b.severity)) return { error: 'severity must be one of ' + SEVERITIES.join(', ') };
  const mitre = (Array.isArray(b.mitre) ? b.mitre : []).map((m) => String(m).trim().toUpperCase()).filter(Boolean);
  if (mitre.length > 20 || mitre.some((m) => !MITRE_RE.test(m))) return { error: 'MITRE techniques look like T1110 or T1059.004' };
  const norm = normalizeDefinition(b.definition);
  if (norm.error) return { error: norm.error };
  return {
    rule: {
      name, kind: b.kind, severity: b.severity, mitre, definition: norm.def,
      description: typeof b.description === 'string' ? b.description.trim().slice(0, 2000) : '',
      category: typeof b.category === 'string' && b.category.trim() ? b.category.trim().slice(0, 100) : null,
      enabled: b.enabled !== false,
    },
  };
}

app.post('/v1/detections/rules/test', ...guarded('detections:rules:write'), async (req, res) => {
  const norm = normalizeDefinition((req.body || {}).definition);
  if (norm.error) return apiError(res, 400, 'INVALID_DEFINITION', norm.error);
  try {
    const rows = await db.withTenant(req.tenant_id, async (client) => {
      await client.query("SET LOCAL statement_timeout = '10s'");
      const q = buildMatch(req.tenant_id, norm.def, { limit: 20 });
      return (await client.query(q.text, q.values)).rows;
    });
    res.status(200).json({
      success: true,
      window_minutes: norm.def.window_minutes,
      alerts_would_raise: rows.length,
      groups: rows.map((r) => ({ group: r.gkey, events: r.n, last_event_at: r.last_at, sample: r.sample_raw ? String(r.sample_raw).slice(0, 300) : null })),
    });
  } catch (error) {
    console.error('Rule test failed:', error.message);
    apiError(res, 400, 'RULE_TEST_ERROR', 'Query failed: ' + String(error.message).slice(0, 200));
  }
});

app.post('/v1/detections/rules', ...guarded('detections:rules:write'), async (req, res) => {
  const p = parseRuleBody(req.body);
  if (p.error) return apiError(res, 400, 'INVALID_RULE', p.error);
  const r = p.rule;
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const n = await client.query('SELECT COUNT(*)::int AS n FROM detection_rules WHERE tenant_id = $1 AND builtin_key IS NULL', [req.tenant_id]);
      if (n.rows[0].n >= 200) return { limit: true };
      const ins = await client.query(
        `INSERT INTO detection_rules (tenant_id, name, description, severity, enabled, mitre, definition, kind, category)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9) RETURNING id`,
        [req.tenant_id, r.name, r.description, r.severity, r.enabled, r.mitre, JSON.stringify(r.definition), r.kind, r.category]
      );
      return { id: ins.rows[0].id };
    });
    if (out.limit) return apiError(res, 409, 'RULE_LIMIT', 'Custom rule limit (200) reached');
    res.status(201).json({ success: true, id: out.id });
  } catch (error) {
    console.error('Rule create failed:', error.message);
    apiError(res, 500, 'RULE_CREATE_ERROR', 'Failed to create rule');
  }
});

app.put('/v1/detections/rules/:id', ...guarded('detections:rules:write'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid rule id');
  const p = parseRuleBody(req.body);
  if (p.error) return apiError(res, 400, 'INVALID_RULE', p.error);
  const r = p.rule;
  try {
    const u = await db.withTenant(req.tenant_id, (client) =>
      client.query(
        `UPDATE detection_rules
         SET name = $3, description = $4, severity = $5, enabled = $6, mitre = $7, definition = $8::jsonb,
             kind = $9, category = $10, last_error = NULL, updated_at = localtimestamp
         WHERE id = $1 AND tenant_id = $2 RETURNING id`,
        [id, req.tenant_id, r.name, r.description, r.severity, r.enabled, r.mitre, JSON.stringify(r.definition), r.kind, r.category]
      )
    );
    if (!u.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Rule not found');
    res.status(200).json({ success: true, id });
  } catch (error) {
    console.error('Rule update failed:', error.message);
    apiError(res, 500, 'RULE_UPDATE_ERROR', 'Failed to update rule');
  }
});

// Put a built-in rule back to the definition shipped with the platform (keeps its enabled state).
app.post('/v1/detections/rules/:id/reset', ...guarded('detections:rules:write'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid rule id');
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const cur = await client.query('SELECT builtin_key FROM detection_rules WHERE id = $1 AND tenant_id = $2', [id, req.tenant_id]);
      if (!cur.rows.length) return { status: 404, code: 'NOT_FOUND', msg: 'Rule not found' };
      const def = BUILTIN_RULES.find((b) => b.key === cur.rows[0].builtin_key);
      if (!def) return { status: 400, code: 'NOT_BUILTIN', msg: 'Only built-in rules can be reset' };
      await client.query(
        `UPDATE detection_rules SET name = $3, description = $4, severity = $5, mitre = $6, definition = $7::jsonb,
                kind = $8, category = $9, last_error = NULL, updated_at = localtimestamp
         WHERE id = $1 AND tenant_id = $2`,
        [id, req.tenant_id, def.name, def.description, def.severity, def.mitre, JSON.stringify(def.definition), def.kind, def.category]);
      return { ok: true };
    });
    if (!out.ok) return apiError(res, out.status, out.code, out.msg);
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Rule reset failed:', error.message);
    apiError(res, 500, 'RULE_RESET_ERROR', 'Failed to reset rule');
  }
});

app.delete('/v1/detections/rules/:id', ...guarded('detections:rules:write'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid rule id');
  try {
    const d = await db.withTenant(req.tenant_id, (client) =>
      client.query('DELETE FROM detection_rules WHERE id = $1 AND tenant_id = $2 AND builtin_key IS NULL RETURNING id', [id, req.tenant_id])
    );
    if (!d.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Custom rule not found (built-in rules cannot be deleted)');
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Rule delete failed:', error.message);
    apiError(res, 500, 'RULE_DELETE_ERROR', 'Failed to delete rule');
  }
});

// ---- XQL-style search ---------------------------------------------------------------
app.post('/v1/search/xql', ...guarded('search:events:read'), async (req, res) => {
  const b = req.body || {};
  const mins = Number(b.minutes);
  const from = b.from ? new Date(b.from) : mins > 0 ? new Date(Date.now() - mins * 60000) : null;
  const to = b.to ? new Date(b.to) : null;
  if ((from && isNaN(from)) || (to && isNaN(to))) return apiError(res, 400, 'INVALID_TIME', 'Invalid time range');
  let q;
  try {
    q = xql.compile(b.query, { tenantId: req.tenant_id, from: from && from.toISOString(), to: to && to.toISOString(), limit: b.limit });
  } catch (e) {
    if (e instanceof xql.XqlError) return apiError(res, 400, 'XQL_SYNTAX', e.message);
    throw e;
  }
  const t0 = Date.now();
  try {
    const rows = await db.withTenant(req.tenant_id, async (client) => {
      await client.query("SET LOCAL statement_timeout = '20s'");
      return (await client.query(q.sql, q.values)).rows;
    });
    const truncated = rows.length > q.limit;
    if (truncated) rows.length = q.limit;
    const str = (v) => (v === null || v === undefined ? null : v instanceof Date ? v.toISOString().replace('T', ' ').replace(/\..*$/, '') : typeof v === 'object' ? JSON.stringify(v) : String(v));
    let columns = q.columns, out;
    if (q.mode === 'raw') {
      const freq = new Map();
      out = rows.map((r) => {
        const row = { _time: str(r._time), source_type: r.source_type, collector_id: r.collector_id, _id: r._id };
        for (const [k, v] of Object.entries(r.parsed || {})) { if (k in row) continue; row[k] = str(v); freq.set(k, (freq.get(k) || 0) + 1); }
        row._raw = r._raw;
        return row;
      });
      columns = ['_time', 'source_type', 'collector_id', ...[...freq.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40).map((e) => e[0]), '_raw'];
    } else {
      out = rows.map((r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, str(v)])));
    }
    res.status(200).json({ success: true, mode: q.mode, columns, rows: out, count: out.length, truncated, took_ms: Date.now() - t0 });
  } catch (error) {
    console.error('XQL search failed:', error.message);
    apiError(res, 400, 'XQL_ERROR', 'Query failed: ' + String(error.message).slice(0, 200));
  }
});

// Fields and datasets seen recently (feeds the Fields panel and the Schema tab).
const flattenObj = (o, p = '') => Object.entries(o || {}).flatMap(([k, v]) => (v && typeof v === 'object' && !Array.isArray(v) ? flattenObj(v, p + k + '.') : [[p + k, v]]));
app.get('/v1/search/fields', ...guarded('search:events:read'), async (req, res) => {
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      await client.query("SET LOCAL statement_timeout = '10s'");
      const fields = await client.query(
        `SELECT k AS name, COUNT(*)::int AS events FROM (
           SELECT jsonb_object_keys(parsed) AS k FROM (
             SELECT parsed FROM events WHERE tenant_id = $1 ORDER BY received_at DESC LIMIT 2000) s
         ) t GROUP BY k ORDER BY events DESC, k LIMIT 200`, [req.tenant_id]);
      const datasets = await client.query(
        `SELECT source_type AS name, COUNT(*)::int AS events, MAX(received_at) AS last_seen FROM events
         WHERE tenant_id = $1 AND received_at > localtimestamp - interval '7 days' GROUP BY 1 ORDER BY 2 DESC`, [req.tenant_id]);
      // Data model fields live nested under parsed.xdm; list them as xdm.a.b so the Search page can offer them.
      const xs = await client.query(
        `SELECT parsed->'xdm' AS x FROM events WHERE tenant_id = $1 AND parsed ? 'xdm' ORDER BY received_at DESC LIMIT 500`, [req.tenant_id]);
      const xc = {};
      for (const row of xs.rows) for (const [k] of flattenObj(row.x, 'xdm.')) xc[k] = (xc[k] || 0) + 1;
      const xdmFields = Object.entries(xc).map(([name, events]) => ({ name, events })).sort((a, b) => b.events - a.events || a.name.localeCompare(b.name));
      return { fields: fields.rows.concat(xdmFields), datasets: datasets.rows };
    });
    res.status(200).json({ success: true, ...out, sampled_events: 2000 });
  } catch (error) {
    console.error('Field listing failed:', error.message);
    apiError(res, 500, 'FIELDS_ERROR', 'Failed to list fields');
  }
});

app.patch('/v1/detections/rules/:id', ...guarded('detections:rules:write'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid rule id');
  if (typeof (req.body || {}).enabled !== 'boolean') {
    return apiError(res, 400, 'INVALID_BODY', 'Body must be {"enabled": true|false}');
  }
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query(
        'UPDATE detection_rules SET enabled = $2, updated_at = localtimestamp WHERE id = $1 AND tenant_id = $3 RETURNING id, enabled',
        [id, req.body.enabled, req.tenant_id]
      )
    );
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Rule not found');
    res.status(200).json({ success: true, rule: r.rows[0] });
  } catch (error) {
    console.error('Rule update failed:', error.message);
    apiError(res, 500, 'RULE_UPDATE_ERROR', 'Failed to update rule');
  }
});

app.get('/v1/alerts/summary', ...guarded('alerts:read'), async (req, res) => {
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query(
        `SELECT severity, COUNT(*)::int AS n FROM alerts
         WHERE tenant_id = $1 AND status IN ('open', 'acknowledged') GROUP BY severity`,
        [req.tenant_id]
      )
    );
    const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
    r.rows.forEach((row) => { counts[row.severity] = row.n; });
    res.status(200).json({ success: true, active: counts, active_total: Object.values(counts).reduce((a, b) => a + b, 0) });
  } catch (error) {
    console.error('Alert summary failed:', error.message);
    apiError(res, 500, 'ALERT_SUMMARY_ERROR', 'Failed to summarise alerts');
  }
});

app.get('/v1/alerts', ...guarded('alerts:read'), async (req, res) => {
  const status = String(req.query.status || 'active');
  const where = ['tenant_id = $1'];
  const params = [req.tenant_id];
  if (status === 'active') where.push("status IN ('open', 'acknowledged')");
  else if (ALERT_STATUSES.includes(status)) { params.push(status); where.push(`status = $${params.length}`); }
  else if (status !== 'all') return apiError(res, 400, 'INVALID_STATUS', 'status must be active, all, open, acknowledged or closed');
  if (req.query.severity) {
    if (!SEVERITIES.includes(String(req.query.severity))) return apiError(res, 400, 'INVALID_SEVERITY', 'Invalid severity');
    params.push(String(req.query.severity));
    where.push(`severity = $${params.length}`);
  }
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query(
        `SELECT id, rule_id, rule_name, severity, status, title, summary, group_key,
                event_count, first_event_at, last_event_at, created_at
         FROM alerts WHERE ${where.join(' AND ')}
         ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                  last_event_at DESC
         LIMIT ${limit} OFFSET ${offset}`,
        params
      )
    );
    res.status(200).json({ success: true, count: r.rows.length, alerts: r.rows });
  } catch (error) {
    console.error('Alert listing failed:', error.message);
    apiError(res, 500, 'ALERTS_LIST_ERROR', 'Failed to list alerts');
  }
});

app.get('/v1/alerts/:id', ...guarded('alerts:read'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid alert id');
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const a = await client.query('SELECT * FROM alerts WHERE id = $1 AND tenant_id = $2', [id, req.tenant_id]);
      if (!a.rows.length) return null;
      const ids = (a.rows[0].details && a.rows[0].details.sample_event_ids) || [];
      const ev = ids.length
        ? await client.query(
            `SELECT id, source_type, collector_id, received_at, event_time, raw
             FROM events WHERE tenant_id = $1 AND id = ANY($2::uuid[])
             ORDER BY COALESCE(event_time, received_at) DESC`,
            [req.tenant_id, ids]
          )
        : { rows: [] };
      return { alert: a.rows[0], events: ev.rows };
    });
    if (!out) return apiError(res, 404, 'NOT_FOUND', 'Alert not found');
    res.status(200).json({ success: true, ...out });
  } catch (error) {
    console.error('Alert detail failed:', error.message);
    apiError(res, 500, 'ALERT_DETAIL_ERROR', 'Failed to load alert');
  }
});

app.patch('/v1/alerts/:id', ...guarded('alerts:write'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid alert id');
  const status = (req.body || {}).status;
  if (!ALERT_STATUSES.includes(status)) return apiError(res, 400, 'INVALID_BODY', 'status must be open, acknowledged or closed');
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query(
        'UPDATE alerts SET status = $2, updated_at = localtimestamp WHERE id = $1 AND tenant_id = $3 RETURNING id, status',
        [id, status, req.tenant_id]
      )
    );
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Alert not found');
    res.status(200).json({ success: true, alert: r.rows[0] });
  } catch (error) {
    console.error('Alert update failed:', error.message);
    apiError(res, 500, 'ALERT_UPDATE_ERROR', 'Failed to update alert');
  }
});

// ---- Threat intelligence: indicators (IOCs) -------------------------------------------
const { TYPES: INDICATOR_TYPES, classify: classifyIndicator } = require('../threat-intel/indicators');
const MAX_IMPORT = 5000;

app.get('/v1/threat-intel/indicators', ...guarded('threatintel:read'), async (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  const where = ['tenant_id = $1'];
  const args = [req.tenant_id];
  if (INDICATOR_TYPES.includes(req.query.type)) { args.push(req.query.type); where.push(`type = $${args.length}`); }
  if (req.query.source) { args.push(String(req.query.source)); where.push(`source = $${args.length}`); }
  if (req.query.q) { args.push('%' + String(req.query.q).toLowerCase().replace(/[%_\\]/g, '\\$&') + '%'); where.push(`value LIKE $${args.length}`); }
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const total = await client.query(`SELECT COUNT(*)::int AS n FROM threat_indicators WHERE ${where.join(' AND ')}`, args);
      const rows = await client.query(
        `SELECT id, type, value, source, severity, description, enabled, expires_at, created_at
         FROM threat_indicators WHERE ${where.join(' AND ')}
         ORDER BY created_at DESC, id LIMIT ${limit} OFFSET ${offset}`, args);
      return { total: total.rows[0].n, indicators: rows.rows };
    });
    res.status(200).json({ success: true, limit, offset, ...out });
  } catch (error) {
    console.error('Indicator listing failed:', error.message);
    apiError(res, 500, 'INDICATOR_LIST_ERROR', 'Failed to list indicators');
  }
});

// Body: { indicators: "one per line" | [..], source?, severity?, description?, expires_in_days? }
app.post('/v1/threat-intel/indicators', ...guarded('threatintel:write'), async (req, res) => {
  const b = req.body || {};
  // Text input: one or more indicators per line (separated by space, comma, semicolon or tab);
  // lines starting with # are comments.
  const lines = Array.isArray(b.indicators)
    ? b.indicators
    : String(b.indicators || '').split(/\r?\n/).filter((l) => !l.trim().startsWith('#')).flatMap((l) => l.split(/[\s,;]+/));
  const severity = b.severity || 'medium';
  if (!SEVERITIES.includes(severity)) return apiError(res, 400, 'INVALID_SEVERITY', 'severity must be one of ' + SEVERITIES.join(', '));
  const source = String(b.source || 'manual').trim().slice(0, 100) || 'manual';
  const days = Number(b.expires_in_days);
  const seen = new Set(); const types = []; const values = []; const invalid = [];
  for (const raw of lines) {
    const t = String(raw || '').trim();
    if (!t || t.startsWith('#')) continue;
    const c = classifyIndicator(t);
    if (!c) { invalid.push(t.slice(0, 80)); continue; }
    const k = c.type + ':' + c.value;
    if (!seen.has(k)) { seen.add(k); types.push(c.type); values.push(c.value); }
  }
  if (types.length > MAX_IMPORT) return apiError(res, 413, 'TOO_MANY', `At most ${MAX_IMPORT} indicators per request`);
  if (!types.length) return apiError(res, 400, 'NO_VALID_INDICATORS', 'No valid indicators found (invalid: ' + invalid.slice(0, 5).join(', ') + ')');
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      `INSERT INTO threat_indicators (tenant_id, type, value, source, severity, description, expires_at)
       SELECT $1, x.t, x.v, $4, $5, $6, CASE WHEN $7::int > 0 THEN localtimestamp + ($7::int * interval '1 day') END
       FROM unnest($2::text[], $3::text[]) AS x(t, v)
       ON CONFLICT (tenant_id, type, value) DO UPDATE
         SET source = EXCLUDED.source, severity = EXCLUDED.severity,
             description = COALESCE(EXCLUDED.description, threat_indicators.description),
             expires_at = EXCLUDED.expires_at, enabled = true, updated_at = localtimestamp
       RETURNING (xmax = 0) AS inserted`,
      [req.tenant_id, types, values, source, severity, b.description ? String(b.description).slice(0, 500) : null, days > 0 ? Math.floor(days) : 0]
    ));
    const added = r.rows.filter((x) => x.inserted).length;
    res.status(200).json({ success: true, added, updated: r.rows.length - added, invalid_count: invalid.length, invalid: invalid.slice(0, 10) });
  } catch (error) {
    console.error('Indicator import failed:', error.message);
    apiError(res, 500, 'INDICATOR_IMPORT_ERROR', 'Failed to import indicators');
  }
});

app.patch('/v1/threat-intel/indicators/:id', ...guarded('threatintel:write'), async (req, res) => {
  const { id } = req.params; const b = req.body || {};
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid indicator id');
  if (b.enabled !== undefined && typeof b.enabled !== 'boolean') return apiError(res, 400, 'INVALID_BODY', 'enabled must be true or false');
  if (b.severity !== undefined && !SEVERITIES.includes(b.severity)) return apiError(res, 400, 'INVALID_SEVERITY', 'severity must be one of ' + SEVERITIES.join(', '));
  if (b.enabled === undefined && b.severity === undefined) return apiError(res, 400, 'INVALID_BODY', 'Nothing to update');
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      `UPDATE threat_indicators SET enabled = COALESCE($2, enabled), severity = COALESCE($3, severity), updated_at = localtimestamp
       WHERE id = $1 AND tenant_id = $4 RETURNING id, enabled, severity`,
      [id, b.enabled ?? null, b.severity ?? null, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Indicator not found');
    res.status(200).json({ success: true, indicator: r.rows[0] });
  } catch (error) {
    console.error('Indicator update failed:', error.message);
    apiError(res, 500, 'INDICATOR_UPDATE_ERROR', 'Failed to update indicator');
  }
});

app.delete('/v1/threat-intel/indicators/:id', ...guarded('threatintel:write'), async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return apiError(res, 400, 'INVALID_ID', 'Invalid indicator id');
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query('DELETE FROM threat_indicators WHERE id = $1 AND tenant_id = $2 RETURNING id', [id, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Indicator not found');
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Indicator delete failed:', error.message);
    apiError(res, 500, 'INDICATOR_DELETE_ERROR', 'Failed to delete indicator');
  }
});

// Library (per source) + type totals + IOC matcher status
app.get('/v1/threat-intel/summary', ...guarded('threatintel:read'), async (req, res) => {
  try {
    const out = await db.withTenant(req.tenant_id, async (client) => {
      const types = await client.query(
        `SELECT type, COUNT(*)::int AS n FROM threat_indicators WHERE tenant_id = $1 GROUP BY type ORDER BY n DESC`, [req.tenant_id]);
      const sources = await client.query(
        `SELECT source, COUNT(*)::int AS indicators,
                COUNT(*) FILTER (WHERE enabled)::int AS enabled,
                array_agg(DISTINCT type) AS types, MAX(updated_at) AS last_updated
         FROM threat_indicators WHERE tenant_id = $1 GROUP BY source ORDER BY MAX(updated_at) DESC`, [req.tenant_id]);
      const active = await client.query(
        `SELECT COUNT(*)::int AS n FROM threat_indicators
         WHERE tenant_id = $1 AND enabled AND (expires_at IS NULL OR expires_at > localtimestamp)`, [req.tenant_id]);
      const matcher = await client.query(
        `SELECT last_run_at, last_error, matched_total::int AS matched_total FROM ioc_scan_state WHERE tenant_id = $1`, [req.tenant_id]);
      const alerts = await client.query(
        `SELECT COUNT(*) FILTER (WHERE status IN ('open','acknowledged'))::int AS open, COUNT(*)::int AS total
         FROM alerts WHERE tenant_id = $1 AND rule_name = 'IOC match'`, [req.tenant_id]);
      return { types: types.rows, sources: sources.rows, active_indicators: active.rows[0].n,
               matcher: matcher.rows[0] || null, ioc_alerts: alerts.rows[0] };
    });
    res.status(200).json({ success: true, ...out });
  } catch (error) {
    console.error('Threat intel summary failed:', error.message);
    apiError(res, 500, 'THREAT_INTEL_SUMMARY_ERROR', 'Failed to build threat intel summary');
  }
});

// ---- Collectors + ingestion keys (installers) ---------------------------------------------
const { generateKey, hashKey, PLATFORMS: KEY_PLATFORMS } = require('../ingest/http-ingest');
const CONNECTED_WITHIN_MIN = 15;

// Registered senders (collectors table) plus built-in ones that only appear in events
// (e.g. the in-cluster syslog collector), so the page shows everything that feeds the SIEM.
app.get('/v1/collectors', ...guarded('collectors:read'), async (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 500);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  try {
    const all = await db.withTenant(req.tenant_id, async (client) => {
      const reg = await client.query(
        `SELECT c.id, c.name, c.alias, c.platform, c.os, c.version, c.last_ip, c.first_seen, c.last_seen,
                c.events_total::bigint AS events_total, k.name AS installer, 'registered' AS origin
         FROM collectors c LEFT JOIN ingestion_keys k ON k.id = c.key_id WHERE c.tenant_id = $1`, [req.tenant_id]);
      const built = await client.query(
        `SELECT NULL::uuid AS id, e.collector_id AS name, NULL AS alias, 'syslog' AS platform, NULL AS os, NULL AS version,
                NULL AS last_ip, MIN(e.received_at) AS first_seen, MAX(e.received_at) AS last_seen,
                COUNT(*)::bigint AS events_total, NULL AS installer, 'built-in' AS origin
         FROM events e
         WHERE e.tenant_id = $1 AND e.collector_id IS NOT NULL AND e.received_at > localtimestamp - interval '7 days'
           AND e.collector_id NOT IN (SELECT name FROM collectors WHERE tenant_id = $1)
         GROUP BY e.collector_id`, [req.tenant_id]);
      const day = await client.query(
        `SELECT collector_id, COUNT(*)::int AS n FROM events
         WHERE tenant_id = $1 AND collector_id IS NOT NULL AND received_at > localtimestamp - interval '24 hours'
         GROUP BY collector_id`, [req.tenant_id]);
      const d = new Map(day.rows.map((r) => [r.collector_id, r.n]));
      const cutoff = Date.now() - CONNECTED_WITHIN_MIN * 60000;
      return reg.rows.concat(built.rows).map((c) => ({
        ...c, events_total: Number(c.events_total), events_24h: d.get(c.name) || 0,
        status: new Date(String(c.last_seen).endsWith('Z') ? c.last_seen : c.last_seen + 'Z').getTime() >= cutoff ? 'connected' : 'disconnected',
      }));
    });
    const q = String(req.query.q || '').toLowerCase();
    const rows = all
      .filter((c) => (!req.query.status || c.status === req.query.status)
        && (!q || [c.name, c.alias, c.platform, c.os, c.last_ip, c.installer].some((v) => v && String(v).toLowerCase().includes(q))))
      .sort((a, b) => String(a.name).localeCompare(String(b.name)));
    res.status(200).json({ success: true, total: rows.length, overall: all.length, connected_within_minutes: CONNECTED_WITHIN_MIN,
      collectors: rows.slice(offset, offset + limit) });
  } catch (error) {
    console.error('Collector listing failed:', error.message);
    apiError(res, 500, 'COLLECTOR_LIST_ERROR', 'Failed to list collectors');
  }
});

app.patch('/v1/collectors/:id', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid collector id');
  const alias = req.body && req.body.alias;
  if (alias !== null && (typeof alias !== 'string' || alias.length > 200)) return apiError(res, 400, 'INVALID_BODY', 'alias must be a string up to 200 chars (or null to clear)');
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      'UPDATE collectors SET alias = $2 WHERE id = $1 AND tenant_id = $3 RETURNING id, alias', [req.params.id, alias ? alias.trim() : null, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Collector not found');
    res.status(200).json({ success: true, collector: r.rows[0] });
  } catch (error) {
    console.error('Collector update failed:', error.message);
    apiError(res, 500, 'COLLECTOR_UPDATE_ERROR', 'Failed to update collector');
  }
});

app.delete('/v1/collectors/:id', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid collector id');
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query('DELETE FROM collectors WHERE id = $1 AND tenant_id = $2 RETURNING id', [req.params.id, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Collector not found');
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Collector delete failed:', error.message);
    apiError(res, 500, 'COLLECTOR_DELETE_ERROR', 'Failed to delete collector');
  }
});

app.get('/v1/ingestion-keys', ...guarded('collectors:read'), async (req, res) => {
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      `SELECT k.id, k.name, k.description, k.platform, k.key_prefix, k.status, k.created_by, k.created_at, k.last_used_at, k.revoked_at,
              (SELECT COUNT(*)::int FROM collectors c WHERE c.key_id = k.id) AS collectors
       FROM ingestion_keys k WHERE k.tenant_id = $1 ORDER BY k.created_at DESC`, [req.tenant_id]));
    res.status(200).json({ success: true, keys: r.rows });
  } catch (error) {
    console.error('Ingestion key listing failed:', error.message);
    apiError(res, 500, 'KEY_LIST_ERROR', 'Failed to list installers');
  }
});

// The plaintext key is returned exactly once, here. Only its SHA-256 hash is stored.
app.post('/v1/ingestion-keys', ...guarded('collectors:write'), async (req, res) => {
  const b = req.body || {};
  const name = String(b.name || '').trim();
  const platform = String(b.platform || 'linux').toLowerCase();
  if (!/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,99}$/.test(name)) return apiError(res, 400, 'INVALID_NAME', 'Name: 1-100 chars, letters, digits, space . _ -');
  if (!KEY_PLATFORMS.includes(platform)) return apiError(res, 400, 'INVALID_PLATFORM', 'platform must be one of ' + KEY_PLATFORMS.join(', '));
  const key = generateKey();
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      `INSERT INTO ingestion_keys (tenant_id, name, description, platform, key_prefix, key_hash, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name, platform, key_prefix, created_at`,
      [req.tenant_id, name, b.description ? String(b.description).slice(0, 500) : null, platform, key.slice(0, 12), hashKey(key), req.user_id || null]));
    res.status(201).json({ success: true, key, installer: r.rows[0] });
  } catch (error) {
    if (error.code === '23505') return apiError(res, 409, 'NAME_IN_USE', 'An installer with that name already exists');
    console.error('Ingestion key create failed:', error.message);
    apiError(res, 500, 'KEY_CREATE_ERROR', 'Failed to create installer');
  }
});

app.post('/v1/ingestion-keys/:id/revoke', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid installer id');
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      "UPDATE ingestion_keys SET status = 'revoked', revoked_at = COALESCE(revoked_at, localtimestamp) WHERE id = $1 AND tenant_id = $2 RETURNING id, status",
      [req.params.id, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Installer not found');
    res.status(200).json({ success: true, installer: r.rows[0] });
  } catch (error) {
    console.error('Ingestion key revoke failed:', error.message);
    apiError(res, 500, 'KEY_REVOKE_ERROR', 'Failed to revoke installer');
  }
});

app.delete('/v1/ingestion-keys/:id', ...guarded('collectors:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid installer id');
  try {
    const r = await db.withTenant(req.tenant_id, (client) =>
      client.query('DELETE FROM ingestion_keys WHERE id = $1 AND tenant_id = $2 RETURNING id', [req.params.id, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Installer not found');
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Ingestion key delete failed:', error.message);
    apiError(res, 500, 'KEY_DELETE_ERROR', 'Failed to delete installer');
  }
});

// ---- Alert notifications (email / Slack / webhook) ---------------------------------------
const notifyBox = require('../notifications/secret-box');
const notifyCh = require('../notifications/channels');
const { testMessage, sendToChannel } = require('../notifications/senders');

const CHANNEL_SELECT = `
  SELECT c.*,
    (SELECT d.status FROM notification_deliveries d WHERE d.channel_id = c.id ORDER BY d.created_at DESC LIMIT 1) AS last_delivery_status,
    (SELECT COALESCE(d.sent_at, d.created_at) FROM notification_deliveries d WHERE d.channel_id = c.id ORDER BY d.created_at DESC LIMIT 1) AS last_delivery_at
  FROM notification_channels c`;
const publicChannel = (row) => {
  try { return notifyCh.toPublic(row, notifyBox.decrypt(row.config_enc)); }
  catch { return { ...notifyCh.toPublic({ ...row }, { to: [] }), config: {}, target: '(cannot be decrypted - encryption key changed?)', config_error: true }; }
};
const notifyError = (res, e, fallback) => {
  if (e.code === 'INVALID_CONFIG') return apiError(res, 400, 'INVALID_CONFIG', e.message);
  if (e.code === 'NO_KEY') return apiError(res, 503, 'NOTIFY_NOT_CONFIGURED', 'Notification encryption key is not configured on the server');
  if (e.code === '23505') return apiError(res, 409, 'NAME_IN_USE', 'A channel with that name already exists');
  console.error(fallback + ':', e.message);
  return apiError(res, 500, 'NOTIFY_ERROR', fallback);
};

app.get('/v1/notifications/channels', ...guarded('notify:read'), async (req, res) => {
  try {
    const r = await db.withTenant(req.tenant_id, (c) => c.query(`${CHANNEL_SELECT} WHERE c.tenant_id = $1 ORDER BY c.name`, [req.tenant_id]));
    res.status(200).json({ success: true, encryption_configured: notifyBox.configured(), channels: r.rows.map(publicChannel) });
  } catch (e) { notifyError(res, e, 'Failed to list channels'); }
});

app.post('/v1/notifications/channels', ...guarded('notify:write'), async (req, res) => {
  try {
    const b = req.body || {};
    const common = notifyCh.validateCommon(b);
    const config = notifyCh.normalizeConfig(b.type, b.config);
    const enc = notifyBox.encrypt(config);
    const r = await db.withTenant(req.tenant_id, (c) => c.query(
      `INSERT INTO notification_channels (tenant_id, name, type, enabled, min_severity, rule_filter, config_enc)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`, [req.tenant_id, common.name, b.type, common.enabled, common.min_severity, common.rule_filter, enc]));
    const row = (await db.withTenant(req.tenant_id, (c) => c.query(`${CHANNEL_SELECT} WHERE c.id = $1`, [r.rows[0].id]))).rows[0];
    res.status(201).json({ success: true, channel: publicChannel(row) });
  } catch (e) { notifyError(res, e, 'Failed to create channel'); }
});

app.patch('/v1/notifications/channels/:id', ...guarded('notify:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid channel id');
  try {
    const b = req.body || {};
    const cur = (await db.withTenant(req.tenant_id, (c) => c.query('SELECT * FROM notification_channels WHERE id = $1 AND tenant_id = $2', [req.params.id, req.tenant_id]))).rows[0];
    if (!cur) return apiError(res, 404, 'NOT_FOUND', 'Channel not found');
    const common = notifyCh.validateCommon(b, cur);
    let enc = cur.config_enc;
    if (b.config !== undefined) enc = notifyBox.encrypt(notifyCh.normalizeConfig(cur.type, b.config, notifyBox.decrypt(cur.config_enc)));
    await db.withTenant(req.tenant_id, (c) => c.query(
      `UPDATE notification_channels SET name=$2, enabled=$3, min_severity=$4, rule_filter=$5, config_enc=$6, updated_at=localtimestamp WHERE id=$1 AND tenant_id=$7`,
      [cur.id, common.name, common.enabled, common.min_severity, common.rule_filter, enc, req.tenant_id]));
    const row = (await db.withTenant(req.tenant_id, (c) => c.query(`${CHANNEL_SELECT} WHERE c.id = $1`, [cur.id]))).rows[0];
    res.status(200).json({ success: true, channel: publicChannel(row) });
  } catch (e) { notifyError(res, e, 'Failed to update channel'); }
});

app.delete('/v1/notifications/channels/:id', ...guarded('notify:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid channel id');
  try {
    const r = await db.withTenant(req.tenant_id, (c) => c.query('DELETE FROM notification_channels WHERE id = $1 AND tenant_id = $2 RETURNING id', [req.params.id, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Channel not found');
    res.status(200).json({ success: true });
  } catch (e) { notifyError(res, e, 'Failed to delete channel'); }
});

// Sends a clearly-marked test message right now (PagerDuty: trigger then immediately resolve).
app.post('/v1/notifications/channels/:id/test', ...guarded('notify:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid channel id');
  try {
    const row = (await db.withTenant(req.tenant_id, (c) => c.query('SELECT * FROM notification_channels WHERE id = $1 AND tenant_id = $2', [req.params.id, req.tenant_id]))).rows[0];
    if (!row) return apiError(res, 404, 'NOT_FOUND', 'Channel not found');
    const tn = (await db.query('SELECT name FROM tenants WHERE id = $1', [req.tenant_id])).rows[0];
    try {
      await sendToChannel(row.type, notifyBox.decrypt(row.config_enc), testMessage({ tenantName: tn && tn.name, baseUrl: process.env.ASIX_PUBLIC_URL }));
    } catch (e) {
      if (e.code === 'NO_KEY') throw e;
      return res.status(502).json({ success: false, error: { code: 'NOTIFY_TEST_FAILED', message: String(e.message || e).slice(0, 300) } });
    }
    res.status(200).json({ success: true });
  } catch (e) { notifyError(res, e, 'Failed to send test notification'); }
});

app.get('/v1/notifications/deliveries', ...guarded('notify:read'), async (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  const status = ['pending', 'sent', 'failed', 'skipped'].includes(req.query.status) ? req.query.status : null;
  try {
    const r = await db.withTenant(req.tenant_id, async (c) => {
      const rows = await c.query(
        `SELECT d.id, d.status, d.attempts, d.last_error, d.sent_at, d.created_at, d.next_attempt_at,
                ch.name AS channel_name, ch.type AS channel_type, a.id AS alert_id, a.title, a.severity
         FROM notification_deliveries d
         JOIN notification_channels ch ON ch.id = d.channel_id JOIN alerts a ON a.id = d.alert_id
         WHERE d.tenant_id = $1 AND ($2::text IS NULL OR d.status = $2)
         ORDER BY d.created_at DESC LIMIT ${limit} OFFSET ${offset}`, [req.tenant_id, status]);
      const total = await c.query('SELECT COUNT(*)::int AS n FROM notification_deliveries WHERE tenant_id = $1 AND ($2::text IS NULL OR status = $2)', [req.tenant_id, status]);
      return { deliveries: rows.rows, total: total.rows[0].n };
    });
    res.status(200).json({ success: true, limit, offset, ...r });
  } catch (e) { notifyError(res, e, 'Failed to list deliveries'); }
});

app.post('/v1/notifications/deliveries/:id/retry', ...guarded('notify:write'), async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_ID', 'Invalid delivery id');
  try {
    const r = await db.withTenant(req.tenant_id, (c) => c.query(
      `UPDATE notification_deliveries SET status='pending', attempts=0, next_attempt_at=localtimestamp, last_error=NULL
       WHERE id=$1 AND tenant_id=$2 AND status IN ('failed','skipped') RETURNING id`, [req.params.id, req.tenant_id]));
    if (!r.rows.length) return apiError(res, 404, 'NOT_FOUND', 'Delivery not found or not retryable');
    res.status(200).json({ success: true });
  } catch (e) { notifyError(res, e, 'Failed to retry delivery'); }
});

// Basic service endpoint.
// ---- Parsing rules (XSIAM-style) ----------------------------------------------------------
const parsingRules = require('../ingestion/parsing-rules');
const rulesStore = require('../ingestion/rules-store');
const { parseLine: parseLineText, jsonEvent: parseJsonEvent } = require('../ingest/http-ingest');
// A pasted line that starts with { is treated as a JSON event (message + fields), like the forwarders send.
const parseIngestLine = (line, collector) => {
  if (line.trim().startsWith('{')) { try { const it = parseJsonEvent(JSON.parse(line), collector); if (it) return it; } catch { /* not JSON: fall back to plain text */ } }
  return parseLineText(line, collector);
};
// Lines pasted from the Windows forwarder ("[Security] Provider id=4625 ...") are simulated as the windows-event dataset.
const WIN_LINE = /^\[(Security|System|Application)\] /;
const ruleErr = (res, e) => apiError(res, 400, 'PARSE_RULES_INVALID', e.message + (e.line ? ` (line ${e.line}, column ${e.column})` : '')) || res;

app.get('/v1/parsing-rules', ...guarded('parsing:rules:read'), async (req, res) => {
  try {
    const row = await rulesStore.loadUser(req.tenant_id);
    let info = [];
    if (row && row.content.trim()) { try { info = parsingRules.compile(row.content).info; } catch { /* shown by the editor on next save */ } }
    res.status(200).json({
      success: true,
      user_defined: { content: row ? row.content : '', version: row ? row.version : 0, updated_at: row ? row.updated_at : null, rules: info },
      default: { content: rulesStore.DEFAULT_SRC, rules: rulesStore.DEFAULT_INFO },
    });
  } catch (error) {
    console.error('Parsing rules load failed:', error.message);
    apiError(res, 500, 'PARSE_RULES_ERROR', 'Failed to load parsing rules');
  }
});

// Save = validate + store. Rejected with the line/column of the first error; ingestion keeps
// using the previously saved rules until a valid set is saved.
app.put('/v1/parsing-rules', ...guarded('parsing:rules:write'), async (req, res) => {
  const content = req.body && req.body.content;
  if (typeof content !== 'string') return apiError(res, 400, 'INVALID_BODY', 'content (text) is required');
  let info = [];
  if (content.trim()) { try { info = parsingRules.compile(content).info; } catch (e) { if (e instanceof parsingRules.RuleError) return ruleErr(res, e); throw e; } }
  try {
    const r = await db.withTenant(req.tenant_id, (client) => client.query(
      `INSERT INTO parsing_rules (tenant_id, content, version, updated_by) VALUES ($1, $2, 1, $3)
       ON CONFLICT (tenant_id) DO UPDATE SET content = EXCLUDED.content, version = parsing_rules.version + 1,
         updated_by = EXCLUDED.updated_by, updated_at = CURRENT_TIMESTAMP
       RETURNING version, updated_at`, [req.tenant_id, content, req.user_id || null]));
    rulesStore.invalidate(req.tenant_id);
    res.status(200).json({ success: true, version: r.rows[0].version, updated_at: r.rows[0].updated_at, rules: info });
  } catch (error) {
    console.error('Parsing rules save failed:', error.message);
    apiError(res, 500, 'PARSE_RULES_ERROR', 'Failed to save parsing rules');
  }
});

// Simulate: run sample log lines through user / default / both rules without storing anything.
// `content` (optional) is the unsaved editor text and is used as the user-defined set.
app.post('/v1/parsing-rules/simulate', ...guarded('parsing:rules:read'), async (req, res) => {
  const b = req.body || {};
  const scope = ['user', 'default', 'both'].includes(b.scope) ? b.scope : 'both';
  const sourceType = /^[A-Za-z0-9._-]{1,50}$/.test(String(b.source_type || '')) ? String(b.source_type) : 'syslog';
  const lines = String(b.logs || '').split(/\r?\n/).filter((l) => l.trim());
  if (!lines.length) return apiError(res, 400, 'NO_LOGS', 'Paste at least one log line');
  if (lines.length > 50) return apiError(res, 400, 'TOO_MANY_LOGS', 'Simulate up to 50 lines at a time');
  try {
    const sets = [];
    if (scope !== 'default') {
      const src = typeof b.content === 'string' ? b.content : ((await rulesStore.loadUser(req.tenant_id)) || {}).content || '';
      if (src.trim()) { try { sets.push(parsingRules.compile(src).rules); } catch (e) { if (e instanceof parsingRules.RuleError) return ruleErr(res, e); throw e; } }
    }
    if (scope !== 'user') sets.push(rulesStore.DEFAULT_RULES);
    const results = lines.map((line) => {
      const it = parseIngestLine(line, 'simulate');
      const before = { ...it.parsed };
      const o = parsingRules.apply(sets, { source_type: WIN_LINE.test(it.raw) ? 'windows-event' : sourceType, raw: it.raw, time: it.time, parsed: it.parsed });
      return { raw: it.raw, source_type: o.source_type, time: o.time, before, after: o.parsed, matched: o.matched, dropped: o.dropped, errors: o.errors };
    });
    res.status(200).json({ success: true, scope, results });
  } catch (error) {
    console.error('Parsing rules simulate failed:', error.message);
    apiError(res, 500, 'PARSE_RULES_ERROR', 'Simulation failed');
  }
});

// ---- Data model rules (XDM) ------------------------------------------------------------------
const xdmSchema = require('../ingestion/xdm-schema');

app.get('/v1/data-model-rules', ...guarded('datamodel:rules:read'), async (req, res) => {
  try {
    const row = await rulesStore.loadUser(req.tenant_id, 'model');
    let info = [];
    if (row && row.content.trim()) { try { info = parsingRules.compile(row.content, 'model').info; } catch { /* shown by the editor on next save */ } }
    res.status(200).json({
      success: true,
      user_defined: { content: row ? row.content : '', version: row ? row.version : 0, updated_at: row ? row.updated_at : null, rules: info },
      default: { content: rulesStore.DEFAULT_MODEL_SRC, rules: rulesStore.DEFAULT_MODEL_INFO },
      schema: { fields: xdmSchema.FIELDS, constants: xdmSchema.CONSTANTS },
    });
  } catch (error) {
    console.error('Data model rules load failed:', error.message);
    apiError(res, 500, 'MODEL_RULES_ERROR', 'Failed to load data model rules');
  }
});

app.put('/v1/data-model-rules', ...guarded('datamodel:rules:write'), async (req, res) => {
  const content = req.body && req.body.content;
  if (typeof content !== 'string') return apiError(res, 400, 'INVALID_BODY', 'content (text) is required');
  let info = [];
  if (content.trim()) {
    try { info = parsingRules.compile(content, 'model').info; }
    catch (e) { if (e instanceof parsingRules.RuleError) return apiError(res, 400, 'MODEL_RULES_INVALID', e.message + ` (line ${e.line}, column ${e.column})`); throw e; }
  }
  try {
    const r = await rulesStore.saveUser(req.tenant_id, 'model', content, req.user_id);
    res.status(200).json({ success: true, version: r.version, updated_at: r.updated_at, rules: info });
  } catch (error) {
    console.error('Data model rules save failed:', error.message);
    apiError(res, 500, 'MODEL_RULES_ERROR', 'Failed to save data model rules');
  }
});

// Simulate the whole path: log line -> saved parsing rules -> model rules (unsaved editor text if given).
app.post('/v1/data-model-rules/simulate', ...guarded('datamodel:rules:read'), async (req, res) => {
  const b = req.body || {};
  const scope = ['user', 'default', 'both'].includes(b.scope) ? b.scope : 'both';
  const sourceType = /^[A-Za-z0-9._-]{1,50}$/.test(String(b.source_type || '')) ? String(b.source_type) : 'syslog';
  const lines = String(b.logs || '').split(/\r?\n/).filter((l) => l.trim());
  if (!lines.length) return apiError(res, 400, 'NO_LOGS', 'Paste at least one log line');
  if (lines.length > 50) return apiError(res, 400, 'TOO_MANY_LOGS', 'Simulate up to 50 lines at a time');
  try {
    const pSets = await rulesStore.getActiveSets(req.tenant_id);
    const mSets = [];
    if (scope !== 'user') mSets.push(rulesStore.DEFAULT_MODEL_RULES);
    if (scope !== 'default') {
      const src = typeof b.content === 'string' ? b.content : ((await rulesStore.loadUser(req.tenant_id, 'model')) || {}).content || '';
      if (src.trim()) { try { mSets.push(parsingRules.compile(src, 'model').rules); } catch (e) { if (e instanceof parsingRules.RuleError) return apiError(res, 400, 'MODEL_RULES_INVALID', e.message + ` (line ${e.line}, column ${e.column})`); throw e; } }
    }
    const results = lines.map((line) => {
      const it = parseIngestLine(line, 'simulate');
      it.parsed.collector_id = 'simulate';
      const o = parsingRules.apply(pSets, { source_type: WIN_LINE.test(it.raw) ? 'windows-event' : sourceType, raw: it.raw, time: it.time, parsed: it.parsed });
      const mo = parsingRules.applyModel(mSets, { source_type: o.source_type, raw: it.raw, time: o.time, parsed: o.parsed });
      return { raw: it.raw, dataset: o.source_type, parsing_rule: o.matched ? o.matched.content_id : null, dropped: o.dropped, xdm: mo.flat, pipelines_matched: mo.pipelines_matched, errors: o.errors.concat(mo.errors) };
    });
    res.status(200).json({ success: true, scope, results });
  } catch (error) {
    console.error('Data model simulate failed:', error.message);
    apiError(res, 500, 'MODEL_RULES_ERROR', 'Simulation failed');
  }
});

app.get('/', (req, res) => {
  res.json({
    service: 'asix-api',
    status: 'running',
  });
});

module.exports = app;
