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
const { ensureBuiltinRules } = require('../detection/rule-runner');
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
                r.definition, r.last_run_at, r.last_error,
                (SELECT COUNT(*)::int FROM alerts a
                  WHERE a.rule_id = r.id AND a.status <> 'closed') AS open_alerts
         FROM detection_rules r
         WHERE r.tenant_id = $1
         ORDER BY CASE r.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, r.name`,
        [req.tenant_id]
      );
      return r.rows;
    });
    res.status(200).json({ success: true, rules });
  } catch (error) {
    console.error('Rule listing failed:', error.message);
    apiError(res, 500, 'RULES_LIST_ERROR', 'Failed to list detection rules');
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

// Basic service endpoint.
app.get('/', (req, res) => {
  res.json({
    service: 'asix-api',
    status: 'running',
  });
});

module.exports = app;
