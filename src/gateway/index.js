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

// Basic service endpoint.
app.get('/', (req, res) => {
  res.json({
    service: 'asix-api',
    status: 'running',
  });
});

module.exports = app;
