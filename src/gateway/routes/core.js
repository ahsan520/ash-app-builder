const express = require('express');
const router = express.Router();
const {
  db, authMiddleware, tenantMiddleware, rbacMiddleware, auditMiddleware, brokerAuthMiddleware,
  guarded, UUID_RE, SEVERITIES, ALERT_STATUSES, apiError,
} = require('../shared');
const { getEventStore } = require('../../events');

router.get('/v1/health/status', async (req, res) => {
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
router.get(
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
router.post('/v1/ingest/events', brokerAuthMiddleware, async (req, res) => {
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

    let stored;
    await db.withTenant(resolvedTenantId, async (client) => {
      // Written through the event store (src/events): validated, NUL-safe, one INSERT per batch.
      stored = await getEventStore().insertBatch(resolvedTenantId, events.map((event) => ({
        source_type,
        collector_id: collector_id || null,
        event_time: event && event.event_time,
        raw: event && event.raw,
        parsed: event && event.parsed,
      })), { client });

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

    res.status(202).json({ success: true, inserted: stored.inserted });
  } catch (error) {
    if (error && (error.code === 'INVALID_ENVELOPE' || error.code === 'INVALID_TENANT')) {
      return res.status(400).json({ success: false, error: { code: 'INGEST_INVALID_EVENT', message: error.message } });
    }
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
router.get(
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
      const limit = Math.min(Math.trunc(Number(req.query.limit)) || 50, 500);
      const offset = Math.max(Math.trunc(Number(req.query.offset)) || 0, 0);
      // from / to: any time the database used to accept ("2026-10-01", "2026-10-01 10:00:00", ISO), read as UTC
      const time = (v, name) => {
        if (v === undefined || v === '') return undefined;
        const ms = typeof v === 'string' ? Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(v) ? v : `${v.replace(' ', 'T')}Z`) : NaN;
        if (Number.isNaN(ms)) throw Object.assign(new Error(`${name} must be a date or time`), { code: 'INVALID_QUERY' });
        return new Date(ms).toISOString();
      };
      const text = (v) => (typeof v === 'string' ? v : undefined);
      // The newest events first (event time, else received time). q is a plain substring, case-insensitive: the raw
      // line is a sequential scan, not an indexed search (see docs/event-store.md for what comes with a search engine).
      const events = await getEventStore().listEvents(req.tenant_id, {
        source_type: text(req.query.source_type), collector_id: text(req.query.collector_id),
        from: time(req.query.from, 'from'), to: time(req.query.to, 'to'), q: text(req.query.q), limit, offset,
      });

      res.status(200).json({
        success: true,
        count: events.length,
        limit,
        offset,
        events: events.map((e) => ({
          id: e.id, source_type: e.source_type, collector_id: e.collector_id, received_at: e.received_at,
          event_time: e.event_time, raw: e.raw, parsed: e.parsed,
        })),
      });
    } catch (error) {
      if (error && error.code === 'INVALID_QUERY') {
        return res.status(400).json({ success: false, error: { code: 'INVALID_QUERY', message: error.message } });
      }
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
router.get(
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
      const rows = await getEventStore().dataSources(req.tenant_id);
      res.status(200).json({
        success: true,
        sources: rows.map((r) => ({
          source_type: r.source_type, collector_id: r.collector_id, events_total: r.events_total,
          events_24h: r.events_recent, last_received: r.last_received,
        })),
      });
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
router.get(
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
router.get(
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
    // The column comes from a fixed list, never from user input.
    const col = req.query.by === 'collector' ? 'collector_id' : 'source_type';
    try {
      const st = await getEventStore().ingestionStats(req.tenant_id, { by: col });
      const t = st.totals;
      res.status(200).json({
        success: true,
        by: col,
        totals: { events_24h: t.events, bytes_24h: t.bytes, events_1h: t.events_1h, source_types: t.source_types, collectors: t.collectors, last_received: t.last_received },
        hourly: st.hourly,
        groups: st.groups.map((g) => ({ key: g.key, events_24h: g.events, bytes_24h: g.bytes })),
      });
    } catch (error) {
      console.error('Ingestion summary failed:', error.message);
      res.status(500).json({
        success: false,
        error: { code: 'INGESTION_SUMMARY_ERROR', message: 'Failed to build ingestion summary' },
      });
    }
  }
);


module.exports = router;
