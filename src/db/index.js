const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST || 'postgresql.asix-platform.svc.cluster.local',
  port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME || 'asix_platform',
  user: process.env.DB_USER || 'asix_admin',
  password: process.env.DB_PASSWORD,
  max: Number(process.env.DB_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

// Idle pooled connections die whenever PostgreSQL restarts (pod recreate, upgrade, failover).
// node-postgres reports that as an 'error' event on the pool; with no listener Node treats it as
// an uncaught exception and the whole API (and its background workers) exits. The pool simply
// opens a fresh connection the next time one is needed.
pool.on('error', (err) => console.error('[db] idle connection lost (a new one will be opened on demand):', err.message));
// A connection that dies while checked out (mid-transaction, or a worker holding an advisory-lock
// connection) raises its error on the connection itself, not on the pool. Every connection gets a
// listener so such an event is logged and surfaces as an ordinary failed query, never a crash.
pool.on('connect', (client) => client.on('error', (err) => console.error('[db] connection error:', err.message)));

async function query(text, params = []) {
  return pool.query(text, params);
}

async function withTenant(tenantId, callback) {
  const client = await pool.connect();
  let broken = false;

  try {
    await client.query('BEGIN');

    await client.query(
      'SELECT set_config($1, $2, true)',
      ['app.current_tenant_id', tenantId]
    );

    const result = await callback(client);

    await client.query('COMMIT');
    return result;
  } catch (error) {
    // if the connection itself died, ROLLBACK fails too: keep the original error and drop the client
    try { await client.query('ROLLBACK'); } catch (_) { broken = true; }
    throw error;
  } finally {
    client.release(broken);
  }
}

async function healthCheck() {
  const result = await pool.query('SELECT 1 AS ok');
  return result.rows[0].ok === 1;
}

async function close() {
  await pool.end();
}

module.exports = {
  pool,
  query,
  withTenant,
  healthCheck,
  close
};
