const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST || 'postgresql.asix-platform.svc.cluster.local',
  port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME || 'siem_platform',
  user: process.env.DB_USER || 'siem_admin',
  password: process.env.DB_PASSWORD,
  max: Number(process.env.DB_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

async function query(text, params = []) {
  return pool.query(text, params);
}

async function withTenant(tenantId, callback) {
  const client = await pool.connect();

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
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
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
