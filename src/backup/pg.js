'use strict';
// Thin wrappers over the PostgreSQL client tools (pg_dump, pg_restore, psql). The password
// only ever travels in the PGPASSWORD environment variable, never on a command line or in a log.
const { spawn } = require('child_process');

function run(cmd, args, { env = process.env, input } = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', (c) => { if (out.length < 1e6) out += c; }); p.stderr.on('data', (c) => { if (err.length < 1e5) err += c; });
    p.on('error', (e) => reject(new Error(`${cmd}: ${e.message}`)));
    p.on('close', (code) => (code === 0 ? resolve({ out, err }) : reject(new Error(`${cmd} exited with ${code}: ${err.replace(/\s+/g, ' ').trim().slice(0, 300)}`))));
    p.stdin.end(input || '');
  });
}
const ident = (n) => { if (!/^[A-Za-z0-9_]{1,63}$/.test(n)) throw new Error('invalid database name: ' + n); return '"' + n + '"'; };
const psql = async (env, db, sql) => (await run('psql', ['-X', '-q', '-v', 'ON_ERROR_STOP=1', '-At', '-d', db, '-c', sql], { env })).out.trim();

module.exports = { run, ident, psql };
