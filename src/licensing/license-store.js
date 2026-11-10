'use strict';
// Stored licenses and the enforcement switch (docs/licensing.md). Licenses are kept in the database, so they survive deploys and restores and can be switched without kubectl.
// Many can be stored ("available"); at most one is "active" (a partial unique index makes a second active row impossible). The tokens are signed public documents, not secrets.
const MAX_FILES = 20;
const ok = (e) => !(e && e.code === '42P01');

async function list(db) {
  try { return (await db.query('SELECT id, label, customer, kind, expires_at, uploaded_at, uploaded_by, active, sha256 FROM license_files ORDER BY uploaded_at DESC LIMIT 50')).rows; }
  catch (e) { if (ok(e)) throw e; return []; }
}
async function activeToken(db) {
  try { const r = (await db.query('SELECT token FROM license_files WHERE active LIMIT 1')).rows[0]; return r ? r.token : null; }
  catch (e) { if (ok(e)) throw e; return null; }
}
async function add(db, { label, token, sha256, customer, kind, expires_at, uploaded_by }) {
  const n = (await db.query('SELECT count(*)::int AS n FROM license_files')).rows[0].n;
  if (n >= MAX_FILES) return { ok: false, code: 'TOO_MANY', message: 'At most ' + MAX_FILES + ' licenses can be stored; remove one first' };
  try {
    const r = await db.query('INSERT INTO license_files (label, token, sha256, customer, kind, expires_at, uploaded_by) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id', [label, token, sha256, customer, kind, expires_at, uploaded_by]);
    return { ok: true, id: r.rows[0].id };
  } catch (e) { if (e && e.code === '23505') return { ok: false, code: 'DUPLICATE', message: 'This license is already stored' }; throw e; }
}
// Makes one stored license the active one (and every other not): both changes in one statement, so there is never none or two in between.
async function activate(db, id) {
  const r = await db.query('UPDATE license_files SET active = (id = $1::uuid) WHERE id = $1::uuid OR active RETURNING id, active', [id]);
  return r.rows.some((x) => x.id === id && x.active);
}
async function deactivate(db) { await db.query('UPDATE license_files SET active = FALSE WHERE active'); }
// Removes a stored license that is not the active one.
async function remove(db, id) {
  const r = await db.query('DELETE FROM license_files WHERE id = $1::uuid AND NOT active RETURNING id', [id]);
  return r.rowCount === 1;
}
async function getEnforce(db) {
  try { const r = (await db.query('SELECT enforce FROM installation LIMIT 1')).rows[0]; return !!(r && r.enforce); }
  catch (e) { if (ok(e)) throw e; return false; }
}
async function setEnforce(db, v) { await db.query('UPDATE installation SET enforce = $1', [!!v]); }

module.exports = { MAX_FILES, list, activeToken, add, activate, deactivate, remove, getEnforce, setEnforce };
