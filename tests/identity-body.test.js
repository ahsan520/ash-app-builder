'use strict';
// GET /v1/auth/me: the shape of the answer, including the caller's permission names (used by the portal shell, docs/portal-shell.md).
const { describe, it } = require('node:test');
const assert = require('assert');
const { identityBody } = require('../src/gateway/identity-body');

const req = (over = {}) => ({ user_id: 'u1', tenant_id: 't1', session_id: 's1', rbac_permissions: ['b:read', 'a:read', 'b:read'], ...over });
const tenant = { name: 'Acme', status: 'active' };

describe('identityBody', () => {
  it('keeps every field the portal and other callers already read', () => {
    const b = identityBody(req(), tenant);
    assert.deepStrictEqual({ ...b, permissions: undefined }, { success: true, authenticated: true, user_id: 'u1', tenant_id: 't1', tenant_name: 'Acme', permissions: undefined, tenant_status: 'active', session_id: 's1' });
  });
  it('lists the caller\'s permissions sorted and without duplicates', () => {
    assert.deepStrictEqual(identityBody(req(), tenant).permissions, ['a:read', 'b:read']);
  });
  it('is an empty list, never missing or null, when the caller has none or the list is not an array', () => {
    for (const v of [[], undefined, null, 'a:read', { 0: 'x' }]) assert.deepStrictEqual(identityBody(req({ rbac_permissions: v }), tenant).permissions, []);
  });
  it('drops anything that is not a permission name', () => {
    assert.deepStrictEqual(identityBody(req({ rbac_permissions: ['ok:read', 7, null, { x: 1 }] }), tenant).permissions, ['ok:read']);
  });
  it('does not alter the list it was given', () => {
    const r = req(); const before = JSON.stringify(r.rbac_permissions);
    identityBody(r, tenant);
    assert.strictEqual(JSON.stringify(r.rbac_permissions), before);
  });
});
