'use strict';
// What each broker says about its syslog-over-TLS port (tls_port and rejected_tls_port in the config report), and the state the Brokers page shows for it.
// Pure rules: report body, tlsState(), the broker row and the summary.
const { describe, it } = require('node:test');
const assert = require('assert');
const config = require('../src/brokers/config');
const view = require('../src/brokers/broker-view');

const NOW = Date.parse('2026-10-18T12:00:00Z');
const ago = (m) => new Date(NOW - m * 60000).toISOString().replace('Z', '');
const row = (o = {}) => ({ config_tls_port: null, config_rejected_tls_port: null, config_reported_at: ago(2), ...o });
const base = { collector: 'broker-1', syslog_port: 514, rejected_port: null };

describe('the TLS fields of the report', () => {
  it('an older script sends neither field: both stay unset (NULL = never said)', () => {
    const r = config.checkReport(base); assert.strictEqual(r.tls, null); assert.strictEqual(r.tlsRejected, null);
  });
  it('null means the broker has no TLS listener (stored as 0), a port is kept, a numeric string is accepted', () => {
    assert.strictEqual(config.checkReport({ ...base, tls_port: null }).tls, 0);
    assert.strictEqual(config.checkReport({ ...base, tls_port: 6514 }).tls, 6514);
    assert.strictEqual(config.checkReport({ ...base, tls_port: '6514', rejected_tls_port: '6515' }).tlsRejected, 6515);
    assert.strictEqual(config.checkReport({ ...base, tls_port: 6514, rejected_tls_port: null }).tlsRejected, null);
  });
  it('anything else is refused with a reason and nothing is stored', () => {
    for (const bad of [0, -1, 70000, 1.5, '65x14', 'abc', true, {}, []]) {
      assert.match(config.checkReport({ ...base, tls_port: bad }).error || '', /tls_port/, 'tls_port ' + JSON.stringify(bad));
      assert.match(config.checkReport({ ...base, tls_port: 6514, rejected_tls_port: bad }).error || '', /rejected_tls_port/, 'rejected ' + JSON.stringify(bad));
    }
  });
  it('recordReport writes both columns, and NULL (not 0) for a script that did not send them', async () => {
    const seen = []; const q = { query: async (sql, args) => { seen.push({ sql, args }); return { rowCount: 1 }; } };
    await config.recordReport(q, 't', 'k', config.checkReport({ ...base, tls_port: null, rejected_tls_port: 6515 }));
    await config.recordReport(q, 't', 'k', config.checkReport(base));
    assert.match(seen[0].sql, /config_tls_port = \$7, config_rejected_tls_port = \$8/); assert.match(seen[0].sql, /WHERE tenant_id = \$1 AND key_id = \$2 AND name = \$3/);
    assert.deepStrictEqual(seen[0].args.slice(6), [0, 6515]); assert.deepStrictEqual(seen[1].args.slice(6), [null, null]);
  });
});

describe('tlsState', () => {
  it('none: nothing is asked (no TLS port set, or the broker is left out)', () => {
    assert.strictEqual(config.tlsState(null, row({ config_tls_port: 6514 }), NOW).state, 'none');
    assert.strictEqual(config.tlsState(undefined, row(), NOW).state, 'none');
    assert.strictEqual(config.tlsState(null, row({ config_tls_port: 6514 }), NOW).reported_port, 6514, 'what it listens on is still returned');
  });
  it('unknown: a port is asked but the broker never said anything about TLS', () => {
    assert.strictEqual(config.tlsState(6514, row(), NOW).state, 'unknown');
    assert.strictEqual(config.tlsState(6514, { config_tls_port: null }, NOW).state, 'unknown');
    assert.strictEqual(config.tlsState(6514, null, NOW).state, 'unknown');
  });
  it('no_listener: the broker says it has no TLS listener, so it ignores the setting', () => {
    const r = config.tlsState(6514, row({ config_tls_port: 0 }), NOW); assert.strictEqual(r.state, 'no_listener'); assert.strictEqual(r.has_listener, false); assert.strictEqual(r.reported_port, null);
  });
  it('applied, rejected, pending, stale', () => {
    assert.strictEqual(config.tlsState(6515, row({ config_tls_port: 6515 }), NOW).state, 'applied');
    assert.strictEqual(config.tlsState(6515, row({ config_tls_port: 6514, config_rejected_tls_port: 6515 }), NOW).state, 'rejected');
    assert.strictEqual(config.tlsState(6516, row({ config_tls_port: 6514, config_rejected_tls_port: 6515 }), NOW).state, 'pending', 'ASIX moved on to another port');
    assert.strictEqual(config.tlsState(6515, row({ config_tls_port: 6514 }), NOW).state, 'pending');
    assert.strictEqual(config.tlsState(6515, row({ config_tls_port: 6514, config_reported_at: ago(16) }), NOW).state, 'stale');
    assert.strictEqual(config.tlsState(6515, row({ config_tls_port: 6514, config_reported_at: ago(15) }), NOW).state, 'pending', 'the 15 minute edge');
    assert.strictEqual(config.tlsState(6515, row({ config_tls_port: 6515, config_reported_at: ago(60) }), NOW).state, 'applied', 'an old report that matches is still applied');
  });
  it('an own TLS rejection is for that port only: a different asked port is pending, not rejected', () => {
    const r = config.tlsState(6517, row({ config_tls_port: 6514, config_rejected_tls_port: 6515 }), NOW); assert.strictEqual(r.state, 'pending'); assert.strictEqual(r.rejected_port, 6515);
  });
});

describe('the broker row and the summary', () => {
  const mk = (o = {}) => ({ id: 'i' + Math.random(), name: 'b', version: 'vector-0.59.0', last_seen: new Date(NOW).toISOString(), key_id: 'k1', key_status: 'active', ...o });
  const shape = (o, opts = {}) => view.shape(mk(o), { now: NOW, tlsPort: 6515, ...opts });
  it('a broker is asked the tenant-wide TLS port; a broker left out is asked nothing (and keeps its own listener)', () => {
    assert.strictEqual(shape(row({ config_tls_port: 6514 })).tls.state, 'pending');
    assert.strictEqual(shape({ ...row({ config_tls_port: 6514 }), syslog_port_exclude: true }).tls.state, 'none');
    assert.strictEqual(shape({ ...row({ config_tls_port: 6514 }), syslog_port_exclude: true }).tls.reported_port, 6514);
  });
  it('an own syslog port does not change the TLS port: it is tenant-wide only', () => {
    assert.strictEqual(shape({ ...row({ config_tls_port: 6515 }), syslog_port_override: 2514 }).tls.state, 'applied');
  });
  it('no TLS port set on ASIX means none for everyone', () => {
    assert.strictEqual(shape(row({ config_tls_port: 6514 }), { tlsPort: null }).tls.state, 'none');
  });
  it('summary counts applied, not applied (unknown, rejected, pending, stale) and no listener separately; none counts nowhere', () => {
    const bs = [shape(row({ config_tls_port: 6515 })), shape(row({ config_tls_port: 6514 })), shape(row({ config_tls_port: 6514, config_rejected_tls_port: 6515 })), shape(row({ config_tls_port: 6514, config_reported_at: ago(30) })),
      shape(row()), shape(row({ config_tls_port: 0 })), shape({ ...row({ config_tls_port: 6514 }), syslog_port_exclude: true })];
    const s = view.summarize(bs);
    assert.strictEqual(s.tls_applied, 1); assert.strictEqual(s.tls_not_applied, 4); assert.strictEqual(s.tls_no_listener, 1);
  });
  it('the TLS state is not a problem: it adds nothing to problems and nothing to with_problems', () => {
    const b = shape(row({ config_tls_port: 6514, config_rejected_tls_port: 6515 })); assert.deepStrictEqual(b.problems, []);
    assert.strictEqual(view.summarize([b]).with_problems, 0);
  });
});
