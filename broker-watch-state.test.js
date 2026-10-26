'use strict';
// No database. What the Brokers page knows about "Alert if down" (src/brokers/broker-view.js shape()): its own button, the tenant-wide
// "Watch everything" switch, or left out of it; and that the portal's column says so.
const test = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const view = require('../src/brokers/broker-view');

const NOW = Date.parse('2026-10-20T12:00:00Z');
const row = (o = {}) => ({ id: 'b1', name: 'broker-1', version: 'vector-0.59.0', last_seen: '2026-10-20 11:59:00', key_id: 'k1', ...o });
const on = { disconnect: true, silent_min: null };
const off = { disconnect: false, silent_min: null };

test('no switch: only the broker\'s own button counts', () => {
  assert.strictEqual(view.shape(row(), { now: NOW }).watch_disconnect_by_default, false, 'default argument is the switch off');
  assert.strictEqual(view.shape(row(), { now: NOW, watchDefaults: off }).watch_disconnect_by_default, false);
  const b = view.shape(row({ watch_disconnect: true }), { now: NOW, watchDefaults: off });
  assert.strictEqual(b.watch_disconnect, true); assert.strictEqual(b.watch_disconnect_by_default, false);
});

test('switch on: covered by the switch unless it has its own button, is left out, or was not seen for a week', () => {
  assert.strictEqual(view.shape(row(), { now: NOW, watchDefaults: on }).watch_disconnect_by_default, true);
  const own = view.shape(row({ watch_disconnect: true }), { now: NOW, watchDefaults: on });
  assert.strictEqual(own.watch_disconnect, true); assert.strictEqual(own.watch_disconnect_by_default, false, 'its own button is what covers it');
  const left = view.shape(row({ watch_exclude: true }), { now: NOW, watchDefaults: on });
  assert.strictEqual(left.watch_exclude, true); assert.strictEqual(left.watch_disconnect_by_default, false);
  assert.strictEqual(view.shape(row({ last_seen: '2026-10-01 00:00:00' }), { now: NOW, watchDefaults: on }).watch_disconnect_by_default, false, 'retired');
  assert.strictEqual(view.shape(row({ last_seen: null }), { now: NOW, watchDefaults: on }).watch_disconnect_by_default, false, 'never seen');
});

test('a left-out broker with its own button is still watched by that button', () => {
  const b = view.shape(row({ watch_exclude: true, watch_disconnect: true }), { now: NOW, watchDefaults: on });
  assert.strictEqual(b.watch_disconnect, true); assert.strictEqual(b.watch_exclude, true);
});

test('the portal column has the four states, and the portal script still parses', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
  assert.match(html, /\{ h: 'Alert if down', f: \(b\) => \(b\.watch_disconnect \? pill\('On', 'ok'\) : b\.watch_disconnect_by_default \? pill\('On \(all\)', 'ok'\) : b\.watch_exclude \? pill\('Left out', 'off'\) : pill\('Off', 'off'\)\) \}/);
  const scripts = [...html.matchAll(/<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  assert.ok(scripts.length >= 1);
  for (const s of scripts) assert.doesNotThrow(() => new Function(s));   // syntax only; nothing runs
});
