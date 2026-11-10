'use strict';
// The license state of this installation, and the three small questions the module system asks about it (docs/licensing.md). This file is the whole of licensing's contact with the
// module resolver: src/modules/index.js calls state(), entitled(), featureFor() and describe(), and nothing else in the module system knows licensing exists.
//
// LICENSING CAN BE OFF. Off means: no module is ever locked for want of a license, no route is refused, no worker is paused, no notice is sent; the platform behaves as if this folder
// did not exist. A development build is OFF unless an admin switches it on in License (or ASIX_LICENSE_MODE=open forces it off, for tests); a release build is always ON. If the
// database cannot be read, a development build stays off and a release build stays on (or keeps its last answer).
const license = require('./license');
const installation = require('./installation');
const store = require('./license-store');
const buildChannel = require('./build-channel');
const { featureFor } = require('./bundles');

let last = null;   // the last good answer, kept when the database cannot be asked

const off = (build, reason, extra = {}) => ({ status: 'off', reason, features: [], limits: {}, mode: 'off', channel: build.channel, enforce: false, ...extra });

async function state(env = process.env, db) {
  const build = buildChannel.get();
  if (build.channel === 'dev' && String(env.ASIX_LICENSE_MODE || '').toLowerCase() === 'open') return off(build, 'ASIX_LICENSE_MODE=open: licensing is off (development builds only)');
  const database = db || require('../db');
  let inst, on = build.channel === 'release', stored = null;
  try {
    inst = await installation.read(database);
    if (build.channel === 'dev') on = await store.getEnforce(database);
    if (on) stored = await store.activeToken(database);
  } catch (e) {
    if (last && last.channel === build.channel) return last;
    inst = { id: installation.lastKnownId(), clock_back: false };   // dev: stays off; release: stays on and unlicensed
  }
  const meta = { channel: build.channel, enforce: on, installation_id: inst.id || null };
  if (!on) return off(build, 'Licensing is off on this development build. Switch it on in License to see what a customer sees.', meta);
  const lic = await license.load(env, new Date(), { iid: inst.id, clockBack: inst.clock_back, token: stored });
  last = { ...lic, mode: 'on', source: stored ? 'stored' : (lic.status === 'none' ? null : 'server'), ...meta };
  return last;
}

// Does this license (or the lack of one) let the module run? Always yes when licensing is off; a module with no license feature (the baseline) is always yes.
function entitled(manifest, features, lic) {
  if (!lic || lic.mode === 'off') return true;
  const f = featureFor(manifest);
  return !f || features.has(f);
}

// The license block of GET /v1/modules.
function describe(lic) {
  return { status: lic.status, customer: lic.customer || null, kind: lic.kind || null, expires_at: lic.expires_at || null, days_left: lic.days_left === undefined ? null : lic.days_left,
    grace_days_left: lic.grace_days_left === undefined ? null : lic.grace_days_left, expiring: !!lic.expiring, features: lic.features || [], reason: lic.reason || null, mode: lic.mode || 'off',
    channel: lic.channel || buildChannel.get().channel, enforce: lic.enforce === true, source: lic.source || null, installation_id: lic.installation_id || null };
}

const reset = () => { last = null; };
module.exports = { state, entitled, describe, featureFor, reset, buildInfo: () => buildChannel.get() };
