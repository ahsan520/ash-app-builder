'use strict';
// Which kind of build this is (docs/licensing.md). The channel is written into the image when it is built (see the Dockerfile): it is NOT read from the environment, so a customer cannot
// change it by setting a variable. 'dev' (the default, and what your own staged builds are) lets an admin switch license enforcement on and off on the License page; 'release' (made by the
// release pipeline for customers) always enforces and has no switch.
const fs = require('fs');
const path = require('path');
const FILE = path.join(__dirname, 'build-channel.json');
let cached = null;
function get() {
  if (cached) return cached;
  let ch = 'dev', version = null;
  try { const j = JSON.parse(fs.readFileSync(FILE, 'utf8')); if (j && j.channel === 'release') ch = 'release'; if (j && typeof j.version === 'string') version = j.version.slice(0, 40); } catch { /* no file: a development build */ }
  cached = { channel: ch, version };
  return cached;
}
const reset = () => { cached = null; };
const override = (v) => { cached = v; };   // for tests only
module.exports = { get, reset, override, FILE };
