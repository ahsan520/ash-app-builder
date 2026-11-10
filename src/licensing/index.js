'use strict';
// Licensing as a self-contained module (docs/licensing.md). Everything about licenses lives in this folder; the rest of the platform touches it in exactly these places (a test lists them):
//   src/modules/index.js   : state(), entitled(), featureFor(), describe(), buildInfo()   (this file)
//   src/gateway/index.js   : ./gate (refuses a locked module's routes) and ./routes (the License API)
//   src/server.js          : ./notices (the lapse notices)
//   src/detection/rule-runner.js and ioc-matcher.js : ./worker-gate (a lapsed license stops detection)
// Licensing is OFF on a development build until an admin switches it on, so other modules are built and tested as if it did not exist. This file deliberately does NOT load the gate, the
// routes or the notices: they need the module system, and the module system needs this file.
module.exports = require('./state');
