'use strict';
// The schedule of IOC feed imports (docs/ioc-feeds.md): every minute, run the feeds whose interval has passed. Same shape as the IOC matcher
// (src/detection/ioc-matcher.js): one cycle at a time, a lapsed license pauses it (workerGate), an error never stops the timer.
// FEEDS_ENABLED=false switches it off (a feed can still be run by hand). FEED_INTERVAL_SECONDS (default 60, at least 15) sets the tick.
const service = require('./service');
const workerGate = require('../licensing/worker-gate');

let timer = null; let running = false;
function start() {
  if (process.env.FEEDS_ENABLED === 'false' || timer) return;
  const every = Math.max(15, Number(process.env.FEED_INTERVAL_SECONDS || 60)) * 1000;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      if (!(await workerGate.enabled('ioc-feeds', 'threat-intel'))) { workerGate.pausedOnce('[feeds]'); return; }
      workerGate.resumed('[feeds]');
      const r = await service.runDue();
      if (r.ran) console.log('[feeds] cycle', JSON.stringify(r));
    } catch (e) { console.error('[feeds] cycle failed:', e.message); } finally { running = false; }
  };
  setTimeout(tick, 40000).unref();
  timer = setInterval(tick, every); timer.unref();
  console.log(`[feeds] import schedule started (every ${every / 1000}s)`);
}
module.exports = { start };
