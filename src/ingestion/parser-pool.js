'use strict';
// A small pool of worker threads that run the parse step (src/ingestion/parse-batch.js) away from the API's
// event loop. What this buys over parsing inline:
//   - a hard time limit per batch: a rule or an input that makes a pattern run for ever costs one worker, which is
//     terminated and replaced, instead of freezing every request the API is serving;
//   - a crash (or running out of memory) in a parser kills one worker, not the API;
//   - parsing uses more than one core, and a full queue becomes back-pressure (the caller answers 503) instead of
//     unbounded memory.
// A batch that times out or crashes a worker is NOT lost: the caller stores its events unparsed (see
// src/ingestion/parse-service.js). A tenant whose rules keep timing out is skipped for a while (quarantine).
//
//   ASIX_PARSER_WORKERS     number of workers, 0 (default) = parse inline in the API process, as before. Max 16.
//   ASIX_PARSER_TIMEOUT_MS  time limit for one batch, default 5000
//   ASIX_PARSER_QUEUE       batches allowed to wait for a free worker, default 100
//
// Errors carry `code`: PARSER_BUSY, PARSER_CLOSED, PARSE_QUARANTINED, PARSE_TIMEOUT, PARSE_WORKER_CRASH, PARSE_FAILED.
const path = require('path');
const { Worker } = require('worker_threads');

const DEFAULT_WORKER = path.join(__dirname, 'parser-worker.js');
const MAX_KNOWN = 32; // rule sets the pool believes a worker holds; the worker's own cache is the authority (need_rules)

const fail = (code, message) => Object.assign(new Error(message), { code });

class ParserPool {
  constructor(opts = {}) {
    this.size = Math.max(1, Math.min(16, Math.floor(opts.size || 1)));
    this.timeoutMs = opts.timeoutMs || 5000;
    this.maxQueue = opts.maxQueue ?? 100;
    this.workerPath = opts.workerPath || DEFAULT_WORKER;
    this.workerData = opts.workerData || {};
    // Memory cap per worker thread: an out-of-memory worker dies alone (PARSE_WORKER_CRASH) instead of the API pod.
    this.maxOldGenMb = opts.maxOldGenerationSizeMb || 192;
    this.quarantineAfter = opts.quarantineAfter || 3;
    this.quarantineMs = opts.quarantineMs ?? 60000;
    this.closed = false;
    this.nextId = 1;
    this.queue = [];
    this.bad = new Map(); // scope + rulesKey -> { n, until }
    this.counts = { completed: 0, failed: 0, timeouts: 0, crashes: 0, rejected: 0, quarantined: 0, rules_resent: 0 };
    this.slots = [];
    for (let i = 0; i < this.size; i++) { const s = { cur: null, worker: null, known: new Set(), timer: null, restart: null }; this.slots.push(s); this._spawn(s); }
  }

  _spawn(slot) {
    if (this.closed) return;
    const worker = new Worker(this.workerPath, {
      workerData: this.workerData,
      resourceLimits: { maxOldGenerationSizeMb: this.maxOldGenMb },
    });
    worker.unref();
    slot.worker = worker; slot.known = new Set();
    worker.on('message', (m) => { if (slot.worker === worker) this._onMessage(slot, m); });
    worker.on('error', (e) => { if (slot.worker === worker) this._onDeath(slot, e); });
    worker.on('exit', (code) => { if (slot.worker === worker) this._onDeath(slot, new Error('worker exited with code ' + code)); });
  }

  _retire(slot) { // detach and stop the current worker; its late events are ignored
    const old = slot.worker; slot.worker = null;
    clearTimeout(slot.timer); slot.timer = null;
    if (old) old.terminate().catch(() => {});
  }

  _onDeath(slot, e) {
    const p = slot.cur; slot.cur = null;
    this._retire(slot);
    if (p) {
      this.counts.crashes++; this._markBad(p.job);
      console.error('[parser] a parser worker died while parsing a batch, it was replaced:', e.message);
      p.reject(fail('PARSE_WORKER_CRASH', 'Parser worker crashed: ' + e.message));
      this._spawn(slot);
    } else if (!this.closed) {
      // Died while idle (for example it cannot start): try again, but not in a tight loop.
      console.error('[parser] an idle parser worker died, restarting in 1 s:', e.message);
      clearTimeout(slot.restart);
      slot.restart = setTimeout(() => { slot.restart = null; if (!slot.worker) { this._spawn(slot); this._pump(); } }, 1000);
    }
    this._pump();
  }

  _onMessage(slot, m) {
    const p = slot.cur;
    if (!p || m.id !== p.id) return;
    if (m.need_rules) {
      if (p.sentRules) return this._onDeath(slot, new Error('worker asked for the rules twice'));
      this.counts.rules_resent++;
      slot.known.delete(p.job.rulesKey);
      return this._send(slot, p);
    }
    clearTimeout(slot.timer); slot.timer = null; slot.cur = null;
    if (m.ok) {
      slot.known.add(p.job.rulesKey);
      while (slot.known.size > MAX_KNOWN) slot.known.delete(slot.known.values().next().value);
      this.bad.delete(this._badKey(p.job));
      this.counts.completed++;
      p.resolve({ kept: m.kept, dropped: m.dropped, ms: m.ms });
    } else {
      this.counts.failed++;
      p.reject(fail('PARSE_FAILED', m.error || 'parse failed'));
    }
    this._pump();
  }

  _send(slot, p) {
    const j = p.job;
    p.sentRules = !slot.known.has(j.rulesKey);
    slot.worker.postMessage({ id: p.id, rulesKey: j.rulesKey, rules: p.sentRules ? j.rules : undefined, sourceType: j.sourceType, items: j.items });
  }

  _run(slot, p) {
    slot.cur = p;
    slot.timer = setTimeout(() => {
      if (slot.cur !== p) return;
      slot.cur = null;
      this.counts.timeouts++; this._markBad(p.job);
      console.error(`[parser] a batch of ${p.job.items.length} events took longer than ${this.timeoutMs} ms; the worker was replaced and the events are stored unparsed`);
      this._retire(slot);
      p.reject(fail('PARSE_TIMEOUT', `Parsing took longer than ${this.timeoutMs} ms`));
      this._spawn(slot);
      this._pump();
    }, this.timeoutMs);
    this._send(slot, p); // the timer is not unref'd: a batch in flight keeps the process alive until it ends or times out
  }

  _pump() {
    for (const slot of this.slots) {
      if (!this.queue.length) return;
      if (!slot.cur && slot.worker) this._run(slot, this.queue.shift());
    }
  }

  _badKey(job) { return String(job.scope || '') + '|' + job.rulesKey; }

  _markBad(job) {
    const k = this._badKey(job), e = this.bad.get(k) || { n: 0, until: 0 };
    if (++e.n >= this.quarantineAfter) {
      e.n = 0; e.until = Date.now() + this.quarantineMs;
      console.error(`[parser] parsing for tenant ${job.scope || '(unknown)'} timed out or crashed ${this.quarantineAfter} times in a row; its events are stored unparsed for ${Math.round(this.quarantineMs / 1000)} s. Check its parsing rules.`);
    }
    this.bad.set(k, e);
  }

  // job: { scope (tenant id, for quarantine), rulesKey, rules: { parsing, model }, sourceType, items }
  // -> Promise<{ kept, dropped, ms }>
  parse(job) {
    if (this.closed) return Promise.reject(fail('PARSER_CLOSED', 'Parser pool is closed'));
    const q = this.bad.get(this._badKey(job));
    if (q && q.until > Date.now()) { this.counts.quarantined++; return Promise.reject(fail('PARSE_QUARANTINED', 'Parsing is paused for this tenant after repeated timeouts')); }
    // Refuse only when nobody is free AND the waiting line is full (maxQueue 0 = never wait, but an idle worker is fine).
    const idle = this.slots.some((s) => !s.cur && s.worker);
    if (!idle && this.queue.length >= this.maxQueue) { this.counts.rejected++; return Promise.reject(fail('PARSER_BUSY', 'All parser workers are busy')); }
    return new Promise((resolve, reject) => { this.queue.push({ id: this.nextId++, job, resolve, reject, sentRules: false }); this._pump(); });
  }

  stats() {
    return { workers: this.size, busy: this.slots.filter((s) => s.cur).length, queued: this.queue.length, ...this.counts };
  }

  async close() {
    this.closed = true;
    for (const p of this.queue.splice(0)) p.reject(fail('PARSER_CLOSED', 'Parser pool is closed'));
    const stops = [];
    for (const slot of this.slots) {
      const p = slot.cur; slot.cur = null;
      if (p) p.reject(fail('PARSER_CLOSED', 'Parser pool is closed'));
      clearTimeout(slot.timer); clearTimeout(slot.restart);
      const w = slot.worker; slot.worker = null;
      if (w) stops.push(w.terminate().catch(() => {}));
    }
    await Promise.all(stops);
  }
}

// --- the process-wide pool, from the environment ----------------------------------------------------------------
let pool = null, made = false;

function configuredSize() {
  const raw = process.env.ASIX_PARSER_WORKERS;
  if (raw === undefined || raw === '') return 0;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0 || n > 16) { console.error(`[parser] ASIX_PARSER_WORKERS="${raw}" is not a whole number from 0 to 16; parsing inline`); return 0; }
  return n;
}
const envNum = (name, dflt) => { const n = Number(process.env[name]); return Number.isFinite(n) && n > 0 ? n : dflt; };

// The shared pool, or null when parsing runs inline (ASIX_PARSER_WORKERS unset or 0).
function getParserPool() {
  if (made) return pool;
  made = true;
  const size = configuredSize();
  if (size > 0) {
    pool = new ParserPool({ size, timeoutMs: envNum('ASIX_PARSER_TIMEOUT_MS', 5000), maxQueue: envNum('ASIX_PARSER_QUEUE', 100) });
    console.log(`[parser] ${size} parser worker thread(s), ${pool.timeoutMs} ms limit per batch, queue ${pool.maxQueue}`);
  }
  return pool;
}

// Tests, and the API's shutdown: replace or stop the shared pool.
function setParserPool(p) { pool = p; made = true; }
async function closeParserPool() { const p = pool; pool = null; made = false; if (p) await p.close(); }

module.exports = { ParserPool, getParserPool, setParserPool, closeParserPool };
