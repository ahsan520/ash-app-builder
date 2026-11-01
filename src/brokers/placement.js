'use strict';
// Broker capacity and where the next endpoint agent should go (docs/broker-groups.md, task E8).
//
// A broker VM that runs a site endpoint manager (broker-vm.md, E4b) can only look after so many agents, and that number depends on the VM's CPUs and memory.
// The broker's heartbeat now says how many CPUs and how much memory the VM has and how many agents are enrolled on its manager (host_cpus, host_mem_mb,
// agents_enrolled). From that this file works out:
//   - a recommended agent limit per broker (an ESTIMATE, see below), which the operator can replace with their own number (agent_limit);
//   - a state per broker (ok, near, full, unknown) and per group of brokers;
//   - which broker of a group should get the next machine: the connected broker running a manager that is the least full in proportion to its limit,
//     so a bigger VM takes more machines than a smaller one;
//   - how many brokers a client of N endpoints needs at the current size (with a spare, so one broker can be down).
// Pure functions, no database, nothing is pushed to a broker and nothing here raises an alert.
//
// THE ESTIMATE IS NOT A MEASUREMENT. It restates the sizing table in docs/endpoints.md (E4b: 4 CPUs and 8 GB for about 50 agents) as two rates, agents per CPU
// and agents per GB of memory, and the smaller of the two wins. Replace both rates with real numbers after the first weeks (ASIX_BROKER_AGENTS_PER_CPU and
// ASIX_BROKER_AGENTS_PER_GB on the API), or set a limit per broker.

const PER_CPU_DEFAULT = 12;       // 4 CPUs -> 48
const PER_GB_DEFAULT = 6;         // 8 GB -> 48 (a VM reports a little under its nominal memory, so 8 GB reads as about 7.6 and gives 45)
const NEAR_PERCENT = 80;          // at or above this share of the limit the broker is "near"
const MAX_CPUS = 4096, MAX_MEM_MB = 16 * 1024 * 1024, MAX_AGENTS = 1000000, MAX_LIMIT = 100000;
const GROUP_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/;

// The two rates, from the environment of the API. A value that is not a whole number from 1 to 1000 means the default (never an error: a typo must not break the page).
function rates(env = process.env) {
  const pick = (raw, dflt) => {
    if (raw === undefined || String(raw).trim() === '') return dflt;
    if (!/^\d{1,4}$/.test(String(raw).trim())) return dflt;
    const n = Number(String(raw).trim());
    return n >= 1 && n <= 1000 ? n : dflt;
  };
  return { per_cpu: pick(env.ASIX_BROKER_AGENTS_PER_CPU, PER_CPU_DEFAULT), per_gb: pick(env.ASIX_BROKER_AGENTS_PER_GB, PER_GB_DEFAULT), near_percent: NEAR_PERCENT };
}

const isInt = (v) => typeof v === 'number' && Number.isInteger(v);

// What the heartbeat says about the VM: { cpus, mem_mb }. Both or nothing (half a description cannot size a VM). Returns null when unusable, so the stored values are left alone.
function parseHost(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const cpus = typeof v.cpus === 'string' && /^\d{1,5}$/.test(v.cpus) ? Number(v.cpus) : v.cpus;
  const mem = typeof v.mem_mb === 'string' && /^\d{1,9}$/.test(v.mem_mb) ? Number(v.mem_mb) : v.mem_mb;
  if (!isInt(cpus) || !isInt(mem) || cpus < 1 || cpus > MAX_CPUS || mem < 256 || mem > MAX_MEM_MB) return null;
  return { cpus, mem_mb: mem };
}

// How many agents are enrolled on the manager of this broker (a count of lines in its client.keys): a whole number from 0 up. null = nothing usable (a broker without a manager sends none).
function parseAgents(v) {
  const n = typeof v === 'string' && /^\d{1,7}$/.test(v) ? Number(v) : v;
  return isInt(n) && n >= 0 && n <= MAX_AGENTS ? n : null;
}

// The recommended limit for a VM of this size, or null when its size is not known.
function recommendedLimit(cpus, memMb, env = process.env) {
  if (!isInt(cpus) || !isInt(memMb) || cpus < 1 || memMb < 1) return null;
  const r = rates(env);
  return Math.max(1, Math.min(cpus * r.per_cpu, Math.floor((memMb / 1024) * r.per_gb)));
}

// What an operator may set on one broker. A group name: null or '' clears it. An agent limit: null or '' clears it (the estimate applies again).
function checkGroup(v) {
  if (v === null || v === undefined || v === '') return { value: null };
  if (typeof v !== 'string' || !GROUP_RE.test(v.trim())) return { error: 'Group: 1 to 40 characters, letters, digits and . _ - only, starting with a letter or digit' };
  return { value: v.trim() };
}
function checkLimit(v) {
  if (v === null || v === undefined || v === '') return { value: null };
  const n = typeof v === 'string' && /^\d{1,6}$/.test(v.trim()) ? Number(v.trim()) : v;
  if (!isInt(n) || n < 1 || n > MAX_LIMIT) return { error: 'Agent limit: a whole number from 1 to ' + MAX_LIMIT + ', or empty to use the estimate' };
  return { value: n };
}

// The capacity of one broker from its row: size, enrolled agents, the limit in force and its source, and a state.
//   limit_source: 'set' (the operator's number), 'estimated' (from the VM size), 'unknown' (the VM never said how big it is and no number was set)
//   state: unknown (no limit, or no agent count: a broker with no manager says none) | ok | near | full
function capacityOf(row, env = process.env) {
  const cpus = row.host_cpus == null ? null : Number(row.host_cpus), mem = row.host_mem_mb == null ? null : Number(row.host_mem_mb);
  const enrolled = row.agents_enrolled == null ? null : Number(row.agents_enrolled);
  const recommended = cpus !== null && mem !== null ? recommendedLimit(cpus, mem, env) : null;
  const set = row.agent_limit == null ? null : Number(row.agent_limit);
  const limit = set !== null ? set : recommended;
  const source = set !== null ? 'set' : recommended !== null ? 'estimated' : 'unknown';
  const out = { cpus, mem_mb: mem, enrolled, recommended, limit, limit_source: source, free: null, used_percent: null, state: 'unknown' };
  if (limit === null || enrolled === null) return out;
  out.free = Math.max(0, limit - enrolled);
  out.used_percent = Math.round((enrolled / limit) * 100);
  out.state = enrolled >= limit ? 'full' : out.used_percent >= NEAR_PERCENT ? 'near' : 'ok';
  return out;
}

const runsManager = (b) => Array.isArray(b.inputs) && b.inputs.some((i) => i.kind === 'wazuh' || i.kind === 'wazuhalerts');

// Why a broker cannot take the next machine, or null when it can. The reasons are words the page shows.
function whyNot(b) {
  if (b.status !== 'connected') return 'not connected';
  if (!runsManager(b)) return b.inputs ? 'no endpoint manager here' : 'does not say what it runs (older script)';
  const c = b.capacity;
  if (!c || c.limit === null) return 'its size is not known and no limit is set';
  if (c.enrolled === null) return 'does not say how many agents it has';
  if (c.free <= 0) return 'full';
  return null;
}

// The broker that should get the next machine among these: the one whose share of its own limit is lowest (so capacity decides, not the plain count), then the most free
// slots, then the name (so the answer does not flip between calls). null when none can take one.
function pickNext(brokers) {
  const can = brokers.filter((b) => whyNot(b) === null);
  if (!can.length) return null;
  can.sort((a, b) => (a.capacity.enrolled / a.capacity.limit) - (b.capacity.enrolled / b.capacity.limit) || b.capacity.free - a.capacity.free || String(a.name).localeCompare(String(b.name)));
  return can[0];
}

// Groups of brokers. A broker with no group stands under the name null ("Not in a group"); it is still sized and judged like the others. The totals count only brokers
// that know their limit and their agent count, and say how many did not (`unknown_brokers`), so a total is never a guess.
function groupsOf(brokers) {
  const by = new Map();
  for (const b of brokers) {
    const k = b.group || null;
    if (!by.has(k)) by.set(k, []);
    by.get(k).push(b);
  }
  const out = [];
  for (const [name, list] of by) {
    const known = list.filter((b) => b.capacity && b.capacity.limit !== null && b.capacity.enrolled !== null);
    const limit = known.reduce((n, b) => n + b.capacity.limit, 0), enrolled = known.reduce((n, b) => n + b.capacity.enrolled, 0);
    const next = pickNext(list);
    const g = {
      name, brokers: list.length, connected: list.filter((b) => b.status === 'connected').length, unknown_brokers: list.length - known.length,
      enrolled, limit, free: known.reduce((n, b) => n + b.capacity.free, 0), used_percent: limit ? Math.round((enrolled / limit) * 100) : null,
      state: !known.length ? 'unknown' : enrolled >= limit ? 'full' : Math.round((enrolled / limit) * 100) >= NEAR_PERCENT ? 'near' : 'ok',
      next: next ? { id: next.id, name: next.name, free: next.capacity.free, used_percent: next.capacity.used_percent } : null,
      members: list.map((b) => ({ id: b.id, name: b.name, status: b.status, state: b.capacity ? b.capacity.state : 'unknown', can_take_next: whyNot(b) === null, why_not: whyNot(b) })),
    };
    out.push(g);
  }
  out.sort((a, b) => (a.name === null) - (b.name === null) || String(a.name).localeCompare(String(b.name)));
  return out;
}

// How many brokers a client of `endpoints` machines needs when each takes `perBroker`. One spare by default, so a broker can be down or being upgraded without
// the machines having nowhere to report. The managers of one client are separate: nothing here shares agents between them.
function plan(endpoints, perBroker, spare = 1) {
  const e = typeof endpoints === 'string' && /^\d{1,7}$/.test(endpoints) ? Number(endpoints) : endpoints;
  if (!isInt(e) || e < 1 || e > MAX_AGENTS) return { error: 'endpoints: a whole number from 1 to ' + MAX_AGENTS };
  if (!isInt(perBroker) || perBroker < 1) return { error: 'no broker has a known limit yet, so there is nothing to plan with' };
  const forLoad = Math.ceil(e / perBroker);
  return { endpoints: e, per_broker: perBroker, brokers_for_load: forLoad, spare, brokers_total: forLoad + spare };
}

// The size to plan with: the median of the known limits of the connected brokers (the typical broker, not the best one). null when none is known.
function typicalLimit(brokers) {
  const l = brokers.filter((b) => b.status === 'connected' && b.capacity && b.capacity.limit !== null).map((b) => b.capacity.limit).sort((a, b) => a - b);
  if (!l.length) return null;
  const m = Math.floor(l.length / 2);
  return l.length % 2 ? l[m] : Math.floor((l[m - 1] + l[m]) / 2);
}

// The address an agent should be given for a broker: what ASIX saw the broker's heartbeat come from. An IPv4-mapped IPv6 address is shown as plain IPv4.
const addressOf = (b) => String((b && b.last_ip) || '').replace(/^::ffff:/i, '');

module.exports = { PER_CPU_DEFAULT, PER_GB_DEFAULT, NEAR_PERCENT, rates, parseHost, parseAgents, recommendedLimit, checkGroup, checkLimit, capacityOf, runsManager, whyNot, pickNext, groupsOf, plan, typicalLimit, addressOf };
