'use strict';
// VM-level metrics read from /proc and statfs. Inside a container these files report the HOST
// (the VM), not the container's cgroup, which is exactly what capacity planning needs.
const fs = require('fs');
const os = require('os');

const read = (p) => fs.promises.readFile(p, 'utf8');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function cpuTimes() {
  const f = (await read('/proc/stat')).split('\n')[0].split(/\s+/).slice(1).map(Number);
  return { idle: f[3] + (f[4] || 0), total: f.reduce((a, b) => a + b, 0) };       // idle + iowait
}
async function cpuPercent(ms = 1000) {
  const a = await cpuTimes(); await sleep(ms); const b = await cpuTimes();
  const dt = b.total - a.total;
  return dt > 0 ? Math.round(1000 * (1 - (b.idle - a.idle) / dt)) / 10 : 0;
}
async function cpuCount() {
  try { const n = (await read('/proc/cpuinfo')).match(/^processor\s*:/gm); if (n && n.length) return n.length; } catch { /* fall through */ }
  return os.cpus().length || 1;
}
async function memory() {
  const m = {};
  for (const line of (await read('/proc/meminfo')).split('\n')) { const x = /^(\w+):\s+(\d+)\s*kB/.exec(line); if (x) m[x[1]] = Number(x[2]) * 1024; }
  const total = m.MemTotal || 0, avail = m.MemAvailable !== undefined ? m.MemAvailable : (m.MemFree || 0) + (m.Buffers || 0) + (m.Cached || 0);
  return { total, available: avail, used_pct: total ? Math.round(1000 * (1 - avail / total)) / 10 : 0, swap_total: m.SwapTotal || 0, swap_used: (m.SwapTotal || 0) - (m.SwapFree || 0) };
}
async function load() { const [a, b, c] = (await read('/proc/loadavg')).split(' ').map(Number); return { load1: a, load5: b, load15: c }; }
async function uptimeSeconds() { return Math.floor(Number((await read('/proc/uptime')).split(' ')[0])); }
// Filesystem backing the container runtime. On k3s's default local-path storage this is the same
// disk that holds the database volumes (the PVC "size" is a request, not an enforced quota).
async function disk(path = '/') {
  const s = await fs.promises.statfs(path);
  const total = s.blocks * s.bsize, free = s.bavail * s.bsize;
  return { total, free, used: total - s.bfree * s.bsize, free_pct: total ? Math.round(1000 * free / total) / 10 : 0 };
}

async function collect({ cpuSampleMs = 1000, diskPath = '/' } = {}) {
  const [cpu_pct, cpu_count, mem, ld, up, dsk] = await Promise.all([cpuPercent(cpuSampleMs), cpuCount(), memory(), load(), uptimeSeconds(), disk(diskPath)]);
  return { cpu_pct, cpu_count, mem, ...ld, uptime_seconds: up, disk: dsk };
}

module.exports = { collect, cpuPercent, cpuCount, memory, load, disk, uptimeSeconds };
