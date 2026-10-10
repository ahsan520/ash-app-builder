'use strict';
// Capacity recommendations: a pure function from measurements to explainable findings.
// Nothing here talks to the cluster. Every finding says what was measured (evidence), what to
// do (action.kind + text + steps) and why. Thresholds are constants so they are easy to tune.
// The platform only RECOMMENDS: creating or resizing VMs is a VirtualBox action.

const GiB = 1024 ** 3, MiB = 1024 ** 2;
const T = {
  disk_free_warn_pct: 20, disk_free_crit_pct: 10, days_full_warn: 30, days_full_crit: 14, reserve_pct: 15,
  mem_warn: 85, mem_crit: 92, swap_warn_bytes: 256 * MiB, cpu_warn: 70, cpu_crit: 85, load_warn: 1.5, load_crit: 3,
  min_partition_bytes: 128 * 1024, pod_hot: 0.8, pod_mem_hot: 0.85, node_cpu_headroom: 60, node_mem_headroom: 80,
  db_conn_warn: 0.8, cache_warn: 0.95, db_ram_warn: 0.25, db_ram_plan: 0.5, min_samples: 12, backlog_warn: 100,
};
const SEV = { critical: 0, warning: 1, info: 2 };
const gb = (n) => (n / GiB).toFixed(n >= 10 * GiB ? 0 : 1) + ' GB';
const pct = (n) => Math.round(n * 10) / 10 + '%';
const isoDay = (ms) => new Date(ms).toISOString().slice(0, 10);
const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;
const isDb = (p) => /postgres/i.test(`${p.app || ''} ${p.name || ''}`);
const isApi = (p) => /asix-api/i.test(`${p.app || ''} ${p.name || ''}`);

const HOW = {
  grow_disk: ['Power off the VM (VirtualBox: Machine > Close > Power Off, or `sudo poweroff`).',
    'Enlarge the virtual disk: Tools > Media > select the disk > Size, or `VBoxManage modifymedium disk "<file>.vdi" --resize <size in MB>`.',
    'Start the VM and grow the partition and filesystem, for example `sudo growpart /dev/sda 1 && sudo resize2fs /dev/sda1` (use `lsblk` first; LVM and XFS layouts differ).',
    'Check with `df -h /` that the new space is visible, then reload this page.'],
  add_ram: ['Power off the VM.', 'VirtualBox > Settings > System > Base Memory: increase it (keep some RAM free for the host).', 'Start the VM; k3s and all pods restart on boot.', 'Reload this page and check memory after a few hours of normal load.'],
  add_vcpu: ['Power off the VM.', 'VirtualBox > Settings > System > Processor: increase the CPU count.', 'Start the VM; k3s picks up the new cores automatically.', 'Reload this page and compare CPU after a few hours of normal load.'],
  add_node: ['Create a second VM (same OS) that can reach this one on the network.', 'On this VM read the join token: `sudo cat /var/lib/rancher/k3s/server/node-token`.',
    'On the new VM: `curl -sfL https://get.k3s.io | K3S_URL=https://<this-vm-ip>:6443 K3S_TOKEN=<token> sh -`.',
    'Confirm with `k3s kubectl get nodes`. Kubernetes will place new API pods there. Postgres and its data stay on the first VM: local-path volumes cannot move between nodes.'],
  add_api_pods: ['Edit `replicas` in k8s/30-asix-api.yaml (currently 2) and deploy; a manual `kubectl scale` is reset by the next deploy.',
    'Each extra pod needs its CPU/memory requests free on a node (see the node table below).', 'Extra API pods help request handling only. Detection rules, IOC matching and retention run once per cluster.'],
  raise_limit: ['Edit the pod\'s `resources.limits` in its manifest under k8s/ and deploy.', 'Raise requests with it so the scheduler reserves the room.', 'Make sure the VM has the spare CPU/RAM first (see the node table below).'],
  dedicated_db: ['Plan a separate VM for PostgreSQL with its own disk and RAM sized for the data set.', 'Take a backup (deploy.sh does one before schema changes), restore it on the new VM, and point DB_HOST at it.',
    'This is a migration project, not a button: ask for it as the next build when the findings above call for it.'],
  retention: ['Open Settings > Storage & retention.', 'Switch on automatic purge and shorten the default or the large datasets.', 'Whole-day partitions are dropped, which frees disk immediately.'],
};
const A = (kind, text, extra = {}) => ({ kind, text, steps: HOW[kind] || [], ...extra });

function forecastDisk({ host, events = {}, now }) {
  const out = { growth_bytes_per_day: null, days_to_full: null, free_bytes: host.disk.free, reserve_bytes: Math.round(host.disk.total * T.reserve_pct / 100), confidence: 'none',
    retention_days: events.retention_days || null, auto_purge: !!events.auto_purge, steady_state_bytes: null, max_days_that_fit: null, events_bytes: events.bytes || 0, extra_disk_needed_bytes: 0 };
  const today = isoDay(now);
  const full = (events.partitions || []).filter((p) => !p.is_default && p.from && p.to && p.to <= today && p.bytes >= T.min_partition_bytes)   // pre-created empty days say nothing about growth
   .sort((a, b) => (a.from < b.from ? 1 : -1)).slice(0, 7);
  if (full.length < 2) return out;
  out.confidence = full.length >= 5 ? 'high' : 'medium';
  out.growth_bytes_per_day = Math.round(mean(full.map((p) => p.bytes)));
  out.days_to_full = Math.floor(host.disk.free / out.growth_bytes_per_day);
  const room = (events.bytes || 0) + host.disk.free - out.reserve_bytes;
  out.max_days_that_fit = Math.max(0, Math.floor(room / out.growth_bytes_per_day));
  if (out.retention_days) {
    out.steady_state_bytes = out.growth_bytes_per_day * out.retention_days;
    out.extra_disk_needed_bytes = Math.max(0, Math.round(out.steady_state_bytes - room));
  }
  return out;
}

function evaluate(input) {
  const now = input.now || Date.now(), host = input.host, hist = input.history || null, k8s = input.k8s && input.k8s.available ? input.k8s : null;
  const f = [], add = (id, severity, area, title, detail, action, evidence) => f.push({ id, severity, area, title, detail, action, evidence: evidence || null });
  const enough = hist && hist.samples >= T.min_samples;
  const cpu = enough && hist.cpu_p95 != null ? hist.cpu_p95 : host.cpu_pct, cpuBasis = enough ? `95th percentile over ${hist.hours}h (${hist.samples} samples)` : 'right now (not enough history yet)';
  const memUsed = enough && hist.mem_p95 != null ? hist.mem_p95 : host.mem.used_pct, memBasis = enough ? `95th percentile over ${hist.hours}h` : 'right now';
  const pods = k8s ? k8s.pods : [], nodes = k8s ? k8s.nodes : [];
  const withCpu = pods.filter((p) => p.cpu_used != null).sort((a, b) => b.cpu_used - a.cpu_used), topCpu = withCpu[0] || null;
  const ev = input.events || {};
  const fc = forecastDisk({ host, events: ev, now });

  // ---------------------------------------------------------------- disk
  const freePct = host.disk.free_pct;
  if (freePct < T.disk_free_crit_pct) add('disk_low', 'critical', 'disk', 'Disk is almost full', `Only ${pct(freePct)} (${gb(host.disk.free)}) of the VM disk is free. PostgreSQL stops accepting writes when the disk fills up.`, A('grow_disk', 'Grow the VM disk now, and enable retention so it does not fill again.'), `${gb(host.disk.free)} free of ${gb(host.disk.total)}`);
  else if (freePct < T.disk_free_warn_pct) add('disk_low', 'warning', 'disk', 'Disk space is getting low', `${pct(freePct)} (${gb(host.disk.free)}) of the VM disk is free.`, A('grow_disk', 'Plan to grow the VM disk, or shorten retention.'), `${gb(host.disk.free)} free of ${gb(host.disk.total)}`);
  if (fc.days_to_full !== null && fc.days_to_full < T.days_full_warn) {
    const crit = fc.days_to_full < T.days_full_crit;
    add('disk_forecast', crit ? 'critical' : 'warning', 'disk', `At the current ingest rate the disk fills in about ${fc.days_to_full} days`,
      `Events grow by about ${gb(fc.growth_bytes_per_day)} per day (${fc.confidence} confidence, from the last completed daily partitions) and ${gb(fc.free_bytes)} is free.`,
      A('grow_disk', 'Grow the disk, and/or shorten retention so old data is dropped.', { alt: 'retention' }), `${gb(fc.growth_bytes_per_day)}/day vs ${gb(fc.free_bytes)} free`);
  }
  if (!ev.retention_days && fc.growth_bytes_per_day) {
    const off = !ev.auto_purge;
    add(off ? 'retention_off' : 'retention_unbounded', off && !(fc.days_to_full !== null && fc.days_to_full < 90) ? 'info' : 'warning', 'disk',
      off ? 'Automatic retention is switched off' : 'A keep-forever rule means data is never fully purged',
      (off ? 'Nothing is deleted automatically, so events grow without limit' : 'Automatic purge is on, but at least one dataset is set to keep forever, so total storage still grows without limit')
        + ` (${gb(fc.growth_bytes_per_day)} per day at the moment). Keeping data for ${fc.max_days_that_fit} days would use the whole disk down to the ${T.reserve_pct}% reserve.`,
      A('retention', off ? 'Choose retention rules and switch on automatic purge.' : 'Give every dataset a retention period, or plan disk for unlimited growth.'), `max days that fit: ${fc.max_days_that_fit}`);
  } else if (ev.auto_purge && fc.steady_state_bytes && fc.extra_disk_needed_bytes > 0) {
    add('retention_too_long', 'warning', 'disk', `The retention period is longer than this disk can hold`,
      `${fc.retention_days} days of data at ${gb(fc.growth_bytes_per_day)}/day needs about ${gb(fc.steady_state_bytes)}, but only about ${gb(fc.steady_state_bytes - fc.extra_disk_needed_bytes)} is available while keeping a ${T.reserve_pct}% reserve. At this rate about ${fc.max_days_that_fit} days fit.`,
      A('grow_disk', `Add at least ${gb(fc.extra_disk_needed_bytes)} of disk, or lower retention to about ${fc.max_days_that_fit} days.`, { alt: 'retention' }), `${fc.retention_days} d x ${gb(fc.growth_bytes_per_day)}/d = ${gb(fc.steady_state_bytes)}`);
  }

  // ---------------------------------------------------------------- memory
  const oomPods = pods.filter((p) => p.oom_killed_24h > 0);
  if (oomPods.length) {
    const nodeRoom = host.mem.used_pct < T.node_mem_headroom;
    add('oom', 'critical', 'memory', `${oomPods.map((p) => p.name).join(', ')} ran out of memory and was killed`, nodeRoom
      ? 'The VM still has free memory, so the pod\'s own memory limit is too low.' : 'The VM itself is short of memory.',
      nodeRoom ? A('raise_pod_limit', 'Raise that pod\'s memory limit.') : A('add_ram', 'Add RAM to the VM.'), oomPods.map((p) => `${p.name}: ${p.oom_killed_24h} OOM kill(s) in 24h, limit ${p.mem_limit ? gb(p.mem_limit) : 'none'}`).join('; '));
  }
  if (memUsed >= T.mem_warn) {
    const crit = memUsed >= T.mem_crit, dbTop = pods.filter((p) => p.mem_used != null).sort((a, b) => b.mem_used - a.mem_used)[0];
    add('mem_high', crit ? 'critical' : 'warning', 'memory', crit ? 'VM memory is nearly exhausted' : 'VM memory use is high',
      `Memory use is ${pct(memUsed)} ${memBasis}; ${gb(host.mem.available)} of ${gb(host.mem.total)} is available right now.${dbTop ? ` Largest consumer: ${dbTop.name} (${gb(dbTop.mem_used)}).` : ''}`,
      A('add_ram', 'Add RAM to the VM.', dbTop && isDb(dbTop) ? { alt: 'dedicated_db' } : {}), `${pct(memUsed)} ${memBasis}`);
  }
  if (host.mem.swap_used > T.swap_warn_bytes) add('swap', 'warning', 'memory', 'The VM is swapping', `${gb(host.mem.swap_used)} of swap is in use, which slows PostgreSQL and the API sharply.`, A('add_ram', 'Add RAM to the VM.'), `swap used ${gb(host.mem.swap_used)}`);

  // ---------------------------------------------------------------- cpu
  const loadPerCore = host.load1 / Math.max(1, host.cpu_count);
  if (cpu >= T.cpu_warn || loadPerCore >= T.load_warn) {
    const crit = cpu >= T.cpu_crit || loadPerCore >= T.load_crit, apiTop = topCpu && isApi(topCpu), dbTop = topCpu && isDb(topCpu);
    add('cpu_high', crit ? 'critical' : 'warning', 'cpu', crit ? 'The VM is CPU-bound' : 'VM CPU use is high',
      `CPU is at ${pct(cpu)} ${cpuBasis} with ${host.cpu_count} vCPU(s); load average per core is ${loadPerCore.toFixed(1)}.${topCpu ? ` Top consumer: ${topCpu.name} (${(topCpu.cpu_used).toFixed(2)} cores).` : ''}`,
      A('add_vcpu', apiTop ? 'Add vCPUs to the VM. Alternatively add a second VM as a k3s node so API pods can run there.' : dbTop ? 'Add vCPUs to the VM; PostgreSQL cannot be spread across nodes, so a bigger VM (or a dedicated database VM later) is the way.' : 'Add vCPUs to the VM.',
        apiTop ? { alt: 'add_node' } : dbTop ? { alt: 'dedicated_db' } : {}), `${pct(cpu)} ${cpuBasis}; load/core ${loadPerCore.toFixed(1)}`);
  }
  for (const p of withCpu) {
    if (!p.cpu_limit || p.cpu_used / p.cpu_limit < T.pod_hot) continue;
    const nodeRoom = host.cpu_pct < T.node_cpu_headroom, line = `${p.name} uses ${(p.cpu_used).toFixed(2)} of its ${p.cpu_limit} core limit (${Math.round(100 * p.cpu_used / p.cpu_limit)}%).`;
    if (isApi(p)) add('pod_cpu_' + p.name, 'warning', 'pods', 'An API pod is close to its CPU limit', `${line} ${nodeRoom ? 'The VM has CPU to spare.' : 'The VM itself is busy, so more pods would not help yet.'}`,
      nodeRoom ? A('add_api_pods', 'Run another API replica (or raise the pod CPU limit).', { alt: 'raise_pod_limit' }) : A('add_vcpu', 'Add vCPUs to the VM first, then add API pods.'), line);
    else add('pod_cpu_' + p.name, 'warning', 'pods', `${p.app || p.name} is close to its CPU limit`, `${line} This workload runs as a single instance.`, nodeRoom ? A('raise_pod_limit', 'Raise its CPU limit.') : A('add_vcpu', 'Add vCPUs to the VM.'), line);
  }
  for (const p of pods) {
    if (!p.mem_limit || p.mem_used == null || p.mem_used / p.mem_limit < T.pod_mem_hot || oomPods.includes(p)) continue;
    const line = `${p.name} uses ${gb(p.mem_used)} of its ${gb(p.mem_limit)} memory limit (${Math.round(100 * p.mem_used / p.mem_limit)}%).`;
    add('pod_mem_' + p.name, 'warning', 'pods', `${p.app || p.name} is close to its memory limit`, `${line} It will be killed if it goes over.`, host.mem.used_pct < T.node_mem_headroom ? A('raise_pod_limit', 'Raise its memory limit.') : A('add_ram', 'Add RAM to the VM.'), line);
  }

  // ---------------------------------------------------------------- database
  const db = input.db || null;
  if (db) {
    if (db.max_connections && db.connections / db.max_connections >= T.db_conn_warn) add('db_conn', 'warning', 'database', 'PostgreSQL connections are nearly used up', `${db.connections} of ${db.max_connections} connections are in use. Each API pod holds a pool of connections.`, A('raise_limit', 'Raise PostgreSQL max_connections or lower DB_POOL_MAX before adding API pods.'), `${db.connections}/${db.max_connections}`);
    if (db.cache_hit != null && db.cache_hit < T.cache_warn && db.bytes > T.db_ram_warn * host.mem.total) add('db_cache', 'warning', 'database', 'The database no longer fits in memory', `Only ${pct(db.cache_hit * 100)} of reads are served from cache and the database (${gb(db.bytes)}) is larger than a quarter of the VM's RAM (${gb(host.mem.total)}). Searches will get slower as it grows.`, A('add_ram', 'Add RAM to the VM.', { alt: 'dedicated_db' }), `cache hit ${pct(db.cache_hit * 100)}, db ${gb(db.bytes)}`);
    if (db.bytes > T.db_ram_plan * host.mem.total) add('db_big', 'info', 'database', 'The database is more than half the size of the VM\'s RAM', `Database ${gb(db.bytes)} vs RAM ${gb(host.mem.total)}. Not urgent, but this is the point to plan a dedicated database VM before searches slow down.`, A('dedicated_db', 'Plan a separate PostgreSQL VM.'), `${gb(db.bytes)} / ${gb(host.mem.total)}`);
  }

  // ---------------------------------------------------------------- cluster state
  if (!k8s) add('k8s_unavailable', 'info', 'cluster', 'Pod and node details are not available', (input.k8s && input.k8s.error) || 'The Kubernetes API could not be read.', A('investigate', 'Apply k8s/31-capacity-rbac.yaml (deploy.sh does this) and check `k3s kubectl -n asix-platform get sa asix-api`.'), (input.k8s && input.k8s.error) || null);
  else {
    if (!k8s.metrics.pods || !k8s.metrics.nodes) add('metrics_unavailable', 'info', 'cluster', 'Per-pod CPU and memory usage is not available', 'metrics-server did not answer, so pod usage and limits-vs-usage checks are skipped. VM-level numbers are unaffected.', A('investigate', 'Check `k3s kubectl top nodes`. k3s normally ships metrics-server; it may have been disabled.'));
    for (const n of nodes) {
      if (!n.ready) add('node_notready_' + n.name, 'critical', 'cluster', `Node ${n.name} is not ready`, 'Kubernetes reports the node as NotReady.', A('investigate', 'Check `k3s kubectl describe node ' + n.name + '` and the VM.'));
      if (n.disk_pressure) add('node_disk_' + n.name, 'critical', 'disk', `Node ${n.name} reports disk pressure`, 'The kubelet is evicting pods because disk is nearly full.', A('grow_disk', 'Grow the disk now.'));
      if (n.memory_pressure) add('node_mem_' + n.name, 'critical', 'memory', `Node ${n.name} reports memory pressure`, 'The kubelet is evicting pods for lack of memory.', A('add_ram', 'Add RAM to the VM.'));
    }
    const notReady = pods.filter((p) => !p.ready && p.phase !== 'Succeeded');
    if (notReady.length) add('pods_not_ready', 'critical', 'pods', `${notReady.length} pod(s) not ready`, notReady.map((p) => `${p.name} (${p.phase})`).join(', '), A('investigate', 'Check `k3s kubectl -n asix-platform describe pod <name>` and its logs.'));
    const restarted = pods.filter((p) => p.recent_termination && !p.oom_killed_24h);
    if (restarted.length) add('pods_restarted', 'warning', 'pods', `${restarted.length} pod(s) restarted in the last 24 hours`, restarted.map((p) => `${p.name}: ${p.recent_termination.reason || 'exit ' + p.recent_termination.exit_code}`).join('; '), A('investigate', 'Check the pod logs around the restart (`k3s kubectl -n asix-platform logs <pod> --previous`).'));
    const short = (k8s.workloads || []).filter((w) => w.ready < w.desired);
    if (short.length) add('workload_short', 'warning', 'pods', 'Some workloads are below their desired replicas', short.map((w) => `${w.name}: ${w.ready}/${w.desired}`).join(', '), A('investigate', 'Pods may be pending for lack of CPU/memory on the node: compare requests with the node table.'));
    if (nodes.length === 1) add('single_node', 'info', 'cluster', 'This is a single-node cluster', 'Adding more pods cannot add capacity here: every pod shares this VM\'s CPU, RAM and disk. More capacity means a bigger VM or a second node.', A('add_node', 'See the steps if you decide to add a node.'));
  }

  // ---------------------------------------------------------------- application health
  const d = input.detection || {};
  if (d.rules_behind > 0) add('detection_behind', 'warning', 'detection', `${d.rules_behind} detection rule(s) are not running on schedule`, `They have not run within their schedule window. ${cpu >= T.cpu_warn ? 'The VM is CPU-heavy, which can starve them.' : 'The detection runner may be disabled or stuck.'}`, A('investigate', cpu >= T.cpu_warn ? 'Relieve CPU first (see the CPU finding).' : 'Check the API pod logs for "[detect]" errors and that DETECTION_RUNNER_ENABLED is not "false".'), `${d.rules_behind} rule(s) overdue`);
  if (d.rules_with_errors > 0) add('detection_errors', 'info', 'detection', `${d.rules_with_errors} detection rule(s) report errors`, 'See Threat Management > Correlations for the error text.', A('investigate', 'Open the rule and read its last error.'));
  if (d.ioc_lag_minutes != null && d.ioc_lag_minutes > 10) add('ioc_lag', 'warning', 'detection', 'IOC matching is behind', `The last IOC cycle finished ${Math.round(d.ioc_lag_minutes)} minutes ago (it normally runs every minute).`, A('investigate', 'Check the API pod logs for "[ioc]" errors.'), `${Math.round(d.ioc_lag_minutes)} min`);
  if ((input.notifications || {}).overdue > T.backlog_warn) add('notify_backlog', 'warning', 'notifications', `${input.notifications.overdue} notifications are waiting to be sent`, 'Deliveries are overdue; the channel may be failing.', A('investigate', 'Open Settings > Delivery log.'));
  if (!enough) add('history_short', 'info', 'history', 'Trend data is still building', `CPU and memory advice uses current values until ${T.min_samples} samples (about an hour) exist. Disk forecasts already use the daily partition sizes.`, A('wait', 'Check back later.'));

  f.sort((a, b) => SEV[a.severity] - SEV[b.severity] || a.area.localeCompare(b.area));
  const verdict = f.some((x) => x.severity === 'critical') ? 'act' : f.some((x) => x.severity === 'warning') ? 'plan' : 'healthy';
  const kinds = (...ks) => f.filter((x) => x.severity !== 'info' && (ks.includes(x.action.kind) || ks.includes(x.action.alt)));
  const ans = (needed, whyNot) => ({ needed: needed.length > 0, reasons: needed.map((x) => x.title), note: needed.length ? null : whyNot });
  const answers = {
    resize_vm: ans(kinds('grow_disk', 'add_ram', 'add_vcpu'), 'CPU, memory and disk all have headroom.'),
    add_api_pods: ans(f.filter((x) => x.severity !== 'info' && x.action.kind === 'add_api_pods'), 'API pods are not near their limits.'),
    add_node: ans(f.filter((x) => x.severity !== 'info' && x.action.alt === 'add_node'), nodes.length === 1 ? 'Not needed now. This VM has capacity; resizing it is the simpler first step.' : 'Not needed now.'),
    dedicated_db: ans(f.filter((x) => x.action.kind === 'dedicated_db' || x.action.alt === 'dedicated_db').filter((x) => x.severity !== 'info' || x.id === 'db_big'), 'The database is small relative to the VM.'),
  };
  const worst = f.find((x) => x.severity !== 'info');
  return { verdict, summary: verdict === 'healthy' ? 'Everything measured is within safe limits.' : verdict === 'plan' ? 'Capacity needs planning soon.' : 'Action needed now.', headline: worst ? worst.title : null, findings: f, forecast: fc, answers, thresholds: T };
}

module.exports = { evaluate, forecastDisk, THRESHOLDS: T, HOW };
