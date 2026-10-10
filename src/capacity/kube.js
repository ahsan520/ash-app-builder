'use strict';
// Read-only view of the cluster, via the pod's own ServiceAccount (see k8s/31-capacity-rbac.yaml).
// Namespace-scoped reads of pods/PVCs/workloads + read-only node info. Metrics (CPU/memory
// usage) come from the metrics API if the cluster has metrics-server (k3s does by default);
// without it the snapshot still works and says so. Nothing here can change the cluster.
const fs = require('fs');
const https = require('https');

const SA = process.env.KUBE_SA_DIR || '/var/run/secrets/kubernetes.io/serviceaccount';
const NS_RE = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

function cpuCores(q) {          // "250m" | "2" | "123456n" | "1500u"
  if (q === undefined || q === null || q === '') return null;
  const m = /^([0-9.]+)([numk]?)$/.exec(String(q)); if (!m) return null;
  return Number(m[1]) * ({ n: 1e-9, u: 1e-6, m: 1e-3, k: 1e3, '': 1 })[m[2]];
}
function bytes(q) {             // "512Mi" | "2Gi" | "1000000" | "123456Ki" | "1G"
  if (q === undefined || q === null || q === '') return null;
  const m = /^([0-9.]+)(Ki|Mi|Gi|Ti|Pi|k|K|M|G|T|P|m)?$/.exec(String(q)); if (!m) return null;
  const mult = { Ki: 1024, Mi: 1024 ** 2, Gi: 1024 ** 3, Ti: 1024 ** 4, Pi: 1024 ** 5, k: 1e3, K: 1e3, M: 1e6, G: 1e9, T: 1e12, P: 1e15, m: 1e-3 }[m[2]] || 1;
  return Math.round(Number(m[1]) * mult);
}

function get(path, { timeoutMs = 5000 } = {}) {
  return new Promise((resolve) => {
    let token, ca;
    try { token = fs.readFileSync(`${SA}/token`, 'utf8').trim(); ca = fs.readFileSync(`${SA}/ca.crt`); }
    catch { return resolve({ status: 0, error: 'not running inside Kubernetes (no service account token)' }); }
    const host = process.env.KUBERNETES_SERVICE_HOST, port = process.env.KUBERNETES_SERVICE_PORT || '443';
    if (!host) return resolve({ status: 0, error: 'KUBERNETES_SERVICE_HOST is not set' });
    const req = https.request({ host, port, path, method: 'GET', ca, headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' }, timeout: timeoutMs, agent: false }, (res) => {   // agent:false = fresh connection per call, so no stale keep-alive sockets between samples
      let b = ''; res.setEncoding('utf8'); res.on('data', (c) => { if (b.length < 5e6) b += c; });
      res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* not json */ } resolve({ status: res.statusCode, json }); });
    });
    req.on('timeout', () => req.destroy(new Error('timed out')));
    req.on('error', (e) => resolve({ status: 0, error: e.message }));
    req.end();
  });
}

const sumContainers = (pod, f) => (pod.spec.containers || []).reduce((a, c) => a + (f(c) || 0), 0);

async function snapshot(ns = process.env.POD_NAMESPACE || 'asix-platform', now = Date.now()) {
  if (!NS_RE.test(ns)) return { available: false, error: 'invalid namespace' };
  const [nodesR, podsR, pvcR, depR, stsR, nmR, pmR] = await Promise.all([
    get('/api/v1/nodes'), get(`/api/v1/namespaces/${ns}/pods`), get(`/api/v1/namespaces/${ns}/persistentvolumeclaims`),
    get(`/apis/apps/v1/namespaces/${ns}/deployments`), get(`/apis/apps/v1/namespaces/${ns}/statefulsets`),
    get('/apis/metrics.k8s.io/v1beta1/nodes'), get(`/apis/metrics.k8s.io/v1beta1/namespaces/${ns}/pods`)]);
  const core = [nodesR, podsR];
  const bad = core.find((r) => r.status !== 200);
  if (bad) {
    const why = bad.status === 403 ? 'forbidden - apply k8s/31-capacity-rbac.yaml and redeploy' : bad.error || `HTTP ${bad.status}`;
    return { available: false, error: `Kubernetes API: ${why}` };
  }
  const nm = new Map((nmR.status === 200 ? nmR.json.items : []).map((n) => [n.metadata.name, n.usage]));
  const pm = new Map((pmR.status === 200 ? pmR.json.items : []).map((p) => [p.metadata.name, p.containers.reduce((a, c) => ({ cpu: a.cpu + (cpuCores(c.usage.cpu) || 0), mem: a.mem + (bytes(c.usage.memory) || 0) }), { cpu: 0, mem: 0 })]));

  const nodes = nodesR.json.items.map((n) => {
    const cond = Object.fromEntries((n.status.conditions || []).map((c) => [c.type, c.status]));
    const u = nm.get(n.metadata.name);
    return { name: n.metadata.name, ready: cond.Ready === 'True', memory_pressure: cond.MemoryPressure === 'True', disk_pressure: cond.DiskPressure === 'True', pid_pressure: cond.PIDPressure === 'True',
      cpu_allocatable: cpuCores(n.status.allocatable.cpu), mem_allocatable: bytes(n.status.allocatable.memory), cpu_used: u ? cpuCores(u.cpu) : null, mem_used: u ? bytes(u.memory) : null,
      kubelet: n.status.nodeInfo && n.status.nodeInfo.kubeletVersion, roles: Object.keys(n.metadata.labels || {}).filter((l) => l.startsWith('node-role.kubernetes.io/')).map((l) => l.split('/')[1]) };
  });

  const pods = podsR.json.items.map((p) => {
    const st = p.status.containerStatuses || [];
    let oom = 0, recent = null;
    for (const c of st) { const t = c.lastState && c.lastState.terminated; if (t && t.finishedAt && now - Date.parse(t.finishedAt) < 86400000) { recent = recent || { reason: t.reason, container: c.name, finished_at: t.finishedAt, exit_code: t.exitCode }; if (t.reason === 'OOMKilled') oom += 1; } }
    const u = pm.get(p.metadata.name);
    return { name: p.metadata.name, app: (p.metadata.labels || {}).app || (p.metadata.labels || {})['app.kubernetes.io/name'] || null, phase: p.status.phase, node: p.spec.nodeName,
      ready: st.length > 0 && st.every((c) => c.ready), restarts: st.reduce((a, c) => a + (c.restartCount || 0), 0), oom_killed_24h: oom, recent_termination: recent,
      cpu_limit: sumContainers(p, (c) => cpuCores(c.resources && c.resources.limits && c.resources.limits.cpu)) || null, mem_limit: sumContainers(p, (c) => bytes(c.resources && c.resources.limits && c.resources.limits.memory)) || null,
      cpu_request: sumContainers(p, (c) => cpuCores(c.resources && c.resources.requests && c.resources.requests.cpu)) || null, mem_request: sumContainers(p, (c) => bytes(c.resources && c.resources.requests && c.resources.requests.memory)) || null,
      cpu_used: u ? u.cpu : null, mem_used: u ? u.mem : null };
  });
  const workloads = [...(depR.status === 200 ? depR.json.items : []).map((d) => ({ kind: 'Deployment', d })), ...(stsR.status === 200 ? stsR.json.items : []).map((d) => ({ kind: 'StatefulSet', d }))]
    .map(({ kind, d }) => ({ kind, name: d.metadata.name, desired: d.spec.replicas ?? 1, ready: d.status.readyReplicas || 0 }));
  const pvcs = (pvcR.status === 200 ? pvcR.json.items : []).map((c) => ({ name: c.metadata.name, storage_class: c.spec.storageClassName || null, requested: bytes(c.spec.resources.requests.storage), phase: c.status.phase }));
  return { available: true, namespace: ns, nodes, pods, workloads, pvcs, metrics: { nodes: nmR.status === 200, pods: pmR.status === 200 } };
}

module.exports = { snapshot, cpuCores, bytes, get };
