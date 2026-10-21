'use strict';
// The inputs a broker VM runs, as its heartbeat reports them (deploy/broker/asix-broker-heartbeat.sh). A broker takes syslog, and optionally
// syslog over TLS, log files, HTTP/JSON and the systemd journal (docs/broker-vm.md). It sends one short text, "syslog:514,syslog-tls:6514,file,http:8088,journald": a name,
// plus a port where there is one. This file checks that text and turns it into what the Brokers page shows. Pure functions, no database.
// Information only: nothing here raises an alert, and a broker that never says (older script) is simply "not reporting".

const KINDS = ['syslog', 'syslog-tls', 'file', 'http', 'https', 'journald'];
const WITH_PORT = new Set(['syslog', 'syslog-tls', 'http', 'https']);
const MAX_STORED = 200;

// Accepts a string "a:1,b" or an array of such tokens. Returns the cleaned text to store, or null when nothing usable was sent (the stored value is
// then left alone). Unknown names and bad ports are dropped, never stored: a newer broker script must not make an older ASIX refuse the heartbeat.
function parseInputs(value) {
  const raw = Array.isArray(value) ? value : typeof value === 'string' ? value.split(',') : null;
  if (!raw) return null;
  const out = []; const seen = new Set();
  for (const t of raw.slice(0, 20)) {
    const m = /^([a-z][a-z-]{0,15})(?::(\d{1,5}))?$/.exec(String(t).trim().toLowerCase());
    if (!m || !KINDS.includes(m[1]) || seen.has(m[1])) continue;
    let port = null;
    if (m[2] !== undefined) {
      if (!WITH_PORT.has(m[1])) continue;
      port = Number(m[2]); if (port < 1 || port > 65535) continue;
    }
    seen.add(m[1]); out.push(port === null ? m[1] : m[1] + ':' + port);
  }
  if (!out.length) return null;
  const text = out.join(',');
  return text.length <= MAX_STORED ? text : null;
}

// Stored text -> [{kind, port}] in the order sent; null when the broker never reported inputs.
function listInputs(stored) {
  if (stored === null || stored === undefined || stored === '') return null;
  const parsed = parseInputs(String(stored));
  if (!parsed) return null;
  return parsed.split(',').map((t) => { const [kind, port] = t.split(':'); return { kind, port: port === undefined ? null : Number(port) }; });
}

const LABEL = { syslog: 'Syslog', 'syslog-tls': 'Syslog TLS', file: 'Log files', http: 'HTTP/JSON', https: 'HTTPS/JSON', journald: 'Journal' };
const label = (i) => LABEL[i.kind] + (i.port ? ' ' + i.port : '');

module.exports = { KINDS, parseInputs, listInputs, label };
