// Phase: first live source — syslog receiver
//
// Deliberately not Kafka/OpenSearch yet. This listens for raw syslog
// (UDP + TCP, newline-delimited), builds a normalized envelope, and
// writes both the envelope and the untouched raw line into the
// source-agnostic `events` table (see db/schema.sql).
//
// A collector is assigned to exactly one tenant at a time (matching
// the model in collector-framework.js) — raw syslog has no tenant
// field of its own, so tenant_id is bound at startup, not per-message.

const dgram = require('dgram');
const net = require('net');
const db = require('../db');
const { EventSpool } = require('./event-spool');

// RFC3164-ish: <PRI>TIMESTAMP HOST TAG: MSG
const RFC3164_RE =
  /^<(\d{1,3})>(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$/;

// RFC5424: <PRI>VERSION TIMESTAMP HOST APP-NAME PROCID MSGID [SD] MSG
const RFC5424_RE =
  /^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:(\[.*?\])\s?)?(.*)$/;

const FACILITIES = [
  'kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news',
  'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'security', 'console', 'solaris-cron',
  'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7',
];

const SEVERITIES = [
  'emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug',
];

function decodePri(pri) {
  const n = Number(pri);
  return {
    facility: FACILITIES[Math.floor(n / 8)] || `unknown(${Math.floor(n / 8)})`,
    severity: SEVERITIES[n % 8] || `unknown(${n % 8})`,
  };
}

/**
 * Best-effort syslog parse. Never throws — falls back to a minimal
 * envelope wrapping the raw text so nothing is dropped on a parse miss.
 */
function parseSyslogLine(line) {
  const trimmed = line.trim();
  if (!trimmed) return null;

  let match = trimmed.match(RFC5424_RE);
  if (match) {
    const [, pri, , timestamp, host, appName, procId, msgId, structuredData, message] = match;
    const { facility, severity } = decodePri(pri);
    return {
      format: 'rfc5424',
      facility,
      severity,
      host,
      app_name: appName === '-' ? null : appName,
      proc_id: procId === '-' ? null : procId,
      msg_id: msgId === '-' ? null : msgId,
      structured_data: structuredData || null,
      message,
      event_time: safeDate(timestamp),
    };
  }

  match = trimmed.match(RFC3164_RE);
  if (match) {
    const [, pri, timestamp, host, tag, message] = match;
    const { facility, severity } = decodePri(pri);
    return {
      format: 'rfc3164',
      facility,
      severity,
      host,
      tag: tag.trim(),
      message,
      event_time: safeDate(`${timestamp} ${new Date().getFullYear()}`),
    };
  }

  // Unrecognized shape — still capture facility/severity if a PRI is present
  const priOnly = trimmed.match(/^<(\d{1,3})>/);
  const { facility, severity } = priOnly
    ? decodePri(priOnly[1])
    : { facility: null, severity: null };

  return {
    format: 'unstructured',
    facility,
    severity,
    host: null,
    message: trimmed,
    event_time: null,
  };
}

function safeDate(str) {
  const d = new Date(str);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

class SyslogListener {
  constructor(options = {}) {
    this.tenantId = options.tenantId;
    this.collectorId = options.collectorId || 'syslog-local';
    this.udpPort = options.udpPort ?? 5514;
    this.tcpPort = options.tcpPort ?? 5514;
    this.bindHost = options.bindHost || '0.0.0.0';
    this.onEvent = options.onEvent; // optional hook, mainly for tests

    if (!this.tenantId) {
      throw new Error('SyslogListener requires a tenantId (collector-to-tenant assignment)');
    }

    this._udpSocket = null;
    this._tcpServer = null;
    this._drainInterval = null;

    // If the DB is briefly unreachable, spool to disk instead of dropping
    // the event — this is the actual durability boundary for ingestion,
    // separate from console/gateway uptime.
    this.spool = new EventSpool({
      filePath: options.spoolPath || '/var/lib/asix/syslog-spool.ndjson',
      maxBytes: options.spoolMaxBytes,
    });
    this.drainIntervalMs = options.drainIntervalMs ?? 5000;
  }

  start() {
    this._startUdp();
    this._startTcp();

    // Periodically retry anything sitting in the spool from a past outage.
    this._drainInterval = setInterval(() => {
      this._drainSpool().catch((err) => {
        console.error('[syslog-listener] spool drain failed:', err.message);
      });
    }, this.drainIntervalMs);
  }

  stop() {
    if (this._udpSocket) this._udpSocket.close();
    if (this._tcpServer) this._tcpServer.close();
    if (this._drainInterval) clearInterval(this._drainInterval);
  }

  async _drainSpool() {
    if (this.spool.size() === 0) return;

    const { drained, remaining } = await this.spool.drain((record) =>
      this._writeToDb(record.envelope, record.raw)
    );

    if (drained > 0) {
      console.log(`[syslog-listener] drained ${drained} spooled event(s), ${remaining} remaining`);
    }
  }

  _startUdp() {
    const socket = dgram.createSocket('udp4');

    socket.on('message', (msg, rinfo) => {
      this._handleLine(msg.toString('utf8'), rinfo.address, 'udp').catch((err) => {
        console.error('[syslog-listener] failed to persist UDP message:', err.message);
      });
    });

    socket.on('error', (err) => {
      console.error('[syslog-listener] UDP socket error:', err.message);
    });

    socket.bind(this.udpPort, this.bindHost, () => {
      console.log(`[syslog-listener] UDP listening on ${this.bindHost}:${this.udpPort}`);
    });

    this._udpSocket = socket;
  }

  _startTcp() {
    // Newline-delimited framing (typical for e.g. rsyslog omfwd over TCP).
    // Octet-counted framing (RFC 6587) is not handled in this v1.
    const server = net.createServer((socket) => {
      let buffer = '';

      socket.on('data', (chunk) => {
        buffer += chunk.toString('utf8');
        const lines = buffer.split('\n');
        buffer = lines.pop(); // last element may be a partial line

        for (const line of lines) {
          this._handleLine(line, socket.remoteAddress, 'tcp').catch((err) => {
            console.error('[syslog-listener] failed to persist TCP message:', err.message);
          });
        }
      });

      socket.on('error', (err) => {
        console.error('[syslog-listener] TCP connection error:', err.message);
      });
    });

    server.on('error', (err) => {
      console.error('[syslog-listener] TCP server error:', err.message);
    });

    server.listen(this.tcpPort, this.bindHost, () => {
      console.log(`[syslog-listener] TCP listening on ${this.bindHost}:${this.tcpPort}`);
    });

    this._tcpServer = server;
  }

  async _handleLine(rawLine, remoteAddress, transport) {
    const trimmed = rawLine.trim();
    if (!trimmed) return;

    const parsed = parseSyslogLine(trimmed);
    if (!parsed) return;

    const envelope = {
      ...parsed,
      transport,
      remote_address: remoteAddress,
      collector_id: this.collectorId,
    };

    try {
      await this._writeToDb(envelope, trimmed);
    } catch (err) {
      // DB unreachable/erroring — spool it rather than lose it, and let
      // the periodic drain retry once the DB is back.
      const spooled = this.spool.append({ envelope, raw: trimmed });
      if (spooled) {
        console.error(`[syslog-listener] DB write failed (${err.message}); event spooled`);
      } else {
        console.error(
          `[syslog-listener] DB write failed (${err.message}) AND spool is full; event dropped`
        );
      }
    }

    if (this.onEvent) this.onEvent(envelope, trimmed);
  }

  async _writeToDb(envelope, raw) {
    await db.withTenant(this.tenantId, (client) =>
      client.query(
        `
        INSERT INTO events (tenant_id, source_type, collector_id, event_time, raw, parsed)
        VALUES ($1, $2, $3, $4, $5, $6)
        `,
        [
          this.tenantId,
          'syslog',
          this.collectorId,
          envelope.event_time,
          raw,
          JSON.stringify(envelope),
        ]
      )
    );
  }
}

module.exports = { SyslogListener, parseSyslogLine };
