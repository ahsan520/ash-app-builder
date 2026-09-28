// Phase: first live source — syslog broker/collector
//
// This is the "Collector + Broker" tier from architecture.md's own
// pipeline (Data Source → Collector → Broker → ... → Storage), NOT the
// data node. It parses raw syslog into a normalized envelope and
// forwards it to the data node's ingestion API over HTTP(S) — it never
// touches Postgres directly.
//
// That split matters once there's more than one of these (broker VMs
// per site/segment, XSIAM-Broker-VM-style): a broker holds no DB
// credentials at all, so a compromised or merely-exposed broker VM
// can't reach the database, only the one narrow ingest endpoint.
//
// A broker is assigned to exactly one tenant at a time — raw syslog has
// no tenant field of its own, so the tenant is configured at startup
// and sent with every batch; the data node resolves/validates it.

const dgram = require('dgram');
const net = require('net');
const { EventSpool } = require('./event-spool');

// RFC3164-ish: <PRI>TIMESTAMP HOST TAG: MSG
const RFC3164_RE =
  /^<(\d{1,3})>(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$/;

// RFC5424: <PRI>VERSION TIMESTAMP HOST APP-NAME PROCID MSGID [SD] MSG
const RFC5424_RE =
  /^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:(\[.*?\]|-)\s?)?(.*)$/;

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
      structured_data: structuredData && structuredData !== '-' ? structuredData : null,
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
    this.tenantId = options.tenantId || null;
    this.tenantName = options.tenantName || null;
    this.collectorId = options.collectorId || 'syslog-local';
    this.udpPort = options.udpPort ?? 5514;
    this.tcpPort = options.tcpPort ?? 5514;
    this.bindHost = options.bindHost || '0.0.0.0';
    this.onEvent = options.onEvent; // optional hook, mainly for tests

    if (!this.tenantId && !this.tenantName) {
      throw new Error('SyslogListener requires tenantId or tenantName (which tenant this broker belongs to)');
    }

    this.ingestApiUrl = options.ingestApiUrl;
    this.ingestApiToken = options.ingestApiToken;
    if (!this.ingestApiUrl || !this.ingestApiToken) {
      throw new Error('SyslogListener requires ingestApiUrl and ingestApiToken (data node ingestion endpoint)');
    }

    this._udpSocket = null;
    this._tcpServer = null;
    this._drainInterval = null;

    // If the data node / network is briefly unreachable, spool to disk
    // instead of dropping the event — this is the actual durability
    // boundary for ingestion, separate from console/gateway uptime and
    // now also separate from the data node's own uptime.
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
      this._sendToDataNode(record.envelope, record.raw)
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
      await this._sendToDataNode(envelope, trimmed);
    } catch (err) {
      // Data node/network unreachable — spool it rather than lose it,
      // and let the periodic drain retry once it's back.
      const spooled = this.spool.append({ envelope, raw: trimmed });
      if (spooled) {
        console.error(`[syslog-listener] ingest send failed (${err.message}); event spooled`);
      } else {
        console.error(
          `[syslog-listener] ingest send failed (${err.message}) AND spool is full; event dropped`
        );
      }
    }

    if (this.onEvent) this.onEvent(envelope, trimmed);
  }

  async _sendToDataNode(envelope, raw) {
    const body = {
      tenant_id: this.tenantId,
      tenant_name: this.tenantName,
      source_type: 'syslog',
      collector_id: this.collectorId,
      events: [
        {
          event_time: envelope.event_time,
          raw,
          parsed: envelope,
        },
      ],
    };

    const response = await fetch(this.ingestApiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.ingestApiToken}`,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(`ingest API responded ${response.status}: ${text.slice(0, 200)}`);
    }
  }
}

module.exports = { SyslogListener, parseSyslogLine };
