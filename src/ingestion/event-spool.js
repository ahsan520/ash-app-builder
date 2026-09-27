// Small on-disk spool for events that failed to insert (DB down/unreachable).
// NDJSON, append-only, drained in order. This is deliberately simple —
// a single file, sequential drain, stop-on-first-failure — because the
// job here is "survive a brief DB outage," not replace a real durable
// queue (Kafka fills that role later per data-architecture.md).

const fs = require('fs');
const path = require('path');

class EventSpool {
  constructor(options = {}) {
    this.filePath = options.filePath;
    this.maxBytes = options.maxBytes ?? 50 * 1024 * 1024; // 50MB default cap

    const dir = path.dirname(this.filePath);
    fs.mkdirSync(dir, { recursive: true });
  }

  /** Append one record (already JSON-serializable). Sync + O_APPEND for durability under concurrent writers. */
  append(record) {
    const line = JSON.stringify(record) + '\n';

    let currentSize = 0;
    try {
      currentSize = fs.statSync(this.filePath).size;
    } catch {
      // File doesn't exist yet — currentSize stays 0
    }

    if (currentSize + line.length > this.maxBytes) {
      console.error(
        `[event-spool] spool at capacity (${this.maxBytes} bytes) — dropping oldest-write event to bound disk usage`
      );
      return false;
    }

    fs.appendFileSync(this.filePath, line, { encoding: 'utf8' });
    return true;
  }

  size() {
    try {
      return fs.statSync(this.filePath).size;
    } catch {
      return 0;
    }
  }

  /**
   * Attempt to drain the spool through insertFn(record), in order.
   * Stops at the first failure and rewrites the file starting from the
   * failed record onward, so nothing is skipped or reordered.
   * Returns { drained, remaining }.
   */
  async drain(insertFn) {
    let content;
    try {
      content = fs.readFileSync(this.filePath, 'utf8');
    } catch {
      return { drained: 0, remaining: 0 };
    }

    if (!content) return { drained: 0, remaining: 0 };

    const lines = content.split('\n').filter(Boolean);
    let drained = 0;

    for (let i = 0; i < lines.length; i++) {
      let record;
      try {
        record = JSON.parse(lines[i]);
      } catch {
        // Corrupt line — skip it rather than blocking the whole spool forever
        drained++;
        continue;
      }

      try {
        await insertFn(record);
        drained++;
      } catch (err) {
        // Still failing — rewrite remaining (including this one) and stop
        const remainingLines = lines.slice(i);
        fs.writeFileSync(this.filePath, remainingLines.join('\n') + '\n', 'utf8');
        return { drained, remaining: remainingLines.length };
      }
    }

    // Everything drained
    fs.writeFileSync(this.filePath, '', 'utf8');
    return { drained, remaining: 0 };
  }
}

module.exports = { EventSpool };
