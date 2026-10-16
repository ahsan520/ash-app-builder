'use strict';
// Picks the event store for this process. ASIX_EVENT_STORE=postgres (default). A new adapter is one
// file next to this one plus one line in FACTORIES; it must pass tests/event-store-conformance.js.

const { EventStore, EventStoreError, encodeCursor, decodeCursor } = require('./event-store');
const { EnvelopeError, makeEnvelope, ENVELOPE_VERSION } = require('./envelope');

const FACTORIES = {
  postgres: () => new (require('./postgres-store').PostgresEventStore)(),
  clickhouse: () => new (require('./clickhouse-store').ClickHouseEventStore)(),   // needs ASIX_CLICKHOUSE_URL
  memory: () => {
    if (process.env.NODE_ENV === 'production') throw new Error('ASIX_EVENT_STORE=memory loses data on restart and is not allowed in production');
    return new (require('./memory-store').MemoryEventStore)();
  },
};

let instance = null;

function getEventStore() {
  if (!instance) {
    const name = (process.env.ASIX_EVENT_STORE || 'postgres').toLowerCase();
    const make = FACTORIES[name];
    if (!make) throw new Error(`Unknown ASIX_EVENT_STORE "${name}" (known: ${Object.keys(FACTORIES).join(', ')})`);
    instance = make();
  }
  return instance;
}

// Tests only: swap or reset the process-wide store.
function setEventStore(store) { instance = store; }

module.exports = { getEventStore, setEventStore, FACTORIES, EventStore, EventStoreError, EnvelopeError, makeEnvelope, ENVELOPE_VERSION, encodeCursor, decodeCursor };
