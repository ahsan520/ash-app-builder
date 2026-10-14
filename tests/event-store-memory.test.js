'use strict';
// Runs the event-store contract against the in-memory adapter (no database, runs in CI).
const crypto = require('crypto');
const { runConformance } = require('./event-store-conformance');
const { MemoryEventStore } = require('../src/events/memory-store');

runConformance('memory', async () => ({
  store: new MemoryEventStore(),
  tenants: [crypto.randomUUID(), crypto.randomUUID()],
}));
