'use strict';
// The XQL search contract against the in-memory adapter (no database, runs in CI).
const crypto = require('crypto');
const { runSearchConformance } = require('./event-search-conformance');
const { MemoryEventStore } = require('../src/events/memory-store');

runSearchConformance('memory', async () => ({ store: new MemoryEventStore(), tenants: [crypto.randomUUID(), crypto.randomUUID()] }));
