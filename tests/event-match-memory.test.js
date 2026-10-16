'use strict';
// The rule-match contract against the in-memory adapter (no database, runs in CI).
const crypto = require('crypto');
const { runMatchConformance } = require('./event-match-conformance');
const { MemoryEventStore } = require('../src/events/memory-store');

runMatchConformance('memory', async () => ({ store: new MemoryEventStore(), tenants: [crypto.randomUUID(), crypto.randomUUID()] }));
