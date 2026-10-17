const express = require('express');
const router = express.Router();
const { guarded, apiError } = require('../shared');
const parserStatus = require('../../ingestion/parser-status');
const { getParserPool } = require('../../ingestion/parser-pool');
const { getEventStore } = require('../../events');

// ---- Parser pool status (read-only) ---------------------------------------------------------------
// Settings and counters of the parser worker threads on the API replica that answers, plus how many recent events were
// stored unparsed (all replicas). Uses capacity:read, so no role changes are needed. See docs/parser-workers.md.
router.get('/v1/parser/status', ...guarded('capacity:read'), async (req, res) => {
  try {
    const out = await parserStatus.build({ pool: getParserPool(), store: getEventStore(), tenantId: req.tenant_id, hours: req.query.hours });
    res.status(200).json({ success: true, generated_at: new Date().toISOString(), ...out });
  } catch (e) {
    console.error('Parser status failed:', e.message);
    apiError(res, 500, 'PARSER_STATUS_ERROR', 'Failed to read the parser status');
  }
});

module.exports = router;
