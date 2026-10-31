'use strict';
const express = require('express');
const router = express.Router();
const { guarded, apiError } = require('../shared');
const api = require('../../endpoints/wazuh-api');
const { handle } = require('./wazuh-manager');

// ---- Configuration checks of ONE machine, straight from the manager (docs/endpoints.md, task E6f) ------------------------------------------------
// Two GET routes. They show which weaknesses a machine has, the same exposure as the Configuration checks tab (which reads event contents), so the permission is that tab's,
// `search:events:read`, and not `capacity:read` like the agent list. The manager, its credentials and the paths are decided as for every E4c call (wazuh-manager.js `handle`,
// wazuh-api.js): nothing in the request chooses an address or a path; the agent id and the policy id are checked here before any call, and the query is checked parameter by parameter.
const idCheck = (req, res, next) => {
  if (!api.AGENT_ID_RE.test(req.params.id)) return apiError(res, 400, 'INVALID_AGENT_ID', 'An agent id is 3 to 8 digits');
  if (req.params.policy !== undefined && !api.POLICY_ID_RE.test(req.params.policy)) return apiError(res, 400, 'INVALID_POLICY_ID', 'A policy id is 1 to 100 letters, digits, dots, dashes or underscores');
  next();
};

// The policies the machine was scanned with, each with its counts and score.
router.get('/v1/endpoints/agents/:id/sca', ...guarded('search:events:read'), idCheck, handle(async (m, req, res) => {
  res.status(200).json({ success: true, agent: req.params.id, policies: await api.scaPolicies(m, req.params.id) });
}));

// Every check of one policy with its current result, paged (`limit`, `offset`, `result`, `search`, `sort`).
router.get('/v1/endpoints/agents/:id/sca/:policy/checks', ...guarded('search:events:read'), idCheck, (req, res, next) => {
  const p = api.parseScaQuery(req.query);
  if (p.error) return apiError(res, 400, 'INVALID_SCA_QUERY', p.error);
  req.scaQuery = p; next();
}, handle(async (m, req, res) => {
  res.status(200).json({ success: true, agent: req.params.id, policy: req.params.policy, ...(await api.scaChecks(m, req.params.id, req.params.policy, req.scaQuery)) });
}));

module.exports = router;
