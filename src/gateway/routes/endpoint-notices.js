'use strict';
const express = require('express');
const router = express.Router();
const { guarded } = require('../shared');
const notices = require('../../endpoints/notices');

// ---- Third-party notices of the endpoint agent and manager (docs/endpoints.md, task E7; rules in docs/branding.md) -------------------------------
// One GET route, fixed text from src/endpoints/notices.js: nothing in the request changes the answer and nothing is read from the database or the manager. The permission is the
// one of the other Endpoints tabs that read agent metadata (`capacity:read`); the notices are not secret, they are shipped inside every installer, so no stronger permission.
router.get('/v1/endpoints/notices', ...guarded('capacity:read'), (req, res) => {
  res.status(200).json({ success: true, ...notices.forApi() });
});

module.exports = router;
