const express = require('express');
const { SearchEngine } = require('./search/search-engine');
const app = express();

app.get('/search', (req, res) => {
  const se = new SearchEngine();
  const result = se.query({ query: req.query.query || '' }, req.user || 'anonymous', req.tenant || 'default');
  res.json(result);
});

module.exports = app;
