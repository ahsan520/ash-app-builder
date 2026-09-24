const express = require('express');
const db = require('../db');

const app = express();

app.disable('x-powered-by');
app.use(express.json());

app.get('/v1/health/status', async (req, res) => {
  try {
    const database = await db.healthCheck();

    res.status(200).json({
      success: true,
      status: 'ok',
      service: 'asix-api',
      version: '0.1.0',
      dependencies: {
        database: database ? 'ok' : 'error'
      }
    });
  } catch (error) {
    console.error('Health check failed:', error.message);

    res.status(503).json({
      success: false,
      status: 'degraded',
      service: 'asix-api',
      version: '0.1.0',
      dependencies: {
        database: 'error'
      }
    });
  }
});

app.get('/', (req, res) => {
  res.json({
    service: 'asix-api',
    status: 'running'
  });
});

module.exports = app;
