const app = require('./gateway');

const port = Number(process.env.PORT || 3000);

const server = app.listen(port, '0.0.0.0', () => {
  console.log(`ASIX API listening on port ${port}`);
});

async function shutdown(signal) {
  console.log(`${signal} received, shutting down`);

  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
