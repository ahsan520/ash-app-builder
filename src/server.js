const app = require('./gateway');
const { getEventStore } = require('./events');
const port = Number(process.env.PORT || 3000);
let server = null;
async function main() {
  // The event store gets ready first (ClickHouse: its table is created if missing). If that cannot be done the process exits,
  // so the platform restarts it and the failure is visible, instead of an API that accepts requests it cannot store.
  try { await getEventStore().init(); }
  catch (e) { console.error('[events] the event store could not be initialised: ' + e.message); process.exit(1); }
  require('./ingestion/parser-pool').getParserPool(); // starts the parser workers now if ASIX_PARSER_WORKERS is set (logs one line)
  server = app.listen(port, '0.0.0.0', () => {
    console.log('ASIX API listening on port ' + port);
    require('./detection/rule-runner').start();
    require('./detection/ioc-matcher').start();
    require('./notifications/dispatcher').start();
    require('./storage/retention').start();
    require('./capacity/capacity').start();
  });
}
main();
async function shutdown(signal) {
  console.log(signal + ' received, shutting down');
  await require('./ingestion/parser-pool').closeParserPool().catch(() => {});
  if (server) server.close(() => process.exit(0)); else process.exit(0);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
