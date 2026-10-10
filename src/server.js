const app = require('./gateway');
const port = Number(process.env.PORT || 3000);
const server = app.listen(port, '0.0.0.0', () => {
  console.log('ASIX API listening on port ' + port);
  require('./detection/rule-runner').start();
  require('./detection/ioc-matcher').start();
  require('./notifications/dispatcher').start();
  require('./storage/retention').start();
  require('./capacity/capacity').start();
});
async function shutdown(signal) {
  console.log(signal + ' received, shutting down');
  server.close(() => process.exit(0));
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
