'use strict';
// The secrets abstraction (docs/plan.md H.7, task SR1, docs/integrations.md). Everything that needs to keep a secret (today: the credentials of an integration)
// goes through seal() and open(), never straight to a cipher, so a Vault or cloud provider can replace the local one without touching the callers.
// Rules from H.7: never plaintext in Git, config, logs or the audit trail; audit only references (a name and the field names), never values.
// The one provider built is `local`: AES-256-GCM with the key ASIX already uses for notification secrets (NOTIFY_ENCRYPTION_KEY, from the k8s secret
// asix-notify-secret; src/notifications/secret-box.js). Same key means one key to back up and rotate; it is also why losing that key loses both.
const box = require('../notifications/secret-box');

const NAME = String(process.env.ASIX_SECRETS_PROVIDER || 'local');
const providers = {
  local: { name: 'local', configured: () => box.configured(), seal: (obj) => box.encrypt(obj), open: (s) => box.decrypt(s) },
};
function current() {
  const p = providers[NAME];
  if (!p) throw Object.assign(new Error(`The secrets provider "${NAME}" is not built (only: ${Object.keys(providers).join(', ')})`), { code: 'NO_PROVIDER' });
  return p;
}
const configured = () => { try { return current().configured(); } catch { return false; } };
const seal = (obj) => current().seal(obj);
const open = (s) => current().open(s);

module.exports = { seal, open, configured, providerName: NAME };
