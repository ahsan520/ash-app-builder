'use strict';
// Integration definitions (task SR1, docs/integrations.md): what ASIX knows how to describe about another product, in code, never created by a tenant (the
// same idea as the action registry, src/actions/catalog.js). A definition says what an account for that product needs: settings that are not secret (config,
// such as the address of a firewall) and credentials (secret, write-only). It does NOT contain a connector: a definition only lets a tenant record an account.
// What talks to the product comes later (SR3 the feeds and the playbook engine, SR4 the firewalls) and finds the account through src/integrations/service.js.
const CATEGORIES = ['firewall', 'threat-intel', 'enrichment', 'ticketing', 'messaging', 'identity', 'endpoint', 'other'];
const KINDS = ['builtin'];   // 'pack' (an integration definition carried by a content pack) is refused until MK1's installer takes it (docs/content-packs.md)
const FIELD_TYPES = ['string', 'url', 'enum', 'boolean'];
const NAME_RE = /^[a-z][a-z0-9_]{0,39}$/;
const ID_RE = /^[a-z][a-z0-9-]{1,39}$/;
const LIMITS = { configString: 200, credentialMax: 4096 };

function checkDefinition(d) {
  const errs = [];
  const bad = (m) => errs.push(m);
  if (!d || typeof d !== 'object') return ['definition must be an object'];
  if (!ID_RE.test(d.id || '')) bad('id must be lower case letters, digits and hyphens');
  for (const k of ['name', 'publisher', 'description']) if (typeof d[k] !== 'string' || !d[k].trim()) bad(`${k} is required`);
  if (!CATEGORIES.includes(d.category)) bad(`category must be one of ${CATEGORIES.join(', ')}`);
  if (!KINDS.includes(d.kind)) bad(`kind must be one of ${KINDS.join(', ')}`);
  const seen = new Set();
  const fields = (list, what, secret) => {
    if (!Array.isArray(list)) return bad(`${what} must be a list`);
    for (const f of list) {
      if (!f || !NAME_RE.test(f.name || '')) { bad(`a ${what} field has a bad name`); continue; }
      if (seen.has(f.name)) bad(`field ${f.name} is named twice`); seen.add(f.name);
      if (typeof f.label !== 'string' || !f.label.trim()) bad(`${f.name} needs a label`);
      if (!secret) {
        if (!FIELD_TYPES.includes(f.type)) bad(`${f.name}: type must be one of ${FIELD_TYPES.join(', ')}`);
        if (f.type === 'enum' && !(Array.isArray(f.values) && f.values.length && f.values.every((v) => typeof v === 'string' && v))) bad(`${f.name}: an enum needs values`);
        if (f.type === 'boolean' && f.required) bad(`${f.name}: a boolean cannot be required (false is an answer)`);
      } else if (f.type !== undefined) bad(`${f.name}: a credential is always text`);
      if (f.max !== undefined && !(Number.isInteger(f.max) && f.max >= 1 && f.max <= (secret ? LIMITS.credentialMax : LIMITS.configString))) bad(`${f.name}: max is not valid`);
    }
  };
  fields(d.config, 'config', false); fields(d.credentials, 'credentials', true);
  return errs;
}

const defs = new Map();
function register(d) {
  const errs = checkDefinition(d);
  if (errs.length) throw new Error(`Integration definition ${d && d.id}: ${errs.join('; ')}`);
  if (defs.has(d.id)) throw new Error(`Integration definition ${d.id} is already registered`);
  defs.set(d.id, Object.freeze(d));
  return d;
}
const get = (id) => defs.get(id) || null;
const list = () => [...defs.values()].sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));

// The definitions that ship with ASIX: what SR3 (IOC feeds) and SR4 (firewalls) will need an account for. Settings and credential names follow what each product
// documents for API access; none has been tried against a real product yet (docs/integrations.md, "Honest limits").
const base = { publisher: 'ASIX', kind: 'builtin' };
const url = (label, extra) => ({ name: 'base_url', label, type: 'url', required: true, ...(extra || {}) });
[
  { ...base, id: 'opnsense', name: 'OPNsense', category: 'firewall', description: 'An OPNsense firewall, reached through its API with an API key and secret (System, Access, Users). Used to read a list ASIX publishes (URL table alias) and, later, to block with approval.',
    config: [url('Address of the firewall (https://…)')], credentials: [{ name: 'api_key', label: 'API key', required: true }, { name: 'api_secret', label: 'API secret', required: true }] },
  { ...base, id: 'pfsense', name: 'pfSense', category: 'firewall', description: 'A pfSense firewall with the REST API package installed, reached with an API key.',
    config: [url('Address of the firewall (https://…)')], credentials: [{ name: 'api_key', label: 'API key', required: true }] },
  { ...base, id: 'fortigate', name: 'FortiGate', category: 'firewall', description: 'A FortiGate firewall, reached with a REST API administrator token.',
    config: [url('Address of the firewall (https://…)')], credentials: [{ name: 'api_token', label: 'API token', required: true }] },
  { ...base, id: 'threat-feed', name: 'Threat feed (HTTP)', category: 'threat-intel', description: 'Any indicator feed served over HTTP: a plain list of addresses, domains, URLs or hashes. The token is optional and, when set, is sent as a bearer token.',
    config: [{ name: 'feed_url', label: 'Address of the feed (https://…)', type: 'url', required: true }, { name: 'format', label: 'Format', type: 'enum', values: ['plain-text', 'csv', 'json'], required: true }],
    credentials: [{ name: 'token', label: 'Token (if the feed needs one)' }] },
  { ...base, id: 'virustotal', name: 'VirusTotal', category: 'enrichment', description: 'Looks up the reputation of an address, domain, URL or file hash. Needs a VirusTotal API key; the free key has a small daily limit.',
    config: [], credentials: [{ name: 'api_key', label: 'API key', required: true }] },
].forEach(register);

module.exports = { CATEGORIES, KINDS, FIELD_TYPES, LIMITS, NAME_RE, checkDefinition, register, get, list };
