'use strict';
// E4q: the two read-only buttons in an agent's detail (src/portal/index.html agentConfigCard), cut out of the page and run with stand-ins.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (name) => { const i = html.indexOf('function ' + name + '('); assert.ok(i >= 0, name); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const el = (tag, props, ...kids) => { const n = Object.assign({ tag, kids: kids.flat(Infinity) }, props || {}); n.props = n; n.replaceChildren = (...k) => { n.kids = k.flat(Infinity); }; return n; };
const all = (n) => (n && typeof n === 'object' ? [n, ...(n.kids || []).flatMap(all)] : []);
const texts = (n) => all(n).flatMap((x) => [x.props && x.props.textContent, ...(x.kids || []).filter((k) => typeof k === 'string')]).filter((x) => typeof x === 'string' && x);
const btn = (n, label) => all(n).find((x) => x.tag === 'button' && x.props.textContent === label);
const make = (api) => new Function('el', 'api', cut('agentConfigCard') + '\nreturn agentConfigCard;')(el, api);

describe('agent detail: what the machine monitors', () => {
  it('requests nothing until a button is pressed; each button asks its own section for the agent (id encoded)', async () => {
    const seen = []; const c = make(async (p, o) => { seen.push({ p, o }); return { config: { items: [], ignored: [], frequency_seconds: null } }; })('002');
    assert.deepStrictEqual(seen, []); await btn(c, 'Show monitored folders').props.onclick(); await btn(c, 'Show logs read').props.onclick();
    assert.deepStrictEqual(seen, [{ p: '/v1/endpoints/agents/002/config/syscheck', o: undefined }, { p: '/v1/endpoints/agents/002/config/logcollector', o: undefined }]);
    assert.ok(!/method:/.test(cut('agentConfigCard')) && !/innerHTML/.test(cut('agentConfigCard')));
  });
  it('shows the items, the ignored list and the scan interval as text; an empty list says so', async () => {
    let c = make(async () => ({ config: { items: ['/etc (check_all)', '/usr/bin'], ignored: ['/etc/mtab'], frequency_seconds: 43200 } }))('001'); await btn(c, 'Show monitored folders').props.onclick();
    const t = texts(c).join(' | '); assert.match(t, /Monitored folders \(2\)/); assert.match(t, /\/etc \(check_all\)/); assert.match(t, /Ignored \(1\)/); assert.match(t, /Scan every 43200 seconds/);
    c = make(async () => ({ config: { items: [], ignored: [], frequency_seconds: null } }))('001'); await btn(c, 'Show logs read').props.onclick(); assert.match(texts(c).join(' '), /nothing configured here/);
  });
  it('a failure shows the message with the connected-agent hint', async () => {
    const c = make(async () => { throw new Error('The manager answered with an unexpected reply (HTTP 400)'); })('001'); await btn(c, 'Show logs read').props.onclick();
    assert.match(texts(c).join(' '), /HTTP 400.*must be connected/);
  });
  it('is drawn in the agent detail next to the configuration checks', () => { assert.match(html, /agentChecksCard\(a\.id\)\),\n\s+el\('div', \{ style: 'margin-top:10px' \}, agentConfigCard\(a\.id\)\)/); });
});
