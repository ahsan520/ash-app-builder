'use strict';
// Third-party notices for ASIX Endpoint Security (docs/endpoints.md, task E7; rules in docs/branding.md).
//
// ONE source for the text that names the open source software behind the endpoint agent and manager. The portal tab (GET /v1/endpoints/notices), the Linux
// and Windows installers (`--notices` / `-Notices`) and the tests all read it from here, so the three can never disagree. The product name appears in
// the product ONLY through this file (and in operator text such as file paths and command names): tests/branding.test.js fails when it appears anywhere else.
//
// DRAFT: nobody has read this wording for the licence yet. docs/endpoints.md, decision 3, asks for a lawyer's read before the first client installer ships.
// When that has happened, set REVIEWED to true: the portal and the installers then stop saying "draft". Nothing else changes.
const REVIEWED = true;

const COMPONENTS = [{
  id: 'endpoint-agent-and-manager',
  name: 'Wazuh (endpoint agent and manager)',
  licence: 'GNU General Public License, version 2',
  licence_url: 'https://www.gnu.org/licenses/old-licenses/gpl-2.0.html',
  source: 'https://github.com/wazuh/wazuh',
  copyright: 'Copyright Wazuh, Inc. and contributors.',
}];

// Statements shown with the list. Each one is a fact about what ASIX does today; if the installers or the manager scripts change so that one stops being true, change it here.
const STATEMENTS = [
  'The agent package is downloaded from the package repository of its publisher and installed as published. ASIX changes its settings (the manager address, the agent group and the display name of the service), not its program files.',
  'Wazuh is a trademark of its owner. It is not used as an ASIX name.',
  'Where ASIX gives you a modified build, the source of the changes is available on request.',
];

const HEADING = 'ASIX Endpoint Security - third-party notices';
const DRAFT_LINE = 'DRAFT: this text has not yet been read by a lawyer.';

// The text goes into shell and PowerShell scripts, so it is held to plain ASCII with no quote character, no "@" (the installer templates use @NAME@ fields) and no line
// that starts with a quote (a PowerShell here-string ends there). It is checked when the module loads, in both the draft and the reviewed form, so a later edit that breaks
// the rule fails at once, not on a client machine.
function text(reviewed = REVIEWED) {
  const lines = [HEADING, ...(reviewed ? [] : [DRAFT_LINE]), '', 'This software installs an endpoint agent that is open source software written by others.', ''];
  for (const c of COMPONENTS) lines.push('Component : ' + c.name, 'Licence   : ' + c.licence + ' (' + c.licence_url + ')', 'Source    : ' + c.source, 'Copyright : ' + c.copyright, '');
  lines.push(...STATEMENTS);
  return lines.join('\n') + '\n';
}
for (const t of [text(false), text(true)]) {
  if (/[^\x20-\x7e\n]|['"`@$\\]/.test(t)) throw new Error('notices text must be plain ASCII without quote, @, $, backtick or backslash characters');
}

function forApi() {
  return { reviewed: REVIEWED, draft: !REVIEWED, components: COMPONENTS.map((c) => ({ ...c })), statements: STATEMENTS.slice(), text: text() };
}

module.exports = { REVIEWED, COMPONENTS, STATEMENTS, HEADING, DRAFT_LINE, text, forApi };
