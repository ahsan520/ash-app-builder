'use strict';
// The endpoint-agent installers (docs/endpoints.md, task E5; Linux and Windows): turn templates/agent-install-linux.sh or agent-install-windows.ps1 into the script for ONE tenant by filling in the manager's
// address, the agent group and the agent package version. The enrolment password is NOT handled here: it is never stored by ASIX, so the script is made without it and the
// portal (or the person running the script) supplies it on the machine side. The only input that reaches a shell script is validated here to a strict alphabet, so a
// group name or an address can never carry shell syntax into the script.
const fs = require('fs');
const path = require('path');

const TEMPLATE = fs.readFileSync(path.join(__dirname, 'templates', 'agent-install-linux.sh'), 'utf8');
const TEMPLATE_WINDOWS = fs.readFileSync(path.join(__dirname, 'templates', 'agent-install-windows.ps1'), 'utf8');
const DEFAULT_AGENT_VERSION = '4.14.9-1';        // the release this repo was tested against (the same number as scripts/deploy/install-wazuh-manager.sh)
const DEFAULT_GROUP = 'default';
const PASSWORD_TOKEN = '__ASIX_ENROLL_PASSWORD__'; // left in the script for the portal to fill; it appears exactly once

class InstallerError extends Error { constructor(code, message) { super(message); this.name = 'InstallerError'; this.code = code; } }

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const HOST_RE = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;
const GROUP_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const VERSION_RE = /^4\.\d{1,2}\.\d{1,2}-\d{1,2}$/;

function checkHost(host) {
  const h = String(host || '');
  if (!h) throw new InstallerError('BAD_HOST', 'The manager has no address');
  if (/^[0-9.]+$/.test(h) ? !IPV4_RE.test(h) : !HOST_RE.test(h)) throw new InstallerError('BAD_HOST', 'The manager address is not a host name or an IPv4 address this installer can use (IPv6 is not supported yet)');
  return h;
}
function checkGroup(group) {
  const g = group === undefined || group === null || group === '' ? DEFAULT_GROUP : String(group);
  if (!GROUP_RE.test(g) || g === '.' || g === '..') throw new InstallerError('BAD_GROUP', 'Group: 1 to 64 characters, letters, digits and . _ - only');
  return g;
}
// The package version to install. An agent must never be newer than its manager, so when the manager tells its version (v4.14.9) the agent package is that release;
// otherwise the version this repo was tested against.
function agentVersion(managerVersion) {
  const m = /^v?(4\.\d{1,2}\.\d{1,2})$/.exec(String(managerVersion || '').trim());
  return m ? { version: m[1] + '-1', fromManager: true } : { version: DEFAULT_AGENT_VERSION, fromManager: false };
}
function fill(template, { host, group, managerVersion }, filename) {
  const h = checkHost(host), g = checkGroup(group), v = agentVersion(managerVersion);
  if (!VERSION_RE.test(v.version)) throw new InstallerError('BAD_VERSION', 'Bad agent version');
  const script = template.split('@MANAGER@').join(h).split('@GROUP@').join(g).split('@VERSION@').join(v.version);
  if (/@(MANAGER|GROUP|VERSION)@/.test(script)) throw new InstallerError('TEMPLATE', 'The installer template still has an unfilled field');
  return { script, manager: h, group: g, agent_version: v.version, from_manager: v.fromManager, filename };
}
function render(opts) { return fill(TEMPLATE, opts, 'asix-endpoint-install.sh'); }
// Windows: the same fields in a PowerShell script. The password token inside it is the base64 of the password's UTF-8 bytes once the portal fills it (no quoting problem in PowerShell
// whatever characters the password has; the script decodes it).
function renderWindows(opts) { return fill(TEMPLATE_WINDOWS, opts, 'asix-endpoint-install.ps1'); }

module.exports = { render, renderWindows, agentVersion, checkHost, checkGroup, InstallerError, DEFAULT_AGENT_VERSION, DEFAULT_GROUP, PASSWORD_TOKEN };
