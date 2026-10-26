'use strict';
// The Windows endpoint-agent installer (docs/endpoints.md, task E5, Windows part): the renderer (renderWindows in src/endpoints/agent-installer.js), the real script it fills in
// (src/endpoints/templates/agent-install-windows.ps1, run by the real PowerShell 7 on Linux) and the route that serves it (GET /v1/endpoints/installer/windows).
// Nothing here installs a real package. The Windows-only commands (Get-ItemProperty on the registry, Get-Service, Set-Service, Stop-Service, Restart-Service, Start-Process for msiexec and
// agent-auth, Get-AuthenticodeSignature, Invoke-WebRequest, icacls) are stand-in functions defined before the script runs, in a made-up agent folder; the manager's ports are real
// listeners on this machine. NOT covered: the real MSI, a real Windows (Windows PowerShell 5.1 differences, the registry, services, ACLs), a real manager accepting an enrolment (the first
// real run is that test). Without pwsh on PATH the script tests skip (GitHub's ubuntu runners have it).
const { describe, it, before, after, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const inst = require('../src/endpoints/agent-installer');
const root = path.join(__dirname, '..');
const TEMPLATE = path.join(root, 'src/endpoints/templates/agent-install-windows.ps1');
const HAS_PWSH = spawnSync('pwsh', ['-NoProfile', '-Command', '1'], { encoding: 'utf8' }).status === 0;
const MSI_BYTES = 'fake-msi-bytes';
const MSI_SHA = crypto.createHash('sha256').update(MSI_BYTES).digest('hex').toUpperCase();

describe('renderer (Windows)', () => {
  it('fills the address, group and version, and leaves exactly one password token', () => {
    const o = inst.renderWindows({ host: '192.168.68.54', group: 'windows', managerVersion: 'v4.14.9' });
    assert.strictEqual(o.agent_version, '4.14.9-1'); assert.strictEqual(o.from_manager, true); assert.strictEqual(o.filename, 'asix-endpoint-install.ps1');
    assert.match(o.script, /^\$MANAGER = '192\.168\.68\.54'; \$GROUP = 'windows'; \$WANT = '4\.14\.9-1'$/m);
    assert.strictEqual(o.script.split(inst.PASSWORD_TOKEN).length - 1, 1);
    assert.ok(!/@(MANAGER|GROUP|VERSION)@/.test(o.script));
  });
  it('is plain ASCII (Windows PowerShell 5.1 reads a file with no byte order mark as ANSI)', () => {
    assert.ok(/^[\x09\x0a\x0d\x20-\x7e]*$/.test(inst.renderWindows({ host: 'h1' }).script));
  });
  it('uses the same validation as Linux: group, address, version rule', () => {
    assert.strictEqual(inst.renderWindows({ host: 'h1' }).group, 'default');
    for (const g of ['a b', "a'b", 'a;b', '$(id)', '`id`', 'a"b', 'a\nb', '..', 'x'.repeat(65), 'ü']) assert.throws(() => inst.renderWindows({ host: 'h1', group: g }), (e) => e.code === 'BAD_GROUP', JSON.stringify(g));
    for (const h of ['', 'a b', "a'b", '$(id)', '999.1.1.1', '[::1]']) assert.throws(() => inst.renderWindows({ host: h }), (e) => e.code === 'BAD_HOST', String(h));
    assert.strictEqual(inst.renderWindows({ host: 'h1', managerVersion: 'v4.15.2' }).agent_version, '4.15.2-1');
    assert.strictEqual(inst.renderWindows({ host: 'h1', managerVersion: 'v4.14.9; calc' }).agent_version, inst.DEFAULT_AGENT_VERSION);
  });
  it('never puts the enrolment password on the msiexec line (it would show in the process list and the installer log)', () => {
    const code = fs.readFileSync(TEMPLATE, 'utf8').split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
    assert.ok(!/WAZUH_REGISTRATION_PASSWORD/.test(code)); assert.ok(!/\$PASSWORD\s*\+\s*'"/.test(code.replace(/WriteAllText[^\n]*/, '')));
  });
  it('the Linux renderer is unchanged', () => { assert.strictEqual(inst.render({ host: 'h1' }).filename, 'asix-endpoint-install.sh'); });
});

describe('the installer script (PowerShell)', { skip: !HAS_PWSH && 'pwsh not installed' }, () => {
  let tmp, agent, listeners, ports;
  before(async () => {
    listeners = []; ports = [];
    for (let i = 0; i < 2; i++) await new Promise((res) => { const s = net.createServer((c) => c.end()); s.listen(0, '127.0.0.1', () => { listeners.push(s); ports.push(s.address().port); res(); }); });
  });
  after(() => { for (const s of listeners) s.close(); });
  const closedPort = () => new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });

  const STUBS = `
function Log($m) { Add-Content -LiteralPath $env:STUB_LOG -Value $m }
function Get-ItemProperty { param($Path, $ErrorAction)
  Log 'registry-read'
  if ($env:STUB_INSTALLED) { [pscustomobject]@{ DisplayName = 'Wazuh Agent'; DisplayVersion = $env:STUB_INSTALLED } }
  [pscustomobject]@{ DisplayName = 'Something Else'; DisplayVersion = '9.9.9' } }
function Get-Service { param($Name, $ErrorAction) if (Test-Path (Join-Path $env:ASIX_AGENT_DIR 'svc.installed')) { [pscustomobject]@{ Name = $Name; Status = 'Running' } } }
function Set-Service { param($Name, $DisplayName, $StartupType) Log ('set-service ' + $Name + ' | ' + $DisplayName + ' | ' + $StartupType) }
function Stop-Service { param($Name, [switch]$Force, $ErrorAction) Log ('stop-service ' + $Name) }
function Restart-Service { param($Name, [switch]$Force)
  Log ('restart-service ' + $Name)
  if (-not $env:STUB_NO_CONNECT) { Add-Content -LiteralPath (Join-Path $env:ASIX_AGENT_DIR 'ossec.log') -Value '2026/10/26 19:36:48 wazuh-agentd: INFO: (4102): Connected to the server ([192.168.68.54]:1514/tcp).' }
  else { Add-Content -LiteralPath (Join-Path $env:ASIX_AGENT_DIR 'ossec.log') -Value '2026/10/26 19:36:48 wazuh-agentd: ERROR: (1216): Unable to connect to 192.168.68.54' } }
function Get-AuthenticodeSignature { param($LiteralPath)
  [pscustomobject]@{ Status = $(if ($env:STUB_SIG_BAD) { 'HashMismatch' } else { 'Valid' }); SignerCertificate = [pscustomobject]@{ Subject = 'CN=Test Publisher, O=Test' } } }
function Invoke-WebRequest { param($Uri, $Method, $OutFile, [switch]$UseBasicParsing, $TimeoutSec)
  Log ('web ' + $(if ($Method) { $Method } else { 'GET' }) + ' ' + $Uri + $(if ($OutFile) { ' -> ' + $OutFile } else { '' }))
  if ($env:STUB_REPO_DOWN) { throw 'no route to host' }
  if ($OutFile) { if ($env:STUB_DL_FAIL) { throw 'download failed' }; [IO.File]::WriteAllText($OutFile, 'fake-msi-bytes') } }
function icacls.exe { Log ('icacls ' + ($args -join ' ')) }
function Start-Process { param($FilePath, $ArgumentList, [switch]$Wait, [switch]$PassThru, [switch]$NoNewWindow)
  Log ('start-process ' + $FilePath + ' ' + $ArgumentList)
  $d = $env:ASIX_AGENT_DIR
  if ($FilePath -like '*msiexec*') {
    if ($env:STUB_MSI_FAIL) { return [pscustomobject]@{ ExitCode = 1603 } }
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    Set-Content -LiteralPath (Join-Path $d 'svc.installed') ''
    if ($env:STUB_MSI_ENROLLS) { Set-Content -LiteralPath (Join-Path $d 'client.keys') '001 name any key' }
    return [pscustomobject]@{ ExitCode = $(if ($env:STUB_MSI_REBOOT) { 3010 } else { 0 }) }
  }
  if ($FilePath -like '*agent-auth*') {
    $pf = Join-Path $d 'authd.pass'
    Log ('authd.pass during enrolment: ' + $(if (Test-Path $pf) { (Get-Content -LiteralPath $pf -Raw).TrimEnd() } else { '<missing>' }))
    if ($env:STUB_AUTH_FAIL) { return [pscustomobject]@{ ExitCode = 2 } }
    Set-Content -LiteralPath (Join-Path $d 'client.keys') '001 name any key'
    return [pscustomobject]@{ ExitCode = 0 }
  }
  throw ('unexpected Start-Process ' + $FilePath)
}
`;
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-win-')); agent = path.join(tmp, 'ossec-agent');
    fs.writeFileSync(path.join(tmp, 'stubs.ps1'), STUBS); fs.writeFileSync(path.join(tmp, 'asix.ps1'), inst.renderWindows({ host: '127.0.0.1', group: 'win', managerVersion: 'v4.14.9' }).script);
    fs.writeFileSync(path.join(tmp, 'pw.txt'), 'S3cret-pass\nsecond line\n');
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const log = () => (fs.existsSync(path.join(tmp, 'log')) ? fs.readFileSync(path.join(tmp, 'log'), 'utf8') : '');
  const seedAgent = (files = {}) => { fs.mkdirSync(agent, { recursive: true }); for (const [n, c] of Object.entries(files)) fs.writeFileSync(path.join(agent, n), c); };
  // args: PowerShell argument text, e.g. "-Check -Name pc1"; env: extra variables.
  const run = (args = '', env = {}, script = 'asix.ps1') => {
    const r = spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command', `. '${path.join(tmp, 'stubs.ps1')}'; & '${path.join(tmp, script)}' ${args}; exit $LASTEXITCODE`], {
      encoding: 'utf8', timeout: 90000, input: '',
      env: { ...process.env, ASIX_AGENT_DIR: agent, ASIX_TEST_ADMIN: '1', ASIX_AGENT_PORT: String(ports[0]), ASIX_ENROL_PORT: String(ports[1]), ASIX_AGENT_WAIT_S: '2', STUB_LOG: path.join(tmp, 'log'),
        COMPUTERNAME: 'WIN-PC01', DOTNET_SYSTEM_GLOBALIZATION_INVARIANT: '1', ...env } });
    return { code: r.status, out: r.stdout, err: r.stderr, all: r.stdout + r.stderr };
  };
  const full = (args = '', env = {}) => run('-PasswordFile "' + path.join(tmp, 'pw.txt') + '" ' + args, env);

  it('the filled script parses as PowerShell', () => {
    const r = spawnSync('pwsh', ['-NoProfile', '-Command', `$e = $null; $t = $null; [void][System.Management.Automation.Language.Parser]::ParseFile('${path.join(tmp, 'asix.ps1')}', [ref]$t, [ref]$e); if ($e.Count) { $e | ForEach-Object { $_.Message }; exit 1 }`], { encoding: 'utf8' });
    assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  });
  it('-Check changes nothing: no download, no install, no enrolment, no agent folder', () => {
    const r = run('-Check'); assert.strictEqual(r.code, 0, r.all); assert.match(r.out, /Checks passed/); assert.match(r.err, /no enrolment password was given/);
    const l = log(); assert.match(l, /web Head https:\/\/packages\.wazuh\.com\/4\.x\/windows\/wazuh-agent-4\.14\.9-1\.msi/); assert.ok(!/start-process|-> |set-service|stop-service|restart-service|icacls/.test(l), l);
    assert.ok(!fs.existsSync(agent)); assert.match(r.out, /installed agent: none; wanted: 4\.14\.9; this machine will be listed as: win-pc01 \(group win\)/);
  });
  it('refuses to run without administrator rights, and says how', () => {
    const r = run('-Check', { ASIX_TEST_ADMIN: '0' }); assert.strictEqual(r.code, 1); assert.match(r.err, /elevated PowerShell/); assert.ok(!/start-process|web /.test(log()));
  });
  it('a closed manager port, an unreachable package, a missing -MsiPath file: each is a problem and nothing changes', async () => {
    let r = run('-Check', { ASIX_AGENT_PORT: String(await closedPort()) }); assert.strictEqual(r.code, 1); assert.match(r.err, /cannot reach 127\.0\.0\.1:\d+\/tcp/); assert.match(r.err, /Nothing was changed/);
    r = run('-Check', { STUB_REPO_DOWN: '1' }); assert.strictEqual(r.code, 1); assert.match(r.err, /cannot reach the agent package/);
    r = run('-Check -MsiPath "' + path.join(tmp, 'none.msi') + '"'); assert.strictEqual(r.code, 1); assert.match(r.err, /does not exist/);
    assert.ok(!fs.existsSync(agent));
  });
  it('a real run with no password available stops before changing anything', () => {
    const r = run(''); assert.strictEqual(r.code, 1); assert.match(r.err, /no enrolment password/); assert.ok(!/start-process|-> /.test(log())); assert.ok(!fs.existsSync(agent));
  });
  it('the full install: package fetched and signature checked, msiexec without the password, enrolled with it in a protected temporary file, service named, connected', () => {
    const r = full(); assert.strictEqual(r.code, 0, r.all); assert.match(r.out, /Done: this machine is connected to the endpoint manager as win-pc01/);
    const l = log(); assert.match(l, /web GET https:\/\/packages\.wazuh\.com\/4\.x\/windows\/wazuh-agent-4\.14\.9-1\.msi -> \S+asix-agent-[0-9a-f]{32}\.msi/);
    const msi = /start-process msiexec\.exe (.*)/.exec(l)[1]; assert.match(msi, /\/i ".+\.msi" \/q \/norestart/); assert.match(msi, /WAZUH_MANAGER="127\.0\.0\.1" WAZUH_AGENT_GROUP="win" WAZUH_AGENT_NAME="win-pc01"/);
    assert.ok(!msi.includes('S3cret-pass') && !/PASSWORD/.test(msi), 'no password on the msiexec line');
    const auth = /start-process \S*agent-auth\.exe (.*)/.exec(l)[1]; assert.strictEqual(auth, '-m "127.0.0.1" -p ' + ports[1] + ' -G "win" -A "win-pc01"'); assert.ok(!auth.includes('S3cret-pass'));
    assert.match(l, /authd\.pass during enrolment: S3cret-pass\n/); assert.ok(!l.includes('second line')); assert.match(l, /icacls \S*authd\.pass \/inheritance:r \/grant:r SYSTEM:\(F\) Administrators:\(F\)/);
    assert.ok(!fs.existsSync(path.join(agent, 'authd.pass')), 'password file removed'); assert.match(l, /set-service WazuhSvc \| ASIX Endpoint Security agent \| Automatic/); assert.match(l, /restart-service WazuhSvc/);
    assert.ok(!r.all.includes('S3cret-pass'), 'the password is never printed'); assert.match(r.out, /signed by: CN=Test Publisher/); assert.match(r.out, new RegExp('package SHA-256: ' + MSI_SHA));
    const dl = /-> (\S+\.msi)/.exec(l)[1]; assert.ok(!fs.existsSync(dl), 'the downloaded package is removed');
  });
  it('the order is: check the signature, install, enrol, then the service', () => {
    const r = full(); assert.strictEqual(r.code, 0, r.all); const l = log();
    const at = (re) => l.search(re); assert.ok(at(/-> /) < at(/msiexec/) && at(/msiexec/) < at(/agent-auth/) && at(/agent-auth/) < at(/set-service/) && at(/set-service/) < at(/restart-service/), l);
  });
  it('a password put into the script by the portal (base64 of its UTF-8 bytes) is used, whatever characters it has', () => {
    const pw = "a'b$&c\\d \u00fc`\"x"; const s = inst.renderWindows({ host: '127.0.0.1', group: 'win' }).script.replace(inst.PASSWORD_TOKEN, Buffer.from(pw, 'utf8').toString('base64'));
    fs.writeFileSync(path.join(tmp, 'embedded.ps1'), s); const r = run('', {}, 'embedded.ps1'); assert.strictEqual(r.code, 0, r.all);
    assert.ok(log().includes('authd.pass during enrolment: ' + pw), log()); assert.ok(!r.all.includes(pw));
  });
  it('a damaged embedded password is refused; an untouched token means "no password inside"', () => {
    fs.writeFileSync(path.join(tmp, 'bad.ps1'), inst.renderWindows({ host: '127.0.0.1' }).script.replace(inst.PASSWORD_TOKEN, 'not base64!!'));
    const r = run('', {}, 'bad.ps1'); assert.strictEqual(r.code, 1); assert.match(r.err, /damaged/); assert.ok(!/start-process/.test(log()));
  });
  it('the password can come from the environment', () => {
    const r = run('', { ASIX_ENROLL_PASSWORD: 'from-env' }); assert.strictEqual(r.code, 0, r.all); assert.ok(log().includes('authd.pass during enrolment: from-env'));
  });
  it('a package whose signature Windows does not accept is never installed', () => {
    const r = full('', { STUB_SIG_BAD: '1' }); assert.strictEqual(r.code, 1); assert.match(r.err, /signature \(HashMismatch\)/); assert.ok(!/msiexec|agent-auth|set-service/.test(log())); assert.ok(!fs.existsSync(agent));
  });
  it('-MsiSha256: a different hash is refused, the right one (any case, spaces) is accepted; a malformed one is a usage error', () => {
    let r = full('-MsiSha256 ' + '0'.repeat(64)); assert.strictEqual(r.code, 1); assert.match(r.err, /not the one you gave/); assert.ok(!/msiexec/.test(log()));
    r = full('-MsiSha256 ' + MSI_SHA.toLowerCase()); assert.strictEqual(r.code, 0, r.all);
    r = full('-MsiSha256 xyz'); assert.strictEqual(r.code, 2); assert.match(r.err, /64 hex/);
  });
  it('-MsiPath installs a package already on the machine, with no download, and checks it the same way', () => {
    const f = path.join(tmp, 'local.msi'); fs.writeFileSync(f, MSI_BYTES);
    let r = full('-MsiPath "' + f + '"'); assert.strictEqual(r.code, 0, r.all); assert.ok(!/web GET/.test(log())); assert.ok(!/web Head/.test(log())); assert.ok(fs.existsSync(f), 'a package the person supplied is not deleted');
    fs.rmSync(path.join(agent), { recursive: true, force: true }); fs.writeFileSync(path.join(tmp, 'log'), '');
    r = full('-MsiPath "' + f + '"', { STUB_SIG_BAD: '1' }); assert.strictEqual(r.code, 1); assert.ok(!/msiexec/.test(log()));
  });
  it('msiexec failing stops with its code and log path; 3010 (restart needed) is accepted', () => {
    let r = full('', { STUB_MSI_FAIL: '1' }); assert.strictEqual(r.code, 1); assert.match(r.err, /msiexec\) stopped with code 1603/); assert.match(r.err, /asix-agent-install\.log/); assert.ok(!/agent-auth/.test(log()));
    fs.writeFileSync(path.join(tmp, 'log'), ''); r = full('', { STUB_MSI_REBOOT: '1' }); assert.strictEqual(r.code, 0, r.all);
  });
  it('a failed download is reported and nothing is installed', () => {
    const r = full('', { STUB_DL_FAIL: '1' }); assert.strictEqual(r.code, 1); assert.match(r.err, /Could not download/); assert.ok(!/msiexec/.test(log()));
  });
  it('running again on an enrolled, current machine keeps the key, installs nothing and needs no password', () => {
    seedAgent({ 'client.keys': '001 old any key', 'svc.installed': '', 'ossec.log': 'old line\n' });
    const r = run('', { STUB_INSTALLED: '4.14.9' }); assert.strictEqual(r.code, 0, r.all); const l = log();
    assert.ok(!/msiexec|agent-auth|web GET|icacls/.test(l), l); assert.match(r.out, /already installed: kept/); assert.match(r.out, /already has an agent key: kept/); assert.strictEqual(fs.readFileSync(path.join(agent, 'client.keys'), 'utf8'), '001 old any key');
  });
  it('another installed version is a problem without -Upgrade, and is replaced with it', () => {
    seedAgent({ 'client.keys': '001 old any key', 'svc.installed': '' });
    let r = run('', { STUB_INSTALLED: '4.13.0' }); assert.strictEqual(r.code, 1); assert.match(r.err, /Agent 4\.13\.0 is installed, not 4\.14\.9/); assert.ok(!/msiexec/.test(log()));
    r = run('-Upgrade', { STUB_INSTALLED: '4.13.0' }); assert.strictEqual(r.code, 0, r.all); assert.match(log(), /msiexec/); assert.ok(!/agent-auth/.test(log()), 'an enrolled machine is not enrolled again');
  });
  it('-ReEnroll keeps the old key as client.keys.before-asix and enrols again', () => {
    seedAgent({ 'client.keys': '001 old any key', 'svc.installed': '' });
    const r = full('-ReEnroll', { STUB_INSTALLED: '4.14.9' }); assert.strictEqual(r.code, 0, r.all); assert.strictEqual(fs.readFileSync(path.join(agent, 'client.keys.before-asix'), 'utf8'), '001 old any key');
    assert.match(log(), /stop-service WazuhSvc/); assert.match(log(), /agent-auth/); assert.notStrictEqual(fs.readFileSync(path.join(agent, 'client.keys'), 'utf8'), '');
  });
  it('a package that enrols by itself is not enrolled twice', () => {
    const r = full('', { STUB_MSI_ENROLLS: '1' }); assert.strictEqual(r.code, 0, r.all); assert.ok(!/agent-auth/.test(log())); assert.match(r.out, /already has an agent key/);
  });
  it('a refused enrolment explains the likely causes and still removes the password file', () => {
    const r = full('', { STUB_AUTH_FAIL: '1' }); assert.strictEqual(r.code, 1); assert.match(r.err, /Enrolment failed\. Is the password right, does the group "win" exist/); assert.ok(!fs.existsSync(path.join(agent, 'authd.pass'))); assert.ok(!/set-service|restart-service/.test(log()));
    assert.ok(!r.all.includes('S3cret-pass'));
  });
  it('never connected: exit 3, with the last problems from the agent log', () => {
    const r = full('', { STUB_NO_CONNECT: '1' }); assert.strictEqual(r.code, 3); assert.match(r.err, /did not say it is connected within 2 seconds/); assert.match(r.err, /Unable to connect to 192\.168\.68\.54/); assert.match(r.err, /1514\/tcp/);
  });
  it('an older "Connected to the server" line in the log does not count', () => {
    seedAgent({ 'ossec.log': '2026/10/20 wazuh-agentd: INFO: (4102): Connected to the server ([x]:1514/tcp).\n' });
    const r = full('', { STUB_NO_CONNECT: '1' }); assert.strictEqual(r.code, 3, r.all);
  });
  it('-Name: used as given; a bad one is a usage error (exit 2) before anything runs; the default is the lower-cased computer name', () => {
    let r = full('-Name Server-01.lab'); assert.strictEqual(r.code, 0, r.all); assert.match(log(), /WAZUH_AGENT_NAME="Server-01\.lab"/); assert.match(log(), /agent-auth\.exe .* -A "Server-01\.lab"/);
    for (const n of ['"a b"', "'x;y'", 'a', '-bad']) { fs.writeFileSync(path.join(tmp, 'log'), ''); r = full('-Name ' + n); assert.strictEqual(r.code, 2, n + r.all); assert.match(r.err, /-Name must be/); assert.ok(!/web |start-process/.test(log())); }
  });
  it('an unknown extra argument is a usage error', () => { const r = run('stray'); assert.strictEqual(r.code, 2); assert.match(r.err, /Unknown argument: stray/); });
});

describe('route GET /v1/endpoints/installer/windows', () => {
  const express = require('express');
  const sharedPath = require.resolve('../src/gateway/shared'), storePath = require.resolve('../src/endpoints/wazuh-manager-store'), apiPath = require.resolve('../src/endpoints/wazuh-api');
  const perms = []; let row = { tenant_id: 'T1' }, info = { version: 'v4.14.9' }, server, base;
  const put = (p, exports) => { require.cache[p] = { id: p, filename: p, loaded: true, exports }; };
  before(async () => {
    class WazuhApiError extends Error { constructor(code, msg) { super(msg); this.code = code; } }
    put(sharedPath, { db: { withTenant: async (t, fn) => fn({}) }, apiError: (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } }),
      guarded: (perm) => { perms.push(perm); return [(req, res, next) => { req.tenant_id = 'T1'; next(); }]; } });
    put(storePath, { readRow: async () => row, credentials: () => ({ api_url: 'https://192.168.68.54:55000', api_user: 'u', api_password: 'p' }), isMissingTable: () => false, view: () => ({}) });
    put(apiPath, { WazuhApiError, managerInfo: async () => { if (info instanceof Error) throw info; return info; } });
    delete require.cache[require.resolve('../src/gateway/routes/wazuh-manager')];
    const app = express(); app.use(require('../src/gateway/routes/wazuh-manager'));
    await new Promise((res) => { server = app.listen(0, '127.0.0.1', res); }); base = 'http://127.0.0.1:' + server.address().port;
  });
  after(() => { server.close(); delete require.cache[require.resolve('../src/gateway/routes/wazuh-manager')]; for (const p of [sharedPath, storePath, apiPath]) delete require.cache[p]; });
  const get = async (q = '', platform = 'windows') => { const r = await fetch(base + '/v1/endpoints/installer/' + platform + q); return { status: r.status, body: await r.json() }; };

  it('is a GET guarded by capacity:read, next to the Linux one', () => {
    assert.ok(perms.length >= 6 && perms.every((p) => p === 'capacity:read'), perms.join());
    const src = fs.readFileSync(path.join(root, 'src/gateway/routes/wazuh-manager.js'), 'utf8'); assert.match(src, /\['windows', installer\.renderWindows\]/); assert.match(src, /router\.get\('\/v1\/endpoints\/installer\/' \+ platform, \.\.\.guarded\('capacity:read'\)/); assert.ok(!/router\.(post|put|patch|delete)\(/.test(src));
  });
  it('returns the PowerShell script for the registered manager, at the manager\'s version, with the group asked for', async () => {
    const { status, body } = await get('?group=servers'); assert.strictEqual(status, 200); const i = body.installer;
    assert.strictEqual(i.platform, 'windows'); assert.strictEqual(i.filename, 'asix-endpoint-install.ps1'); assert.strictEqual(i.manager, '192.168.68.54'); assert.strictEqual(i.group, 'servers'); assert.strictEqual(i.agent_version, '4.14.9-1');
    assert.strictEqual(i.password_token, '__ASIX_ENROLL_PASSWORD__'); assert.match(i.script, /\$MANAGER = '192\.168\.68\.54'; \$GROUP = 'servers'; \$WANT = '4\.14\.9-1'/);
  });
  it('the Linux route still answers with the Linux script', async () => { const { body } = await get('', 'linux'); assert.strictEqual(body.installer.platform, 'linux'); assert.strictEqual(body.installer.filename, 'asix-endpoint-install.sh'); });
  it('the group defaults to "default"; the address cannot be chosen by the request; a bad group is a 400', async () => {
    let r = await get('?host=evil.example.com'); assert.strictEqual(r.body.installer.group, 'default'); assert.ok(!r.body.installer.script.includes('evil.example.com'));
    for (const q of ['?group=a%20b', '?group=%24(id)', "?group=a%27b", '?group=a&group=b']) { r = await get(q); assert.strictEqual(r.status, 400, q); assert.strictEqual(r.body.error.code, 'INSTALLER_BAD_GROUP'); }
  });
  it('a manager that does not answer still gets a script at the tested version; no manager is a 404', async () => {
    info = new Error('down'); let r = await get(); info = { version: 'v4.14.9' }; assert.strictEqual(r.status, 200); assert.strictEqual(r.body.installer.from_manager, false); assert.strictEqual(r.body.installer.agent_version, inst.DEFAULT_AGENT_VERSION);
    row = null; r = await get(); row = { tenant_id: 'T1' }; assert.strictEqual(r.status, 404); assert.strictEqual(r.body.error.code, 'WAZUH_NO_MANAGER');
  });
});
