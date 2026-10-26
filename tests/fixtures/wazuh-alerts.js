'use strict';
// Alerts as a Wazuh manager writes them to /var/ossec/logs/alerts/alerts.json (one JSON object per line; on by default through jsonout_output).
// Shape: timestamp ("2026-10-25T13:00:00.123+0000": milliseconds, zone without a colon), rule { level, description, id, firedtimes, groups[], mitre { id[], tactic[],
// technique[] } }, agent { id, name, ip }, manager { name }, id, full_log, decoder { name }, data { ... }, location, and for file integrity a syscheck { ... } object.
// These are hand-made samples of that documented shape, not captures from a live manager: the first real run on a broker VM is where one real alert of each kind
// gets checked (docs/endpoints.md, "E4d as built").
const base = (o) => ({ timestamp: '2026-10-25T13:00:00.123+0000', manager: { name: 'wazuh-mgr' }, agent: { id: '002', name: 'web1', ip: '10.0.0.30' }, ...o });

const alerts = {
  sshBruteForce: base({
    rule: { level: 10, description: 'sshd: brute force trying to get access to the system. Authentication failed.', id: '5763', firedtimes: 3, mail: false,
      groups: ['syslog', 'sshd', 'authentication_failures'], mitre: { id: ['T1110'], tactic: ['Credential Access'], technique: ['Brute Force'] }, pci_dss: ['11.4', '10.2.4'] },
    id: '1761397200.1001', full_log: 'Oct 25 13:00:00 web1 sshd[991]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2',
    decoder: { parent: 'sshd', name: 'sshd' }, data: { srcip: '203.0.113.9', srcuser: 'admin' }, location: '/var/log/auth.log' }),
  windowsLogonFailure: base({
    agent: { id: '001', name: 'WIN-DC01', ip: '10.0.0.21' },
    rule: { level: 5, description: 'Logon failure - Unknown user or bad password.', id: '60122', firedtimes: 1, mail: false, groups: ['windows', 'windows_security', 'authentication_failed'],
      mitre: { id: ['T1078'], tactic: ['Defense Evasion', 'Persistence', 'Privilege Escalation', 'Initial Access'], technique: ['Valid Accounts'] } },
    id: '1761397201.1002', full_log: '{"win":{"system":{"eventID":"4625"}}}', decoder: { name: 'windows_eventchannel' },
    data: { win: { system: { providerName: 'Microsoft-Windows-Security-Auditing', eventID: '4625', channel: 'Security', computer: 'WIN-DC01.corp.local', eventRecordID: '1001' },
      eventdata: { targetUserName: 'admin', ipAddress: '10.0.0.99', logonType: '3', status: '0xc000006d' } } }, location: 'EventChannel' }),
  fileChanged: base({
    rule: { level: 7, description: 'Integrity checksum changed.', id: '550', firedtimes: 1, mail: false, groups: ['ossec', 'syscheck', 'syscheck_entry_modified', 'syscheck_file'],
      mitre: { id: ['T1565.001'], tactic: ['Impact'], technique: ['Stored Data Manipulation'] } },
    id: '1761397202.1003', full_log: 'File \'/etc/passwd\' modified\nMode: scheduled\nChanged attributes: size,mtime,md5,sha1,sha256',
    decoder: { name: 'syscheck_integrity_changed' }, location: 'syscheck',
    syscheck: { path: '/etc/passwd', mode: 'scheduled', size_before: '1520', size_after: '1581', perm_after: 'rw-r--r--', uname_after: 'root', event: 'modified',
      md5_before: 'aaaa', md5_after: 'bbbb', changed_attributes: ['size', 'mtime', 'md5'], diff: '1a2\n> backdoor:x:0:0::/root:/bin/bash\n' } }),
  lowLevel: base({
    rule: { level: 3, description: 'Successful sudo to ROOT executed.', id: '5402', firedtimes: 2, mail: false, groups: ['syslog', 'sudo'] },
    id: '1761397203.1004', full_log: 'Oct 25 13:00:03 web1 sudo: alice : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls', decoder: { parent: 'sudo', name: 'sudo' },
    data: { srcuser: 'alice', dstuser: 'root', tty: 'pts/0', pwd: '/home/alice', command: '/bin/ls' }, location: '/var/log/auth.log' }),
  awkwardNames: base({
    rule: { level: 8, description: '  Multi   line\r\n description with\ttabs  ', id: '99001', firedtimes: 1, groups: [], mitre: {} },
    id: '1761397204.1005', full_log: 'a'.repeat(2500), decoder: { name: 'json' }, location: 'custom',
    data: { 'weird key.with dots': 'v1', audit: { exe: '/usr/bin/sudo', 'a b': 'x' }, vulnerability: { cve: 'CVE-2026-0001', references: ['https://a.example', 'https://b.example'] }, long: 'x'.repeat(900), number: 42, flag: true, nothing: null } }),
  badTime: base({ timestamp: 'yesterday around noon', rule: { level: 4, description: 'Alert with a timestamp nobody can read.', id: '5501' }, id: '1761397205.1006', location: 'x' })
};
// Lines that must be skipped: a JSON object without a rule (the manager's own status message), a rule without an id, a Windows RAW event from the archive file, and text.
const noRule = JSON.stringify({ timestamp: '2026-10-25T13:00:06.000+0000', agent: { id: '000', name: 'wazuh-mgr' }, full_log: 'ossec: Agent started' });
const noRuleId = JSON.stringify({ timestamp: '2026-10-25T13:00:07.000+0000', rule: { level: 5, description: 'no id' } });
const garbageLine = 'this is not json {"rule":';

module.exports = { base, alerts, noRule, noRuleId, garbageLine, line: (a) => JSON.stringify(a) };
