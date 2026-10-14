'use strict';
// Content pack: a Linux box at home (NAS, Raspberry Pi, home server) that runs sshd and sudo and
// forwards syslog to ASIX. Rules use the xdm.* fields the built-in Linux parsers already produce,
// plus a few raw-text matches for things the parsers do not cover.
const PRIV = String.raw`^(10\\.|127\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|169\\.254\\.)`;
const rt = { threshold: 1, window_minutes: 5, run_every_minutes: 1, mode: 'realtime' };

module.exports = {
  id: 'home-linux',
  name: 'Home Linux server',
  description: 'SSH and sudo watching for a Linux machine at home: logins from the internet, password logins, guessing of usernames, root attempts, and a few risky commands.',
  version: '1.0.0',
  audience: 'residential',
  sources: ['Linux syslog (sshd, sudo, cron)'],
  rules: [
    {
      key: 'ssh-login-external', kind: 'bioc', category: 'Initial Access', name: 'SSH login from the internet',
      description: 'A successful SSH login from a public address. If the machine is only used on your home network, this is unexpected.',
      severity: 'high', mitre: ['T1078'],
      definition: { ...rt, event_type: 'event_log', group_by: 'field:xdm.source.ipv4', suppression: { enabled: true, minutes: 60 },
        xql: String.raw`xdm.event.type = "authentication" and xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS and xdm.source.ipv4 != null and not xdm.source.ipv4 ~= "${PRIV}"` },
    },
    {
      key: 'ssh-password-login', kind: 'bioc', category: 'Initial Access', name: 'SSH login with a password',
      description: 'A successful SSH login using a password instead of a key. Useful if you meant to allow keys only.',
      severity: 'low', mitre: ['T1078'],
      definition: { ...rt, event_type: 'event_log', group_by: 'field:xdm.target.host.hostname', suppression: { enabled: true, minutes: 60 },
        xql: String.raw`xdm.event.type = "authentication" and xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS and xdm.auth.auth_method = "password"` },
    },
    {
      key: 'ssh-username-guessing', kind: 'correlation', category: 'Credential Access', name: 'SSH username guessing',
      description: 'Many attempts with usernames that do not exist, from one address. Typical of an internet scanner.',
      severity: 'medium', mitre: ['T1110'],
      definition: { regex: '(Invalid user|Failed password for invalid user) ', group_by: 'source_ip', threshold: 5, window_minutes: 10, suppression: { enabled: true, minutes: 60 } },
    },
    {
      key: 'ssh-root-failures', kind: 'correlation', category: 'Credential Access', name: 'Repeated failed root logins over SSH',
      description: 'Three or more failed logins as root from one address within 10 minutes.',
      severity: 'medium', mitre: ['T1110.001'],
      definition: { event_type: 'event_log', group_by: 'field:xdm.source.ipv4', threshold: 3, window_minutes: 10, suppression: { enabled: true, minutes: 60 },
        xql: String.raw`xdm.event.type = "authentication" and xdm.event.outcome = XDM_CONST.OUTCOME_FAILED and xdm.target.user.username = "root" and xdm.source.ipv4 != null` },
    },
    {
      key: 'sudo-failures', kind: 'correlation', category: 'Privilege Escalation', name: 'Repeated failed sudo attempts',
      description: 'Three or more failed sudo attempts on one host within 10 minutes.',
      severity: 'medium', mitre: ['T1548.003'],
      definition: { event_type: 'event_log', group_by: 'field:xdm.target.host.hostname', threshold: 3, window_minutes: 10,
        xql: String.raw`xdm.event.type = "privilege_use" and xdm.event.outcome = XDM_CONST.OUTCOME_FAILED` },
    },
    {
      key: 'download-pipe-shell', kind: 'bioc', category: 'Execution', name: 'Download piped straight into a shell',
      description: 'curl or wget output piped into sh or bash, the usual one-line installer pattern (and a common attack pattern).',
      severity: 'medium', mitre: ['T1105', 'T1059.004'],
      definition: { ...rt, group_by: 'host', regex: '(curl|wget) [^|;]*\\| *(sudo )?(ba|z|da)?sh( |$)' },
    },
    {
      key: 'authorized-keys-edit', kind: 'bioc', category: 'Persistence', name: 'SSH authorized_keys changed from the command line',
      description: 'A command that appends to or overwrites an authorized_keys file, which gives someone permanent SSH access.',
      severity: 'high', mitre: ['T1098.004'],
      definition: { ...rt, group_by: 'host', regex: '(>>?|tee( -a)?) *[^ ]*\\.ssh/authorized_keys' },
    },
    {
      key: 'fail2ban-ban', kind: 'bioc', category: 'Credential Access', name: 'fail2ban banned an address',
      description: 'fail2ban blocked a source after repeated failures. Informational: it shows the machine is being probed.',
      severity: 'low', mitre: ['T1110'],
      definition: { ...rt, group_by: 'host', regex: 'fail2ban.*\\] Ban ' },
    },
  ],
};
