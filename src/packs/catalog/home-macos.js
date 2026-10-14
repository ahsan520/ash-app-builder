'use strict';
// Content pack: a Mac at home. The rules match command lines that appear in the logs a Mac sends
// (for example sudo COMMAND= lines and shell audit logging), so they only fire for commands that
// reach ASIX as text. They match on raw text and need no extra parser.
const rt = { threshold: 1, window_minutes: 5, run_every_minutes: 1, mode: 'realtime', group_by: 'host' };

module.exports = {
  id: 'home-macos',
  name: 'Home Mac',
  description: 'Catches commands that weaken macOS protections or give a program permanent access: Gatekeeper, SIP, quarantine, LaunchAgents, Keychain and Remote Login.',
  version: '1.0.0',
  audience: 'residential',
  sources: ['macOS syslog forwarding (sudo, shell command logs)'],
  rules: [
    {
      key: 'gatekeeper-disabled', kind: 'bioc', category: 'Defense Evasion', name: 'Gatekeeper turned off',
      description: 'spctl was used to disable Gatekeeper, which lets unsigned apps run.',
      severity: 'high', mitre: ['T1562.001'],
      definition: { ...rt, regex: 'spctl +(--master-disable|--global-disable)' },
    },
    {
      key: 'sip-disabled', kind: 'bioc', category: 'Defense Evasion', name: 'System Integrity Protection turned off',
      description: 'csrutil disable was run (normally from Recovery, so seeing it in logs is unusual).',
      severity: 'high', mitre: ['T1562.001'],
      definition: { ...rt, regex: 'csrutil +(authenticated-root +)?disable' },
    },
    {
      key: 'quarantine-removed', kind: 'bioc', category: 'Defense Evasion', name: 'Download quarantine flag removed',
      description: 'xattr was used to strip the quarantine flag that makes macOS check a downloaded app.',
      severity: 'medium', mitre: ['T1553.001'],
      definition: { ...rt, regex: 'xattr .*(com\\.apple\\.quarantine|-cr )' },
    },
    {
      key: 'launch-agent-added', kind: 'bioc', category: 'Persistence', name: 'LaunchAgent or LaunchDaemon installed',
      description: 'A property list was copied into, or loaded from, a LaunchAgents or LaunchDaemons folder. This is how macOS programs start themselves at login.',
      severity: 'medium', mitre: ['T1543.001'],
      definition: { ...rt, regex: '(launchctl +(load|bootstrap)|cp |mv |tee ).*/(launchagents|launchdaemons)/[^ ]+\\.plist' },
    },
    {
      key: 'admin-prompt-script', kind: 'bioc', category: 'Privilege Escalation', name: 'Script asking for administrator rights',
      description: 'osascript used "with administrator privileges", the standard trick for showing a fake password prompt.',
      severity: 'medium', mitre: ['T1059.002', 'T1548'],
      definition: { ...rt, regex: 'osascript .*with administrator privileges' },
    },
    {
      key: 'user-account-created', kind: 'bioc', category: 'Persistence', name: 'Local user account created',
      description: 'dscl or sysadminctl was used to create a user account.',
      severity: 'medium', mitre: ['T1136.001'],
      definition: { ...rt, regex: '(dscl +\\. +-create +/users/|sysadminctl .*-adduser)' },
    },
    {
      key: 'keychain-read', kind: 'bioc', category: 'Credential Access', name: 'Keychain read from the command line',
      description: 'The security tool was used to read a saved password or dump a keychain. Developers do this legitimately, so expect some noise.',
      severity: 'medium', mitre: ['T1555.001'],
      definition: { ...rt, regex: 'security +(find-generic-password|find-internet-password|dump-keychain)' },
    },
    {
      key: 'privacy-db-edit', kind: 'bioc', category: 'Defense Evasion', name: 'Privacy permissions database edited',
      description: 'sqlite3 was pointed at TCC.db, the file that stores which apps may use your camera, microphone and files.',
      severity: 'high', mitre: ['T1548'],
      definition: { ...rt, regex: 'sqlite3 .*tcc\\.db' },
    },
    {
      key: 'remote-login-enabled', kind: 'bioc', category: 'Lateral Movement', name: 'Remote Login (SSH) turned on',
      description: 'systemsetup was used to enable SSH access to the Mac.',
      severity: 'medium', mitre: ['T1021.004'],
      definition: { ...rt, regex: 'systemsetup +-setremotelogin +on' },
    },
  ],
};
