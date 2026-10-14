'use strict';
// Content pack: a home router or firewall that sends syslog to ASIX. The patterns are written for
// OpenWrt (dropbear, luci, hostapd, miniupnpd, kernel firewall logs); other firmware that logs
// similar text will match too. They match on raw text, so no extra parser is needed.
const rt = { threshold: 1, window_minutes: 5, run_every_minutes: 1, mode: 'realtime' };

module.exports = {
  id: 'home-router',
  name: 'Home router and firewall',
  description: 'Watches the router: failed admin logins, wifi password guessing, new UPnP port openings and floods of blocked traffic.',
  version: '1.0.0',
  audience: 'residential',
  sources: ['Router or firewall syslog (OpenWrt-style messages)'],
  rules: [
    {
      key: 'admin-login-failures', kind: 'correlation', category: 'Credential Access', name: 'Failed router admin logins',
      description: 'Repeated failed logins to the router (SSH or web interface) from one address.',
      severity: 'medium', mitre: ['T1110'],
      definition: { regex: '(dropbear|luci|uhttpd|sshd).*(bad password|failed login|login attempt for nonexistent user|authentication failure)', group_by: 'source_ip', threshold: 3, window_minutes: 10, suppression: { enabled: true, minutes: 60 } },
    },
    {
      key: 'admin-login-success', kind: 'bioc', category: 'Initial Access', name: 'Router admin login',
      description: 'Someone logged in to the router. Informational: check it was you.',
      severity: 'low', mitre: ['T1078'],
      definition: { ...rt, group_by: 'host', regex: '(dropbear.*password auth succeeded|luci: accepted login)', suppression: { enabled: true, minutes: 30 } },
    },
    {
      key: 'wifi-password-guessing', kind: 'correlation', category: 'Credential Access', name: 'Wifi password guessing',
      description: 'Several failed wifi handshakes in a short time, which can mean someone is trying passwords against your network.',
      severity: 'medium', mitre: ['T1110'],
      definition: { regex: 'hostapd.*(4-way handshake failed|authentication failed|ap-sta-possible-psk-mismatch)', group_by: 'host', threshold: 5, window_minutes: 10, suppression: { enabled: true, minutes: 60 } },
    },
    {
      key: 'upnp-port-opened', kind: 'bioc', category: 'Command and Control', name: 'UPnP port opened',
      description: 'A device on your network asked the router to open an inbound port. Games and torrent clients do this, but so can malware.',
      severity: 'medium', mitre: [],
      definition: { ...rt, group_by: 'host', regex: 'miniupnpd.*(addportmapping|addanyportmapping)', suppression: { enabled: true, minutes: 60 } },
    },
    {
      key: 'blocked-traffic-flood', kind: 'correlation', category: 'Discovery', name: 'Flood of blocked traffic',
      description: 'Over 200 blocked or rejected packets logged in 5 minutes. Often a port scan from the internet.',
      severity: 'low', mitre: ['T1046'],
      definition: { regex: '(kernel:|filterlog).*(drop|reject|block)', group_by: 'host', threshold: 200, window_minutes: 5, suppression: { enabled: true, minutes: 60 } },
    },
  ],
};
