'use strict';
// Built-in data model rules (read-only in the portal). They map the fields produced by the default
// parsing rules onto XDM. Every matching pipeline runs in order, so the first one gives all syslog
// events a base mapping and the later ones add detail for sshd, sudo, account changes and cron.
// User-defined model rules run after these and override them.

module.exports = String.raw`/* -------------------------------------
   ---------- System mappings ----------
   ------------------------------------- */

[MODEL: dataset=syslog]
// Base mapping for every syslog event.
alter
    xdm.event.description = message,
    xdm.source.process.name = app_name,
    xdm.source.process.pid = to_number(proc_id),
    xdm.target.host.hostname = host,
    xdm.observer.name = collector_id,
    xdm.observer.type = "asix-collector";

// linux_sshd: logins, failures, invalid users
filter _content_id = "linux_sshd"
| alter
    xdm.event.type = "authentication",
    xdm.event.original_event_type = "sshd",
    xdm.event.outcome = if(event_outcome = "success", XDM_CONST.OUTCOME_SUCCESS, XDM_CONST.OUTCOME_FAILED),
    xdm.auth.auth_method = auth_method,
    xdm.target.user.username = user,
    xdm.source.ipv4 = if(src_ip contains ":", null, src_ip),
    xdm.source.ipv6 = if(src_ip contains ":", src_ip, null),
    xdm.source.port = src_port;

// linux_sudo: privilege use
filter _content_id = "linux_sudo"
| alter
    xdm.event.type = "privilege_use",
    xdm.event.original_event_type = "sudo",
    xdm.event.outcome = if(event_outcome = "success", XDM_CONST.OUTCOME_SUCCESS, XDM_CONST.OUTCOME_FAILED),
    xdm.source.user.username = user,
    xdm.target.user.username = run_as,
    xdm.target.process.command_line = command;

// linux_accounts: useradd, userdel, usermod, passwd ...
filter _content_id = "linux_accounts"
| alter
    xdm.event.type = "account_management",
    xdm.event.operation = event_action,
    xdm.target.user.username = target_user;

// linux_cron: scheduled tasks
filter _content_id = "linux_cron"
| alter
    xdm.event.type = "scheduled_task",
    xdm.source.user.username = user,
    xdm.target.process.command_line = command;
`;
