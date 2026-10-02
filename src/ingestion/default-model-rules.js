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

/* -------------------------------------
   ---------- Windows events ----------
   ------------------------------------- */

[MODEL: dataset=windows-event]
// Base mapping for every Windows event.
alter
    xdm.event.description = message,
    xdm.event.id = to_string(event_id),
    xdm.event.original_event_type = provider,
    xdm.event.tags = arraycreate(channel),
    xdm.target.host.hostname = host,
    xdm.target.host.os_family = XDM_CONST.OS_FAMILY_WINDOWS,
    xdm.observer.name = collector_id,
    xdm.observer.type = "asix-collector";

// windows_logon: 4624 success, 4625 failure
filter _content_id = "windows_logon"
| alter
    xdm.event.type = "authentication",
    xdm.event.outcome = if(event_outcome = "success", XDM_CONST.OUTCOME_SUCCESS, XDM_CONST.OUTCOME_FAILED),
    xdm.event.outcome_reason = failure_reason,
    xdm.auth.auth_method = auth_package,
    xdm.auth.logon_type = logon_type,
    xdm.target.user.username = target_user,
    xdm.target.user.domain = target_domain,
    xdm.target.user.identifier = target_sid,
    xdm.source.host.hostname = workstation,
    xdm.source.ipv4 = if(src_ip contains ":", null, src_ip),
    xdm.source.ipv6 = if(src_ip contains ":", src_ip, null),
    xdm.source.port = src_port,
    xdm.target.process.executable.path = process_path;

// windows_process: 4688 process creation
filter _content_id = "windows_process"
| alter
    xdm.event.type = "process",
    xdm.event.operation = event_action,
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS,
    xdm.source.user.username = user,
    xdm.source.user.domain = user_domain,
    xdm.target.process.executable.path = process_path,
    xdm.target.process.name = process_name,
    xdm.target.process.pid = to_number(process_id),
    xdm.target.process.command_line = command_line,
    xdm.source.process.executable.path = parent_path,
    xdm.source.process.name = parent_name,
    xdm.source.process.pid = to_number(parent_pid);

// windows_scheduled_task: 4698-4702
filter _content_id = "windows_scheduled_task"
| alter
    xdm.event.type = "scheduled_task",
    xdm.event.operation = event_action,
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS,
    xdm.source.user.username = user,
    xdm.source.user.domain = user_domain,
    xdm.target.task.name = task_name,
    xdm.target.process.command_line = command_line;

// windows_account: 4720-4740
filter _content_id = "windows_account"
| alter
    xdm.event.type = "account_management",
    xdm.event.operation = event_action,
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS,
    xdm.source.user.username = user,
    xdm.source.user.domain = user_domain,
    xdm.target.user.username = target_user,
    xdm.target.user.domain = target_domain,
    xdm.target.user.identifier = target_sid;

// windows_group: members added to or removed from groups
filter _content_id = "windows_group"
| alter
    xdm.event.type = "group_membership",
    xdm.event.operation = event_action,
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS,
    xdm.source.user.username = user,
    xdm.source.user.domain = user_domain,
    xdm.target.user.username = member_name,
    xdm.target.user.identifier = member_sid,
    xdm.target.group.name = group_name,
    xdm.target.group.id = group_sid;

// windows_log_cleared: 1102, 104
filter _content_id = "windows_log_cleared"
| alter
    xdm.event.type = "log_cleared",
    xdm.event.operation = event_action,
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS,
    xdm.source.user.username = user,
    xdm.source.user.domain = user_domain;

// windows_service: 7045, 4697
filter _content_id = "windows_service"
| alter
    xdm.event.type = "service_install",
    xdm.event.operation = event_action,
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS,
    xdm.source.user.username = user,
    xdm.target.service.name = service_name,
    xdm.target.service.path = service_path,
    xdm.target.user.username = service_account;
`;
