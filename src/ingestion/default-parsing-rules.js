'use strict';
// Built-in parsing rules shipped with ASIX (read-only in the portal). User-defined rules are
// evaluated first, so a custom rule with the same match can override these.
// String.raw keeps the regex backslashes exactly as written.

module.exports = String.raw`/* -------------------------------------
   ------------ Installed Rules --------------
   ------------------------------------- */

/* ------------ linux_sshd --------- */
[INGEST:vendor="linux", product="sshd", no_hit=keep, content_id="linux_sshd"]
// Accepted/Failed logins, invalid users and pre-auth disconnects from OpenSSH.
filter app_name = "sshd" and message ~= "^(Accepted|Failed|Invalid user|Disconnected from invalid user|Connection closed by authenticating user)"
| alter
    event_category = "authentication",
    event_outcome = if(message ~= "^Accepted", "success", "failure"),
    auth_method = arrayindex(regextract(message, "^(?:Accepted|Failed) (\S+) for"), 0),
    user = arrayindex(regextract(message, "(?:for|user) (?:invalid user )?(\S+) from"), 0),
    src_ip = arrayindex(regextract(message, "from ([0-9a-fA-F:.]+) port"), 0),
    src_port = to_integer(arrayindex(regextract(message, " port (\d+)"), 0));
/* ------------ linux_sshd --------- */

/* ------------ linux_sudo --------- */
[INGEST:vendor="linux", product="sudo", no_hit=keep, content_id="linux_sudo"]
// Failed sudo first: these lines also contain COMMAND=, so they must be tested before the success case.
// Failed sudo: "alice : 3 incorrect password attempts ; ..."
filter app_name = "sudo" and message contains "incorrect password"
| alter
    event_category = "privilege_use",
    event_outcome = "failure",
    user = arrayindex(regextract(message, "^\s*(\S+) :"), 0),
    run_as = arrayindex(regextract(message, "USER=(\S+)"), 0),
    command = arrayindex(regextract(message, "COMMAND=(.*)$"), 0);

// Successful sudo command: "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls"
filter app_name = "sudo" and message contains "COMMAND="
| alter
    event_category = "privilege_use",
    event_outcome = "success",
    user = arrayindex(regextract(message, "^\s*(\S+) :"), 0),
    run_as = arrayindex(regextract(message, "USER=(\S+)"), 0),
    tty = arrayindex(regextract(message, "TTY=(\S+)"), 0),
    command = arrayindex(regextract(message, "COMMAND=(.*)$"), 0);
/* ------------ linux_sudo --------- */

/* ------------ linux_accounts --------- */
[INGEST:vendor="linux", product="shadow-utils", no_hit=keep, content_id="linux_accounts"]
// useradd / userdel / usermod / groupadd / passwd changes.
filter app_name in ("useradd", "userdel", "usermod", "groupadd", "groupdel", "passwd", "chage")
| alter
    event_category = "account_management",
    event_action = app_name,
    target_user = arrayindex(regextract(message, "(?:name=|user '|for )([A-Za-z0-9._-]+)"), 0);
/* ------------ linux_accounts --------- */

/* ------------ linux_cron --------- */
[INGEST:vendor="linux", product="cron", no_hit=keep, content_id="linux_cron"]
// "(root) CMD (/usr/local/bin/backup.sh)"
filter app_name ~= "^(CRON|cron|crond)$" and message contains "CMD"
| alter
    event_category = "scheduled_task",
    user = arrayindex(regextract(message, "^\((\S+)\) CMD"), 0),
    command = arrayindex(regextract(message, "CMD \((.*)\)\s*$"), 0);
/* ------------ linux_cron --------- */

/* -------------------------------------
   ---------- Windows events ----------
   Sent by the ASIX Windows forwarder as
   "[Channel] Provider id=N <message text>"
   ------------------------------------- */

/* ------------ windows_logon --------- */
[INGEST:vendor="microsoft", product="windows", source_type="windows-event", no_hit=keep, content_id="windows_logon"]
// 4625: failed logon
filter message ~= "^\[\w+\] .+? id=4625 "
| alter
    event_id = 4625,
    channel = arrayindex(regextract(message, "^\[(\w+)\]"), 0),
    provider = arrayindex(regextract(message, "^\[\w+\] (.+?) id="), 0),
    event_category = "authentication",
    event_outcome = "failure",
    tmp_user = arrayindex(regextract(message, "Account For Which Logon Failed: Security ID: \S+ Account Name: (.+?) Account Domain:"), 0),
    tmp_domain = arrayindex(regextract(message, "Account For Which Logon Failed: Security ID: \S+ Account Name: .+? Account Domain: (?!Failure Information)(\S+)"), 0),
    target_user = if(tmp_user = "-", null, tmp_user),
    target_domain = if(tmp_domain = "-", null, tmp_domain),
    logon_type = to_integer(arrayindex(regextract(message, "Logon Type: (\d+)"), 0)),
    failure_reason = arrayindex(regextract(message, "Failure Reason: (.+?) Status:"), 0),
    auth_package = arrayindex(regextract(message, "Authentication Package: (\S+)"), 0),
    workstation = arrayindex(regextract(message, "Workstation Name: (\S+)"), 0),
    src_ip = arrayindex(regextract(message, "Source Network Address: ([0-9a-fA-F:.]+)"), 0),
    src_port = to_integer(arrayindex(regextract(message, "Source Port: (\d+)"), 0))
| fields -tmp_*;

// 4624: successful logon
filter message ~= "^\[\w+\] .+? id=4624 "
| alter
    event_id = 4624,
    channel = arrayindex(regextract(message, "^\[(\w+)\]"), 0),
    provider = arrayindex(regextract(message, "^\[\w+\] (.+?) id="), 0),
    event_category = "authentication",
    event_outcome = "success",
    tmp_user = arrayindex(regextract(message, "New Logon: Security ID: \S+ Account Name: (.+?) Account Domain:"), 0),
    tmp_domain = arrayindex(regextract(message, "New Logon: Security ID: \S+ Account Name: .+? Account Domain: (\S+)"), 0),
    target_user = if(tmp_user = "-", null, tmp_user),
    target_domain = if(tmp_domain = "-", null, tmp_domain),
    target_sid = arrayindex(regextract(message, "New Logon: Security ID: (\S+)"), 0),
    logon_type = to_integer(arrayindex(regextract(message, "Logon Type: (\d+)"), 0)),
    auth_package = arrayindex(regextract(message, "Authentication Package: (\S+)"), 0),
    process_path = arrayindex(regextract(message, "Process Name: (.+?) Network Information:"), 0),
    workstation = arrayindex(regextract(message, "Workstation Name: (\S+)"), 0),
    src_ip = arrayindex(regextract(message, "Source Network Address: ([0-9a-fA-F:.]+)"), 0),
    src_port = to_integer(arrayindex(regextract(message, "Source Port: (\d+)"), 0))
| fields -tmp_*;
/* ------------ windows_logon --------- */

/* ------------ windows_process --------- */
[INGEST:vendor="microsoft", product="windows", source_type="windows-event", no_hit=keep, content_id="windows_process"]
// 4688: process creation. The command line is only present when the audit policy
// "Include command line in process creation events" is enabled.
filter message ~= "^\[\w+\] .+? id=4688 "
| alter
    event_id = 4688,
    channel = arrayindex(regextract(message, "^\[(\w+)\]"), 0),
    provider = arrayindex(regextract(message, "^\[\w+\] (.+?) id="), 0),
    event_category = "process",
    event_action = "process_created",
    event_outcome = "success",
    user = arrayindex(regextract(message, "Subject: Security ID: \S+ Account Name: (.+?) Account Domain:"), 0),
    user_domain = arrayindex(regextract(message, "Subject: Security ID: \S+ Account Name: .+? Account Domain: (\S+)"), 0),
    process_path = arrayindex(regextract(message, "New Process Name: (.+?) (?:Token Elevation Type|Mandatory Label|Creator Process ID)"), 0),
    process_name = arrayindex(regextract(process_path, "([^\\]+)$"), 0),
    process_id = arrayindex(regextract(message, "New Process ID: (0x[0-9a-fA-F]+)"), 0),
    parent_path = arrayindex(regextract(message, "Creator Process Name: (.+?)(?: Process Command Line:|$)"), 0),
    parent_name = arrayindex(regextract(parent_path, "([^\\]+)$"), 0),
    parent_pid = arrayindex(regextract(message, "Creator Process ID: (0x[0-9a-fA-F]+)"), 0),
    command_line = arrayindex(regextract(message, "Process Command Line: (?!Token Elevation Type indicates)(.+?)(?: Token Elevation Type indicates|$)"), 0);
/* ------------ windows_process --------- */

/* ------------ windows_scheduled_task --------- */
[INGEST:vendor="microsoft", product="windows", source_type="windows-event", no_hit=keep, content_id="windows_scheduled_task"]
// 4698 created, 4699 deleted, 4700 enabled, 4701 disabled, 4702 updated
filter message ~= "^\[\w+\] .+? id=(?:4698|4699|4700|4701|4702) "
| alter
    event_id = to_integer(arrayindex(regextract(message, " id=(\d+) "), 0)),
    channel = arrayindex(regextract(message, "^\[(\w+)\]"), 0),
    provider = arrayindex(regextract(message, "^\[\w+\] (.+?) id="), 0),
    event_category = "scheduled_task",
    event_action = if(event_id = 4698, "task_created", event_id = 4699, "task_deleted", event_id = 4700, "task_enabled", event_id = 4701, "task_disabled", "task_updated"),
    event_outcome = "success",
    user = arrayindex(regextract(message, "Subject: Security ID: \S+ Account Name: (.+?) Account Domain:"), 0),
    user_domain = arrayindex(regextract(message, "Subject: Security ID: \S+ Account Name: .+? Account Domain: (\S+)"), 0),
    task_name = arrayindex(regextract(message, "Task Name: (.+?)(?: Task Content:| Other Information:|$)"), 0),
    tmp_cmd = arrayindex(regextract(message, "<Command>(.*?)</Command>"), 0),
    tmp_args = arrayindex(regextract(message, "<Arguments>(.*?)</Arguments>"), 0),
    command_line = if(tmp_cmd = null, null, tmp_args != null, concat(tmp_cmd, " ", tmp_args), tmp_cmd)
| fields -tmp_*;
/* ------------ windows_scheduled_task --------- */

/* ------------ windows_account --------- */
[INGEST:vendor="microsoft", product="windows", source_type="windows-event", no_hit=keep, content_id="windows_account"]
// 4720 created, 4722 enabled, 4723 password change, 4724 password reset, 4725 disabled, 4726 deleted,
// 4738 changed, 4740 locked out
filter message ~= "^\[\w+\] .+? id=(?:4720|4722|4723|4724|4725|4726|4738|4740) "
| alter
    event_id = to_integer(arrayindex(regextract(message, " id=(\d+) "), 0)),
    channel = arrayindex(regextract(message, "^\[(\w+)\]"), 0),
    provider = arrayindex(regextract(message, "^\[\w+\] (.+?) id="), 0),
    event_category = "account_management",
    event_action = if(event_id = 4720, "user_created", event_id = 4722, "user_enabled", event_id = 4723, "password_change", event_id = 4724, "password_reset", event_id = 4725, "user_disabled", event_id = 4726, "user_deleted", event_id = 4740, "user_locked_out", "user_changed"),
    event_outcome = "success",
    user = arrayindex(regextract(message, "Subject: Security ID: \S+ Account Name: (.+?) Account Domain:"), 0),
    user_domain = arrayindex(regextract(message, "Subject: Security ID: \S+ Account Name: .+? Account Domain: (\S+)"), 0),
    target_user = arrayindex(regextract(message, "(?:New Account|Target Account|Account That Was Locked Out): Security ID: \S+ Account Name: (.+?) (?:Account Domain|Additional Information):"), 0),
    target_domain = arrayindex(regextract(message, "(?:New Account|Target Account): Security ID: \S+ Account Name: .+? Account Domain: (\S+)"), 0),
    target_sid = arrayindex(regextract(message, "(?:New Account|Target Account|Account That Was Locked Out): Security ID: (\S+)"), 0);
/* ------------ windows_account --------- */

/* ------------ windows_group --------- */
[INGEST:vendor="microsoft", product="windows", source_type="windows-event", no_hit=keep, content_id="windows_group"]
// 4728/4732/4756 member added (global/local/universal group), 4729/4733/4757 member removed
filter message ~= "^\[\w+\] .+? id=(?:4728|4729|4732|4733|4756|4757) "
| alter
    event_id = to_integer(arrayindex(regextract(message, " id=(\d+) "), 0)),
    channel = arrayindex(regextract(message, "^\[(\w+)\]"), 0),
    provider = arrayindex(regextract(message, "^\[\w+\] (.+?) id="), 0),
    event_category = "group_membership",
    event_action = if(event_id in (4728, 4732, 4756), "member_added", "member_removed"),
    event_outcome = "success",
    user = arrayindex(regextract(message, "Subject: Security ID: \S+ Account Name: (.+?) Account Domain:"), 0),
    user_domain = arrayindex(regextract(message, "Subject: Security ID: \S+ Account Name: .+? Account Domain: (\S+)"), 0),
    member_sid = arrayindex(regextract(message, "Member: Security ID: (\S+)"), 0),
    member_name = arrayindex(regextract(message, "Member: Security ID: \S+ Account Name: ([^\s-]\S*)"), 0),
    group_name = arrayindex(regextract(message, "Group Name: (.+?) Group Domain:"), 0),
    group_sid = arrayindex(regextract(message, "Group: Security ID: (\S+)"), 0);
/* ------------ windows_group --------- */

/* ------------ windows_log_cleared --------- */
[INGEST:vendor="microsoft", product="windows", source_type="windows-event", no_hit=keep, content_id="windows_log_cleared"]
// 1102: Security log cleared, 104: another event log cleared
filter message ~= "^\[\w+\] .+? id=(?:1102|104) "
| alter
    event_id = to_integer(arrayindex(regextract(message, " id=(\d+) "), 0)),
    channel = arrayindex(regextract(message, "^\[(\w+)\]"), 0),
    provider = arrayindex(regextract(message, "^\[\w+\] (.+?) id="), 0),
    event_category = "log_cleared",
    event_action = if(event_id = 1102, "security_log_cleared", "event_log_cleared"),
    event_outcome = "success",
    user = arrayindex(regextract(message, "Subject: Security ID: \S+ Account Name: (.+?) (?:Account Domain|Domain Name):"), 0),
    user_domain = arrayindex(regextract(message, "Subject: Security ID: \S+ Account Name: .+? (?:Account Domain|Domain Name): (\S+)"), 0);
/* ------------ windows_log_cleared --------- */

/* ------------ windows_service --------- */
[INGEST:vendor="microsoft", product="windows", source_type="windows-event", no_hit=keep, content_id="windows_service"]
// 7045 (System log) and 4697 (Security log): a service was installed
filter message ~= "^\[\w+\] .+? id=(?:7045|4697) "
| alter
    event_id = to_integer(arrayindex(regextract(message, " id=(\d+) "), 0)),
    channel = arrayindex(regextract(message, "^\[(\w+)\]"), 0),
    provider = arrayindex(regextract(message, "^\[\w+\] (.+?) id="), 0),
    event_category = "service_install",
    event_action = "service_installed",
    event_outcome = "success",
    user = arrayindex(regextract(message, "Subject: Security ID: \S+ Account Name: (.+?) Account Domain:"), 0),
    service_name = arrayindex(regextract(message, "Service Name: (.+?) Service File Name:"), 0),
    service_path = arrayindex(regextract(message, "Service File Name: (.+?) Service Type:"), 0),
    service_account = arrayindex(regextract(message, "Service Account: (.+?)$"), 0);
/* ------------ windows_service --------- */

/* ------------ windows_generic --------- */
[INGEST:vendor="microsoft", product="windows", source_type="windows-event", no_hit=keep, content_id="windows_generic"]
// Any other Windows event: at least extract the channel, provider and event id.
filter message ~= "^\[\w+\] .+? id=\d+ "
| alter
    event_id = to_integer(arrayindex(regextract(message, " id=(\d+) "), 0)),
    channel = arrayindex(regextract(message, "^\[(\w+)\]"), 0),
    provider = arrayindex(regextract(message, "^\[\w+\] (.+?) id="), 0),
    event_category = "windows_event";
/* ------------ windows_generic --------- */
`;
