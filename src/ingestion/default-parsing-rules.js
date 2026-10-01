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
`;
