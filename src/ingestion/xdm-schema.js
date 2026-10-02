'use strict';
// ASIX Data Model (XDM): the common field names that data model rules map every dataset onto,
// so searches and detections are written once instead of once per log format.
// Stored on each event as a nested object under parsed.xdm (query it as xdm.source.ipv4).

const F = (name, type, description) => ({ name, type, description });

const FIELDS = [
  F('xdm.event.type', 'string', 'Kind of activity: authentication, privilege_use, account_management, scheduled_task, ...'),
  F('xdm.event.operation', 'string', 'The specific action, e.g. the command that changed an account (useradd)'),
  F('xdm.event.outcome', 'enum', 'XDM_CONST.OUTCOME_SUCCESS / OUTCOME_FAILED / OUTCOME_PARTIAL / OUTCOME_UNKNOWN'),
  F('xdm.event.outcome_reason', 'string', 'Why the outcome happened, when the log says'),
  F('xdm.event.description', 'string', 'Human-readable summary (usually the log message)'),
  F('xdm.event.original_event_type', 'string', 'Source-specific event name, e.g. sshd'),
  F('xdm.event.id', 'string', 'Source-specific event id'),
  F('xdm.event.tags', 'array', 'Free labels, e.g. arraycreate("VPN")'),
  F('xdm.auth.auth_method', 'string', 'password, publickey, ...'),
  F('xdm.source.ipv4', 'string', 'Where the activity came from (IPv4)'),
  F('xdm.source.ipv6', 'string', 'Where the activity came from (IPv6)'),
  F('xdm.source.port', 'number', 'Source port'),
  F('xdm.source.user.username', 'string', 'Account that performed the action'),
  F('xdm.source.host.hostname', 'string', 'Machine the action was performed from'),
  F('xdm.source.host.os_family', 'enum', 'XDM_CONST.OS_FAMILY_LINUX / OS_FAMILY_MACOS / OS_FAMILY_WINDOWS'),
  F('xdm.source.process.name', 'string', 'Process that produced the event'),
  F('xdm.source.process.pid', 'number', 'Process id'),
  F('xdm.target.user.username', 'string', 'Account acted on (the user logged in, the account created, the user sudo ran as)'),
  F('xdm.target.host.hostname', 'string', 'Machine the action happened on'),
  F('xdm.target.ipv4', 'string', 'Destination IPv4'),
  F('xdm.target.port', 'number', 'Destination port'),
  F('xdm.target.process.name', 'string', 'Process that was started or targeted'),
  F('xdm.target.process.command_line', 'string', 'Command that was run'),
  F('xdm.target.file.path', 'string', 'Full path of the file acted on'),
  F('xdm.target.file.filename', 'string', 'File name'),
  F('xdm.target.file.sha256', 'string', 'File SHA-256'),
  F('xdm.target.registry.key', 'string', 'Registry key (Windows sources)'),
  F('xdm.target.registry.value', 'string', 'Registry value name'),
  F('xdm.target.registry.data', 'string', 'Registry value data'),
  F('xdm.target.module.path', 'string', 'Path of the loaded module / library'),
  F('xdm.target.module.sha256', 'string', 'SHA-256 of the loaded module'),
  F('xdm.observer.name', 'string', 'Collector / sensor that reported the event'),
  F('xdm.observer.type', 'string', 'Kind of sensor'),
];

const CONSTANTS = {
  OUTCOME_SUCCESS: 'SUCCESS', OUTCOME_FAILED: 'FAILED', OUTCOME_PARTIAL: 'PARTIAL', OUTCOME_UNKNOWN: 'UNKNOWN',
  OS_FAMILY_LINUX: 'LINUX', OS_FAMILY_MACOS: 'MACOS', OS_FAMILY_WINDOWS: 'WINDOWS',
};

module.exports = { FIELDS, FIELD_NAMES: new Set(FIELDS.map((f) => f.name)), CONSTANTS };
