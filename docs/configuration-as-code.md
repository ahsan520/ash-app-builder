# Configuration-as-Code

Status: DESIGN

## Format
- YAML (primary) and JSON (alternative) for all platform configuration
- Git repository as source of truth for settings, roles, policies, detection rules, playbooks, module configs

## Features (Design)
- Versioning: all config versioned; git history shows changes
- Diff: compare versions between branches or tags; show impact
- Validation: JSON Schema / YAML schema validation before application; reject invalid configs
- Import / Export: import from YAML/JSON; export current state to YAML/JSON for backup
- Rollback: restore previous version from git or from exported backup; audit event recorded
- Approval: high-risk config changes (roles, policies, control plane settings) require approval before deployment
- Audit: every config change links to git commit; audit event includes commit hash and author

## Module Config
Each module defines its own config schema; module loader validates; module settings stored in DB (with git sync option)
