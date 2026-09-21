# Module / Plugin Architecture

## Design Requirement
The platform must not be a monolithic application. Each capability (SIEM, XDR, SOAR, Threat Intel, Cases, Posture, Inventory, AI, Reports, Compliance) must be a module that can be installed, upgraded, disabled, or replaced independently.

## Module Definition
A module provides:
- Backend services (REST / event handlers)
- APIs (namespaced by module)
- Database models (migrations isolated to module schema namespace)
- UI pages (modular routing; new module = new navigation section or sub-navigation)
- Permissions (module-specific roles and actions)
- Settings (modular settings categories; expandable, not one huge page)
- Events (publish / subscribe to internal event bus)
- Metrics (exposes health / performance metrics)
- Workers (background tasks: ingestion, parsing, detection, enrichment, playbook execution)
- Playbooks (module-specific playbook templates and actions)
- Detection rules (module-specific Sigma/custom rules)

## Example Modules
- `siem`: ingestion, search, correlation, dashboards
- `xdr`: endpoint telemetry, network telemetry, identity telemetry, behavioral analytics
- `soar`: playbooks, actions, connectors, approvals, rollback
- `threat-intel`: IOC feeds, MISP/OpenCTI integration, reputation providers, watchlists
- `cases`: case management, incidents, tasks, evidence, timeline
- `posture`: security posture, vulnerability correlation, asset health
- `inventory`: assets, users, IP labels, device inventory
- `collectors`: collector framework, broker framework, installation profiles
- `brokers`: broker services, health, capacity, failover
- `ai`: AI agent framework, tool registry, model routing, permission controls, audit
- `reports`: reporting engine, templates, scheduling, export
- `compliance`: audit logging, compliance reports, data retention policies

## Module Lifecycle
Install → Configure → Enable → Upgrade → Disable → Uninstall
- Each module defines dependencies (e.g., `soar` depends on `cases`; `xdr` depends on `siem` for events)
- Upgrade does not require full platform restart; module reloads independently
- Disabled module stops workers, hides UI, stops APIs, but retains data
- Uninstall removes module-specific APIs and UI routes; data retention controlled by admin policy

## Dependency Management
Modules declare:
- Required modules (must be installed/enabled)
- Optional modules (enhanced functionality if present)
- Conflicting modules (cannot be installed together or must be configured to avoid resource conflict)

## Integration Strategy
Module-to-module communication uses:
- Internal event bus (Kafka / message bus)
- Shared entity model (user, device, IP, domain, process, file, cloud resource, application, alert, incident, threat actor, IOC)
- Shared policy engine (policies apply across modules)
- Shared audit model (every module writes audit events)
