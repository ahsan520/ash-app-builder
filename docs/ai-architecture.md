# AI / Agentic Security Architecture

## Design Principle
AI is not a chatbot. AI is an agent with controlled tool access.

## Agentic Assistant Architecture
AI Agent → Tool Registry → Permission Check → Tenant Check → Action Policy → Tool Execution → Audit

## Tool Registry
Every AI action is a registered tool: search SIEM, investigate alert, explain detection, correlate entities, query threat intel, summarize incident, recommend response, generate query, generate detection rule, analyze logs, diagnose platform issues, recommend infrastructure change.

## Controls
- Tool access requires explicit permission per user / role / tenant
- No unrestricted backend access
- Every AI action audited with full trace
- AI usage / cost controls per tenant
- Model routing (local vs hosted) configurable
- AI audit log tracked as a first-class audit event

## Integration Points
- Search SIEM (Query module)
- Case / Investigation (Cases module)
- Detection (Detection module)
- Threat Intelligence (Threat module)
- Platform Health (Control Plane / Self-managing)
- Playbooks (SOAR module)
