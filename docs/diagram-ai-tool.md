# AI Tool Architecture Diagram

AI Agent → Tool Registry → Permission Check → Tenant Check → Action Policy → Tool Execution → Audit

Tool Registry defines allowed actions (search, investigate, explain, correlate, query threat intel, summarize, recommend, generate rules, diagnose platform, recommend infra change).
Every tool access requires: user role + tenant + resource + action approval (Level 0-4 configured).
Audit event for every tool call: tool name, input, result, user, tenant, session, time.
