# SluiceGate Policy DSL (Beta)

This document defines the **Beta-stable** policy format for SluiceGate Open Core.

## Summary (Beta)

- Policy is YAML.
- Rules are evaluated **top-to-bottom**.
- **First match wins**.
- Each rule’s `when` is an **AND-only** list of conditions.
- If no rule matches, the `default` decision applies.
- Rules may attach **obligations** to a decision.

## Decisions

- `ALLOW` — proceed immediately
- `PAUSE` — require explicit approval before proceeding
- `BLOCK` — do not proceed

## Request model (conceptual)

Policies evaluate a request with top-level objects:

- `actor` — identity and attributes of the requester (agent/user/service)
- `action` — the requested operation and its parameters
- `target` — the resource or system the action applies to
- `context` — environmental/risk metadata (env, risk_score, sensitivity, etc.)

Example request shape:

```yaml
actor:
  type: "agent"
  id: "agent-123"
action:
  name: "payments.charge"
  params:
    amount: 500
    currency: "USD"
target:
  type: "payment"
  id: "invoice-456"
context:
  env: "prod"
  risk_score: 72
