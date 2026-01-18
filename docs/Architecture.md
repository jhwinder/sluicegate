# SluiceGate Open Core Beta — Architecture

## What SluiceGate is

SluiceGate is a deterministic policy gate for agent-initiated actions. It evaluates an incoming request
against policy and returns one of three decisions:

- `ALLOW` — proceed immediately
- `PAUSE` — require explicit approval before proceeding
- `BLOCK` — do not proceed

SluiceGate also emits audit events describing what it did and why, and may attach **obligations**
(policy-driven requirements) to guide downstream handling (e.g., approvals, redaction, logging).

## Canonical flow

1. Receive a `GateRequest` describing:
   - `actor` (who/what is requesting)
   - `action` (what they want to do)
   - `target` (what the action affects)
   - `context` (risk signals and environment attributes)
2. Evaluate policy rules (AND-only conditions in Beta)
3. Produce:
   - `decision` (`ALLOW|PAUSE|BLOCK`)
   - `obligations` (zero or more)
   - `policy_hash` (policy version/provenance)
4. Enforce invariants:
   - No execution occurs unless decision allows it
   - `BLOCK` never executes
   - `PAUSE` never executes until approval is recorded (outside core)
5. Emit audit events at key milestones.

## Components

### Open Core (Beta)
- `sluicegate_core/gate.py`
  - Public entrypoint: `Gate.evaluate(request)`
- `sluicegate_core/policy.py`
  - Policy loading + policy_hash provenance
  - Rule evaluation and condition matching
- `sluicegate_core/decision_loop.py`
  - Canonical decision loop implementation (internal)
- `sluicegate_core/models.py`
  - Data contracts: request/response/audit models
- `sluicegate_core/obligations.py`
  - Obligation types and validation

### Adapters (outside core)
Adapters are replaceable integrations around the core:
- HTTP API adapter (FastAPI, etc.)
- Connector executors (Stripe, cloud APIs, internal tools)
- Approval notifiers and approval recorders
- Audit sinks (in-memory, JSONL, SIEM, database)

## Invocation modes

The Open Core can be invoked:
- In-process (direct Python call to `Gate.evaluate`)
- Via HTTP (web API calls into the same core)
- Via other adapters (gRPC, event-bus, sidecar)

HTTP is an adapter: it is a transport mechanism, not the definition of the system’s behavior.
