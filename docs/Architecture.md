# SluiceGate Open Core Beta — Architecture

## What SluiceGate is

SluiceGate is a deterministic policy gate for agent-initiated actions. It evaluates an incoming request against policy and returns one of three decisions:

- `ALLOW` — proceed immediately
- `PAUSE` — require explicit approval before proceeding
- `BLOCK` — do not proceed

SluiceGate also emits audit events describing what it did and why, and may attach **obligations** (policy-driven requirements) to guide downstream handling (e.g., approvals, redaction, logging).

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

##System Elements

* Policy Engine
* Control Plane API
* Decision Ledger
* Policy DSL
* Local Agent Runtime

###Control Plane API

The Control Plane API is the transport-facing boundary that exposes the core as a service interface for external callers (agents, services, gateways, or orchestration layers). It accepts evaluation requests (often via HTTP/gRPC) and returns the decision payload from the Policy Engine, optionally including trace/explain output and policy metadata. Inputs include serialized requests, authentication/authorization context, and sometimes multi-tenant identifiers (org/project/environment). Outputs are structured responses (JSON/protobuf) containing decision, obligations, policy hash/version, and correlation IDs; it may also emit operational telemetry (metrics/logs) and enforce request validation and rate limits. The API is an adapter: it should be “thin,” translating between network formats and the in-process policy engine.

###Policy Engine v1

The Policy Engine is the deterministic evaluation core that takes a normalized request context (typically structured as `actor`, `action`, `target`, and `context`) plus an active policy document and produces a policy decision (`ALLOW`, `PAUSE`, `BLOCK`) along with structured obligations and a policy provenance identifier (e.g., a content hash). Inputs include a policy (YAML/DSL), a request object, and optionally evaluation options such as “explain mode.” Outputs include a `GateDecision` (decision, obligations, abbreviated policy hash, message, request_id if invoked via Gate) and, when requested, a rich explanation trace describing which rule matched and which conditions passed/failed. The engine is pure: it describes what must happen, but it does not execute actions or trigger notifications.

###Policy DSL

The Policy DSL is the human-authored configuration language that describes governance intent in a constrained, auditable format. It consumes a schema (what fields exist in `actor`/`action`/`target`/`context`), rule definitions, and defaults, and it produces a structured policy model that the Policy Engine can evaluate deterministically. Inputs include the policy YAML text, optional policy metadata (version, owner, environment), and validation constraints (allowed operators, required fields). Outputs include a parsed internal representation (rules + conditions + default + obligations), a stable provenance hash/version, and validation results (errors/warnings). The DSL’s job is to be expressive enough to cover many domains while remaining non-executable and safe to reason about.

###Decision Ledger

The Decision Ledger is the append-only record of “what was asked, what was decided, and why,” designed for auditability, compliance, and forensic reconstruction. It consumes decision events (request received, decision made, approvals granted, action executed/blocked) and stores them in an immutable or tamper-evident form keyed by request IDs and policy hashes. Inputs include event payloads (request summary, decision, obligations, matched rule, policy hash, timestamps, actor identity, tenant info) and optionally cryptographic signing material if tamper-evidence is required. Outputs include queryable audit views (per request, per actor, per policy version), export artifacts, and integrity proofs (hash chains/signatures) depending on the implementation. In Beta, you have ephemeral in-memory audit events; a full ledger makes those durable and reviewable.

###Local Agent Runtime

The Local Agent Runtime is an embed-friendly execution loop that sits “next to” an agent or automation and uses the Open Core as its decision boundary before actions are carried out. It consumes proposed actions from an agent (tool calls, external API calls, state mutations), converts them into the normalized request schema, invokes the Policy Engine (locally/in-process), then routes the outcome to the correct handling path. Inputs include agent intents/actions, local context signals (risk scores, environment tags, identity, user presence), policy location/refresh rules, and adapter hooks (approval systems, notification systems, tool executors). Outputs include allowed action execution, paused workflows awaiting approvals, blocked actions with reason codes, and events submitted to the Decision Ledger. The runtime is where “policy meets execution,” but it must keep policy logic in core and side effects in adapters.

### Open Core (Beta)

- `sluicegate_core/decision_loop.py`
  - What it is: Implements the `Gate` object that callers embed. It wraps the pure evaluator with “decision loop” concerns: request IDs, audit event emission, stable messages, and the evaluate() / explain() user-facing API. This file is the interface to the core.
  - Inputs: `GateRequest`, `PolicyEngine`, optional `audit_sink` callback.
  - Outputs: 
      `evaluate()` → `GateDecision` (+ emits audit events to the sink)
      `explain()` → `ExplainResult` (pure simulation, no audit by default)

- `sluicegate_core/policy.py`
  - What it is: The deterministic evaluator over the parsed policy document. It loads policy YAML, computes a policy hash (provenance), evaluates rules (AND-only, first-match wins), and can produce an explain trace. This is the “brains” of the policy engine.
  - Inputs: Policy YAML bytes/path, and a normalized request context dict containing `actor`/`action`/`target`/`context`. Optional explain flag (or separate `explain()` method).
  - Outputs:
      `decide()` → (`Decision`, [`Obligation`], `policy_hash`)
      `explain()` → `ExplainResult` (rule + condition traces)

- `sluicegate_core/models.py`
  - What it is: The typed data contracts for the core. This file defines the shape of inputs/outputs so every adapter (demo, SDK, API, runtime) speaks the same language.
  - Inputs: None (it defines types).
  - Outputs: Dataclasses/types such as `GateRequest`, `GateDecision`, `Obligation`, and `ExplainResult`, plus trace models (`RuleTrace`, `ConditionTrace`). These are the canonical payload formats used everywhere else.

- `sluicegate_core/obligations.py`
  - What it is: The parser/normalizer for obligations declared in policy. It ensures the Policy Engine produces obligations in a consistent structured form, regardless of how they’re written in YAML. It’s also the home for obligation validation and future schema evolution.
  - Inputs: Raw obligation YAML fragments (list/dict), and optionally validation constraints.
  - Outputs: A list of `Obligation` objects (type + data). 

- `sluicegate_core/obligation_adapter.py`
  - What it is: Defines a tiny protocol/interface for code outside the core that “handles” obligations (email, Slack, ticketing, approvals, etc.).
  - Inputs: `GateRequest`, `GateDecision`
  - Outputs: None, but the Open Core itself does not invoke this automatically. Keeping it as an interface preserves purity and extensibility.

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