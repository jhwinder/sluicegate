# SluiceGate Open Core

This directory contains the SluiceGate Open Core: a pure, deterministic policy engine for governing actions taken by autonomous systems (AI agents, services, workflows, humans-in-the-loop).

The Open Core is intentionally side-effect free. It evaluates requests against policy, returns decisions and obligations, and emits audit events — but it does not execute actions, send emails, or integrate with vendors.

Those behaviors belong in adapters (demos, SDKs, enterprise deployments).

----------------------------------------------------------------

WHAT THE OPEN CORE IS

- A policy evaluation engine
- A decision point for agent actions
- A governance control plane, not an approval workflow
- A library, not a service

Given a request, the core returns:
- a decision: ALLOW, PAUSE, or BLOCK
- a policy provenance hash
- zero or more structured obligations (e.g. require_approval)
- optional audit events (via a callback)

----------------------------------------------------------------

WHAT THE OPEN CORE IS NOT

- Not an email system
- Not a workflow engine
- Not a UI
- Not tied to HTTP, REST, or any transport
- Not opinionated about how obligations are enforced

Those concerns are deliberately kept outside the core.

----------------------------------------------------------------

REPOSITORY STRUCTURE

open-core/
├── pyproject.toml
├── README.md
├── src/
│   └── sg_core/
│       ├── __init__.py
│       ├── adapters.py
│       ├── decision_loop.py
│       ├── models.py
│       ├── obligation_adapter.py
│       ├── pause_api.py
│       ├── policy.py
│       └── py.typed
├── examples/
│   └── run_local_decision.py
├── policies/
│   └── example-policy.yml
└── tests/            (future pytest tests)

----------------------------------------------------------------

PUBLIC API (BETA-STABLE)

The primary entrypoint is the Gate object.

Import pattern:

  from sg_core import Gate, PolicyEngine, GateRequest

Key methods:

- Gate.evaluate(request)
    Returns a GateDecision (decision + obligations + policy hash)

- Gate.explain(request)
    Returns an ExplainResult (decision + obligations + full trace)
    This is a pure simulation with no side effects.

The core never performs execution or notification.

----------------------------------------------------------------

DEVELOPMENT SETUP (USING UV)

Prerequisites:
- Python 3.11 or newer
- uv installed (https://github.com/astral-sh/uv)

Setup steps:

  cd open-core
  uv sync
  uv pip install -e .

Sanity check:

  uv run python -c "import sg_core; print('sg_core import ok')"

----------------------------------------------------------------

RUNNING THE EXAMPLE HARNESS

The example harness runs a set of policy test cases entirely in-process.

It demonstrates:
- rule matching
- ALLOW vs PAUSE decisions
- default fallback behavior
- obligation generation
- policy provenance hashing
- explain / trace output per request

Run it with:

  uv run -m examples.run_local_decision

The harness prints both the decision and the explain trace for each test.

----------------------------------------------------------------

POLICY DSL

Policies are defined as YAML files under the policies/ directory.

They operate over four top-level request domains:
- actor
- action
- target
- context

Rules are evaluated top-to-bottom.
All conditions within a rule must match (AND-only in Beta).
The first matching rule wins; otherwise the policy default applies.

See docs/Policy_DSL.md at the repo root for the full DSL specification.

----------------------------------------------------------------

EXPLAIN MODE (POLICY SIMULATION)

Gate.explain() provides a pure, side-effect-free evaluation trace, including:
- which rule matched (or default)
- which conditions passed or failed
- actual vs expected values
- resulting decision and obligations

Explain mode is intended for:
- policy authoring
- debugging
- audit review
- UI visualization
- dry-run simulations

Explain mode does not emit audit events or execute anything.

----------------------------------------------------------------

OBLIGATIONS AND ADAPTERS

The Open Core returns obligations as data:

  Obligation(type="require_approval", data={...})

How those obligations are enforced is left to adapters.

A minimal adapter interface (ObligationAdapter) is defined, but the core never invokes it automatically. This preserves purity and extensibility.

----------------------------------------------------------------

AGENT ADAPTERS / WEBSOCKETS / FASTAPI ENDPOINTS

-PollingPauseAdapter (sync)
-AsyncPollingPauseAdapter (async)

They implement the “if PAUSE → wait → resume with ALLOW or BLOCK” pattern in one reusable component (so PAUSE is not treated as an error.)


“Wait” without polling: SSE + WebSocket

-SSE: GET /pause/{token}/events
Streams event: pause messages with JSON payloads; auto-closes when resolved/expired.

-WebSocket: WS /ws/pause/{token}
Sends initial state then pushes updates; closes on resolved/expired.

FastAPI endpoints

`GET /pause/{token}` → returns { pause: ..., decision: ... }
`GET /pause/{token}/decision` → returns the current decision (PAUSE|ALLOW|BLOCK)
`POST /pause/{token}/approve` body: { "approver": "...", "comment": "..." }
`POST /pause/{token}/deny` body: { "approver": "...", "comment": "..." }

----------------------------------------------------------------

DESIGN PRINCIPLES

- Deterministic
- Declarative
- Transport-agnostic
- Side-effect free
- Explicit separation of decision and execution
- Extensible without modifying core logic

----------------------------------------------------------------

LICENSE

See LICENSE.md at the repo root.

----------------------------------------------------------------

STATUS

Beta.

The core API and Policy DSL are considered stable for experimentation and early adoption. Future versions may add features in a backward-compatible manner.
