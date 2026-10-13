🚀 **SluiceGate is now public (v0.1.3).**
This is an early open-core release; interfaces may evolve.
Feedback welcome via GitHub Issues.

**SluiceGate**

SluiceGate is a policy-enforcing control plane for autonomous and semi-autonomous software systems.  As AI agents and automated workflows gain the ability to act—spend money, modify systems, trigger real-world effects—SluiceGate ensures that nothing executes without passing through an explicit, auditable gate.  SluiceGate sits in the execution path, not on the sidelines.

This monorepo contains the source-available `sg_core` policy library, the first-party `sg_service` application, Minion protocol/reference implementations, deployment tooling, and a runnable demo. `sg_core` remains a distinct Python distribution, but first-party builds resolve it from this repository rather than requiring a PyPI release.

**The Problem**

Autonomous systems are increasingly capable of taking meaningful actions:

* Charging customers
* Deploying infrastructure
* Modifying data or permissions
* Triggering downstream workflows
* Existing safeguards focus on:
* Model alignment
* Monitoring and alerts
* Post-hoc auditing

These approaches fail at the critical moment: execution.  Once an action is triggered, it is often too late.

**The SluiceGate Approach**

SluiceGate introduces a simple but powerful architectural shift:

All sensitive actions must pass through a policy-enforced gate before execution.
At the gate, each action is evaluated against explicit rules and context, resulting in one of three outcomes:

    ALLOW – execute immediately
    PAUSE – hold pending approval (human or system)
    BLOCK – deny outright

This enables human-in-the-loop control without eliminating autonomy.

**What SluiceGate Is (Conceptually)**

A proxy for execution, not a watcher
A control plane, not a chatbot
A decision point, not an after-the-fact monitor

It is designed to be:

* Deterministic
* Auditable
* Policy-driven
* System-agnostic

**Core Capabilities**

Policy-Driven Enforcement

* Human-readable policies (e.g., YAML)
* Deterministic evaluation
* Hot-reloadable rules
* Clear ALLOW / PAUSE / BLOCK semantics

Execution Gating

* Sits directly in front of real actions
* No execution bypass
* Explicit decision trail

Human-in-the-Loop Control

* Approvals for high-risk actions
* Supports async workflows
* Extensible to chat, email, ticketing systems

Connector Model

* Pluggable integrations (payments, infra, APIs, internal tools)
* Safe stubs for testing
* Designed for community and partner expansion

**Example Use Cases**

* AI agents initiating payments or refunds
* Automated infrastructure changes
* Autonomous customer-facing actions
* High-risk enterprise workflows
* Regulated or compliance-sensitive environments

In all cases, SluiceGate ensures that AI autonomy operates only within explicitly defined bounds.

**Repository Structure**

```text
sluice/
  open-core/              # sg_core policy library and sg_poledit
  sg-service/             # API, durable Mission queue, Minion Mission Control (see sg-service/README.md)
  minion-registry/        # protocol schemas and Minion implementations
  deployment/             # Compose and Windows deployment tooling
  sluice-demo/             # UI/BFF and local reference stack
  docs/
  planning/
```

**Development**

Use `uv` from the repository root to resolve the local workspace packages:

```sh
uv sync --all-packages
uv build --package sg-core
uv build --package sg-service
uv run --package sg-service --group dev pytest -q sg-service/tests
```

To run the local demo stack, generate development signing keys with `deployment/compose/Generate-DemoKeys.ps1`, copy `sluice-demo/.env.example` to `sluice-demo/.env`, replace the development placeholders, then run:

```sh
docker compose --env-file sluice-demo/.env -f sluice-demo/docker-compose.yml up --build
```

The demo Minion is a safe no-op; it does not patch servers or perform real payments. The Windows Server 2022 deployment scripts are under `deployment/windows/`; a complete release bundle also requires the signed Windows Minion service executable.

**Status**

SluiceGate is currently in:

* Early product definition
* Reference implementation and demos
* Architecture validation with real workflows

The current focus is on:

* Clear execution semantics
* Simple, explainable policy models
* Demonstrable value in high-risk automation scenarios

**What Comes Next**

Planned evolution includes:

* Hardened core engine
* SDK for connectors and integrations
* Enterprise deployment models
* Persistent audit and compliance features
* Policy authoring and simulation tools

**Philosophy**

SluiceGate is built on a single, non-negotiable principle:

<b>Autonomous systems should not be trusted to act without explicit, enforceable boundaries.</b>

SluiceGate provides those boundaries—clearly, transparently, and at the moment it matters most.

## License

SluiceGate Core is source-available under the SluiceGate Source-Available
License. You may inspect, modify, and evaluate the software freely for
non-commercial purposes only.

Commercial and production use requires a commercial license.
See LICENSE for details.