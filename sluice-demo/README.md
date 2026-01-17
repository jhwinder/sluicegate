**SluiceGate Demo**

SluiceGate is a policy-enforcing control plane for autonomous and semi-autonomous software actions.
This demo illustrates how SluiceGate sits in the execution path of sensitive operations (e.g., payments), evaluates them against explicit policies, and either allows, pauses for approval, or blocks execution.

This repository contains a local, runnable reference demo intended for product exploration, investor walkthroughs, and early customer conversations. It is not the production core engine.

**What This Demo Shows**

The demo implements an end-to-end transaction gating flow:

An external system submits an action request (e.g., stripe.charge)

SluiceGate evaluates the request against a YAML-defined policy

One of three outcomes occurs:

    ALLOW – request executes immediately

    PAUSE – request is held pending human approval

    BLOCK – request is denied outright

Approved requests execute via a connector (stubbed for safety)

This demonstrates human-in-the-loop control without removing autonomy.

**Architecture Overview**

Browser UI
   │
   ▼
SluiceGate API (FastAPI)
   │
   ├── Policy Engine (YAML)
   ├── Decision Logic (ALLOW / PAUSE / BLOCK)
   ├── Approval Workflow
   └── Connector Layer (Stripe stub)

All execution paths flow through the gate.

Repo Structure
sluicegate-demo/
  docker-compose.yml
  policies/
    policy.yml        # Human-readable policy rules
  backend/
    app/              # SluiceGate API + enforcement logic
  frontend/
    index.html        # Minimal UI for demoing decisions

**Running the Demo Locally**

<u>Prerequisites</u>

macOS

Docker Desktop (see install instructions below)

Start the demo

From inside sluicegate-demo/:

    docker compose up --build


Then open:

    UI: http://localhost:8080

    API Health: http://localhost:8000/health

    API Docs (Swagger): http://localhost:8000/docs

**Demo Scenarios**

Use the UI to submit a stripe.charge request (amounts are in cents):

    Amount	Outcome
    3000	ALLOW → executes immediately
    15000	PAUSE → requires approval
    30000	BLOCK → denied by policy

Approvals can be performed directly in the UI.

**Important Notes**

Stripe execution is stubbed (no real charges)

Data is stored in memory only

Policies can be edited live and reloaded

This demo is intentionally minimal and auditable