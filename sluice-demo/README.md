**SluiceGate Demo**

SluiceGate is a policy-enforcing control plane for autonomous and semi-autonomous software actions.
This demo illustrates how SluiceGate sits in the execution path of sensitive operations (e.g., payments), evaluates them against explicit policies, and either allows, pauses for approval, or blocks execution.

This repository contains a local, runnable reference demo intended for product exploration, investor walkthroughs, and early customer conversations. It is not the production core engine.

**What This Demo Shows**

The demo implements an end-to-end transaction gating flow:

1. An external system submits an action request (e.g., stripe.charge)
2. SluiceGate evaluates the request against a YAML-defined policy
3. One of three outcomes occurs:

        ALLOW – request executes immediately
        PAUSE – request is held pending human approval
        BLOCK – request is denied outright

Approved requests execute via a connector (stubbed for safety).

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

**Repo Structure**

    sluicegate-demo/
      docker-compose.yml
      policies/
        policy.yml        # Human-readable policy rules
      backend/
        app/              # SluiceGate API + enforcement logic
      frontend/
        index.html        # Minimal UI for demoing decisions

## Email approvals (optional)

The demo supports human-in-the-loop approvals via email using Resend.

To enable approval emails, set the following environment variables in `docker-compose.yml`:

- `RESEND_API_KEY` – your Resend API key
- `APPROVER_EMAIL` – email address that will receive approval requests
- `RESEND_FROM` – verified sender address in Resend (optional)

If these variables are not set, the demo will still work, however
approvals must be completed via the web UI instead of via email.

**Running the Demo Locally**

<ins>Prerequisites</ins>

macOS

Docker Desktop

<ins>Start the demo</ins>

From open-core:

    docker compose -f sluice-demo/docker-compose.yml build --no-cache backend
    docker compose -f sluice-demo/docker-compose.yml up --force-recreate

Then open:

    UI: http://localhost:8080
    API Health: http://localhost:8000/health
    API Docs (Swagger): http://localhost:8000/docs

**Demo Scenarios**

Use the UI to submit a stripe.charge request:

    Amount	Outcome
    100     ALLOW → executes immediately
    500   	PAUSE → requires approval
    1000  	BLOCK → denied by policy

Approvals can be performed directly in the UI.

**Important Notes**

* Stripe execution is stubbed (no real charges)
* Data/auditing is stored in memory only
* Policies can be edited live and reloaded
* This demo is intentionally minimal and auditable