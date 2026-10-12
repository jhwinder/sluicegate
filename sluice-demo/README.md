## SluiceGate Demo

SluiceGate is a policy-enforcing control plane for autonomous and
semi-autonomous software actions. This demo illustrates how SluiceGate
sits in the execution path of sensitive operations (e.g., payments),
evaluates them against explicit policies, and either allows, pauses for
approval, or blocks execution.

This repository contains a local, runnable reference demo intended for
product exploration, investor walkthroughs, and early customer
conversations. It is not the production core engine.

## What This Demo Shows

The demo implements an end-to-end transaction gating flow:

1. An external system submits an action request (e.g., stripe.charge)
2. SluiceGate evaluates the request against a YAML-defined policy
3. One of three outcomes occurs:

        ALLOW – request executes immediately
        PAUSE – request is held pending human approval
        BLOCK – request is denied outright

Approved requests execute via a connector (stubbed for safety).

This demonstrates human-in-the-loop control without removing autonomy.

## Architecture Overview

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

## Repo Top-level Structure

    sluice-demo
    ├── backend
    │   └── app/           # SluiceGate API + enforcement logic
    ├── docker-compose.yml
    ├── frontend
    │   └── index.html     # Minimal UI for demoing decisions
    └── policies
        └── policy.yml     # Human-readable policy rules

## Email approvals (optional)

The demo supports human-in-the-loop approvals via email using Resend.

To enable approval emails, set the following environment variables in
`docker-compose.yml`:

- `RESEND_API_KEY` – your Resend API key
- `APPROVER_EMAIL` – email address that will receive approval requests
- `RESEND_FROM` – verified sender address in Resend (optional)

If these variables are not set, the demo will still work, however
approvals must be completed via the web UI instead of via email.

## Running the Demo Locally

### Prerequisites

- macOS
- Docker Desktop

### Start the demo

The local stack runs the legacy demo UI/BFF alongside `sg_service` and a safe no-op demo Minion. It does not access Windows servers or install patches. The demo Minion claims Missions and reports signed results, but intentionally performs no external action.

From the repository root, create the development signing keys and local environment file:

```powershell
./deployment/compose/Generate-DemoKeys.ps1
Copy-Item sluice-demo/.env.example sluice-demo/.env
```

Edit `sluice-demo/.env` and replace all three placeholder API keys with unique local-only values. Then start the stack:

```sh
docker compose --env-file sluice-demo/.env -f sluice-demo/docker-compose.yml up --build
```

Then open:

    UI: http://localhost:8080
    API Health: http://localhost:8000/health
    API Docs (Swagger): http://localhost:8000/docs
    Minion Central Command: http://127.0.0.1:8443/health

## Demo Scenarios

Use the UI to submit a stripe.charge request:

    Amount Outcome
    100  ALLOW → executes immediately
    500  PAUSE → requires approval
    1000 BLOCK → denied by policy

Approvals can be performed directly in the UI.

## Important Notes

- Stripe execution is stubbed (no real charges)
- Data/auditing is stored in memory only
- Policies can be edited live and reloaded
- This demo is intentionally minimal and auditable
- `sg_core` is built from the local monorepo source; demo containers do not install `sg-core` from PyPI
- The `demo-minion` service only acknowledges and completes no-op Missions; patching uses the separate Windows deployment package
