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
    └── frontend
        └── index.html     # Minimal UI for demoing decisions

The active demo policy is `sg-service/policies/demo-policy.yml`, evaluated by `sg-service`. The backend forwards canonical action requests to that service; it does not evaluate a separate policy file.

## Email approvals (optional)

Approval emails are sent by `sg-service`, not by the demo backend. To enable them:

1. Set `RESEND_API_KEY` in `.env` (read by `sg-service`).
2. In the Admin Console (`http://localhost:8443/admin`), open **Notification Adapters**, add a Resend adapter with your verified sender address, and use **Send test email** to verify it.
3. Under **Notification Profiles**, create a profile for `PAUSE_CREATED` that uses the adapter and lists the approver's address.

The email links to the Admin Console, where an authenticated administrator approves or rejects. Opening a link never changes approval state. Without a profile, approvals are completed in the web UI.

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
    Minion Mission Control: http://127.0.0.1:8443/health

## Demo Scenarios

Use the UI to submit a stripe.charge request:

    Amount Outcome
    100  ALLOW → executes immediately
    500  PAUSE → requires approval
    1000 BLOCK → denied by policy

Approvals can be performed directly in the UI.

## Important Notes

- Stripe execution is stubbed (no real charges)
- The service stores missions and audit events in the Compose database volume.
  The demo Audit Trail shows each event's policy decision, or a dash if none
  was recorded. The Mission status column shows the event's status and any
  available details; for non-mission events, this may be an event outcome
  rather than a mission status. For a selected request, its latest decision
  and status are shown separately above the table;
  use **Refresh Audit** to update that snapshot. Event times use the browser's
  local time zone.
- Policies can be edited live and reloaded
- This demo is intentionally minimal and auditable
- `sg_core` is built from the local monorepo source; demo containers do not install `sg-core` from PyPI
- The `demo-minion` service only acknowledges and completes no-op Missions; patching uses the separate Windows deployment package

## Request Details

The request details panel reads durable submitted values from `sg-service`, including the selected action, amount, currency, and metadata. Currency is normalized to uppercase; amount units are unchanged. Metadata cannot override the amount or currency used for policy evaluation. Missing legacy values are shown as `null`, with `payload_source` identifying any Mission-envelope fallback.

Existing requests with stored parameters display their actual amounts through the corrected reader. This does not rewrite historical audit events or infer missing amounts from an ALLOW/PAUSE/BLOCK decision. In the service's **Missions & Audit** tab, Inspect shows the same submitted request and its separately labeled current Mission state.

## DEMO and TEST Workflows

DEMO advertises only `stripe.refund` and `stripe.charge` and blocks patch requests. `DEMO-STUB-1.1.0` belongs to the `demo-stub` family. The separate `TEST-STUB-1.0.0` release belongs to `test-stub` and simulates patching only. The Windows Patching Minion remains the real patching implementation.

From the repository root, install browser dependencies once and run either suite:

```sh
npm ci --prefix sluice-demo/tests/e2e
npm exec --prefix sluice-demo/tests/e2e -- playwright install chromium
bash sluice-demo/tests/e2e/run.sh
bash sg-service/tests/integration/run.sh
```

The first runner starts a clean payment demo and exercises its browser flows. The second provisions a TEST Minion through authenticated APIs, using a separate service, keys, policy copy, temporary template catalog, and database. It exercises the admin registry, template selection, policy editing, patching simulation, and release drift. Neither runner edits the checked-in policy or uses the ordinary demo volume. Both remove their own temporary resources on exit. Set `SG_TEST_FORCE_FAILURE=true` for the TEST runner to verify failure cleanup.

Unit tests run independently with `uv run --locked --package sg-service --group dev pytest -q sg-service/tests`; they do not require a worker container. Normal service/DEMO image builds exclude TEST workers, policies, manifests, and test dependencies. The default CI workflow builds and validates both sets of artifacts.

## Upgrade an Existing DEMO Database

The new DEMO release removes patching and generic test capabilities. Registered releases remain immutable, and restarting the service does not automatically reassign an existing `DEMO-STUB-1.0.0` instance.

1. Pause new demo submissions and let outstanding Missions finish under the old worker/policy. Back up the demo database if preserving its history.
2. Stop the old DEMO worker. Build the updated service and DEMO images, then start the service using the clean demo policy and the existing database volume.
3. In **Minion Registry**, make `DEMO-STUB-1.1.0` available from `minion-registry/minions/demo_stub/minion-release.json` if it is not already listed. Development bootstrap makes the new type available, but preserves the instance's existing assignment.
4. Edit `DEMO-STUB-01` to retain only `stripe.refund` and `stripe.charge`, with target scope `stripe.refund, stripe.charge`. Remove `windows.patch.reconcile`, `demo.action`, and the old wildcard scope before assigning the narrower release.
5. Select **Assign Release** and assign `DEMO-STUB-1.1.0`. The service requires no unfinished Missions and clears the old release report.
6. Start the updated DEMO worker and confirm **MATCH** and healthy check-in before resuming submissions. Verify that a payment demo succeeds and a patch request is blocked.

Keep old release identities, Missions, and audit records for history. TEST belongs in the disposable integration stack; retire obsolete test-capable deployments explicitly. Only reset the demo database volume when its contents are disposable, and keep operational deployments separate.
