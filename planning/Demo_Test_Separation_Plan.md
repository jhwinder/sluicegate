# DEMO and TEST Separation, Policy Templates, and Request Inspection Plan

**Status:** PENDING — planning complete; implementation not started.
**Related backlog items:** [Backlog 1.7–1.10](Backlog.md)

## Objective

Separate the customer-facing DEMO Minion and policy from automated TEST collateral. Keep both available to the normal development build and CI workflow, while loading TEST artifacts only when a test run needs them. Ordinary service and demo container startup must not load, register, or launch TEST collateral.

DEMO remains a safe payment/action walkthrough. TEST owns simulated patching, test hosts, and automated scenario setup. The real Windows Patching Minion remains a separate implementation.

Also add a template selector to the Policies tab so creating a policy prompts the administrator to choose a template before opening its editor. Show this choice even while Patching Policy is the only available template, and support additional YAML templates in the future.

Expand Missions & Audit **Inspect** to show the submitted request, including action, target, parameters, and relevant context. Correct the demo request-detail response so each trial reports its actual amount, currency, action, and metadata instead of fabricated defaults.

## Current Repository Findings

| Area | Current behavior | Required change |
| --- | --- | --- |
| `minion-registry/minions/demo_stub/` | A safe no-op worker whose release advertises `windows.patch.reconcile`, `demo.action`, `stripe.refund`, and `stripe.charge`. | Remove patching from DEMO and provide an independently identified TEST worker. |
| `sg-service/policies/demo-policy.yml` | Combines Stripe rules with patching rules for `patch-test.example.gov` and `patch-reboot-test.example.gov`. | Keep demo rules here; move patching test rules to a test-owned YAML file. |
| `sg-service/src/sg_service/mission_control.py` | `SG_DEV_BOOTSTRAP=true` provisions `DEMO-STUB-01` from a manifest and gives it wildcard target scope. | Keep development bootstrap specific to DEMO; provision TEST from the test harness. Review DEMO scope after removing patching capability. |
| `sg-service/Dockerfile` | Copies the DEMO release manifest into the service image. It does not copy a DEMO worker or the service test directory into the final image. | Preserve that packaging boundary and exclude the new TEST artifacts from the final service image. |
| `sluice-demo/docker-compose.yml` | Starts the service, DEMO Minion, backend, and frontend; activates the mixed demo policy. | Start only the clean DEMO stack with its own active policy. |
| `sluice-demo/tests/e2e/` | Uses the demo Compose stack for payment flows, registry lifecycle, patching-policy editing, patch requests, and release-drift checks. | Retain real DEMO smoke coverage and move broader test scenarios to an isolated TEST stack. |
| `sg-service/tests/` | Most tests already create temporary policies, keys, and registrations. `test_mission_control_tls.py` imports the DEMO worker directly. | Extend existing test helpers; keep focused DEMO worker tests and add equivalent TEST worker coverage. |
| `sluice-demo/policies/policy.yml` | A second, older policy mounted into the backend via `POLICY_PATH`; the current backend submits actions to `sg-service` rather than evaluating that file. | Confirm references and remove the obsolete mount/file, or document any remaining distinct use. |
| Policies tab in `sg-service/src/sg_service/static/admin.html` | The creation action is currently labeled **Create New** and calls `openPolicyWizard()` directly, opening the patching wizard. **Load YAML** separately imports a local file. | Insert an explicit template-selection step before creating a policy; preserve local YAML import. |
| Missions & Audit **Inspect** | Mission inspection displays `/admin/v1/requests/{request_id}`, which returns status and identifiers but omits request content. Audit inspection displays only the selected event. | Add submitted request details to the authenticated detail API and both inspection flows. |
| Request persistence in `mission_control.py` | Action and patch submission save the validated request in `missions.raw_request`; the stored Mission envelope also contains capability, targets, and execution parameters. | Read existing persisted data, preserving the distinction between submitted input and policy-resolved execution details. |
| `sluice-demo/backend/app/main.py` | `get_request()` hard-codes `action: stripe.refund`, `amount: 0`, `currency: USD`, and empty metadata. Submission sends real parameters to the service. | Project actual stored request values into the demo detail response. Check metadata merging so metadata cannot overwrite the amount/currency submitted for policy evaluation. |

The service currently selects one active policy through `SG_POLICY_PATH`. Building both sets of artifacts does not mean evaluating both policies in one service instance. DEMO and TEST should use separate service instances, databases, credentials, and policy mounts.

## Target Layout and Runtime Contract

Proposed paths retain the existing DEMO locations to limit disruption:

```text
minion-registry/minions/
  demo_stub/                         # DEMO worker, Dockerfile, release manifest
  test_stub/                         # TEST worker, Dockerfile, release manifest
sg-service/
  policies/demo-policy.yml           # Active policy for the DEMO stack
  tests/
    minion_helpers.py                # Test-only provisioning helpers
    fixtures/policies/test-policy.yml
    integration/                    # TEST Compose configuration and runner
sluice-demo/tests/e2e/                # DEMO browser smoke tests
```

Use distinct release families and deployment IDs: retain the `demo-stub` family and `DEMO-STUB-01` instance; introduce a `test-stub` family and `TEST-STUB-01` instance. TEST uses independent credentials and signing keys. Removing DEMO capabilities changes immutable release metadata, so publish a new DEMO type ID and version rather than rewriting `DEMO-STUB-1.0.0`.

| Workflow | Artifacts available/built | Loaded when the service starts |
| --- | --- | --- |
| Normal service deployment | Service distributions and protocol runtime files. | Explicitly configured operational policy and existing persisted registrations; no automatic DEMO or TEST provisioning. |
| DEMO startup | Service, DEMO worker, DEMO manifest, and DEMO policy. | DEMO policy and explicitly enabled DEMO bootstrap only. |
| Unit tests | Test modules and requested fixtures from the checkout. | Temporary policy and registrations created by fixtures; no worker container required. |
| TEST integration/browser tests | Service plus TEST worker image and test policy staged for the run. | TEST policy in a disposable service instance; harness registers TEST through authenticated APIs before starting its worker. |
| Default full development/CI workflow | Build/verify DEMO and TEST artifacts and run their relevant suites. | Test processes and containers exist only for their test phases; the deliverable service image excludes TEST files and dependencies. |

An individual service image build need not also produce a TEST image. The full development workflow should cover both by default; TEST availability at build time must not create a startup dependency. Do not add a `test_stub` import, fixture search, automatic TEST catalog scan, or `SG_TEST_BOOTSTRAP` branch to the service.

## Implementation Work

### 1. Establish TEST artifacts before removing shared behavior

- [ ] Inventory the existing browser, service, TLS, release, and patching tests and assign each scenario to DEMO smoke, TEST integration, or real Windows patching coverage.
- [ ] Add `test_stub/` with its own worker configuration, Dockerfile, dependencies, release manifest, family, type ID, and instance ID.
- [ ] Move simulated patching support to TEST. Advertise only capabilities exercised by its tests; use explicit test target scope and a matching test environment in action submissions.
- [ ] Keep the TEST worker a deterministic no-op with signed status/results and release reporting. Mark its results as TEST simulation with `executed: false`; it must not install patches or perform payments.
- [ ] Add `test-policy.yml` under test fixtures with the existing patching approval, constraints, maintenance-window, and blocked-target scenarios. Retain small inline policies where a unit test needs a deliberately narrow or invalid case.
- [ ] Extend `minion-registry/release_manifest.py` to verify both DEMO and TEST manifests. Include every runtime dependency shared by their workers in the relevant release fingerprints.

**Exit condition:** TEST has an independent identity, executable artifact, policy, and reproducible release manifest, without changing ordinary startup.

### 2. Make DEMO independent of patching tests

- [ ] Remove `windows.patch.reconcile` from DEMO release metadata and keep only intentionally demonstrated actions. Audit `demo.action` usage before deciding whether to retain it.
- [ ] Remove patching rules, test hosts, patch sources, reboot settings, and maintenance windows from `demo-policy.yml`.
- [ ] Preserve the demonstrated Stripe ALLOW, PAUSE/approve, reject, and BLOCK flows with `default: BLOCK`.
- [ ] Publish the changed DEMO release under a new type ID and version, with its new fingerprint. Update bootstrap inputs and expected release values together.
- [ ] Update development bootstrap and Compose configuration so DEMO registration has only DEMO capabilities and the scope required by the demo API targets. Keep normal routing checks active; remove the obsolete DEMO `SG_PATCH_MINION_ID` setting.
- [ ] Make the service-side DEMO policy the documented authoritative demo YAML. Remove the backend's unused policy setting/mount and obsolete policy file after checking their references.

**Exit condition:** The payment demo works using DEMO alone; neither its policy nor its Minion registration authorizes patching.

### 3. Load TEST collateral just in time

- [ ] Extend test-only helpers/fixtures to create temporary databases, service and Minion keys, policy copies, agent registrations, TEST type registration, instance registration, and matching release check-in as needed.
- [ ] Clear inherited development-bootstrap configuration in fixtures and test runners so a developer's shell cannot seed DEMO into TEST.
- [ ] Configure `SG_POLICY_PATH` before creating the test service/client. Never edit the checked-in policy or a developer's active policy during a test run.
- [ ] Use function scope for mutable unit-test state. Reserve suite-scoped setup for genuinely shared immutable inputs; avoid eagerly loading fixtures for tests that do not need them.
- [ ] Provision container-based TEST instances through existing authenticated administrative APIs. Wait for a matching release report before submitting routable missions.
- [ ] Generate credentials for each run. Supply only the worker credential/key to the TEST worker; keep administrative provisioning in the harness.
- [ ] Ensure teardown runs after success, failure, or interruption, stopping workers and removing disposable volumes, policy backups, generated keys, and temporary files belonging to that run. Report incomplete cleanup.

**Exit condition:** Unit tests work without Docker or a running Minion, while worker integration tests start and provision TEST only for their own execution.

### 4. Separate browser coverage and enforce packaging boundaries

- [ ] Keep DEMO browser smoke tests on the unmodified DEMO stack: payment decisions, approval/rejection, signed no-op completion, and audit display.
- [ ] Move patching-policy editing/activation, patch request execution, test registry lifecycle, and destructive drift scenarios into the TEST integration/browser runner. Reuse the admin UI under test without activating TEST policy in a DEMO instance.
- [ ] Parameterize test assertions with the expected instance/release rather than assuming every mission completes on `DEMO-STUB-01`. Assert that TEST patch missions complete on `TEST-STUB-01` and remain simulations.
- [ ] Give TEST Compose an explicit invocation and independent project name, database volume, ports, policy directory, and secrets. Do not add TEST to ordinary DEMO startup; if any Compose file is shared, gate TEST services behind an explicit profile.
- [ ] Retain explicit file copying in runtime Docker stages and wheel package boundaries. Verify TEST workers, manifests, fixture YAML, pytest, and browser tooling do not enter the final service or DEMO worker images.
- [ ] Build or mount TEST artifacts only into the disposable TEST worker and test environment. Make sure a broad build-stage copy cannot leak them into the deliverable image.
- [ ] Update `.github/workflows/test.yml` so the standard workflow verifies/builds both Minions, runs DEMO smoke and TEST integration separately, and preserves the existing Linux/Windows application and Windows Minion coverage.

**Exit condition:** A normal DEMO or service startup has no TEST process or artifact dependency; the full development/CI workflow still exercises both sets of artifacts.

### 5. Handle existing installations and document the workflows

- [ ] Document separate commands for service deployment, DEMO startup, unit tests, TEST integration, and the full development validation workflow.
- [ ] Update `README.md`, `sg-service/README.md`, and `sluice-demo/README.md` with policy ownership, release identities, and which commands build versus start TEST.
- [ ] Change the service operator quick start to use an explicitly selected operational/starter policy rather than presenting the DEMO policy as the deployment default.
- [ ] Provide an upgrade procedure for persistent demo databases: import the new DEMO release, stop accepting new work on the old instance, finish outstanding missions, deploy the updated worker, assign compatible capabilities/release, and confirm a matching check-in before re-enabling routing.
- [ ] Do not silently mutate immutable registered releases or delete historical missions/audit records. Offer a documented reset only for disposable demo volumes; retain an explicit upgrade path for users preserving demo state.
- [ ] Explain that stopping TEST provisioning does not remove registrations from an existing database. Inspect and explicitly retire legacy test-capable DEMO registrations where necessary; leave operational deployments intact.
- [ ] Link this plan from the backlog and mark the implementation complete only after the acceptance checks pass.

### 6. Select a policy template before creating a policy

This work can proceed independently of the Minion split. The production patching-policy template remains available to administrators; it is distinct from the patching TEST policy and fixtures being isolated above.

- [ ] Change the current **Create New** entry point (the Add Policy flow) to open a **Choose policy template** dialog before any template-specific wizard or YAML content loads.
- [ ] List available templates with a readable name and short description. Initially list **Patching Policy**; require explicit selection and **Continue**, even when it is the only entry. Do not automatically open the patching wizard.
- [ ] Provide **Cancel** and keyboard-accessible selection. Canceling or closing the selector must preserve the current draft and active policy.
- [ ] Selecting **Patching Policy** and continuing opens the existing patching wizard. Preserve its rule editor, blank default-BLOCK policy generation, validation, and lossless-edit restrictions.
- [ ] Define a template catalog with stable IDs, display names, descriptions, and an editor mode. A catalog entry should reference either a supported wizard or a YAML template file, so future YAML templates can load into the generic editor without requiring a new visual wizard.
- [ ] Keep file-backed templates in an explicit application template directory, proposed as `sg-service/src/sg_service/policy_templates/`, with catalog metadata alongside them. Keep the initial patching entry backed by its existing wizard; do not require a second YAML implementation of that generator.
- [ ] Expose catalog metadata and selected file content through authenticated, read-only administrative endpoints if served by the backend. Resolve selection by catalog ID against approved template entries rather than accepting arbitrary filesystem paths. Include the catalog and approved template files in built wheels and service images.
- [ ] Make adding an ordinary YAML template a catalog-and-file change, without changing the creation button or adding a template-specific conditional to the selector. Report unknown template IDs, missing files, unsupported editor modes, and invalid YAML without replacing the current draft or falling back to Patching Policy.
- [ ] Load a selected YAML template as an editable draft only. Preserve the existing confirmation before replacing unsaved content, and apply it when wizard output or YAML content would replace the draft. Recheck for draft changes while template content is loading.
- [ ] Keep **Load YAML** as the local policy-file import path and **Edit Policy** as editing the current draft. Choosing a template does not switch `SG_POLICY_PATH`, select another active server-side policy, or activate policy content.
- [ ] Preserve explicit **Validate** and confirmed **Save and Activate**, including backups and concurrent-change protection. Generic YAML templates must remain editable even when the patching wizard cannot represent them.
- [ ] Exclude TEST fixture YAML and TEST-only templates from the normal template catalog and runtime package. A test may register a temporary additional template to exercise extensibility in an isolated test instance.
- [ ] Update the operator guide and existing browser tests to include the selector step. Add meaningful coverage for the one-template prompt, explicit selection, cancellation, unsaved-draft protection, a second file-backed template, load errors, and activation remaining separate.

**Exit condition:** Creating a policy always starts with template selection; Patching Policy still works, and a second YAML template can be added through catalog metadata and a file. Selection and loading leave the active policy unchanged until explicit activation.

### 7. Show submitted request details in Missions & Audit Inspect

This work can proceed independently of the Minion and template changes. Implement the additive request-detail API fields first; both the admin console and the demo correction in section 8 depend on them.

- [ ] Extend authenticated `GET /admin/v1/requests/{request_id}` with a structured submitted-request object sourced from `missions.raw_request`. Preserve existing response fields for current clients. Return the submitting agent and the action/capability, requested targets, parameters, and submitted context available in that stored record.
- [ ] Include separately labeled policy-resolved Mission details from the persisted envelope: authorized targets, execution parameters, obligations, policy hash/decision, and approval/rejection evidence when present. Do not merge them into the original request or imply that a queued, blocked, or simulated action executed.
- [ ] Present a readable request summary in Mission **Inspect**, including the Stripe amount and currency when present, followed by expandable structured request and Mission details. Support other actions generically and patch requests with their submitted server lists.
- [ ] For audit **Inspect**, retain the selected event's timestamps, status, actor, signature verification, and complete event details. When a request ID is present, fetch and display its submitted request alongside the event so administrators can understand what that event concerns.
- [ ] Label linked current request/Mission state separately from the historical event snapshot. Fetching current details must not change stored audit records, signed envelopes, signature-verification results, or event-time decisions.
- [ ] Handle events without request IDs and missing legacy request records without hiding the selected event. Show unavailable fields explicitly; do not substitute a zero amount, a default action, or an empty object that implies the original value is known. If envelope data is used as a legacy fallback, label its source.
- [ ] Check HTTP errors and display useful loading, not-found, and failed-fetch states. Prevent a delayed response for one inspection from overwriting a different request/event selected afterward.
- [ ] Keep full inspection data behind the existing administrator authentication and render submitted values as text/escaped JSON. Keep the low-information agent polling endpoint unchanged.
- [ ] Add service and browser coverage for Stripe requests with different amounts, a non-payment action, a patch request, BLOCK/PAUSE/ALLOW outcomes, events without linked requests, missing legacy data, and correct historical-event/current-state labeling.

**Exit condition:** An administrator can inspect a request or one of its audit events and see what was actually submitted, including its refund amount, without relying on a Mission result or reconstructing input from a status summary.

### 8. Correct DEMO request-detail values

The reported `amount: 0` is directly explained by hard-coded response values in the demo backend's `get_request()`. Repository code persists submitted action parameters in the service; no live database inspection has been performed, so historical recovery must use whatever data each stored record actually contains.

- [ ] Replace the hard-coded demo `payload` in `GET /api/requests/{request_id}` with a projection of the service's stored submitted request from section 7. Map the actual capability/action, amount, currency, and metadata consistently with submission.
- [ ] Define a lossless mapping for demo metadata through submission and retrieval. The current submission flattens metadata into parameters and spreads it after amount/currency; prevent reserved metadata keys from overriding those authoritative fields. Preserve user metadata separately where necessary and distinguish it from service-added context.
- [ ] Preserve numeric values and the existing currency/amount convention; do not introduce unit conversion as part of this fix. Preserve a genuine zero if submitted, and represent missing values as unavailable rather than inventing zero or USD. Keep `stripe.charge` and `stripe.refund` distinct.
- [ ] Populate detail responses from durable service data so refresh, request lookup, and backend/container restart show the same input values. Do not depend on browser state or an in-memory cache of the latest trial.
- [ ] Handle non-success service responses before interpreting JSON as request data. A failed lookup must not produce a successful-looking response populated with defaults.
- [ ] Ensure original request details remain visible for blocked and unassigned requests, paused requests before/after approval or rejection, and completed no-op demos.
- [ ] Test independent trials for amounts 100, 500, and 1000 across their ALLOW, PAUSE, and BLOCK paths. Assert the actual values in the service detail API, the demo detail API/UI, and the admin Mission/audit inspectors; repeat lookup after reload and restart.
- [ ] Add coverage for differing action/currency/metadata values, a genuine zero where accepted, missing legacy fields, and reserved-key collisions. Extend the DEMO smoke suite to catch the specific regression where every trial is reported as zero.
- [ ] Document that existing records with stored amounts become visible through the corrected reader without rewriting history. Do not infer missing historical amounts from policy decisions or the standard demo trial choices.

**Exit condition:** Each demo request reports its own stored input values throughout its lifecycle, and Inspect shows matching request details for the same request ID. Unknown historical values remain explicitly unavailable.

## Acceptance Checks

| Check | Expected evidence |
| --- | --- |
| Clean service startup | Starts with its configured operational policy, without access to the TEST source directory or fixtures; creates no automatic DEMO/TEST type, instance, or credential. |
| Clean DEMO startup | Only DEMO collateral is provisioned. Active policy and registered DEMO capabilities contain no `windows.patch.*` actions or patch-test hosts. |
| DEMO behavior | Amounts 100, 500, and 1000 retain ALLOW, PAUSE, and BLOCK behavior; approval/rejection and signed no-op results remain covered. |
| Separation holds | A patch request to DEMO is blocked. In TEST, approved patch scenarios route to TEST, unauthorized targets are blocked, and no external action executes. |
| Unit-test lifecycle | Tests create only the fixtures they request, use temporary state, and pass with no worker container. TEST never loads through a production import/startup path. |
| Integration lifecycle | A fresh TEST stack provisions independently, reports a matching release, passes its scenarios, and cleans up after normal and deliberately failed runs. |
| Policy isolation | DEMO and TEST use different policy copies and databases. Test policy edits and backups do not change repository files or a running developer demo. |
| Release management | Both manifests verify; DEMO uses a new immutable release identity; drift and mismatch routing protections still pass for the relevant workers. |
| Packaging | Inspect built wheels and final images for the absence of TEST runtime files, fixture policies, manifests, and test-only dependencies. Build-stage TEST availability is acceptable. |
| Existing state | A persisted DEMO deployment upgrades through the documented steps without manifest conflicts or lost mission/audit history. |
| Template selection | **Create New** first shows **Choose policy template**, including when Patching Policy is the sole entry. Explicit selection opens the chosen editor; cancel leaves the draft and active policy unchanged. |
| Template extensibility | An isolated test adds a second YAML template through catalog metadata and a file, selects it, and receives its content in the generic editor without selector code changes. TEST fixtures are absent from the ordinary catalog. |
| Template draft safety | Failed loads and declined replacement preserve the current draft. Successful loads create drafts only; validation and confirmed activation retain existing backup and concurrency protections. |
| Request inspection | Both Mission and linked audit-event **Inspect** show submitted action, target, parameters, and available context. A Stripe request displays its actual amount/currency; patch and other actions remain inspectable. |
| Event integrity | Selected audit-event details retain their original event-time values; linked current Mission state is clearly identified. Missing request context does not prevent inspecting the event. |
| DEMO input accuracy | Separate 100/500/1000 trials report their respective stored values in demo detail responses and admin inspectors, including BLOCK with `UNASSIGNED`; reload/restart preserves the values. |
| Missing values and metadata | Genuine zero remains zero, unavailable amounts are not fabricated, action/currency/metadata round-trip correctly, and metadata cannot override the submitted amount/currency used for policy evaluation. |

Run the existing application suite as the regression baseline:

```sh
uv run --locked --package sg-service --group dev pytest -q -rs sg-service/tests
uv run --locked --package sg-service --group dev python minion-registry/release_manifest.py
uv build --package sg-core
uv build --package sg-service
```

Add the DEMO smoke, TEST integration, artifact-inspection, and cleanup checks described above to the implementation's documented validation commands. Preserve the existing PowerShell and Windows-host CI checks. This planning change itself does not require executing application tests.

## Scope Limits

This work separates artifacts, setup, packaging, and tests; adds policy-template selection; and exposes accurate stored request details in admin inspection and demo reporting. It does not change the policy DSL, introduce multiple simultaneously active policies or a server-side active-policy file switcher, replace the real Windows Patching Minion, add Minion load balancing, or implement an online release catalog. Shared protocol code may be reused when useful, but neither DEMO nor the service runtime may depend on TEST code. Request inspection and the demo reporting fix must preserve historical audit records and existing Mission signatures.
