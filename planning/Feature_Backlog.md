# SluiceGate Feature Backlog

**Purpose:** Track the material implementation gaps found by comparing the current repository with [SluiceGate Minion Architecture & Patching Pilot Requirements](SluiceGate_Minions_Requirements.md).

**Review basis:** Source, deployment assets, docs, and tests in the `minion` branch as of 2026-10-12. This is a requirements gap review, not a claim that the system is production-ready or a security certification.

## Priority Guide

- **P0 - Pilot / operational blocker:** Resolve before enabling Windows patch execution or describing the Windows package as installable for the pilot.
- **P1 - Required pilot capability:** Required for the stated service, protocol, audit, or administration behavior, but can be completed as a separate workstream before pilot acceptance.
- **P2 - Operational hardening / open decision:** Required to make operation supportable or close an explicit open design decision; sequence with the deployment environment and pilot team.

## P0 - Pilot And Execution Blockers

### P0.1 Make the Windows service package install and run end to end

**Requirements:** Sections 3.9, 12.4, 22.4, 23.

The checked-in service host looks for `PatchingMinion.ps1` and `minion.config.json` beside the executable. The deployment bundle builder currently copies the executable and installer assets, but not the PowerShell Minion, its modules, templates, or a protected configuration. The installer does not provision those files. Its service command line supplies `--config`, `--minion-id`, and `--mission-control-url`, but `Program.cs` does not parse/use those arguments; the worker instead uses fixed adjacent paths. As built, the package does not establish a complete working Minion installation.

**Acceptance criteria:**

- Bundle the versioned PowerShell runtime, Patching Minion modules, protocol/schema assets required at runtime, and non-secret configuration template in a predictable layout.
- Define one configuration contract and make the installer, Windows host, and PowerShell runtime agree on its path and values.
- Keep API keys and private keys out of command-line arguments and ordinary package defaults; provision protected configuration using a documented mechanism and restrictive ACLs.
- Ensure service startup fails visibly and reports an unhealthy state when runtime/configuration is missing instead of sleeping indefinitely in standby.
- Exercise install, service start, check-in, Mission claim, controlled test execution, upgrade, restart, and uninstall on Windows Server 2022.

### P0.2 Enforce safe, constrained patch execution

**Requirements:** Sections 3.5, 10, 15 steps 7-9, 17.14, 19.4.

`PatchingEngine.psm1` interpolates catalog `install_command` into `cmd.exe /c`; this is an unrestricted shell execution path and does not satisfy the constrained process requirement. Its `WaitForExit(timeout)` result is ignored, so timeout is not reliably enforced or reported. The Python mirror's non-dry-run path reports success without staging or executing anything and must not be treated as execution validation.

**Acceptance criteria:**

- Replace shell-string execution with a narrowly specified executable/argument contract and safe `%PATCHPATH%` handling; reject unsupported executables, switches, and substitutions.
- Verify the source digest before staging, then verify the staged file on the target before execution.
- Enforce the timeout, terminate/contain timed-out processes, and return an explicit machine-readable timeout outcome.
- Capture bounded output and exit status; clean up only the operation's own staging directory/files on both success and failure.
- Keep Python logic as a test/reference implementation or clearly separate it from the production Windows execution path; never return success for work that was not performed.
- Add Windows integration tests using a harmless test installer and negative tests for shell injection, invalid paths, hash mismatch, timeout, and cleanup.

### P0.3 Apply Mission constraints to WSUS updates and target scope

**Requirements:** Sections 3.5, 12.2, 15 steps 5-6, 19.4.

The WSUS path currently installs all downloaded software updates returned by WUA. It does not enforce allowed patch types, maintenance window, or reboot constraints; `AllowReboot` is not used to govern installation/reboot behavior. The target mapping/resolution also does not currently verify the configured pilot server-group boundary independently of the signed target list.

**Acceptance criteria:**

- Define which WUA metadata maps to the Mission's allowed patch types and source constraints; fail closed when metadata cannot be classified.
- Enforce the signed reboot and maintenance-window constraints before installation and before any reboot.
- Keep the server list restricted to the policy-authorized Mission targets and validate it against the configured pilot scope.
- Test allowed, filtered, unknown-metadata, disallowed-source, reboot-required, and out-of-scope cases against a controlled WSUS test environment.

### P0.4 Repair Mission claim recovery and Minion resume behavior

**Requirements:** Sections 3.1.2, 3.3, 8, 10, 11, 15 step 10, 19.2, 19.4.

SQLite persistence preserves queued Missions, but claiming a Mission changes it to `CLAIMED` without a lease, heartbeat, timeout, or requeue/recovery policy. A service/Minion restart after claim can strand the Mission. The Windows worker currently performs a single pass and sleeps for a fixed hour; no durable local execution/resume state is demonstrated.

**Acceptance criteria:**

- Add claim leases/heartbeats and deterministic recovery for abandoned claims, without allowing concurrent duplicate execution.
- Define cancellation, expiry, max attempts, retry interval, per-attempt timeout, and overall timeout behavior from Mission execution parameters.
- Persist Minion-side in-progress state needed to report after service/host restart or authorized reboot; revalidate expiry/cancellation before resuming target work.
- Report state transitions promptly, independent of idle poll interval; make polling/backoff configurable and actually honor configuration.
- Add restart/crash/reboot tests covering before claim, after claim, during execution, and before result submission.

### P0.5 Implement service-owned email notification delivery

**Requirements:** Sections 2.6, 3.7, 3.10, 19.6.

The demo BFF directly invokes its Resend approval adapter after a PAUSE response. The requirements assign SluiceGate notification selection and delivery to `sg_service`. The service currently has mock/webhook plumbing but no email sender; webhook delivery outcomes are not reliably checked before being marked delivered. This is required for the pilot's approval notifications, but email remains a Notification Adapter, not a Minion.

`sg_service` shall support two selectable email-provider configurations: **Resend**, authenticated by an API key, or **SMTP** through an on-premises Microsoft Exchange server. Provider credentials and secrets must be held in service-side protected configuration/secret storage, not in profiles or Agent/Minion data. Recipient references and event selection remain service-managed.

**Acceptance criteria:**

- Add a service-owned Resend adapter configured with a secret `RESEND_API_KEY`, sender identity, and service-managed recipients.
- Add a service-owned SMTP adapter configured with Exchange hostname, port, TLS mode, sender identity, and the authentication mode required by the Exchange deployment; any SMTP username/password must come from protected secret storage. Support approved relay/no-auth configurations where Exchange policy permits them.
- Make provider selection explicit per adapter/profile and validate required configuration at creation/startup without exposing secret values in the Admin UI or logs.
- Move demo approval email invocation behind a notification event handled by `sg_service`; keep the BFF as a client and remove its direct notification side effect.
- Require explicit authenticated approval/rejection confirmation; email delivery or link fetch must not itself change approval state.
- Check provider response/SMTP status, persist accurate delivery outcomes, and implement bounded retries/idempotency according to the selected policy.
- Test both provider modes, absent/invalid configuration, Exchange TLS/authentication failures, Resend errors/timeouts, retries, duplicate events, PAUSE notification, and authenticated approval.

An Email Minion is not required for approval/operations notification. It is only relevant in the future if sending email is itself a policy-controlled target-system action, as described in requirement Section 3.7.1 and explicitly deferred in Section 23.

### P0.6 Provide authenticated TLS for Minion Mission Control

**Requirements:** Sections 3.9, 8, 8.1, 17, 22.5.

The Windows Minion examples use an HTTPS endpoint, but the current service container runs plain HTTP and the Compose stack publishes that HTTP port. API-key authentication and signed envelopes do not replace transport confidentiality/integrity. A self-signed certificate is acceptable for this deployment if the Minion explicitly trusts the provisioned certificate (or pinned public-key/fingerprint) and validates that it is connecting to the intended SluiceGate host.

**Acceptance criteria:**

- Support certificate provisioning for a self-signed server certificate and define protected storage, renewal/rotation, and distribution of its trust anchor to the Minion.
- Terminate TLS at a documented trusted endpoint or configure the service itself for TLS; ensure the Minion validates the certificate/identity and does not fall back to insecure certificate bypass.
- Keep plaintext HTTP limited to isolated local development; production and pilot API keys must not traverse unprotected network connections.
- Test trusted self-signed connection success, hostname/fingerprint mismatch, expired certificate, and untrusted certificate rejection.

### P0.7 Make patch capabilities truthful and prevent false success

**Requirements:** Sections 3.5, 8.4, 10, 15, 19.4.

This is serious because a capability is the Minion's advertised contract: SluiceGate may authorize and issue a Mission for an advertised operation believing it can be performed, while the worker's dispatch falls through and fails only after claim. `PatchingMinion.ps1` advertises `windows.patch.inspect` and `windows.patch.install`, but implements only reconcile, discover, and status. Separately, the Python mirror's non-dry-run reconciliation returns success-shaped results without actually staging or installing anything. That can make tests or callers mistake a simulation for a real patch operation. Together these gaps make capability discovery and reported outcomes unreliable; until fixed, unsupported operations must not be advertised and the Python mirror must clearly refuse execution or identify itself as simulation-only.

**Acceptance criteria:**

- Immediately remove unsupported capabilities from the Minion's advertised set until their handlers exist; test that routing cannot issue a Mission for an unimplemented capability.
- Implement `inspect` and `install` only with narrow, typed parameters and the same policy-authorized target, approved-source, hash, and constrained-execution safeguards as reconcile.
- Make the Python mirror reject non-dry-run execution with a clear unsupported-execution error, or implement actual execution through the same reviewed safe contract; never return success for work it did not perform.
- Return explicit no-op reasons for empty qualifying sets and preserve per-target/per-patch partial results.
- Enforce result schema, bounded output, and terminal transition rules; do not report success for skipped/failed required work.
- Ensure every Minion status/result update is retried safely and correlated with the Mission.

### P0.8 Retarget the Windows Minion Service to .NET 10 LTS

**Requirements:** Sections 3.9, 12.4, 22.4.

The checked-in Windows Service currently targets .NET 8, whose support ends on November 10, 2026. The deployment target under consideration is Windows Server 2019, which is supported by .NET 10. Move the service to the supported .NET 10 LTS runtime before deployment so the pilot does not begin on a runtime immediately reaching end of support.

**Acceptance criteria:**

- Change the service target framework to `net10.0` and confirm its Windows Service dependencies support that target.
- Rebuild and check in the framework-dependent Windows x64 executable; do not bundle the .NET runtime.
- Update Windows deployment and build documentation to require the .NET 10 x64 Runtime instead of .NET 8.
- Build and run the service on Windows Server 2019 with the supported .NET 10 x64 Runtime installed.
- Confirm service startup, PowerShell worker launch, Event Log behavior, and clean stop on the target OS.

## P1 - Required Service, Protocol, And Audit Work

### P1.1 Complete transaction and administrative audit history

**Requirements:** Sections 3.1.2, 6, 8.4, 11, 17.16-17.17, 18.3, 19.7.

The service durably stores Mission rows, Minion-submitted status/result events, approval/rejection events, and notification deliveries. This is useful persistence, but there is no complete append-only transaction history for request receipt, policy decision (including BLOCK before dispatch), routing, claim/dispatch, signature verification outcome, administrative mutations, and final state. The current operator detail endpoint returns a Mission summary rather than the event chain and execution detail required for reconstruction.

**Acceptance criteria:**

- Persist typed, correlated lifecycle events for authenticated request, normalized action, policy decision/hash, PAUSE/approval evidence, routing, Mission creation/signature, claim/dispatch attempts, Minion status, result/signature verification, and terminal transaction outcome.
- Record actor identity and timestamp for credential/Agent/Minion/notification/policy administrative changes without logging secrets.
- Derive approver identity from authenticated administrative credentials; do not treat the caller-supplied `approver` field as authoritative audit evidence.
- Persist signature verification outcome and enough signed result/envelope data to support later authorized audit.
- Add an authorized event-history API/UI with search/filter by request, transaction, Mission, Agent, Minion, status, and time.
- Test that BLOCK, PAUSE, approval re-evaluation, failed signature, duplicate event, administrative change, and terminal success/failure are reconstructable after service restart.
- Define retention, backup/restore, access controls, and tamper-resistance appropriate to the pilot; SQLite persistence alone is not tamper-resistant audit storage.

### P1.2 Make deduplication atomic under concurrent requests

**Requirements:** Sections 3.1.2, 5.5, 19.2, 22.8.

Both request paths search for equivalent open work before creating a Mission, but the check and insert are not one atomic operation and there is no unique idempotency/equivalence constraint. Sequential duplicates are tested; concurrent duplicates can create more than one Mission.

**Acceptance criteria:**

- Canonicalize the authenticated Agent, capability, target, and parameters into a stable equivalence key.
- Enforce uniqueness transactionally for open work, including concurrent submissions and multiple service workers.
- Preserve intended behavior when an equivalent request is terminal, policy changes, or an explicit idempotency key is reused.
- Add concurrency tests proving that simultaneous equivalent requests produce exactly one open Mission.

### P1.3 Use the Mission schema and harden protocol/replay validation

**Requirements:** Sections 8.1, 8.3-8.4, 9.4, 17.4-17.8, 19.3.

The JSON Schema is present but is not integrated into service/runtime validation. The PowerShell runtime checks several fields, but does not require all schema-required fields before use; its nonce file check/add sequence is not atomic and evicts older values, allowing a sufficiently old still-valid Mission nonce to be replayed. Service tests verify a valid signed result, but do not establish invalid/expired/replayed Mission rejection by the actual PowerShell runtime. Result verification is performed before accepting a result, but the verification outcome is not separately audited.

**Acceptance criteria:**

- Validate Mission and result payloads against a versioned schema at service and Minion boundaries; reject unknown/malformed required fields before execution.
- Define and validate the schema for generic action Missions as well as patch Missions, and add a versioned Mission Result schema; the current Mission schema is patch-specific.
- Sign progress/status event payloads as required by the protocol, or document and approve an explicit authenticated-transport-only exception.
- Make nonce consumption durable and atomic, with retention at least through the maximum Mission validity/replay window; do not evict unexpired replay records.
- Require valid expiry, intended Minion, capability, signature, and nonce before accepting work.
- Add cross-language canonicalization/signature test vectors shared by Python and PowerShell.
- Test tampered signature, wrong Minion, unsupported capability/version, malformed schema, expired Mission, duplicate nonce, duplicate event, invalid result signature, and key revocation.

### P1.4 Enforce deterministic Minion routing eligibility and scope

**Requirements:** Sections 3.3, 7, 19.3.

`resolve_minion()` selects on enabled state, environment, and capability, but does not use target/scope metadata despite accepting those inputs. The `PATCH_MINION_ID` fallback can assign work when no registered eligible Minion matches; this can route to a disabled, unregistered, or otherwise ineligible runtime.

**Acceptance criteria:**

- Apply explicit scope matching for target/environment/capability and any configured health/staleness policy.
- Remove implicit fallback routing from production mode; allow development fallback only through an explicit development configuration with visible audit.
- Persist the routing decision and reason, and fail closed when no eligible Minion exists.
- Test enabled/disabled, stale, capability mismatch, environment mismatch, scope mismatch, and fallback-disabled behavior.

### P1.5 Complete the operator registry and audit surface

**Requirements:** Sections 3.2-3.3, 18.1-18.4.

The UI provides useful core Agent/Minion/Mission/notification workflows, but lacks a complete transaction event view, key fingerprints/status/lifecycle presentation, approved package hash/version registration, and health/staleness visibility. Some service-side metadata exists without a corresponding operator workflow.

**Acceptance criteria:**

- Show Minion key fingerprint, key lifecycle, package/version/hash approval, last contact/health, capabilities, scope, and recent Mission history.
- Show Agent key status/rotation/revocation, rate limits, last use, and auditable enable/disable changes.
- Provide searchable transaction/audit details as described in P1.1.
- Validate inputs and avoid displaying reusable secrets after their one-time issuance response.

## P2 - Deployment And Operational Readiness

### P2.1 Finish Windows install, upgrade, and uninstall safeguards

**Requirements:** Sections 3.9, 22.4, 23.

Beyond the missing runtime payload/configuration tracked in P0.1, the scripts need end-to-end validation on the target platform. The installer expects pre-provisioned files under `InstallRoot` before it creates/copies into that directory. The uninstall script removes the Docker container but intentionally preserves the named SQLite volume; backup/retention behavior should be explicit. The bundle hash manifest is generated but the installer does not validate it.

**Acceptance criteria:**

- Validate prerequisites and create/copy directories in a safe order without overwriting secrets during upgrades.
- Verify artifact hashes before install and document what is signed versus only hashed; keep signature bypass restricted to explicit development/lab use.
- Preserve/export the SQLite volume and required Minion state on uninstall unless an explicit destructive option is selected.
- Add idempotent install/upgrade/uninstall tests or scripted validation on clean Windows Server 2022 snapshots.
- Verify gMSA/service-logon setup, PowerShell edition/runtime, Docker Engine mode/support, local port binding, firewall, and target permissions with the deployment environment.

### P2.2 Secure bootstrap and administration operations

**Requirements:** Sections 3.1.2, 3.2-3.3, 17.17, 18.1-18.3.

The service uses bearer API keys and a bootstrap admin key; production TLS, operator authentication integration, least-privilege administrative roles, and durable auditing of administrative actions are not complete. The pilot allows a shared server-authenticated admin boundary, so a full application RBAC model is not required for the initial pilot, but the deployed authentication boundary must be explicit and protected.

**Acceptance criteria:**

- Define how human operators authenticate to the admin UI/API in the Windows deployment and protect credentials in transit.
- Enforce one-time bootstrap behavior and document removal/rotation; avoid long-lived shared bootstrap credentials.
- Validate key rotation/revocation and failure recovery, with audit events for each administrative mutation.
- Do not log bearer tokens, signing keys, or patch repository credentials.

### P2.3 Establish deployment observability and support procedures

**Requirements:** Sections 3.9, 11, 12.4, 16, 22.6, 22.15.

The service has `/health` and database-backed Mission state, and the Windows host emits standard .NET logs. Operational health checks, stale-Minion detection/alerting, log retention/export, database backup/restore, and documented recovery procedures remain incomplete.

**Acceptance criteria:**

- Provide readiness checks for database, policy, signing key, and required service dependencies; distinguish readiness from process liveness.
- Configure Windows Event Log and container log retention/collection, with correlation IDs and secret redaction.
- Define SQLite backup/restore and schema migration behavior; exercise recovery from a valid backup.
- Configure stale-Minion/long-running-Mission detection and an operator-visible remediation path.
- Define and test Mission/event/notification retention and cleanup policies.

### P2.4 Support URI-based patch package sources

**Requirements:** Sections 3.5, Patching Catalog Contract, and 15 steps 7-8 (extend the current UNC-only source contract).

The patch catalog currently assumes `patch_path` names a local or UNC file that the Minion can read directly. Add support for HTTPS and S3 object locations as alternatives, while keeping UNC paths working for existing deployments. The Minion should resolve each approved source to a controlled local cache file, verify the catalog SHA-256 against the fetched bytes, and only then stage that verified file to the target. Source URIs identify content locations; they must not carry reusable credentials or bypass source policy.

**Acceptance criteria:**

- Define accepted `patch_path` forms and parsing rules for UNC, HTTPS, and S3; reject unsupported schemes and malformed locations.
- Add a source resolver that downloads/copies packages into a Minion-controlled cache, enforces size/time limits, handles partial downloads safely, and avoids treating an incomplete cache file as valid.
- Restrict HTTPS hosts and S3 buckets/prefixes to deployment-approved allowlists; validate TLS certificates and reject unapproved redirects or endpoints.
- Obtain S3/HTTPS credentials only from protected Minion host configuration or the platform's supported workload identity; never embed credentials, bearer tokens, or signed temporary URLs in catalog rows, Missions, or logs.
- Verify SHA-256 after fetching and before any remote staging; do not stage or execute on mismatch, fetch failure, or policy/source validation failure.
- Keep UNC behavior compatible and test UNC, successful HTTPS/S3 downloads, expired/unavailable credentials, untrusted TLS, redirects, oversized/partial downloads, digest mismatch, and cache cleanup.
- Update the catalog contract, configuration documentation, and Agent publishing workflow to describe each supported backend without making the Minion responsible for discovering or choosing alternate patch sources.

## Explicitly Deferred / Not Backlog Items

Do not treat the following as missing initial-pilot features unless scope changes: automated Minion generation/spawning, intelligent multi-Minion load balancing, a generalized AI planner, an Email Minion for email as a controlled action, broad enterprise rollout, SQL catalog backend, or production deployment beyond the scoped pilot. Approval/operational email is a service-owned Notification Adapter and is covered by P0.5. These are explicitly deferred or future capabilities in Sections 3.5, 3.7, 23, and 22.

## Validation Snapshot

- `uv run --all-packages pytest -q`: **13 passed**.
- The suite covers service/API flows, registry basics, approval/re-evaluation, notification profile/delivery records, and Python patch-selection logic.
- It does not execute the PowerShell Minion, perform real Windows patch installation, exercise Windows service install/upgrade/uninstall, or establish TLS behavior on Windows Server 2022.
- `deployment/windows/MinionHost/Program.cs` has no reported editor diagnostics in the reviewed workspace.
