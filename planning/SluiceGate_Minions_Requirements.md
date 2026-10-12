# SluiceGate Minion Architecture & Patching Pilot Requirements

**Status:** First-cut requirements / architecture specification  
**Purpose:** Define the SluiceGate enhancements required to support policy-controlled execution through cryptographically authenticated, non-autonomous Minions, using a safe demo action stub and a Microsoft Windows patching Minion as a reference implementation. The demo's approval-notification email is an adapter, not an Email Minion.

---

## 1. Purpose and Scope

SluiceGate is intended to serve as an authoritative control plane between autonomous or agentic AI systems and consequential actions in enterprise environments. This enhancement introduces a generalized execution architecture in which external AI agents request actions from SluiceGate, SluiceGate evaluates those requests against policy, and approved actions are executed by tightly constrained **Minions**.

A Minion is a registered, minimally privileged execution component that exposes a fixed set of capabilities and performs only tasks specifically authorized by SluiceGate. A Minion does not independently interpret policy, determine whether an action should occur, or exercise delegated decision authority.

The first implementation will support a government pilot in which an AI patching agent requests Windows Server patch reconciliation. SluiceGate authorizes the target server scope and patch constraints; the Patching Minion selects qualifying OS updates and Nessus/IAVM catalog patches. The environment uses WSUS-integrated Microsoft SCCM/Configuration Manager. The initial pilot population is approximately twelve Windows servers belonging to a single team.

This specification intentionally defines a generic SluiceGate/Minion architecture first and treats the Windows patching Minion as the first reference implementation. The architecture shall not assume that all future Minions use PowerShell, Windows Update, SCCM, Windows, or a particular transport mechanism.

---

## 2. Core Architectural Principles

The implementation shall preserve the following principles.

### 2.1 SluiceGate is authoritative, not advisory

SluiceGate determines whether requested actions may occur. Controlled AI agents should not possess an alternate privileged execution path that allows them to bypass SluiceGate when an action is blocked or paused.

### 2.2 Agents know outcomes, not policy

Requesting AI agents receive sufficient information to coordinate their behavior and avoid unnecessary retries, but shall not receive detailed SluiceGate policy rules, internal policy evaluation results, approval requirements, infrastructure details, or other information that could facilitate policy discovery or circumvention.

### 2.3 Minions have capability, but no authority

Minions may possess the technical capability and credentials necessary to execute narrowly defined operations. They shall not independently decide whether an operation is appropriate, permitted, safe, or desirable. Execution authority originates only from SluiceGate Core.

### 2.4 Intelligence and authority remain centralized

Policy evaluation, PAUSE behavior, approval workflows, transaction state, routing, execution parameters, retry behavior, timeout behavior, and audit logic should reside in SluiceGate wherever practical. Minions should remain lightweight and deterministic.

### 2.5 Minions shall not become general-purpose remote shells

SluiceGate shall invoke defined Minion capabilities with validated parameters. A Minion shall not expose arbitrary command, arbitrary PowerShell, arbitrary shell, or equivalent unrestricted execution functionality.

### 2.6 Notifications are service-owned

Only `sg_service` may select and invoke Notification Adapters to send messages. Agents and Minions shall not send SluiceGate notifications or invoke Notification Adapters. Minions report status and results to `sg_service` through the Mission Comms contract; the service decides whether to notify anyone.

---

## 3. Solution Components

The enhancement consists of the reusable policy library, SluiceGate service/orchestration layer, Agent and Minion Registry functionality, reusable Minion templates, functional Minions, Windows deployment package, and migration of the demo execution path to the new service and Minion protocol.

### 3.1 SluiceGate Core and Service

SluiceGate shall retain a reusable policy library (`sg_core`) and add a service/orchestration layer (`sg_service`) for the new control-plane behavior. `sg_core` remains the policy decision component; `sg_service` exposes the agent/admin interfaces, owns durable transactions and Missions, and coordinates the registries and Minions. Their source/package boundaries are defined in Section 3.8; new transport, queue, registry, and Minion-dispatch behavior shall not turn the `sg_core` policy library into a service framework.

#### 3.1.1 Existing `sg_core` Functionality to Preserve

- **Policy evaluation:** `Gate.evaluate()` accepts a `GateRequest` with `actor`, `action`, `target`, and `context`; the YAML `PolicyEngine` evaluates rules in order, uses AND semantics for conditions and first-match-wins behavior, and returns `ALLOW`, `PAUSE`, or `BLOCK` with structured obligations and a policy provenance hash. Supported condition operators currently include `exists`, `eq`, `in`, `gt`, `gte`, `lt`, and `lte`; the policy default applies when no rule matches.
- **Explain/simulation:** `Gate.explain()` and `PolicyEngine.explain()` provide a side-effect-free rule and condition trace, including the matched rule/default, actual and expected values, decision, obligations, and policy hash. Explain does not emit audit events or execute actions.
- **Request and decision models:** Preserve the public typed request, decision, obligation, pause, and explain/trace models, including the request ID, message, reason code, resume token, pause status, and timeout fields where applicable.
- **Obligations:** Policy obligations are normalized into typed `Obligation` values. Core returns them as data; the `ObligationAdapter` is an interface for external handling and is not automatically invoked by `Gate`.
- **Gate audit events:** `Gate.evaluate()` assigns a request ID and can emit request-created and decision events, as well as pause-created/resolved events, through its optional audit callback. Audit destinations are injected; Core does not itself provide durable audit storage.
- **PAUSE continuation:** A PAUSE decision creates a resumable record and token. The current default store is in-memory, uses a one-hour default TTL (overridable by an approval/pause obligation), and loses records on process restart. Approval, denial, and expiry are tracked; unresolved records remain PAUSE, while denial or expiry resolves to BLOCK. Missing tokens fail closed in the supplied polling adapters.
- **Approval resolution behavior:** The current `resolve_pause()` returns ALLOW after approval without re-evaluating the original request against policy. `sg_service` shall not treat that result alone as execution authorization; after approval it shall re-evaluate the request under the current policy as specified in Section 6.2.
- **PAUSE integrations:** Preserve the pause notifier interface and best-effort in-memory pub/sub implementation, synchronous and asynchronous polling adapters, and optional FastAPI endpoints for pause inspection, decision lookup, approval/denial, Server-Sent Events, and WebSocket updates. These are integration primitives, not an authenticated, persistent production approval service.
- **Extension contracts:** Preserve the optional approval and connector interfaces and the experimental `RequestStore` and audit-sink protocols unless superseded through a documented compatibility decision. The connector registry is not used by `Gate`; its target location and role in the Minion architecture are described in Section 3.1.2. The request-store protocol is not the persistence backend for Gate or PAUSE records.

#### 3.1.2 Proposed `sg_service` Functionality

`sg_service` shall provide the authoritative service/orchestration layer around `sg_core`. It shall:

- Receive authenticated action requests from registered AI agents, derive actor identity from authenticated context, and normalize requests into `GateRequest` or a documented compatible model.
- Expose the versioned Agent API, status endpoint, and shared-authenticated administrative interfaces for Agent and Minion Registry management.
- Maintain durable transactions and missions, including a persistent queue/outbox so accepted work is not lost on process restart and mission dispatch can be retried safely.
- Apply policy by calling `sg_core`; own transaction status, pause/resume coordination, idempotency, rate limiting, queue/mission scheduling, Minion routing, and audit correlation.
- On ALLOW, resolve an eligible Minion through the Minion Registry, create and sign a Mission Envelope, and persist it for that Minion to claim through Minion Central Command.
- Accept Minion-initiated check-ins, Mission claims, status updates, and results through Minion Central Command. Authenticate/verify each request/update, correlate it to the transaction and Mission, and persist each accepted state transition. The initial deployment shall not require `sg_service` to poll Minions for status.
- Expose a private Minion check-in API, named **Minion Central Command**, for registered Minion runtimes to authenticate, check in, claim or retrieve assigned Missions, and submit status/results. `sg_service` owns the Mission queue and dispatch authorization; Minion Central Command is the Mission Comms interface, not a second authority.
- Keep the transaction `IN_PROGRESS` while an accepted mission is executing or awaiting completion. Close it only when the mission reaches a terminal outcome; expose `SUCCEEDED` only for success and `CLOSED` for every terminal non-success.
- Provide deliberately limited request status to the originating agent, enforce request ownership, and apply configured request/poll limits and escalating controls for agents that repeatedly resubmit or poll impatiently.
- Persist policy provenance, transaction/mission history, approval evidence, dispatch attempts, status updates, result signatures and verification outcomes, and administrative changes for authorized review.

The `ConnectorRegistry` and connector execution path shall move out of `sg_core` into `sg_service` or an adapter package; they shall not be the Minion orchestration mechanism inside the policy library. Preserve existing public imports for a documented compatibility period if needed, then deprecate them. New execution routing and dispatch belong in `sg_service` and the Minion integration; the demo stub and approval-email adapter are specified in Sections 3.6 and 3.7.

SluiceGate, through `sg_core` and `sg_service`, shall remain the sole authority that permits execution. This does not require the registries or Minion implementations to be independently useful products: they may be modular components in one deployable SluiceGate system.

### 3.2 Agent Registry

The Agent Registry shall be a lightweight administrative interface and backing data model associated with the SluiceGate inbound API. It shall identify agentic AI systems permitted to submit requests to SluiceGate.

The Agent Registry is distinct from the Minion Registry because the two registries represent opposite sides of the SluiceGate trust boundary:

- **Agent Registry:** who may ask SluiceGate to consider an action.
- **Minion Registry:** what trusted execution component may carry out an action SluiceGate has authorized.

Initial Agent Registry attributes should include:

- Agent ID.
- Name.
- Description.
- Owner/team.
- Environment or logical domain.
- Enabled/disabled state.
- Authentication method.
- API key hash or other credential metadata.
- Created/updated timestamps.
- Last-used timestamp.
- Configurable request rate limit.
- Configurable status-polling rate limit.

The initial authentication method shall support SluiceGate-generated API keys. The data model should not assume API keys are the only future mechanism. Future methods may include OAuth/OIDC, mTLS, client certificates, JWTs, workload identity, government PKI, etc.

The Agent Registry shall authenticate identity only. Authorization to perform actions shall remain a SluiceGate policy function.

The Agent Registry shall use the same server-authenticated administrative control plane as the Minion Registry. Agent registration and credential data may be implemented within `sg_service`; it need not be a separately deployable product.

### 3.3 Minion Registry

The Minion Registry shall provide centralized creation, registration, configuration, discovery, routing, cryptographic identity management, lifecycle management, and operational status for SluiceGate Minions.

The Registry shall include a front-end web administration interface and persistent backend data store.

A Minion registration should support, at minimum:

- Minion ID.
- Name.
- Description.
- Minion implementation/runtime type.
- Version.
- Environment.
- Enabled/disabled/revoked state.
- Supported capabilities.
- Scope metadata where applicable.
- Minion Central Command protocol/client configuration and endpoint profile; the initial Minion initiates outbound check-in and work claims.
- Executable/package location or other Minion deployment information.
- Configured Minion-initiated check-in/Mission polling cadence, status reporting mode, and timeout/stale-contact settings.
- Minion Central Command API-key identifier/hash, enabled/revoked state, issue/expiry/rotation metadata, and last check-in. The reusable API key itself shall be shown only at issuance and stored by the Minion in protected service configuration.
- Local operational state needed to resume an accepted Mission after service or target reboot, without storing reusable credentials in Mission data.
- Execution identity metadata, without requiring storage of the execution identity's reusable password.
- Minion public key/certificate and fingerprint.
- Key status and rotation/revocation metadata.
- Approved package/script hash.
- Health/status information.
- Last contact/heartbeat where applicable.
- Last Mission information where appropriate.

The Registry shall provide deterministic runtime Minion resolution. Given a capability, environment, scope, and other applicable routing metadata, it shall identify an eligible enabled Minion and return the execution information required by Core.

Routing shall not require autonomous reasoning or an LLM. Initial routing should be deterministic. Priority, failover, or load balancing may be added later if multiple Minions implement the same capability.

The Registry shall also define and version the common Minion Mission/Result Protocol described in Section 8. Keep registry code, protocol contracts, templates, and Minion implementations together under the top-level `minion-registry/` project directory, in the subdirectories defined in Section 3.8. Registry Python package code, if implemented, should follow the `src/` layout (for example, `minion-registry/src/sgm_registry/`).

### 3.4 PowerShell Minion Template

A reusable PowerShell Minion template/framework shall be created as the first Minion implementation framework.

The template is reusable source/scaffolding, not a separately deployed Minion. Functional PowerShell Minions shall be instantiated from this template.

The common framework should provide:

- Mission receipt/invocation handling.
- Mission schema validation.
- SluiceGate signature verification.
- Minion ID validation.
- Protocol version validation.
- Expiration validation.
- Nonce/replay protection.
- Capability validation and dispatch.
- Execution according to parameters supplied in the signed envelope.
- Standard result formatting.
- Result signing.
- Local operational logging.
- Health/status functionality where required.
- Consistent error/result codes.

The template shall contain no autonomous reasoning, policy evaluation, or discretionary retry logic. Store templates under `minion-registry/templates/`.

### 3.5 Patching Minion

The Patching Minion shall be the first functional Minion built using the PowerShell Minion Template.

It shall provide a narrowly defined set of Windows patch-management capabilities. Initial capabilities should include at least:

- `windows.patch.reconcile` — evaluate the allowed patch sources for the Mission-authorized server list and apply only updates/packages satisfying the signed constraints.
- `windows.patch.discover`
- `windows.patch.inspect`
- `windows.patch.install`
- `windows.patch.status`

The exact capability vocabulary may be refined during implementation, but capability names shall describe the requested operation rather than underlying Windows Update, WSUS, or SCCM commands.

For bulk policy-controlled remediation, SluiceGate should request `windows.patch.reconcile` with authorized servers and constraints; it should not send arbitrary PowerShell or instruct the Minion to invoke an arbitrary local command or SCCM cmdlet. `windows.patch.install` may remain available for a narrowly scoped, explicitly identified patch operation.

The Patching Minion shall translate approved capabilities into predetermined Windows patching operations, execute them using its configured Windows/AD execution identity, and return structured results. For OS updates, it shall invoke the target server's configured Windows Update client and use the approved WSUS/SCCM patch source configuration on that target. It shall not require SCCM communication as the execution authority for a Mission, unless SCCM-specific reporting or validation is explicitly required by policy.

For patch remediation, the Agent shall maintain two inputs outside SluiceGate: the patch catalog and a Nessus finding-to-host mapping CSV. The Agent may submit a simple list of server names to remediate; it need not submit patch IDs or catalog rows. SluiceGate policy shall determine which requested servers are authorized and put only those servers in the signed Mission Envelope, together with patch-selection constraints such as permitted `patch_type` values, reboot allowance, maintenance window, and execution limits. Mission Command shall not read or query either CSV.

The Patching Minion shall read the Nessus mapping CSV, retain only rows whose `DNS_NAME` matches a server authorized in the Mission, and join their `PLUGIN_ID` values to the current approved patch-catalog rows. It shall execute only joined catalog rows that satisfy every Mission constraint. The Agent-based maintenance process is responsible for maintaining and publishing both CSVs and downloading/publishing patch files; the Minion shall not update those inputs. If no finding maps to a target, no approved catalog row matches a plugin, no row satisfies Mission constraints, a source is inaccessible, or a hash check fails, the Minion shall report the condition without broadening the server scope or using an unapproved source.

Store the Patching Minion source under `minion-registry/minions/patching/`.

#### Patching Catalog Contract

The patch repository and both CSV inputs are external operational inputs to the Patching Minion, not SluiceGate policy storage. An authorized Agent-based or other controlled maintenance process shall maintain the CSVs and download/publish patch files to the approved repository. That process is responsible for keeping one current row per Nessus `plugin_id` in the patch catalog, validating mapping/catalog consistency, and publishing complete rows and patch files before marking catalog entries `APPROVED`. SluiceGate Mission Command shall not inspect, maintain, or resolve these inputs.

The initial catalog format shall be UTF-8 CSV with a header row and one current row per `plugin_id`. The initial required columns are:

| Field | Meaning |
|---|---|
| `patch_status` | Catalog lifecycle state; the Minion may install only `APPROVED` rows. |
| `plugin_id` | Nessus plugin identifier used to associate a finding with the catalog entry. |
| `iavm_id` | IAVM identifier associated with the finding, when applicable. |
| `vendor` | Software or patch publisher. |
| `title` | Product/application name, such as `Acrobat`. |
| `patch_id` | Vendor patch identifier or package identifier. |
| `patch_title` | Human-readable patch/advisory title. |
| `patch_type` | Normalized policy classification, initially including values such as `SECURITY`, `FEATURE`, `SERVICE_PACK`, `DRIVER`, `BUGFIX`, `OTHER`, and `UNKNOWN`. The controlled vocabulary and definitions shall be versioned as part of the Agent/catalog-to-Minion contract; missing or unknown values do not qualify for allow-only categories. |
| `requires_reboot` | Boolean catalog assertion (`true` or `false`) used to filter rows against Mission constraints. |
| `patch_path` | Minion-accessible path to the staged patch file, normally an approved UNC path. |
| `patch_sha256` | Expected SHA-256 digest of the patch file at `patch_path`. |
| `source_url` | Vendor/source provenance for the package or advisory; informational and not an instruction for the Minion to download from the Internet. |
| `install_command` | Vendor-specific command template, including executable available through the target server's `PATH` and its arguments. `%PATCHPATH%` is the only required substitution token and resolves to the selected row's patch path. The Minion shall launch it using a constrained process invocation, not an unrestricted shell. |
| `notes` | Optional human-readable maintenance notes; not executable instructions or policy input unless separately specified. |

The separate Nessus finding-to-host mapping shall be UTF-8 CSV with the required columns `PLUGIN_ID` and `DNS_NAME`. Each row represents a Nessus finding association between a plugin and a scanned host. Multiple rows may use the same plugin ID or DNS name. The Minion shall normalize DNS names consistently for matching, reject malformed rows, and intersect mappings only with the target servers in the signed Mission. The Agent/maintenance process shall publish a complete mapping file atomically so the Minion does not consume a partially written file.

Example mapping CSV:

```csv
PLUGIN_ID,DNS_NAME
123456,SERVER03.example.gov
123456,SERVER07.example.gov
234567,SERVER03.example.gov
```

Example row (illustrative only; identifiers, hash, arguments, and reboot value must be validated for the actual package):

```csv
patch_status,plugin_id,iavm_id,vendor,title,patch_id,patch_title,patch_type,requires_reboot,patch_path,patch_sha256,source_url,install_command,notes
APPROVED,123456,IAVM-2026-001,Adobe,Acrobat,AA123,"Acrobat Security Update 2026",SECURITY,false,"\\patchrepo\approved\Adobe\Acrobat\AcrobatUpdate.msp",dd7806c6d3a20b248454a0565951c0fd8212277c34e0439d758b85ff3a3b9e77,https://www.adobe.com/example-advisory,"msiexec.exe /p ""%PATCHPATH%"" /qn /norestart","Illustrative only"
```

The Minion shall load both CSV inputs from configurable UNC paths. It shall load the patch catalog from its configured backend (initially UNC-hosted CSV; a future SQL backend may use ODBC connection configuration) and the Nessus mapping CSV from its configured UNC path. The catalog backend shall expose the same logical patch-record shape so backend selection does not change Mission semantics. The Minion considers only catalog rows where `patch_status` is `APPROVED`, ignoring `DRAFT` or `RETIRED` rows; it shall reject malformed catalog rows, duplicate `plugin_id`s among approved rows, invalid field values, unsupported placeholders, inaccessible paths, and hash mismatches. It shall read each candidate patch from the approved repository using its service identity, calculate SHA-256 before remote staging, and compare it with the selected row; only a matching file may be copied to a controlled target-local staging path. This check establishes correspondence to the catalog's expected hash; trustworthiness of catalog content, vendor instructions, source review, and repository administration remain responsibilities of the separately engineered maintenance process and its controls.

CSV access and patch-file access shall use the SG Minion Windows service identity. SQL configuration and credentials, if later used, shall be supplied through protected service configuration/secret management and shall not be embedded in Missions or catalog rows. Catalog backend choice shall be configurable for the Minion deployment; SQL support is a future capability, not required for the initial CSV implementation.

### 3.6 Demo Stub Minion

The existing demo executes an action through a local Stripe stub connector; it does not currently perform real Stripe operations. Migrate this safe stub execution path to a registered demo Minion so the demo continues to demonstrate ALLOW/PAUSE/BLOCK and post-approval execution through the same signed Mission/Result protocol as other Minions.

The demo Minion shall:

- Be registered through the Minion Registry and run with a Minion identity suitable for local development.
- Advertise only the fixed action capability/capabilities already supported by the demo stub.
- Accept only signed Missions addressed to its registered identity and validate capability, parameters, expiration, and replay state.
- Preserve stub-only behavior; it shall not make real payment calls or require production payment credentials.
- Return a signed structured result that `sg_service` persists and the demo displays.

Store the demo Minion under `minion-registry/minions/demo_stub/`. Its purpose is to preserve and test the current demo execution workflow, not to represent a production payment integration.

### 3.7 Notification Adapters and Profiles

Notification Adapters are a separate class of integration from Agents and Minions. An adapter delivers a SluiceGate-generated message through a provider such as email, SMS, or Slack. It does not request policy decisions, approve actions, or execute target-system Missions.

`sg_service` shall own notification selection and delivery. A service-managed Notification Profile shall associate SluiceGate event types (for example, approval required, mission progress, or terminal outcome) with one or more configured Notification Adapters and recipient references. The profile and event determine the notification; neither an Agent nor a Minion may select an adapter or recipient by supplying arbitrary envelope/request data.

- Only `sg_service` may invoke Notification Adapters or send SluiceGate messages. This applies before Mission creation as well as during and after execution.
- Notification Adapters receive a bounded notification event and return a delivery result. They shall not make policy decisions, record approval as authorized merely by delivery, or execute Missions.
- Approval/rejection is a separate authenticated request to `sg_service`; a delivered message or clicked link is not itself policy authorization. Approval behavior is defined in Section 6.2.
- Provider credentials remain in service-side configuration or secret storage and are never sent to Agents or Minions.
- Delivery attempts, outcomes, and retries shall be correlated to the transaction and audited by `sg_service`. Notification failure shall not itself authorize execution.

#### 3.7.1 Demo Approval-Email Adapter

The demo's current Resend integration sends approval-notification email. Preserve it as an optional Notification Adapter invoked by `sg_service` when a configured Notification Profile matches a PAUSE event. It is not an email-action executor and shall not be represented as an Email Minion.

- Approval and rejection shall be recorded through the authenticated SluiceGate administrative/approval flow and bound to the paused transaction.
- An email link shall not approve or reject merely because it was fetched (for example, by a mail-security scanner); require an authenticated confirmation flow and an explicit state-changing request.
- If notification email is unavailable, the demo shall continue to support approval through its authenticated UI.
- Missing Resend credentials or approver configuration shall disable email notifications without preventing the demo backend or service stack from starting.

If a future requirement calls for sending email as a controlled target-system action, define that separately as an Email Minion capability; it is not a Notification Adapter and is not a migration of the current approval notifier.

### 3.8 Repository Organization

All first-party components shall remain in one repository because the policy engine, service, registries, Minions, deployment package, and reference demo form one integrated system. The repository shall have clear product, package, runtime, and release boundaries; `open-core/` names the policy-library product boundary and shall not be treated as the parent directory for all SluiceGate code.

The target top-level layout is:

```text
sluice/
  open-core/                            # source-available policy library and tightly coupled policy tooling
    pyproject.toml
    src/sg_core/                        # deterministic policy evaluation and public Core contracts
    src/sg_poledit/                     # policy authoring/validation CLI and editor, while Core-coupled
    tests/
    examples/
    policies/
  sg-service/                           # first-party SluiceGate service and orchestration runtime
    pyproject.toml
    src/sg_service/                     # Agent API, admin API, Mission Central Command, transactions/queue
    tests/
  minion-registry/                      # registry, protocol, templates, and functional Minion sources
    pyproject.toml                      # only if registry code has its own Python distribution
    src/sgm_registry/                   # registry package, if maintained as Python code
    protocol/                           # versioned Mission/Result and Mission Central Command contracts
    templates/                          # reusable Minion templates/frameworks
    minions/
      demo_stub/                        # safe reference Minion
      patching/                         # Windows Patching Minion source
    tests/
  deployment/
    windows/                            # Windows VM installer/configuration and service lifecycle tooling
    containers/                         # service image/build and deployment assets, if shared
  sluice-demo/                          # runnable reference UI/BFF and demo-only notification adapter
  sdk/                                  # supported external client SDKs, when implemented
  tools/                                # repository-level developer/maintenance tools not owned by a package
  docs/
  planning/
```

The tree is a target, not a requirement to create empty packages or directories. Add a package or project manifest only when that component has maintained source, dependencies, tests, or a distinct build/deployment responsibility. The Minion Registry may initially be configuration/protocol material rather than a separately deployable application; `minion-registry/pyproject.toml` and `src/sgm_registry/` are conditional on it containing maintained Python package code.

#### 3.8.1 Component Ownership and Packaging

- `open-core/` owns `sg_core`: deterministic policy evaluation, policy/request/decision contracts, and Core-scoped tests. It shall not acquire HTTP service hosting, durable transaction/mission storage, authentication, service credentials, Minion dispatch, Notification Adapter selection, or privileged target-system execution.
- `sg_poledit` may remain in the `open-core` distribution while it is a policy authoring/validation tool directly coupled to Core policy schemas. If it becomes an independently released application, give it its own project boundary rather than making Core depend on it.
- `sg-service/` owns the `sg_service` Python application: Agent and administrative APIs, Minion Central Command, transaction and Mission lifecycle, durable persistence/queueing, policy orchestration, registries where appropriate, notification selection, and audit coordination. It may depend on `sg_core` from the same repository revision.
- `minion-registry/` owns Minion registration/protocol definitions, reusable templates, and functional Minion implementations. The Patching Minion source belongs here; Windows service installation, VM configuration, and container deployment packaging belong under `deployment/windows/`.
- `sluice-demo/` remains a consumer/reference deployment. It shall not become the authoritative owner of policy, transaction, Mission, or audit state. Demo-specific UI/BFF code and the safe demo Minion may remain together only where that does not duplicate shared service or Minion implementations.
- SDKs belong under `sdk/` only when they are supported client libraries with their own API compatibility and test expectations. Do not make `sg_service` or `sg_core` depend on an SDK that is intended for external callers.
- Adapter code shall live with the runtime that owns its lifecycle and credentials: Notification Adapters with `sg_service` (or demo-only adapters with the demo), and target-system execution with the relevant Minion. Do not retain a generic `sg_adapters` package under `open-core` if it mixes these distinct trust boundaries.
- CLI commands shall be assigned by responsibility: policy authoring/validation commands may remain with `sg_poledit`; service administration/client commands belong with `sg_service` or an SDK/tooling package; Minion-local commands belong with their Minion. A generic `sg_cli` package shall not become a dumping ground.

Each Python distribution shall have its own `pyproject.toml`, declared runtime/development dependencies, tests, and build configuration when it has an independent package/build boundary. A root workspace/lock configuration may coordinate development and CI, but packages shall not rely on undeclared imports caused only by running from the repository root. First-party development, integration tests, container builds, and deployment artifacts shall resolve components from one tested repository revision; they shall not require publishing `sg-core` to PyPI as an intermediate step. The already-published `sg-core` artifact may remain available, but an independent release is not required by this specification.

#### 3.8.2 Migration Requirements

Repository reorganization shall preserve behavior and make the new ownership boundaries explicit. Perform the migration in reviewed, buildable steps:

1. Inventory tracked source, tests, package metadata, entry points, Dockerfiles/Compose files, policy paths, CI workflows, scripts, documentation links, and user-facing import/CLI paths. Distinguish populated packages from empty scaffolding; do not create implementation packages solely because a target-tree example names them.
2. Move only files whose ownership is understood. Preserve Git history where practical, and update imports, package discovery/build settings, CLI entry points, policy/configuration paths, and relative resource loading as part of each move.
3. Add or update per-project tests and build/install checks. Verify Core can be built and tested independently; verify `sg_service` can resolve the local Core source; verify Minion protocol/runtime tests; and run demo integration tests against the service rather than a duplicate policy/execution path.
4. Update Docker Compose/build contexts, container mounts, Windows deployment inputs, CI paths, developer commands, README files, and architecture documentation so they match the new tree. The demo and Windows deployment build shall consume the same tested repository revision without requiring an intermediate public package release.
5. Remove obsolete compatibility paths only after repository-wide search and tests confirm that no supported import, entry point, deployment script, or documented workflow still depends on them. Any retained compatibility import or CLI alias shall have an explicit deprecation/removal plan.

The reorganization shall not change policy semantics, public Core behavior, Mission protocol behavior, licensing, or trust boundaries as an incidental effect. Any such change requires its own documented compatibility decision and tests.

### 3.9 Initial Windows Deployment Model

The initial deployment target shall be a Windows Server 2022 VM hosting both the `sg_service` container and a Windows SG Minion service. Use the latest stable Docker version supported for the required Windows Server 2022 deployment. The container runs the SluiceGate Python service; it does not require a Windows/AD execution identity. The SG Minion runs as a Windows service under a dedicated, least-privilege AD identity (a gMSA is preferred where supported) and performs authorized remote work using that identity. For the Patching Minion, that identity shall have only the required read access to the approved patch catalog/repository and the required remote patching rights on authorized target servers. Other Minion types, such as a production-deployment Minion, shall receive their own appropriately scoped permissions; separate identities per Minion or trust domain are preferred over one shared, broadly privileged account. The identity shall not be embedded in Mission Envelopes or supplied by Agents.

`sg_service` shall expose Minion Central Command as a private authenticated API. On the single-VM deployment, the container API shall be published only to a host-local or otherwise restricted interface reachable by the Windows Minion service, not exposed as a public endpoint. Minion Central Command shall support Minion authentication/check-in, retrieval or claiming of work assigned to that Minion, and authenticated status/result submission. Mission and result signatures remain required protocol protections in addition to transport/API authentication. Minions shall not be able to select arbitrary callback URLs or claim Missions assigned to another Minion.

The Minion check-in interval, work-claim behavior, heartbeat cadence, status retry cadence, and stale-contact thresholds shall be configurable. An initial idle check-in interval of approximately one hour is a candidate, not a fixed requirement. The Minion shall submit status promptly on Mission acknowledgement, start, wait/reboot, and terminal transitions; a long idle polling interval shall not delay execution-status reporting. Exact heartbeat/stale-contact behavior remains a pilot design decision and shall account for patch duration, reboot/resume behavior, service load, and acceptable dispatch latency.

The Windows deployment package shall install/configure the Windows SG Minion service and start the `sg_service` Docker container on the target Windows Server 2022 VM. It shall include versioned Minion binaries/scripts and container image/build or image-pull configuration, service registration and startup configuration, Minion Central Command endpoint configuration, health/logging setup, and upgrade/uninstall handling. Deployment documentation shall identify prerequisites and the administrator-provided configuration required for AD identity, share/server permissions, certificates or keys, Docker installation/configuration, and network access. The package shall not provision or distribute reusable AD passwords or silently grant target permissions.

### 3.10 Demo Integration and Compatibility

The existing `sluice-demo` shall remain a runnable reference experience for action submission, ALLOW/PAUSE/BLOCK behavior, approval, execution, and audit viewing. It shall exercise the same `sg_service` and Mission protocol used by SluiceGate rather than maintaining a second policy/execution implementation.

- Run the demo UI, its optional backend-for-frontend (BFF), `sg_service`, the Minion Registry, and the demo stub Minion together through the local development stack. The demo may retain its existing HTTP routes as a thin compatibility facade or update the frontend to the versioned SluiceGate APIs; in either case there shall be one authoritative service state.
- The demo BFF/UI shall submit requests to `sg_service` as a registered demo Agent. Any Agent API credential shall remain server-side and shall never be embedded in browser code.
- Map existing demo action fields (`action`, `amount`, `currency`, and `metadata`) into the canonical request model. The authenticated Agent identity shall come from the service credential, not from caller-controlled `metadata`.
- Remove direct `PolicyEngine`/`Gate` ownership, the authoritative in-memory request `STORE`, the local authoritative audit log, and direct calls to `execute_action()` from the demo backend. Transaction, decision, approval, mission, execution, and audit state shall be read from or written through `sg_service`.
- On ALLOW, `sg_service` shall dispatch a signed Mission to the registered demo stub Minion; the demo must not invoke the stub directly. The stub shall remain incapable of real payment execution.
- Preserve the operator experience for request submission, request details/status refresh, approve/reject, audit viewing, and policy reload. Operator-only decision details and audit information shall use authorized administrative endpoints; the normal Agent status response remains limited as defined in Section 5.3.
- Keep Resend approval notifications optional. `sg_service` may invoke the demo Notification Adapter from a PAUSE event before any Mission exists; approval/rejection shall be confirmed through an authenticated admin flow and cause the current-policy re-evaluation in Section 6.2.
- Update Docker Compose/build configuration so demo images build against the local SluiceGate source from the same repository revision. The demo shall not require a separately published `sg-core` PyPI version. A separate packaging/release check may validate the full SluiceGate release artifact.
- Mount or configure the demo policy for `sg_service`, and route policy reload through its authorized administrative interface rather than reloading a second in-process `PolicyEngine` in the demo.

The demo migration shall preserve its safe, stub-only nature and remain usable when email notification credentials are absent. It is a client/reference deployment of SluiceGate, not an alternate authority or a production payment integration.

---

## 4. Canonical Action Model

SluiceGate shall define a canonical action representation independent of the implementation technology used to execute the action.

At minimum, an action should contain:

- Requesting Agent identity, derived from authentication rather than trusted from request content.
- Capability/action.
- Target.
- Parameters.
- Request timestamp.
- Request ID and/or correlation metadata.

Example conceptual action:

```json
{
  "capability": "windows.patch.reconcile",
  "target": {
    "servers": ["SERVER03"]
  },
  "parameters": {
    "patch_sources": ["wsus", "nessus_catalog"],
    "patch_constraints": {
      "allowed_patch_types": ["SECURITY"],
      "allow_reboot": false
    },
    "maintenance_window": "approved-window-reference"
  }
}
```

The canonical model shall not expose Minion selection to the requesting AI agent. The agent requests a desired action from SluiceGate; SluiceGate determines whether and how that action is executed.

---

## 5. Inbound Agent API

### 5.1 Authentication

All action requests shall be authenticated.

For the initial implementation, SluiceGate shall support API-key authentication for registered Agent Registry entries. API secrets shall be handled using standard secure credential practices and shall not be stored as recoverable plaintext where avoidable.

Authentication establishes the requesting principal. Policy establishes authorization.

### 5.2 Action Submission

The API shall expose a versioned action-submission endpoint conceptually equivalent to:

```text
POST /api/v1/actions
Authorization: Bearer <agent credential>
```

A request shall specify the desired capability, target, and parameters. The API shall not allow the requesting agent to select a Minion or supply Minion execution credentials.

Upon valid receipt, Core shall create an internal transaction and return a low-information external Request ID.

Conceptual response:

```json
{
  "request_id": "REQ-10038",
  "status": "ACCEPTED"
}
```

The external Request ID need not expose the internal SluiceGate Transaction ID.

### 5.3 External Status Model

Requesting agents shall receive sufficient status information to coordinate behavior without receiving internal policy reasoning.

For patch-remediation requests, the Agent submits the requested server list and receives only a low-information acceptance/aggregate terminal status. It shall not receive policy-derived server filtering details, per-plugin eligibility decisions, patch selection, Minion identity, or detailed installation output through the standard Agent API. Detailed per-server/per-patch results remain available only to authorized operators through the administrative/audit interface.

The initial external state vocabulary should be:

- `ACCEPTED` — SluiceGate has accepted the request for processing.
- `PENDING` — SluiceGate continues to own/process the request; the agent should not resubmit it.
- `SUCCEEDED` — the requested action completed successfully.
- `CLOSED` — SluiceGate has closed the request and the agent should not retry it.

Internal states may be substantially richer and may include BLOCKED, PAUSED, WAITING_FOR_APPROVAL, ROUTING, QUEUED, DISPATCHED, IN_PROGRESS, FAILED, TIMED_OUT, CANCELLED, EXPIRED, and other states.

Internal policy states and reasons shall not automatically be exposed through the agent API. The external status remains `PENDING` while internal state is nonterminal, including `IN_PROGRESS`; every terminal non-success maps to `CLOSED` as specified in Section 5.3.

A status response may include explicit retry guidance, for example:

```json
{
  "request_id": "REQ-10038",
  "status": "PENDING",
  "retry": false
}
```

or:

```json
{
  "request_id": "REQ-10038",
  "status": "CLOSED",
  "retry": false
}
```

The initial system shall return `retry: false` for requests SluiceGate already owns or has definitively closed. Every terminal outcome other than successful completion, including BLOCK, denial, failure, timeout, cancellation, expiry, invalid mission/result, or exhausted retries, shall be exposed to the agent only as `CLOSED`; no terminal failure distinction or internal reason shall be exposed through the standard agent API.

### 5.4 Status Query

The API should expose a versioned request-status endpoint conceptually equivalent to:

```text
GET /api/v1/requests/{request_id}
```

An authenticated agent shall only be permitted to retrieve status for requests created by that same registered agent identity.

Status responses shall not expose:

- Detailed policy rules.
- Specific BLOCK reasons unless explicitly approved as safe to expose.
- PAUSE/approval internals.
- Minion identity or capabilities/configuration or other infrastructure details unless required by a future use case.
- Other agents' requests or transaction information.

### 5.5 Duplicate and Rate Control

SluiceGate shall not depend solely on requesting agents behaving reasonably.

`sg_service` and/or the Agent Registry shall support:

- Configurable action-submission rate limits.
- Configurable status-polling rate limits.
- Protection against request flooding.
- Idempotent handling of equivalent outstanding requests: an inbound request matching an open mission for the same authenticated agent shall be associated with that existing transaction/mission and shall not spawn another mission.
- Escalating controls for agents that repeatedly resubmit equivalent work or poll more frequently than permitted. The service may first delay or pause acceptance and ultimately disable/block the agent, with thresholds and reset behavior defined in configuration.

For the Patching Pilot, the upstream patching agent should also be configured with a reasonable reevaluation cadence, such as approximately once per day rather than continuous repeated submission.

The exact canonicalization and equivalence rules, matching window, rate thresholds, escalation and recovery behavior remain implementation decisions, provided concurrent duplicates cannot create multiple missions and the service cannot be trivially overwhelmed.

---

## 6. Core Transaction Lifecycle

`sg_service` shall own the durable transaction and mission lifecycle, using `sg_core` for policy decisions. Minions shall not own SluiceGate transaction state or approval state; they may retain the local execution/replay state needed to safely process their assigned mission.

The nominal lifecycle is:

```text
AI REQUEST
    |
    v
AUTHENTICATE
    |
    v
NORMALIZE / CREATE TRANSACTION
    |
    v
POLICY EVALUATION
    |
    +---- BLOCK ----> PERSIST AUDIT ----> EXTERNAL CLOSED
    |
    +---- PAUSE ----> PERSIST PAUSE / APPROVAL STATE ----> RESOLVE UNDER PAUSE POLICY
    |
    +---- ALLOW
              |
              v
       MINION REGISTRY LOOKUP
              |
              v
        PERSIST + SIGN MISSION FOR MINION CLAIM
              |
              v
        MINION POLLS / CLAIMS
              |
              v
      MINION EXECUTION / STATUS EXCHANGE
              |
              v
       SIGNED EXECUTION RESULT RETURN
              |
              v
       VERIFY + PERSIST
              |
              v
      SUCCEEDED / CLOSED (EXTERNAL)
```

### 6.1 BLOCK

A BLOCK decision shall prevent Minion Mission invocation.

Core shall persist sufficient internal information to reconstruct the decision, including the requesting agent, requested action, target, relevant policy/rule identifiers, reason, timestamps, and transaction identifiers.

Externally, a blocked request may ultimately appear as `CLOSED` without disclosing the internal policy reason.

### 6.2 PAUSE

Existing SluiceGate PAUSE logic shall be preserved and integrated into the persistent transaction model.

A PAUSED transaction shall remain owned by Core. No Minion task shall be issued while the action remains paused.

The requesting AI should normally see the request as `PENDING`, not as `PAUSED`, and should receive `retry: false`.

No Mission shall be created or made claimable while a request is paused. Approval is evidence for policy evaluation, not an authorization decision by itself. After approval, `sg_service` shall:

1. Bind the approval evidence to the transaction and an immutable fingerprint of the normalized action and target, including approver identity, approval time, and applicable expiry.
2. Reconstruct the original normalized request without allowing its action, target, or parameters to be changed by the approval flow.
3. Refresh mutable context facts where available and include verifiable, transaction-scoped approval evidence in the policy evaluation context.
4. Evaluate against the current active policy version and persist the new decision and policy hash alongside the original PAUSE decision.
5. Create and make a Mission claimable only if the new decision is ALLOW. A new BLOCK closes the request; a new PAUSE keeps it pending and requires any approval evidence required by the current policy. Existing approval evidence may satisfy a repeated requirement only when the current policy explicitly accepts that evidence.

Denial or expiry shall not dispatch a Mission. An approval shall not be reusable for another transaction or authorize a changed action/target. The policy version, approval evidence, refreshed facts, and resulting decision shall be auditable.

### 6.3 ALLOW

An ALLOW decision authorizes Core to continue toward execution. `sg_service` shall resolve an appropriate Minion through the Minion Registry, construct and sign the Mission Envelope, persist it for that Minion to claim through Minion Central Command, verify the returned result, and update the transaction.

An ALLOW decision does not authorize arbitrary execution by a Minion; it authorizes the specific action represented by the signed mission.

---

## 7. Minion Routing and Capability Resolution

Minion selection shall be internal to SluiceGate.

The requesting AI shall not be required to know:

- Which Minion exists.
- Which implementation technology is used.
- Which credentials are used.
- Where the Minion resides.
- Which underlying enterprise management API or command is invoked.

Core shall request a Minion from the Registry using deterministic criteria such as:

- Capability.
- Environment.
- Scope.
- Enabled/revoked state.
- Health/availability where applicable.
- Explicit priority if later required.

A future Intune Minion, for example, could potentially expose the same logical `windows.patch.install` capability as a Patching Minion without changing the upstream agent API.

---

## 8. Minion Task/Result Protocol

The Minion Registry shall define/version the common protocol. `sg_service` and all Minion frameworks shall implement it. The initial Windows deployment shall use Minion-initiated check-in and polling through Minion Central Command for Mission retrieval and authenticated status/result updates. The protocol may support service-initiated delivery or callbacks for other deployment environments. Each Minion definition shall specify applicable check-in/status cadence and timeout values; the service shall use that configuration to detect stale or lost Minions and Missions. This Mission Comms contract is for Mission delivery and status/result reporting; it is not a Notification Adapter contract.

### Minion Central Command API

Minion Central Command is the private `sg_service` API used by Minion runtimes for check-in and Mission Comms. At minimum, the API shall support authenticated operations to:

- Check in with Minion identity, version, reported runtime capabilities, health, and current execution state. Reported capabilities are informational and shall not modify the Minion Registry's authorized capability set.
- Claim or retrieve only unexpired Missions assigned to that registered Minion.
- Acknowledge Mission receipt and report accepted, rejected, or executing state.
- Submit signed progress updates and terminal Mission Result Envelopes.

The initial Minion Central Command API authentication shall use a per-Minion API key issued and managed by the Minion Registry/service. The service shall store only a verifier/hash, display the key only at issuance/rotation, and support disablement, revocation, and rotation. The Minion shall store the key in protected Windows service configuration/secret storage; it shall not appear in a Mission Envelope, log, command line, or patch catalog. TLS shall protect API traffic even on the single-VM deployment. API-key authentication establishes the Minion identity and is separate from SluiceGate-signed Mission validation and Minion-signed result verification.

The API shall authorize every operation by the authenticated registered Minion ID, and verify Mission/result signatures as applicable. Check-in shall not itself grant a Mission or broaden capability. `sg_service` remains the authority for policy, Mission creation, assignment, and terminal transaction state. On a single VM the API shall bind only to a restricted host-local interface reachable by the Windows Minion service; for cross-host traffic it shall use private network exposure and TLS.

The initial implementation shall use Minion-initiated polling to claim work and post updates. Poll interval, heartbeat interval, empty-queue response behavior, retry/backoff, and stale-Minion thresholds shall be configurable per deployment or Minion profile. Approximately hourly polling while idle is a candidate starting value; the Minion shall report state transitions promptly rather than waiting for the next idle poll. Long-running work and reboots shall not require the Minion to hold an HTTP request open: it shall persist local execution state and report through subsequent authenticated check-ins/status submissions.

Conceptual endpoint shapes (exact routes and payload schema remain to be specified):

```text
POST /internal/v1/minions/{minion_id}/check-in
POST /internal/v1/minions/{minion_id}/missions/claim
POST /internal/v1/minions/{minion_id}/missions/{mission_id}/status
POST /internal/v1/minions/{minion_id}/missions/{mission_id}/result
```

### 8.1 Task Envelope

A signed Task Envelope should contain, at minimum:

- Protocol version.
- Internal Transaction ID.
- Task ID.
- Intended Minion ID.
- Capability.
- Target.
- Parameters.
- Execution parameters.
- Mission Comms profile/reference identifying the permitted Mission reporting channel and configured status/check-in behavior.
- Issue timestamp.
- Expiration timestamp.
- Nonce or equivalent replay-protection value.
- SluiceGate signing identity/key identifier.
- Cryptographic signature.

Conceptual example:

```json
{
  "protocol_version": "1.0",
  "transaction_id": "TX-10038",
  "mission_id": "MISSION-10038-01",
  "minion_id": "PATCH-01",
  "capability": "windows.patch.reconcile",
  "target": {
    "servers": ["SERVER03"]
  },
  "parameters": {
    "patch_sources": ["wsus", "nessus_catalog"],
    "patch_constraints": {
      "allowed_patch_types": ["SECURITY"],
      "allow_reboot": false
    },
    "maintenance_window": "approved-window-reference"
  },
  "mission_comms": {
    "profile_id": "patching-minion-central-command-v1",
    "reporting_mode": "minion-poll",
    "status_endpoint_ref": "minion-central-command"
  },
  "execution": {
    "max_attempts": 3,
    "retry_interval_seconds": 30,
    "attempt_timeout_seconds": 300,
    "overall_timeout_seconds": 900
  },
  "issued_at": "...",
  "expires_at": "...",
  "nonce": "...",
  "signing_key_id": "...",
  "signature": "..."
}
```

The precise schema and encoding shall be versioned.

Mission Comms data shall be selected or resolved by SluiceGate from the Minion Registry and bound into the signed Mission. References shall identify only an authorized SluiceGate reporting route; they shall not permit a Minion to choose an arbitrary callback destination. The envelope shall not contain Notification Adapter IDs, Notification Profiles, recipient lists, provider credentials, or instructions for sending notifications. Notification delivery remains exclusively service-owned under Section 2.6.

### 8.2 Execution Parameters

Minions shall not choose their own mission retry or timeout policy.

Core shall specify applicable execution behavior in the signed Mission Envelope, including as appropriate:

- Maximum attempts.
- Retry interval.
- Per-attempt timeout.
- Overall task timeout/expiration.

Any future backoff strategy or retry pattern shall likewise be specified by Core/protocol rather than autonomously selected by the Minion.

### 8.3 Minion Validation

Before executing a Mission task, the Minion shall validate at least:

- Envelope/schema validity.
- Supported protocol version.
- SluiceGate signature.
- Intended Minion ID.
- Supported capability.
- Required parameters.
- Mission expiration.
- Nonce/replay state.

Failure of validation shall result in no target-system action.

Where possible, the Minion shall return a signed `REJECTED` result identifying a machine-readable validation failure without exposing unnecessary secrets.

### 8.4 Mission Result Envelope

The Minion shall return a signed Mission Result Envelope containing, at minimum:

- Protocol version.
- Transaction ID.
- Mission ID.
- Minion ID.
- Outcome.
- Attempts made.
- Start/end timestamps.
- Structured result data.
- Underlying system reference/job/deployment ID where applicable.
- Machine-readable error information where applicable.
- Minion signing key identifier.
- Cryptographic signature.

Minion-to-service Mission states shall include, at minimum:

- `MISSION_ACKNOWLEDGED` — the Minion accepted the assigned Mission for processing.
- `MISSION_IN_PROGRESS` — execution has started; progress updates may include the current target, patch identifier, and bounded phase code.
- `MISSION_WAITING_FOR_REBOOT` — installation requires a reboot and the Mission is awaiting an authorized reboot/resumption step.
- `MISSION_COMPLETE_SUCCEEDED` — all required Mission work completed successfully, including an explicitly defined no-op when no catalog rows qualify.
- `MISSION_COMPLETE_PARTIAL` — some targets/patches succeeded and others did not, when partial completion is permitted by the Mission contract.
- `MISSION_COMPLETE_FAILED` — required work failed without satisfying the completion rule.
- `MISSION_REJECTED` — the Minion rejected the Mission before performing target-system changes.
- `MISSION_CANCELLED` or `MISSION_EXPIRED` — the Mission ended without execution or further execution, as applicable.

Status updates shall be authenticated, correlated to the Mission, idempotently processed, and time-stamped by both Minion and service receipt. The service shall validate allowed state transitions, persist accepted events, and derive transaction state from them. Status strings supplied by a Minion shall not independently authorize additional work.

Core shall verify the Mission Result Envelope signature using the registered Minion public key before trusting the result.

---

## 9. Cryptographic Identity and Trust

### 9.1 Separate identities

SluiceGate and each Minion shall have independent cryptographic identities.

SluiceGate signs tasks. Minions verify SluiceGate task signatures.

Minions sign results. SluiceGate verifies Minion result signatures.

### 9.2 Minion key generation

The administrative experience may initiate key creation from the Minion Registry UI, but the preferred architecture is for each Minion to generate its own private key on the Minion host during enrollment and provide only its public key/certificate to SluiceGate.

A Minion private key should not need to exist in the SluiceGate database.

For the pilot, each Minion may generate its own key pair on the host and use an appropriately secured software key store; only its public key shall be enrolled with SluiceGate. The design should permit future TPM-backed keys, certificate stores, HSMs, or government PKI without redesigning the protocol.

### 9.3 Key lifecycle

The Registry shall support or be designed to support:

- Key enrollment.
- Fingerprint display.
- Key rotation.
- Key revocation.
- Minion disablement.
- SluiceGate signing-key rotation/version identification.

### 9.4 Replay protection

The protocol shall include mission expiration and nonce or equivalent replay protection. A Minion shall not execute a previously consumed signed mission simply because its signature remains valid.

### 9.5 Minion package integrity

The Registry should store the approved cryptographic hash of the Minion implementation/package. For PowerShell Minions, normal PowerShell code signing may also be used.

The architecture should permit verification that the executing Minion code corresponds to the approved registered version.

---

## 10. Minion Behavioral Requirements

A Minion shall be intentionally non-autonomous.

A Minion shall:

1. Receive or be invoked with a SluiceGate Mission Envelope.
2. Validate the Mission Envelope and SluiceGate authorization.
3. Map the authorized capability to a predetermined implementation function.
4. Execute only the specified operation against the specified target and parameters.
5. Retry only according to the signed execution instructions.
6. Stop when success, failure, rejection, expiration, or instructed timeout criteria are reached.
7. Construct and sign a Mission Result Envelope.
8. Return the result to SluiceGate Core.

A Minion shall report Mission status and results only through the Mission Comms contract. It shall not send approval, progress, completion, or other SluiceGate notifications directly to people or external messaging providers.

A Minion shall not:

- Interpret SluiceGate policy.
- Decide that a blocked/paused operation should proceed.
- Seek human approval.
- Select an alternate target.
- Select an alternate capability.
- Modify the requested operation to make it succeed.
- Choose its own retry cadence.
- Decide to reboot unless a specifically authorized reboot capability/task exists.
- Accept arbitrary shell/PowerShell commands.
- Delegate the operation to another Minion on its own authority.

Local technical validation and failure handling are permitted where necessary to safely invoke the target system, provided they do not constitute policy or authorization decisions.

---

## 11. Persistence, Logging, and Audit

The current `sg_core` audit hook is destination-injected and does not itself persist events; its default PAUSE store is also in-memory. `sg_service` shall make relevant control-plane events, transaction state, and missions durable and transaction-correlated. Accepted missions shall be written to persistent storage/queue before dispatch so process restart does not lose authorized work or its state.

The exact database technology is an implementation choice for the first release.

Persistent data shall include, as applicable:

- Agent registrations and credential metadata.
- Minion registrations and cryptographic metadata.
- Transactions.
- Requests/actions.
- Policy decisions.
- PAUSE state and existing approval data required for transaction continuity.
- Minion routing decisions.
- Mission metadata and signatures or verifiable signature records.
- Result metadata and signatures or verifiable signature records.
- Execution outcomes.
- Relevant administrative actions.

Each request shall be traceable across its lifecycle using internal transaction/mission identifiers.

Authorized SluiceGate users should be able to reconstruct a chain conceptually equivalent to:

```text
AI request
  -> authenticated Agent identity
  -> normalized action
  -> policy decision
  -> PAUSE/BLOCK/ALLOW events
  -> selected Minion
  -> signed mission envelope
  -> execution result
  -> signature verification
  -> final transaction state
```

The existing SluiceGate logging/UI should be enhanced where practical rather than replaced by a wholly separate audit product.

---

## 12. Patching Pilot Environment Requirements

The government environment shall provide/configure the following external dependencies.

### 12.1 Dedicated pilot server scope

The approximately twelve pilot servers should be identified through a dedicated server group, collection, or another equivalent scope boundary, unless an existing grouping provides an equivalent isolation boundary.

Example logical name:

```text
SG-PILOT-PATCHING
```

The scope boundary shall provide an independent operational boundary in addition to SluiceGate policy. SCCM collection membership may continue to represent the enterprise patching scope where relevant, but it is not required to be the Minion's execution authority.

### 12.2 Least-privilege execution identity

The Patching Minion shall execute under a dedicated Windows/AD identity with the minimum privileges required for the approved patching capabilities. The identity shall be permitted to invoke Windows Update/WSUS operations on the target server and to perform required local installation and reboot behavior.

A group Managed Service Account (gMSA) is preferred where compatible with the selected hosting/execution approach.

SluiceGate should not store or require the reusable password for the Minion's Windows execution identity.

SCCM RBAC is not the execution authority for this Minion. It may still be used to define the pilot collection, deployment policy, or reporting boundary, but the Minion's operational authorization shall come from the targeted server's Windows Update/WSUS configuration and its permitted local execution identity.

### 12.3 No AI bypass credentials

The requesting AI patching agent should not possess SCCM administrative credentials, direct server administrative credentials, or another privileged mechanism that allows it to perform the controlled patching action outside SluiceGate.

This is a core deployment assumption for SluiceGate to operate as an authoritative control plane.

### 12.4 Minion host

The Patching Minion shall run as a Windows service on the designated SG Windows VM, not as a service installed on each target server. The host shall provide:

- Network access to Minion Central Command, the configured CSV/patch repository, and authorized target servers.
- A supported Windows service runtime and secure execution under the designated AD service identity.
- Secure storage for the Minion private signing key and Minion Central Command API key.
- The approved Patching Minion package and required remote-management components.

The deployment target is Windows Server 2022 with the latest stable Docker version supported for that platform. The Windows service installer and container startup/configuration tooling shall be implemented and tested for this target as part of the Windows deployment package.

---

## 13. Patching Pilot Policy/Test Progression

The pilot should deliberately increase authority in stages.

### Stage 0 — Observe / Dry Run

The AI proposes patch actions and SluiceGate evaluates/logs them, but no Minion execution occurs.

Purpose: validate request normalization, authentication, policy decisions, transaction persistence, and audit behavior before enabling privileged execution.

### Stage 1 — One Patch / One Server

Allow exactly one predetermined patch on exactly one predetermined pilot server, subject to defined policy constraints.

Purpose: validate the complete signed execution chain with the smallest possible blast radius.

### Stage 2 — All Eligible Patches / One Server

Allow the patching agent to request multiple applicable patches on one pilot server, provided each requested action independently satisfies policy.

### Stage 3 — Canary Group

Extend authorized execution to a small subset of pilot servers.

### Stage 4 — Full Pilot Collection

Extend authorized execution to the full approximately twelve-server pilot collection, subject to policy exclusions and PAUSE conditions.

Promotion between stages should require defined success criteria rather than elapsed time alone.

---

## 14. Initial Patching Policy Considerations

The exact policy shall be configured in existing SluiceGate policy functionality. Initial categories should distinguish BLOCK conditions from PAUSE conditions.

### 14.1 Candidate BLOCK conditions

Examples include:

- Target server outside authorized pilot scope.
- Patch explicitly excluded by policy.
- Patch classification not authorized.
- Publisher/source not authorized.
- Requested capability not authorized.
- Attempt to use an unapproved distribution point or patch source.
- Attempt to modify SCCM/WSUS policy.
- Attempt to expand SCCM collection membership.
- Attempt to modify credentials or privileges.
- Attempt to execute arbitrary PowerShell or an undefined Minion capability.

### 14.2 Candidate PAUSE conditions

Examples include:

- Patch requires reboot.
- Server already has a pending reboot.
- Request is outside an approved maintenance window.
- Required prerequisite/dependency requires review.
- Pre-patch health condition is not satisfied.
- Insufficient disk space or other defined operational prerequisite.
- Human approval is required by policy.

Existing SluiceGate policy shall determine how these conditions produce PAUSE and what approval evidence is required. Following approval, the current active policy shall be re-evaluated as specified in Section 6.2; approval alone shall not authorize execution.

---

## 15. Patching Minion Functional Behavior

For an authorized patching Mission, the Patching Minion shall conceptually:

1. Authenticate to Minion Central Command, check in, and claim an unexpired Mission addressed to its registered identity.
2. Validate the signed Task Envelope, intended Minion ID, protocol/capability, expiration, nonce/replay state, target list, patch constraints, reboot constraints, and execution limits.
3. Acknowledge the Mission and report `MISSION_ACKNOWLEDGED` before target-system changes.
4. Read the current patch catalog and Nessus mapping CSV from configured backends/UNC paths using the Minion service identity.
5. Intersect mapping rows with the authorized Mission server list by normalized `DNS_NAME`; join the resulting `PLUGIN_ID` values to current `APPROVED` patch-catalog rows. Apply all Mission constraints, including allowed patch types and reboot permission. The Mission does not carry a patch list, and the Minion shall not process mappings for servers omitted from the Mission.
6. For WSUS OS updates, query each authorized target for applicable updates and install only those whose available update metadata satisfies the Mission constraints. For cataloged Nessus/IAVM patches, process each authorized server/plugin pair from the mapping CSV and corresponding approved catalog row; the Minion shall not invent or infer an additional server/plugin association.
7. Read each candidate patch file from `patch_path` on the approved repository, calculate SHA-256 on the Minion host, and compare it with `patch_sha256` before transfer. Do not transfer or execute a file whose hash fails or whose catalog row is no longer approved.
8. Establish authenticated remote access to the target, copy the verified patch to a controlled target-local staging path, substitute `%PATCHPATH%` with that staged path, resolve the installer executable from the target's `PATH`, and launch it as a remote process using constrained process creation without an unrestricted shell. Reading and verifying the source file on the Minion host before staging avoids requiring the remote target to make a second-hop connection to the patch UNC share.
9. Capture process start/exit status and bounded output; report per-target/per-patch progress to Minion Central Command. A zero exit code is installer-reported success, not independent post-install verification.
10. Reboot only when permitted by the signed Mission and required by the selected patch/install result. Preserve enough local Mission state to resume reporting after the target or Minion host reboots; recheck Mission validity and authorization before any work resumed after expiry or cancellation.
11. Clean up staged files according to configured retention policy, without deleting files owned by another operation.
12. Report terminal per-patch/per-server outcomes and aggregate Mission outcome, including reboot performed/required, source path identifier, hash result, process exit code, and structured failures.

The Minion shall not broaden the Mission's server scope or patch constraints, substitute a different patch, or use an unapproved source. For non-OS IAVM work, the Agent-maintained `PLUGIN_ID,DNS_NAME` mapping is the explicit association between findings and targets; the Minion filters that association to SG-authorized Mission servers and joins it to the catalog. An empty qualifying set shall be reported as a completed no-op with explicit per-target reason codes, not as an install failure. If only some targets or patches succeed, the result shall preserve partial outcomes; the Mission shall not report aggregate success unless all required work succeeded according to the Mission's defined completion rule.

For OS updates already made available through WSUS/SCCM, the Minion uses the target's configured update client and available update metadata; it does not use the non-OS patch catalog. The precise OS-update capability and its metadata-to-policy mapping shall be specified by implementation. For non-OS IAVM patches, the Patching Minion installs the cataloged package using the remote process flow above; it shall not require SCCM communication as the execution authority. If a catalog source is unreachable or the patch cannot be staged, the Minion reports the failure and does not download from an unapproved location.

---

## 16. Transport and Invocation

The Minion Registry shall be transport-neutral.

Future Minions may be invoked through mechanisms such as:

- HTTPS endpoints.
- Local processes.
- Remote execution hosts.
- Approved script/package locations.
- Other authenticated transports.

For the Patching Pilot, a UNC location may be used to identify the approved PowerShell Minion package/script, but the UNC share itself should not necessarily be treated as the security/execution boundary.

The preferred design is for the Patching Minion to execute within a controlled Windows host/runtime that provides a stable execution identity, private-key storage, logging boundary, and appropriate target-server connectivity. The final pilot invocation mechanism remains an implementation decision and should be documented before deployment.

---

## 17. Security Requirements

At minimum:

1. All inbound agent requests shall be authenticated.
2. Agent credentials shall be revocable/disableable.
3. Agent identity shall be supplied to policy evaluation from authenticated Core context, not trusted request parameters.
4. Minion mission envelopes shall be cryptographically signed by SluiceGate.
5. Minions shall verify mission envelope signatures before execution.
6. Minion results shall be cryptographically signed by the Minion.
7. Core shall verify Minion result signatures before trusting them.
8. Replay protection shall be implemented.
9. Minion private keys shall be protected and preferably generated/stored on the Minion host.
10. Minion execution identities shall follow least privilege.
11. AI agents shall not receive Minion execution credentials.
12. AI agents shall not select Minions directly.
13. AI agents shall not receive detailed policy reasoning through the standard action API.
14. Minions shall not expose arbitrary command execution.
15. Minion packages/scripts shall support integrity verification.
16. Persistent audit data shall be protected from unauthorized modification/access.
17. Agent and Minion administrative actions shall themselves be auditable.
18. A compromised or malfunctioning requesting agent shall be rate-limitable and disableable.
19. A compromised or malfunctioning Minion shall be revocable/disableable centrally.

---

## 18. Initial Administrative UI Requirements

### 18.1 Agent Administration

The SluiceGate administrative UI should provide:

- Agent list.
- Register Agent.
- Generate initial API key.
- Display API key once at creation/rotation where appropriate.
- Rotate/revoke credential.
- Enable/disable agent.
- Configure rate limits.
- View last-used/basic activity metadata.

### 18.2 Minion Registry UI

The Minion Registry UI should provide:

- Minion list.
- Create/register Minion.
- View/edit metadata.
- Define supported capabilities.
- Define environment/scope/routing metadata.
- Define transport/location information.
- View public-key fingerprint.
- Initiate/complete enrollment.
- Rotate/revoke keys.
- Enable/disable/revoke Minion.
- Record/display approved package hash/version.
- Display health/last-contact information where supported.
- Display recent task/execution information or link to the corresponding transaction audit view.

### 18.3 Transaction/Audit UI

The administrative interface shall use the same server-authenticated access boundary for Agent Registry and Minion Registry operations. Initial deployments shall not require a separate application RBAC model: users able to authenticate to the SluiceGate server's administrative control plane may manage either registry. This is a pilot simplification, not a claim that server login alone is an appropriate long-term authorization design.

Existing SluiceGate logging interfaces should be enhanced to support persistent transaction-oriented viewing, including:

- Search/filter by transaction/request/mission.
- Requesting Agent.
- Requested capability/target.
- Internal ALLOW/BLOCK/PAUSE decision and reason.
- PAUSE/approval history.
- Selected Minion.
- Mission envelope dispatch/result.
- Signature verification status.
- Final transaction outcome.

This full detail is for authorized human operators, not the requesting AI API.

### 18.4 Notification Profiles

The SluiceGate administrative interface should provide service-owned management for Notification Profiles and configured Notification Adapters, including:

- Create/enable/disable a profile and associate event types with one or more adapter instances.
- Configure recipient references and message templates without placing provider credentials in the profile or exposing them to Agents/Minions.
- Configure a provider secret reference and show adapter health/basic delivery status without revealing secret values.
- View notification attempts and delivery outcomes correlated with transaction/mission audit records.

Only `sg_service` may use these profiles to send messages. A notification-management screen is not a separate Agent or Minion Registry.

---

## 19. Initial Acceptance Criteria

The first release/pilot should demonstrate at least the following.

### 19.1 Agent/API

- A registered AI agent can authenticate using an API key.
- An unregistered/disabled agent cannot submit an action.
- An agent cannot retrieve another agent's request status.
- The agent receives only the defined low-information external status vocabulary.
- Equivalent repeated requests and excessive polling are handled safely according to configured controls.

### 19.2 Policy/Core

- Core assigns persistent transaction identity and records the request.
- Existing SluiceGate policy evaluates the normalized action.
- BLOCK prevents Minion invocation and is persistently audited.
- PAUSE uses SluiceGate PAUSE behavior, persists its state, and prevents mission creation/dispatch until approval/denial/expiry is resolved.
- After approval, policy is re-evaluated using the current policy version, the original action/target, transaction-scoped approval evidence, and refreshed mutable facts where available; no Mission is dispatched unless this evaluation returns ALLOW.
- A policy change while a request is paused is honored at resume, and the original and resumed policy versions/decisions are retained for audit.
- A request that becomes BLOCKED under the current policy while paused remains unexecuted after approval and is exposed to the agent as `CLOSED`.
- ALLOW triggers Minion resolution and signed mission envelope generation.
- An accepted mission survives service restart, is not duplicated by an equivalent request from the same agent while open, and keeps its transaction `IN_PROGRESS` until a terminal result is recorded.
- A Minion can authenticate to Minion Central Command, claim only its assigned Mission, and submit authenticated state transitions; the service does not need to poll Minions for status.
- Every terminal non-success is exposed to the originating agent as `CLOSED`, without a failure reason or category.
- Internal policy reasons are visible to authorized operators but not exposed through the normal agent status API.

### 19.3 Registry/Cryptography

- An administrator can register a Minion.
- Minion Central Command can issue, rotate, disable, and revoke a per-Minion API key; the Minion authenticates without exposing that key in Missions, logs, or process command lines.
- A Minion check-in cannot change its registered capability authorization or claim another Minion's Missions.
- Idle Mission polling cadence is configurable; state changes are reported promptly, independently of the next idle check-in.
- The Minion has a unique cryptographic identity.
- Core can resolve the correct Minion for a supported capability.
- A valid signed mission is accepted by the intended Minion.
- A mission with an invalid signature is rejected without execution.
- An expired mission is rejected without execution.
- A replayed mission is rejected without repeated target action.
- A mission addressed to another Minion is rejected.
- Core rejects or flags a Mission Result Envelope whose Minion signature cannot be verified.

### 19.4 Patching Minion

- The Agent-maintained Nessus mapping CSV associates each `PLUGIN_ID` with one or more `DNS_NAME` values; the Minion joins those associations to approved catalog rows only for servers authorized by the Mission.
- The Patching Minion selects only approved catalog rows that satisfy the Mission's patch-type and reboot constraints.
- The Patching Minion can install a cataloged test patch on an authorized pilot server by verifying its hash, staging the file to the target, and launching the constrained remote installer command.
- WSUS OS-update processing is separate from the Nessus mapping/catalog flow and uses only the authorized targets and Mission constraints.
- A server/plugin association absent from the Agent-maintained mapping is not inferred by the Minion.
- Hash mismatch, inaccessible catalog/share, or malformed mapping/catalog data causes a structured failure/no-install result.
- The Patching Minion cannot be used through the SluiceGate protocol to execute arbitrary PowerShell.
- Retry cadence and timeout behavior follow the signed Task Envelope.
- Execution occurs under the designated least-privilege AD identity.
- No independent post-install confirmation is claimed in the initial implementation; installer exit status and reboot result are reported.
- A structured signed result is returned and persisted.

### 19.5 Demo Integration

- The demo starts against the local SluiceGate source and `sg_service`; it does not require a standalone `sg-core` PyPI release.
- The demo preserves request submission, operator-visible status/details, approve/reject, audit viewing, policy reload, and optional Resend approval notifications.
- An ALLOW action executes only through a signed Mission handled by the registered safe demo stub Minion; BLOCK and unresolved PAUSE never invoke it.
- Approval uses an authenticated explicit confirmation flow, triggers current-policy re-evaluation, and cannot execute an action that the current policy now blocks.
- The demo UI reflects authoritative transaction/audit state from SluiceGate and remains correct across service restarts.
- Missing email notification credentials do not prevent use of the demo's authenticated approval UI.
- No real payment is performed and no production payment credential is needed.

### 19.6 Notification Adapters

- `sg_service` can select and invoke a configured Notification Adapter for a transaction event, including a PAUSE event before any Mission has been created.
- A Notification Adapter can deliver through its configured provider and return a delivery result that is correlated and audited by `sg_service`.
- Notification delivery failure does not independently authorize target-system execution.
- Mission Envelopes contain only authorized Mission Comms references; they contain no Notification Adapter/Profile IDs, recipients, or provider credentials.
- Minions can report status/results through Mission Comms but cannot invoke Notification Adapters or send SluiceGate messages directly.

### 19.7 Auditability

For a completed pilot action, an authorized operator can reconstruct:

1. Which registered AI agent requested the action.
2. What action and target were requested.
3. What SluiceGate policy decision occurred.
4. Whether the action was blocked, paused, or allowed.
5. Which Minion was selected if execution was allowed.
6. What signed mission envelope was issued.
7. Whether Minion validation succeeded.
8. What execution result was returned.
9. Whether the result signature was verified.
10. The final transaction state.

---

## 20. Negative/Security Test Matrix for Patching Pilot

The pilot should intentionally include attempts that SluiceGate is expected to prevent or pause. Example tests include:

| Test | Expected Internal Behavior | Minion Invoked? |
|---|---|---:|
| Agent requests patch reconciliation for authorized server and policy permits matching updates | ALLOW | Yes |
| Agent includes unauthorized server in reconciliation request | BLOCK that target; unauthorized server omitted from Mission | No for unauthorized target |
| Catalog patch excluded by policy constraints | Minion does not install excluded patch and reports filtered/no-op outcome | Yes |
| Reboot-required patch under initial no-reboot policy | Minion filters patch and reports no-op/filtered outcome | Yes |
| Request outside maintenance window | PAUSE if configured | No |
| Undefined patch capability | BLOCK | No |
| Attempted arbitrary PowerShell capability | BLOCK | No |
| Attempt to patch entire enterprise outside scope | BLOCK | No |
| Attempt to alter SCCM collection membership | BLOCK | No |
| Invalid Minion mission envelope signature | Minion REJECTED | Request reached Minion only for protocol validation |
| Expired Minion mission envelope | Minion REJECTED | Request reached Minion only for protocol validation |
| Replayed valid mission | Minion REJECTED | No repeated target action |
| Valid mission with execution failure | Result FAILED | Yes |
| Valid mission exceeding Core-specified timeout | Result TIMED_OUT | Yes |

The external AI response shall remain deliberately less informative than the internal operator/audit record.

---

## 21. Pilot Promotion Criteria

Before expanding authority from one pilot stage to the next, the team should confirm at least:

- No unauthorized target-system action occurred.
- Expected BLOCK cases were blocked.
- Expected PAUSE cases remained unexecuted until policy allowed continuation.
- Minion signature/replay controls operated correctly.
- All executed actions were traceable to signed SluiceGate tasks.
- All returned results were attributable to registered Minions.
- Persistent audit records were complete enough to reconstruct the transaction.
- Operational scope controls remained effective.
- No uncontrolled retry/flood behavior occurred.
- Target-server post-action condition was acceptable for the tested patch scenario.

Exact numeric thresholds and required number of successful executions may be established with the government test team before each promotion.

---

## 22. Open Design Decisions

The following items remain to be resolved/documented during detailed design:

1. Exact persistence/database technology.
2. Exact cryptographic algorithms, certificate formats, and key-storage implementation.
3. Exact Minion enrollment handshake/workflow, beyond host-generated pilot software keys and public-key enrollment.
4. Exact Windows service implementation and deployment-package format, including Windows container-runtime prerequisites and upgrade/uninstall behavior.
5. Minion Central Command API local endpoint binding details and TLS certificate provisioning for the selected deployment.
6. Per-Minion polling/check-in cadence, retry/backoff, and stale-contact/timeout behavior, including final values suitable for long-running patch/install/reboot operations; approximately hourly idle polling is the initial candidate.
7. Exact canonical capability naming/schema conventions.
8. Exact canonicalization/equivalence rules and matching window for idempotency; concurrent equivalent requests from the same agent must never spawn multiple open missions.
9. Exact default Agent API rate limits, polling limits, and escalation/decay behavior for cease-and-desist controls.
10. Exact default Task Envelope retry/timeout values.
11. Exact Minion health/heartbeat model.
12. Whether/how Minion package integrity is checked at every execution versus deployment/startup.
13. Detailed Windows patching implementation, Windows Update/WSUS source validation, and server RBAC model validated against the government environment.
14. Exact handling of asynchronous patch installation and post-reboot completion where installation may continue after the Minion's initial submission; transaction remains `IN_PROGRESS` until terminal completion/failure.
15. Retention period and tamper-resistance requirements for persistent audit data.
16. Exact server authentication integration and operational controls for the initial shared registry-admin boundary. A separate application RBAC model is not required for the pilot; longer-term authorization separation remains a future decision.
17. Notification Profile schema and administrative configuration, including event-to-profile mapping, recipient references, and how sensitive notification content is minimized/redacted.
18. Notification delivery retry/idempotency policy and behavior when a notification cannot be delivered, especially for approval-required PAUSE events. Delivery failure shall never itself authorize execution.

---

## 23. Out of Scope for Initial Pilot

Unless required by the government test environment, the first release should not attempt to implement:

- Automated generation/spawning of Minions from templates.
- A production-ready Windows deployment package that installs/configures the SG Minion service and `sg_service` container on a Windows VM. This is a required follow-on deployment deliverable, but is outside the initial application implementation.
- A generalized AI planner inside SluiceGate.
- Multiple competing Minions with intelligent load balancing.
- A large catalog of production Minions beyond the Patching Minion and the safe demo stub Minion.
- An Email Minion for sending email as a controlled target-system action. The demo's approval-notification email remains an adapter, not a Minion.
- Autonomous Minion decision-making.
- Arbitrary shell/PowerShell execution.
- Full enterprise patch rollout beyond the defined pilot population.
- General-purpose workflow automation unrelated to SluiceGate policy enforcement.

The architecture should permit future expansion without requiring these capabilities in the pilot.

---

## 24. Summary Architecture

```text
REQUESTING AI AGENTS        DEMO UI / BFF
      |                       |
      +---- authenticated APIs+
          |
          v
     +---------------------+
     |  SLUICEGATE SERVICE |
     |     sg_service      |
     | API / transactions  |
     | queue / audit       |
     | signing / verify    |
     +----------+----------+
        |
       policy evaluation
        v
      +-----------+
      |  sg_core  |
      +-----------+
        |
       mission routing
        v
     +---------------------+
     |   MINION REGISTRY   |
     +----------+----------+
        |
       signed Missions
         +------+------+
         |             |
         v             v
    +----------------+  +-------------------+
    | Demo Stub      |  | Patching Minion  |
    | Minion         |  | PowerShell/Windows|
    +-------+--------+  +------+------------+
        |                  |
        v                  v
    Safe demo result    Windows servers

sg_service -- PAUSE event --> Notification Profile --> Demo email Adapter --> Email provider
Human approver --> authenticated admin flow --> sg_service

Minions return authenticated, signed status/results to sg_service through Mission Comms.
Minions have no Notification Adapter route or provider credentials.
```

The target operating model is intentionally simple:

**AI agents request. SluiceGate decides. Minions execute. Target systems perform the underlying operation.**

