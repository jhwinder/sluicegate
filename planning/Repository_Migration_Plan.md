# SluiceGate Repository Migration Plan

**Status:** Proposed execution plan  
**Related requirements:** [SluiceGate Minion Architecture & Patching Pilot Requirements](SluiceGate_Minions_Requirements.md)

## Recommendation

Execute the repository restructuring **before implementing the new `sg_service`, Minion Central Command, Patching Minion, and deployment-package features**. Do not wait until all new code has been written: building those features inside the legacy layout would create avoidable path changes across imports, package builds, Docker contexts, tests, CI, and deployment artifacts.

First complete an inventory and baseline verification in the current layout. Then perform the structural move as a dedicated, reviewable change and prove that existing Core, policy editor, and demo workflows still build/run. Only after that checkpoint should new service and Minion implementation begin in their intended locations. This is a sequencing recommendation, not a requirement to move all existing files in one risky operation.

**Ordering decision:** perform the source/layout migration for existing code **before** implementing the new `sg_service`, Patching Minion, and Windows deployment features. The sequence is baseline -> move existing owned code and repair builds -> verify the migrated baseline -> implement new features. It is not necessary to create empty target packages or fully implement the future service during the restructuring phase.

## Target Layout

```text
sluice/
  open-core/                 # existing sg_core and Core-coupled sg_poledit distribution
  sg-service/                # new sg_service distribution/application
  minion-registry/           # protocol, optional registry code, templates, Minion sources
  deployment/
    windows/                 # Windows Minion service and deployment package
    containers/              # shared container assets, if needed
  sluice-demo/               # demo UI/BFF and reference Compose deployment
  docs/
  planning/
  tools/                     # only maintained repository-wide tooling
  sdk/                       # only when supported client SDKs are implemented
```

Do not create empty packages solely to fill out the layout. In particular, `sg_cli`, `sg_adapters`, and `sg_sdk` are currently empty scaffolds in the inspected workspace; inventory tracked contents/history before removing or assigning them. Keep policy evaluation in `open-core`; service APIs/transactions/queue/Mission Central Command in `sg-service`; privileged target operations in Minion implementations; and installation/host configuration in `deployment`.

## Migration Sequence

### Phase 0: Inventory and Baseline

1. Record the current commit and working-tree state; do not discard existing user changes.
2. Inventory tracked files, package distributions, import paths, console-script entry points, tests, lockfiles, Dockerfiles/Compose contexts, policy/config paths, CI workflows, scripts, docs links, and generated artifacts.
3. Inspect Git history for the empty scaffold directories and determine whether any external import/CLI compatibility commitments exist.
4. Run and record existing Core tests, policy-editor checks, demo build/run checks, and `git diff --check`. Separate pre-existing failures from migration regressions.
5. Agree on supported public Core imports, `sg-poledit` behavior, licensing boundaries, and whether the existing `sg-core` PyPI release remains maintained independently.

**Exit gate:** Inventory and baseline are reviewed; every tracked source/config file has an intended owner or an explicit deferred disposition.

### Phase 1: Establish the Target Structure

1. Move the existing `open-core/` project only as needed to ensure its directory/package name is intentional; retain its current independent `pyproject.toml` and `sg-core` distribution unless a separate packaging decision says otherwise.
2. Keep `sg_core` and Core-coupled `sg_poledit` together in the Core distribution for this migration. Do not mix `sg_service` into that wheel.
3. Create only the minimal `sg-service/`, `minion-registry/`, and `deployment/` directories needed for maintained contracts, initial service source, or deployment source. The new service gets its own `pyproject.toml`; a registry distribution is conditional on actual Python registry code.
4. Move Minion template and demo/Patching Minion source to the agreed `minion-registry/templates/` and `minion-registry/minions/{demo_stub,patching}/` paths when those files exist.
5. Keep the existing demo as a consumer. Do not use it as the owner of authoritative service state or privileged patch execution.
6. Preserve history where practical; keep moves and behavioral changes separate so reviewers can distinguish path-only changes from new behavior.

**Exit gate:** Imports and package builds work from the new paths; no new feature behavior is required to pass this gate.

### Phase 2: Repair Build and Developer Workflows

1. Update package discovery, editable/local dependencies, entry points, and developer commands for each moved project.
2. Add a root-level workspace/lock or documented multi-project setup only if it improves reproducibility without coupling independently built packages accidentally.
3. Update Docker build contexts, Compose files, mounts, policy/config paths, and local environment variables to use the new layout.
4. Update CI paths and add separate Core build/test and repository integration checks.
5. Update root/component READMEs, architecture docs, and contribution instructions; remove stale path references after a repository-wide search.

**Exit gate:** Core builds/tests independently; the demo starts using the intended local source paths; CI validates paths and package boundaries.

### Phase 3: Introduce New Features in Their Owning Projects

1. Implement `sg_service` in `sg-service/`, consuming the local `sg_core` source from the same repository revision.
2. Implement Mission Central Command and its persistent Mission lifecycle in `sg_service`; the initial Minion interaction is authenticated Minion polling/check-in and Minion-submitted status updates. Do not implement a service-side Minion polling loop for operational status.
3. Implement the Minion protocol and functional Minion source under `minion-registry/`; do not place privileged operations in `sg_core` or the demo.
4. Implement the Patching Minion CSV readers, Nessus `PLUGIN_ID,DNS_NAME` join, patch catalog join, SHA-256 verification, remote staging/process execution, reboot resumption, and structured status reporting under the Minion boundary.
5. Create Windows deployment tooling under `deployment/windows/` for the required Windows Server 2022 target using the latest stable Docker version supported on that platform. Include the Windows SG Minion service installation/configuration, Docker/container startup and configuration, Minion Central Command endpoint configuration, health/logging, and upgrade/uninstall operations. Add deployment scripts, package assets, documentation, and tests as needed; do not defer this tooling to a later project phase. The installer and image-bundle scripts are implemented, but a production Windows Minion service executable is not yet present; building a complete deployable bundle is blocked until that runtime is implemented, signed, and tested.
6. Migrate the demo to exercise `sg_service` and the safe demo Minion over the same Mission protocol.

**Exit gate:** Focused unit/integration tests cover each owner boundary; the demo demonstrates the complete signed Mission/Result loop; no real payment or unapproved patch operation is possible.

### Phase 4: Compatibility Cleanup and Release Readiness

1. Search all tracked files for legacy paths, imports, CLI aliases, and packaging assumptions.
2. Retain compatibility shims only when needed by a documented consumer; give each a deprecation/removal plan.
3. Verify a clean checkout can install/build/test each intended package and reproduce the local demo without depending on an independently published `sg-core` release.
4. Verify container and Windows deployment artifacts are built from one tagged/tested repository revision and have documented configuration/upgrade/uninstall steps.
5. Review the final diff for accidental policy, protocol, licensing, or trust-boundary changes.

**Exit gate:** CI and release checks pass from a clean checkout; documentation and actual paths agree.

## Validation Checklist

- `sg_core` imports, tests, public API, and `sg-core` distribution build remain valid.
- `sg_poledit` entry point and policy editor work from their intended owner project.
- No service/API/queue/Minion dispatch implementation is added to the Core package.
- `sg_service` resolves the local Core package deterministically without a PyPI bootstrap dependency.
- Minion Central Command and Minion protocol schemas are versioned and covered by tests.
- Demo Compose builds from the repository and uses service-owned authoritative state.
- Windows deployment tooling installs/configures the SG Minion Windows service and starts/configures the `sg_service` container on Windows Server 2022 with the latest stable Docker version supported on that platform.
- Windows deployment package tests cover install/configuration, service and container startup, upgrade, and uninstall behavior without provisioning AD credentials or granting target permissions implicitly.
- No secret, AD credential, API key, or private signing key is included in source, image defaults, Missions, or logs.
- Repository-wide searches find no broken old path/import/documentation references.

## Explicitly Deferred Decisions

This plan does not decide whether the `sg-core` PyPI package will receive future releases, whether the Minion Registry becomes a separately installable service, or which root workspace tool is used. The deployment target is Windows Server 2022 and the latest stable Docker version supported on that platform; deployment tooling for that target is in scope and shall be created during this plan.
