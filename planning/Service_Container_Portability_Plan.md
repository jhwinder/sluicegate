# SluiceGate Service Container Portability Plan

**Status:** Proposed architecture and feasibility plan  
**Related documents:** [SluiceGate Minion Architecture & Patching Pilot Requirements](SluiceGate_Minions_Requirements.md), [Feature Backlog](Feature_Backlog.md)  
**Decision status:** Pending government deployment-platform decision

## 1. Purpose

Evaluate and plan how to run `sg-service` on both Linux container platforms (including OpenShift) and Windows Server 2022. The current image is Linux-based. That works for Linux container platforms, but Windows Server's Docker Engine runs Windows containers, not Linux containers. This makes a same-host deployment with a Windows Patching Minion problematic when the host is restricted to Windows Server 2022.

This plan proposes keeping the existing Linux image for OpenShift/Linux and investigating a separate Windows Server 2022 image built from the same Python application source. The first step is a small feasibility spike, not an immediate rewrite or a commitment to Windows containers as the only deployment model.

## 2. Current State

- `sg-service` is a Python 3.12 FastAPI application packaged by [sg-service/Dockerfile](../sg-service/Dockerfile) on `python:3.12-slim` Linux images.
- The service uses SQLite, Ed25519 keys, environment-configured paths, and static HTML assets. The application source is primarily platform-neutral Python.
- The Linux container expects paths such as `/data/sg-service.sqlite3`, `/run/secrets/sg-signing-key.pem`, and `/config/policy.yml`.
- The current Windows deployment assumes that a Linux service container can run locally through Docker on the Windows Minion host. That assumption is not supported by the Windows Server Docker Engine.
- The Windows Service is a separate C# process that launches the PowerShell Patching Minion. It communicates with `sg-service` over HTTP(S); it need not share the same OS image or container.

## 3. Proposed Architecture

Keep one application source tree and build two platform-specific service images:

```text
                          +-----------------------------+
                          | Shared sg-service source    |
                          | FastAPI / policy / SQLite   |
                          +--------------+--------------+
                                         |
                   +---------------------+---------------------+
                   |                                           |
                   v                                           v
       Linux image / OpenShift                         Windows image
    Linux container runtime                         Windows Server 2022
                   |                                           |
                   +------------------- HTTPS ----------------+
                                       ^
                                       |
                         Windows Minion Service
                         PowerShell patch runtime
```

The image is a packaging and runtime-target choice, not a second implementation of policy or service behavior. Platform-specific differences should be limited to the container base image, Python installation/dependencies, filesystem locations, entrypoint, health checks, and deployment manifests.

The Linux image remains the supported path for OpenShift and Linux hosts. A Windows image is considered only for the Windows Server 2022 same-host deployment scenario. If the government team selects OpenShift or a separate Linux host, there may be no need to build or maintain the Windows image; the Windows Minion can call the remote service endpoint over TLS.

## 4. Portability Assessment

### 4.1 Likely portable

- FastAPI, Uvicorn, Python policy and request logic.
- SQLite and cryptographic operations using maintained Python packages, subject to Windows wheel availability.
- Service configuration via environment variables.
- Static admin HTML packaged with the Python distribution.

### 4.2 Work to investigate or adapt

- **Base image and Python distribution:** Select and pin a Windows Server Core or Nano Server-compatible Python image/runtime. Confirm all dependencies, especially `cryptography`, have usable Windows x64 wheels and do not require an unsupported native build toolchain.
- **Filesystem configuration:** Make database, policy, and signing-key paths configurable and use Windows-compatible paths in the Windows deployment. Do not make the application assume POSIX mount paths.
- **Persistent storage:** Mount a Windows directory/volume for the SQLite database. Validate filesystem permissions, SQLite locking, process shutdown, and backup/restore on the selected container storage.
- **Secrets and policy files:** Define how Windows host files are mounted or injected and ACLed. Do not bake private keys, API keys, populated environment files, or production policy into the image.
- **Process lifecycle:** Run Uvicorn as the foreground container process, handle termination signals/shutdown, and provide health/readiness checks that work with the selected Windows container runtime.
- **Networking:** Bind the service to the container interface; publish only an appropriately restricted host endpoint. Minion-to-service traffic must use TLS and server identity validation.
- **Image/host compatibility:** A Windows Server 2022 host requires a compatible Windows Server 2022-based image and appropriate isolation mode. Pin the OS image tag and validate the host/image patch compatibility requirements.
- **Image distribution:** Build and publish the Windows image from Windows-capable CI/build infrastructure, then pull it from a registry or package it for offline import. A Windows image cannot be run on the Mac's Linux Docker Desktop VM.
- **Operational support:** Define Windows base-image servicing, Python/runtime patching, vulnerability scanning, image rebuild cadence, and support ownership separately from the Linux image.

## 5. MacBook Development Model

A MacBook remains suitable for most day-to-day development:

1. Develop and unit-test the shared Python application locally with `uv`.
2. Build and run the Linux image using Docker Desktop for local service and demo integration tests.
3. Keep a Windows-specific Dockerfile and deployment files in the repository, but do not expect Docker Desktop on macOS to execute that Windows image.
4. Build the Windows image in a Windows Server 2022 CI runner or a dedicated Windows build machine with the Windows container engine.
5. Run Windows image smoke/integration tests on a compatible Windows Server 2022 test host. The deployment target should also be tested with the exact OS edition, Docker Engine/runtime, storage layout, TLS configuration, and security policy the government environment uses.
6. Publish platform-specific image tags or manifests from the same source revision, for example `sg-service:<version>-linux` and `sg-service:<version>-windows-ltsc2022`. Do not advertise a multi-platform manifest as runnable everywhere unless each variant has actually been built and tested.

The Windows build/test host is a delivery prerequisite for the Windows image, but not for ordinary Python development. The checked-in Windows Minion Service executable is separately built for Windows and does not prove that the `sg-service` container image can be built or run there.

## 6. Feasibility Spike

Time-box the initial investigation to a small vertical slice before committing to a production image.

### Spike tasks

1. Add a separate Windows container Dockerfile without changing the Linux Dockerfile.
2. Build a minimal Windows image from a Windows Server 2022-compatible Python base and install the service wheels/dependencies.
3. Start `sg-service` as the foreground process with temporary local test configuration.
4. Confirm `/health`, `/admin/ui`, policy loading, signing-key loading, SQLite initialization, and an authenticated API request.
5. Persist a Mission/registration, stop and restart the container, and confirm state survives via a mounted Windows volume.
6. Confirm the Windows Minion host can reach Mission Control over TLS, including self-signed certificate trust if that remains the selected certificate approach.
7. Measure image size, cold-start time, memory/CPU use, and the amount of duplicated build/deployment configuration.
8. Record base-image lifecycle, patching mechanism, CVE-scanning support, and a repeatable image update procedure.

### Go/no-go criteria

Proceed with a supported Windows image only if:

- All runtime dependencies install from maintained Windows x64 packages without fragile hand-built native dependencies.
- The service starts and behaves correctly as a Windows container on the intended Server 2022 host/runtime.
- SQLite persistence and secret/policy file handling meet the deployment security requirements.
- TLS and Minion connectivity work without bypassing certificate validation.
- The team has an ongoing Windows build runner and can regularly rebuild, patch, scan, and publish the Windows base image.
- The government team prefers co-location strongly enough to justify maintaining a second container target.

If these conditions are not met, prefer running `sg-service` on OpenShift or a separate supported Linux VM/host and connecting the Windows Minion to it over TLS.

## 7. Implementation Phases After Go Decision

### Phase A: Configuration and runtime portability

- Remove assumptions that service paths use POSIX-only locations; document the environment-variable contract and choose platform-specific defaults only where required.
- Add startup validation for writable database location, readable policy/signing key, and required credentials.
- Define graceful process shutdown and health/readiness behavior.

### Phase B: Windows image and deployment assets

- Add a Windows Server 2022-compatible Dockerfile and image build pipeline while retaining the Linux image unchanged.
- Add Windows-specific image configuration, volume mounts, log collection, health check, and startup command.
- Update the Windows deployment package so it starts the Windows `sg-service` image rather than expecting a Linux image.
- Keep the Windows Minion service and service container as separate processes/containers with explicit configuration and restart behavior.

### Phase C: Validation and release

- Add CI checks for both image builds and shared service tests.
- Run platform-specific integration tests on Linux/OpenShift and Windows Server 2022.
- Validate container startup, persistent database behavior, TLS, secrets, upgrades, rollback, and clean shutdown.
- Publish both image variants from the same tagged source revision and document which runtime/platform each tag supports.

## 8. Security And Operations Constraints

- Containerization does not grant the service an AD execution identity; the Windows Minion continues to run under its separately configured least-privilege Windows service identity.
- The service container must not receive target-server administrative credentials.
- Keep the service signing key and Minion/admin/API credentials in protected host/platform secret storage, not in image layers or source control.
- Expose Mission Control only on an approved interface and require TLS for Minion API keys and Mission traffic.
- Use a persistent volume for SQLite and explicitly limit the initial SQLite deployment to one active service replica. If high availability or multiple replicas become necessary, plan a database migration rather than sharing SQLite over an arbitrary network filesystem.
- Windows base images are version-sensitive and need a documented servicing/rebuild process. Do not assume a Windows image built on a different OS generation will run on Server 2022.

## 9. Open Decisions

1. Is same-host co-location of `sg-service` and the Windows Minion required, or is a remote OpenShift/Linux endpoint acceptable?
2. Which Windows Server 2022 edition, virtualization features, Docker Engine/runtime, and isolation mode will the approved host provide?
3. Can the organization provide a Windows Server 2022 CI/build runner and a test host with the required container features?
4. Which Windows Python base image and servicing lifecycle are approved?
5. What Windows host paths and ACL model should hold SQLite, policy, TLS trust material, signing keys, and service environment configuration?
6. Is the Windows image required for production, or only for an isolated pilot deployment?
7. What are the image retention, vulnerability scanning, signing, and release approval requirements for the Windows image?

No Windows image implementation is authorized by this planning document alone; the container platform decision and spike results should be reviewed before committing to the second image target.
