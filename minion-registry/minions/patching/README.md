# SluiceGate Windows Patching Minion

This directory contains the SluiceGate Windows Patching Minion runtime, implementing policy-constrained OS and non-OS IAVM patching on target servers without requiring SCCM as an execution authority.

## Architecture

- **`PatchingMinion.ps1`**: The main Minion entry point and worker pass. Connects to SluiceGate Minion Mission Control via HTTP/TLS, claims missions assigned to `PATCH-01`, validates SluiceGate cryptographic signatures, and executes reconciliation.
- **`PatchingCatalog.psm1`**:
  - `Import-PatchCatalog`: Reads the patch catalog CSV (schema matching Section 3.5 of the Requirements document), enforces that only `APPROVED` rows are processed, and validates uniqueness per `plugin_id`.
  - `Import-NessusMapping`: Reads the separate `PLUGIN_ID,DNS_NAME` CSV mapping.
  - `Resolve-TargetPatches`: Intersects the authorized servers in the Mission Envelope with the mapping, joins to approved catalog rows, and filters by Mission constraints (`allowed_patch_types`, `allow_reboot`).
- **`PatchingEngine.psm1`**:
  - `Test-PatchFileHash`: Performs pre-flight SHA-256 verification of the patch file against the catalog digest before staging.
  - `Invoke-TargetPatchInstall`: Stages the patch file onto the target server, substitutes `%PATCHPATH%` in `install_command`, executes the process directly without an unrestricted shell, captures exit codes, detects reboot requirements, and cleans up staging files.
  - `Invoke-TargetWsusUpdate`: Invokes the target server's Windows Update Agent (WUA) COM session to detect and install pending WSUS updates.
  - `Invoke-PatchReconcile`: Orchestrates the complete `windows.patch.reconcile` capability across all authorized targets and aggregates the structured result.

## Capabilities

- `windows.patch.reconcile`: Full multi-target reconciliation of WSUS updates and Nessus catalog patches according to Mission constraints.
- `windows.patch.discover`: Reads and reports available catalog and mapping status.
- `windows.patch.status`: Reports Minion health and reachability.

## Configuration

Copy `minion.config.example.json` to `minion.config.json` and configure:
- `MissionControlUrl`: URL to SluiceGate Service (e.g. `https://127.0.0.1:8443`).
- `MinionId`: Registered Minion identifier (`PATCH-01`).
- `ApiKey`: Per-Minion API key issued by SluiceGate Mission Control.
- `SluiceGatePublicKeyPath`: Path to SluiceGate's Ed25519 public key.
- `MinionPrivateKeyPath`: Path to Minion's Ed25519 private key.
- `CatalogPath`: UNC path to the patch catalog CSV.
- `NessusMappingPath`: UNC path to the `PLUGIN_ID,DNS_NAME` mapping CSV.
- `DryRun`: If true, validates files, hashes, and connectivity without performing target installations.
