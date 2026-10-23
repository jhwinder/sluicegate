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

The PowerShell Minion does not advertise `windows.patch.inspect` or `windows.patch.install` because those handlers are not implemented. The Python implementation is a reference/simulation mirror: it supports dry-run validation only and raises an explicit error if called with `dry_run=False`. Do not use its dry-run success results as evidence that patches were installed.

## Patch Command Authorization

The Agent submits only the requested server names. The service intersects them with the matched policy rule's `allowed_patch_targets.servers` obligation and includes only authorized targets in the signed Mission. The `patch_constraints` obligation supplies patch sources/types, reboot permission, and the maintenance interval; the Minion must not substitute Agent-selected values.

Patch catalog commands are authorized by the matched policy rule, not a Minion-wide executable list. An `ALLOW` rule may include an `allowed_patch_executables` obligation such as `executables: [msiexec.exe]`. The Minion rejects catalog rows whose command does not begin with one of those executable names, and rejects commands when the Mission has no such obligation. See [Policy DSL](../../../docs/Policy_DSL.md#policy-authorized-patch-executables) for the YAML example.

WUA update-classification IDs map to the shared policy vocabulary:

| WUA classification | Policy patch type |
| --- | --- |
| Security Updates | `SECURITY` |
| Feature Packs | `FEATURE` |
| Service Packs | `SERVICE_PACK` |
| Drivers | `DRIVER` |
| Critical Updates | `BUGFIX` |
| Updates, Definition Updates, Tools, Update Rollups | `OTHER` |

The Minion installs only mapped WUA types listed in the signed Mission's `allowed_patch_types`; unmapped or conflicting metadata is `UNKNOWN` and is never installed. Updates requiring reboot are skipped when the signed Mission disallows reboot.

Maintenance intervals use explicit UTC `start_utc` and `end_utc` timestamps. The policy also selects `outside_window_decision: PAUSE` or `BLOCK`. Approval never bypasses the interval; Mission Control withholds claims until it is open, and the Minion rechecks the signed interval before scanning/installing updates and before launching a catalog installer.

## Configuration

Copy `minion.config.example.json` to `minion.config.json` and configure:

- `MissionControlUrl`: must be `https://`; the Minion will not start with plain HTTP.
- `TrustedServerCertificatePath` (optional): PEM file with the provisioned self-signed certificate or private CA. When set, only that certificate chain is trusted and the host name and validity dates are still checked. Omit it to use the Windows trust store.
- `TrustedServerCertificateSha256` (optional): fingerprints of the only certificates allowed in that file; use it to detect an altered trust file. For rotation, list both the old and new certificate until the old one is retired.
- `AllowInsecureHttp` (development only): permits `http://` for a loopback address. Do not set it for a pilot.

Validation failures (untrusted, wrong host name, or expired certificate) appear in the Minion log as `Mission Control TLS validation failed ... : <reason>`.

## Mission Recovery

The current pilot runs one registered Minion identity on one Minion host. Mission Control grants a 120-second claim lease, renewed every 30 seconds with a claim token; a resumed claim rotates the token and increments the claim generation. The PowerShell worker keeps a per-Mission, per-attempt, per-generation Diary in `MissionDiaryDirectory`. A resumed worker verifies the Mission ID and envelope signature against the prior Diary, records a new generation, and retires the prior host Diary only after the new one is durable.

For catalog installs, the target writes a separate operation journal under `C:\ProgramData\SluiceGate\Minion\TargetDiary`. An exclusive per-Mission/target/patch lock prevents overlapping Minion launches. The journal records the installer PID and process start time. A takeover checks that identity and waits for the journal outcome; if state is unreadable or ambiguous, it fails closed rather than rerunning the installer. MSI exit 1618 is treated as another Windows Installer operation being active and is retried according to the signed Mission interval.

The worker reports its own PID and the target process identity in heartbeat details. On an authorized reboot, it records `REBOOTING`, reports `MISSION_WAITING_FOR_REBOOT`, initiates the reboot, and checks the target's boot time on resume so it does not reboot twice. Host and target Diaries are removed only after Mission Control acknowledges a terminal result. This pilot does not support takeover by a different registered Minion host; the Diary is not a shared coordination store.

Operator cancellation is deferred. There is no operator cancellation route or authorization workflow in this pilot, and Mission Control does not terminate active target installers. Missions finish through normal result reporting, configured retries/attempt limits, or expiry.
