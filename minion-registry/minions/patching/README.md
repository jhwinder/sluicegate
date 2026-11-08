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

Maintenance windows are recurring weekly windows (`timezone`, `days`, `start`, `end`). Policy sets `outside_window: WAIT|BLOCK`; with WAIT, Mission Control withholds the claim until the window opens. A PAUSE approval given while the window is closed adds a signed `window_override`, which makes the Minion skip the window. Otherwise the Minion rechecks the window before scanning/installing and before launching a catalog installer, failing closed on an unresolvable timezone.

## Configuration

Copy `minion.config.example.json` to `minion.config.json` and configure:

- `MissionControlUrl`: must be `https://`; the Minion will not start with plain HTTP.
- `ApiKeyPath`: file holding the Minion API key (store it with `deployment/windows/Set-MinionApiKey.ps1`). An inline `ApiKey` setting is rejected, so the configuration file itself contains no secrets.
- `TrustedServerCertificatePath` (optional): PEM file with the provisioned self-signed certificate or private CA. When set, only that certificate chain is trusted and the host name and validity dates are still checked. Omit it to use the Windows trust store.
- `TrustedServerCertificateSha256` (optional): fingerprints of the only certificates allowed in that file; use it to detect an altered trust file. For rotation, list both the old and new certificate until the old one is retired.
- `AllowInsecureHttp` (development only): permits `http://` for a loopback address. Do not set it for a pilot.

Validation failures (untrusted, wrong host name, or expired certificate) appear in the Minion log as `Mission Control TLS validation failed ... : <reason>`.

## Sample CSVs and Safe Test Workflow

The manually triggered **Windows patching Minion smoke test** GitHub Actions workflow runs the real PowerShell worker and Mission Control together on a disposable `windows-2022` runner. The workflow file must first be present on the repository's default branch for GitHub to enable manual runs. Then, in the repository's **Actions** tab, select that workflow, choose **Run workflow**, and select the branch containing it. The job starts an isolated loopback-only service, generates temporary credentials, registers the repository release, and submits signed synthetic catalog patch Missions with `DryRun: true`. It checks a successful hash verification and rejection after the synthetic file changes, then uploads JUnit results.

This is not a Windows service installation or a real patch installation: it does not exercise a second host, WinRM, WSUS, share permissions, reboot or recovery. It also uses loopback HTTP for this isolated test, not the production TLS configuration. GitHub-hosted runners are temporary and Actions usage may be billable; check the repository's billing before running.

The `samples` directory contains `sample-patch-catalog.csv` and `sample-nessus-mapping.csv`. The sample uses the real public Tenable finding [plugin 214542, 7-Zip < 24.09 (ZDI-25-045)](https://www.tenable.com/plugins/nessus/214542), with IAVA `2025-A-0042-S`; the matching CVE is `CVE-2025-0411`. It is still only a template: the catalog row is `DRAFT`, and the target host, staged installer filename, SHA-256, and package reboot behavior must be confirmed in your environment. Do not mark it `APPROVED` or submit it as-is. Nessus must actually detect plugin 214542 on the target for this mapping to match.

For a controlled catalog test, 7-Zip x64 MSI is a simple third-party package to install and inventory. Prefer a disposable Windows test VM; deliberately testing an outdated vulnerable version on the SluiceGate control-plane host increases risk. Run an authorized Nessus scan against the exact host and use the exported finding's `PLUGIN_ID` plus that host's exact `DNS_NAME` in the mapping. Select a finding that corresponds to the installed 7-Zip version, then stage the matching vendor MSI on a Minion-readable share, verify its provenance and SHA-256, and replace every catalog placeholder. Keep the row `DRAFT` while preparing it; only an administrator-approved, hash-verified row should become `APPROVED`.

Start with `DryRun: true`. DryRun can validate the mapping, policy match, executable authorization, package existence, and source hash without installing the MSI. It does not prove the installation succeeds. Only after that review, on a disposable authorized target and within an approved maintenance window, use the normal installation workflow with policy allowing `msiexec.exe`. Nessus `PLUGIN_ID` values are scanner/plugin-version specific; obtain them from your own scan export rather than copying an example ID.

## Mission Recovery

The current pilot runs one registered Minion identity on one Minion host. Mission Control grants a 120-second claim lease, renewed every 30 seconds with a claim token; a resumed claim rotates the token and increments the claim generation. The PowerShell worker keeps a per-Mission, per-attempt, per-generation Diary in `MissionDiaryDirectory`. A resumed worker verifies the Mission ID and envelope signature against the prior Diary, records a new generation, and retires the prior host Diary only after the new one is durable.

For catalog installs, the target writes a separate operation journal under `C:\ProgramData\SluiceGate\Minion\TargetDiary`. An exclusive per-Mission/target/patch lock prevents overlapping Minion launches. The journal records the installer PID and process start time. A takeover checks that identity and waits for the journal outcome; if state is unreadable or ambiguous, it fails closed rather than rerunning the installer. MSI exit 1618 is treated as another Windows Installer operation being active and is retried according to the signed Mission interval.

The worker reports its own PID and the target process identity in heartbeat details. On an authorized reboot, it records `REBOOTING`, reports `MISSION_WAITING_FOR_REBOOT`, initiates the reboot, and checks the target's boot time on resume so it does not reboot twice. Host and target Diaries are removed only after Mission Control acknowledges a terminal result. This pilot does not support takeover by a different registered Minion host; the Diary is not a shared coordination store.

Operator cancellation is deferred. There is no operator cancellation route or authorization workflow in this pilot, and Mission Control does not terminate active target installers. Missions finish through normal result reporting, configured retries/attempt limits, or expiry.
