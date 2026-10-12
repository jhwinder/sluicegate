# Patching Agent Plan

**Status:** Proposed workflow and implementation plan  
**Related requirements:** [SluiceGate Minion Architecture & Patching Pilot Requirements](SluiceGate_Minions_Requirements.md)

## Purpose and Boundary

The Patching Agent prepares approved non-OS IAVM remediation content for the Patching Minion. It analyzes Nessus findings, obtains vendor patch packages and installation metadata, stores packages in a designated network repository, and maintains the SluiceGate Minion's patch-registry CSV.

The Agent does not authorize or install patches. SluiceGate policy authorizes target servers and patch constraints; the Patching Minion joins the Agent-maintained `PLUGIN_ID,DNS_NAME` mapping to the patch registry and executes only qualifying rows under the signed Mission Envelope.

This plan covers the connected patch-preparation environment and the data it publishes to its designated repository. It does **not** include:

- Generating or maintaining the separate `PLUGIN_ID,DNS_NAME` mapping file on the SluiceGate/target-server air-gapped network. That tooling is a separate project.
- Transferring the mapping CSV, patch-registry CSV, or patch files across the air gap. An out-of-band process will be designed and governed separately.
- Installing Windows OS updates delivered by SCCM/WSUS. Those updates are handled through the OS-patching Mission path.
- Direct access to target servers, SCCM/WSUS administration, SluiceGate Mission authorization, or patch installation.

## Inputs

- Nessus scan reports containing plugin findings and affected host identifiers.
- An operator-maintained list of machines in the remediation scope.
- Vendor security advisories and official package download locations.
- A configured internal network-share repository for approved package files.
- The current Patching Minion patch-registry CSV and its agreed schema.
- A controlled `patch_type` vocabulary shared with SluiceGate policy, initially including `SECURITY`, `FEATURE`, `SERVICE_PACK`, `DRIVER`, `BUGFIX`, `OTHER`, and `UNKNOWN`.

The Agent shall treat a Nessus plugin finding on a host as the source association for remediation. It shall not infer that a finding applies to other machines merely because they share a product or network segment.

## Core Tasks

### 1. Ingest and Analyze Nessus Reports

- Accept configured Nessus export formats and validate schema/version before processing.
- Extract plugin identifier, IAVM identifier where present, host DNS name, plugin output/severity, and scan/report timestamp.
- Normalize host and plugin identifiers without discarding source values needed for traceability.
- Exclude findings already resolved, informational-only findings, and operating-system updates delegated to SCCM/WSUS according to configurable rules.
- Correlate findings to the supplied machine scope and report unknown/unmatched hosts for operator resolution.
- Produce a reviewable candidate set of host/plugin findings; do not treat model-generated patch recommendations as approved catalog entries.

### 2. Find and Prepare Non-OS Patches

For each distinct eligible Nessus `plugin_id` in scope:

- Research the vendor advisory and determine whether a non-OS patch addresses the finding.
- Prefer the vendor's official distribution source; record its URL as provenance.
- Determine package identity, product title, patch title, patch classification, reboot requirement, and vendor-provided silent installation command.
- Distinguish package prerequisites, architecture/product applicability, and known conflicts. These are review inputs for the catalog-maintenance process; they do not authorize broader targets.
- Download the package into a temporary quarantine/staging area, verify that it is a supported package type, calculate SHA-256, and scan it using the organization's separate content-security controls.
- Do not download or register packages for OS patches already managed by SCCM/WSUS.
- Do not publish arbitrary shell/PowerShell payloads as `install_command`. The command is executable configuration with Minion privileges and must be bounded, reviewed, and tested for the package type.
- If the correct patch, source, reboot behavior, or silent command cannot be established, leave the entry unapproved and report it for human review; do not invent these values.

AI may assist with advisory research, field extraction, and candidate command drafting. Any controls required to approve, test, or review AI-generated catalog content must be defined by the patch-repository owner; a successful hash check by the Minion does not establish that the catalog instructions themselves are safe or correct.

### 3. Publish Packages to the Designated Network Share

- Store each package under a deterministic, non-overwriting path rooted in the configured patch repository.
- Verify the final file's SHA-256 after copying into its published location.
- Avoid replacing a package file in place while an approved CSV row points to it. Publish a new path first, then publish the matching catalog row.
- Apply repository ACLs through infrastructure administration, not by the Agent. The Agent receives only the rights needed to stage/publish content and update the catalog.
- Never publish credentials, temporary download tokens, or unreviewed files in catalog notes or package paths.

### 4. Maintain the Patch Registry CSV

The Agent shall maintain UTF-8 CSV with one current row per Nessus `plugin_id`, using the exact schema defined in the Minion Requirements document:

```text
patch_status,
plugin_id,
iavm_id,
vendor,
title,
patch_id,
patch_title,
patch_type,
requires_reboot,
patch_path,
patch_sha256,
source_url,
install_command,
notes
```

The canonical header is one CSV header record, not a multi-line header. Required behaviors:

- Validate the header names, field count, encoding, quoting, and required values before publication.
- Maintain at most one active (`DRAFT` or `APPROVED`) row per `plugin_id`. When a patch is superseded or withdrawn, mark the existing row `RETIRED` and create a new row with the replacement patch details. Historical `RETIRED` rows remain in the single CSV for audit.
- Use `patch_status` values `DRAFT`, `APPROVED`, or `RETIRED`. The agent marks all newly downloaded candidate patches as `DRAFT`. A human operator reviews candidate rows and updates `patch_status` to `APPROVED`. Only rows in `APPROVED` status are eligible for execution by the Minion.
- Limit `patch_type` to the shared vocabulary. Use `UNKNOWN` rather than guessing; allow-only SluiceGate rules should not authorize unknown classifications.
- Store `requires_reboot` as a CSV boolean (`true`/`false`). Use `patch_path` for the internal share location and `patch_sha256` for the exact package hash.
- Store `source_url` as provenance only; it is not an instruction for the Minion to download directly from the Internet.
- Store `install_command` using the Minion contract's supported `%PATCHPATH%` token. The command must use an executable available on the target server's PATH and pass the staged target-local file path correctly.
- Do not add post-install confirmation fields unless the Minion schema is deliberately revised.
- Validate the generated CSV by parsing it back and checking that every approved row resolves to an existing package whose digest matches `patch_sha256`.
- Publish the new CSV atomically (write a temporary complete file, validate it, then replace/publish the current file) so the Minion cannot observe a partial update.
- Keep a separate change/audit log for catalog revisions, approvals, source advisory, package digest, and publishing identity; the Minion CSV itself has no record-version field.

Example row shape (illustrative only):

```csv
patch_status,plugin_id,iavm_id,vendor,title,patch_id,patch_title,patch_type,requires_reboot,patch_path,patch_sha256,source_url,install_command,notes
APPROVED,123456,IAVM-2026-001,Adobe,Acrobat,AA123,"Acrobat Security Update 2026",SECURITY,false,"\\patchshare\approved\Adobe\Acrobat\AcrobatUpdate.msp",<64-hex-sha256>,https://vendor.example/advisory,"msiexec.exe /p ""%PATCHPATH%"" /qn /norestart","Reviewed package metadata"
```

## Workflow

1. Receive a Nessus report and an operator-provided machine scope.
2. Parse, validate, normalize, and de-duplicate findings.
3. Exclude OS-update findings and findings outside the provided scope.
4. Build a review queue keyed by `plugin_id`, retaining the affected hosts and source report references.
5. Find the vendor package and silent-install metadata for eligible non-OS findings.
6. Download, stage, validate, hash, and publish each candidate patch package to the designated network share.
7. Build or update one patch-registry row per plugin; do not mark entries `APPROVED` until package and metadata checks pass.
8. Validate the complete CSV and all referenced files, then publish it atomically.
9. Produce an operator summary listing published entries, unresolved findings, skipped OS findings, failures, and required human review.
10. Leave air-gap transfer to the separate out-of-band process. That process must transfer the patch registry and patch files as a consistent set and verify hashes after transfer.

## Failure and Safety Behavior

- Unsupported report format or invalid/missing host/plugin fields: reject the report or affected records and report actionable validation errors.
- Nessus host absent from operator scope: do not prepare a patch row for that host; report the mismatch.
- OS patch finding: classify as SCCM/WSUS-managed and exclude from this Agent's package-download workflow.
- No authoritative vendor source or ambiguous package: leave `DRAFT`/unpublished and request review.
- Download failure, digest mismatch, failed content scan, or catalog validation error: do not publish `APPROVED`.
- Duplicate plugin records with conflicting package metadata: stop publication for that plugin and require resolution.
- Share or CSV publication failure: retain the previous published catalog and report failure; never expose a partially written catalog.
- Out-of-band transfer mismatch: destination content remains unavailable to the Patching Minion until the transfer process verifies the package hash and matching CSV version as a consistent batch.

## Operational Configuration

At minimum, configure:

- Nessus report input location and supported export format/version.
- Operator-supplied machine scope source.
- Patch repository UNC root and staging/quarantine locations.
- Current catalog CSV location and publication mechanism.
- Vendor-source allowlist and package/content scanning integration.
- Shared `patch_type` vocabulary and OS/SCCM exclusion rules.
- Human review/approval workflow for catalog entries and install commands.
- Retention for source reports, staged downloads, published packages, and Agent audit records.
- Secret storage for any vendor/repository credentials; credentials shall not be written to CSV.

## Acceptance Criteria

- The Agent correctly extracts plugin/host finding pairs from supported Nessus reports and identifies malformed rows.
- The Agent processes only hosts in the operator-provided remediation scope.
- OS/SCCM/WSUS findings are excluded from non-OS package acquisition.
- Each approved catalog row maps to exactly one current `plugin_id` and an existing patch file on the configured share.
- CSV fields and values match the Minion Requirements contract; unsupported or missing values cannot become `APPROVED`.
- `patch_sha256` matches the package bytes at the published path and can be independently rechecked.
- `install_command` is preserved as a validated vendor instruction using `%PATCHPATH%`, not altered or run by the Agent against target servers.
- Publication is atomic and preserves the previous valid catalog on failure.
- Agent output clearly separates approved entries, unresolved findings, errors, and findings excluded as OS updates.
- The Agent has no SluiceGate Minion credentials and does not submit Missions or install packages on servers.
- The separate `PLUGIN_ID,DNS_NAME` mapping generator and air-gap transfer tooling are documented as external dependencies and are not silently implemented as part of this Agent.
- If the patch for a given plugin_id is not clear for any reason (for example, a plugin_id that can be fixed by more than one package, or a plugin_id that has no patch) then escalate to a human for review.
- All newly downloaded patches will be marked as `DRAFT` by the agent.  A human will review, and flip rows to `APPROVED` as desired.  If the agent wants to withdraw a patch for a given finding that was previously in `DRAFT`/`APPROVED` status, rather than just overwriting the row the agent should change the status to `RETIRED` and create a new row.  At all times, just the one CSV will be managed.

## Deferred Decisions

- Exact Nessus report export format(s) and update cadence.
- Exact AI model/tooling and human approval requirements for vendor research and install-command changes.
- Package scanning and vendor-signature verification integrations.
- Out-of-band batch manifest format, transfer media/channel, integrity attestation, and destination-side installation process; these belong to the separate air-gap transfer project.
- Whether the catalog later moves from CSV to SQL/ODBC, while preserving the same logical record contract consumed by the Minion.
