# Mission Status Events

Minions authenticate to Minion Mission Control with a per-Minon API key and submit status events after state changes. Idle claim polling is configurable (initial candidate: one hour). Status updates are event-driven and shall not wait for the next idle poll.

Initial event names:

- `MISSION_ACKNOWLEDGED`
- `MISSION_IN_PROGRESS`
- `MISSION_WAITING_FOR_REBOOT`
- `MISSION_COMPLETE_SUCCEEDED`
- `MISSION_COMPLETE_PARTIAL`
- `MISSION_COMPLETE_FAILED`
- `MISSION_REJECTED`
- `MISSION_CANCELLED`
- `MISSION_EXPIRED`

Status updates identify the mission, event name, occurrence time, and bounded structured detail. The service validates Minion identity, Mission assignment, current claim token/lease, and allowed state transition before persistence. Duplicate submissions are idempotent. Mission status detail is operator-facing; the originating Agent receives only aggregate request status.

Claiming a Mission returns a random claim token that fences later heartbeat, status, and result submissions. Mission Control stores only its hash. The active Minion renews the lease through `POST /internal/v1/minions/{minion_id}/missions/{mission_id}/heartbeat`; the heartbeat includes the worker process ID/start time and bounded target-process details. If the lease expires, Mission Control may reissue the same Mission to the same registered Minion identity with a new claim token and incremented claim generation. Requests carrying an old token are rejected.

The single-host pilot stores per-Mission attempt/generation state in a protected local Mission Diary. A takeover verifies the Diary against the same Mission/envelope before resuming. Cross-host Minion takeover is not supported by this local-diary design.

## Initial Pilot Timing Defaults

The following values are initial configurable pilot defaults:

| Setting | Default | Meaning |
| --- | ---: | --- |
| Idle claim poll interval | 3600 seconds | Wait between checks when no Mission is available. |
| Retry interval | 30 seconds | Wait before retrying an eligible failed attempt. |
| Per-attempt timeout | 300 seconds | Maximum duration of one execution attempt. |
| Overall timeout | 900 seconds | Maximum elapsed execution time across attempts. |
| Heartbeat interval | 30 seconds | How often an active Minion renews its Mission claim. |
| Claim lease | 120 seconds | How long an active claim remains valid without renewal. |

The lease must exceed the heartbeat interval. Retry, timeout, heartbeat, and lease values are service-controlled execution instructions, not Agent-selected options. The effective Mission values must be signed and honored by the Minion.

## Claim Ownership and Recovery

Claiming a Mission creates an exclusive, time-limited lease for the registered Minion identity. Mission Control returns a random claim token; it stores only the token hash. The Minion includes the current token in heartbeat, status, and result requests. A heartbeat renews the lease and records the PowerShell worker PID/start time plus bounded current process details. Once the lease expires, the previous token is fenced and cannot update Mission state.

This pilot supports one registered Minion identity on one Minion host. A worker restart or lease takeover on that host rotates the claim token and increments `claim_generation`. If the previous attempt remains within its attempt/overall deadline, the same attempt resumes; after a signed retryable timeout, the service waits `retry_interval_seconds` and issues the next bounded attempt. The service expires Missions after `overall_timeout_seconds` or exhausted `max_attempts`. A claim response includes the attempt, generation, resume flag, and prior Mission state.

The Minion host keeps a local Mission Diary under its configured protected diary directory. Each file is scoped to a Mission attempt and claim generation. On resume, the Minion verifies that the prior Diary identifies the same Mission and signed envelope, then reads it as evidence and creates a new generation record. It does not overwrite the prior generation. The Diary records worker identity, progress, target/patch operations, target process ID and start time, reboot state, and result submission state.

Before a catalog installer starts, the Minion writes a per-Mission/per-target/per-patch operation record to the target's protected `ProgramData\SluiceGate\Minion\TargetDiary` directory and holds an exclusive operation lock. A later attempt checks that record and the recorded process ID plus start time. A running matching process is observed, not relaunched; a completed success is reconciled as success; unreadable or ambiguous state fails closed. MSI exit code `1618` is treated as another Windows Installer operation being active and is retried after the signed interval. Target journals and the host Mission Diary are removed only after Mission Control acknowledges a terminal result. A takeover retires the previous host Diary generation after the new generation is safely recorded.

The Minion reports `MISSION_WAITING_FOR_REBOOT` before a policy-authorized reboot and resumes the same Mission after the target returns. The target reboot marker and `LastBootUpTime` let a resumed worker recognize that the reboot already occurred and avoid repeating it. Cross-host takeover is not supported by this pilot; the local Diary is not a shared multi-host coordination store.

Operator cancellation is deferred from this pilot. Although `MISSION_CANCELLED` is present in the status vocabulary, there is no operator cancellation route or authorization workflow, and the Minion does not use that status as a cancellation command. Active target installers are never terminated by Mission Control. Missions end through their normal result, retry/attempt limits, or expiry; cancellation requires a separately designed operator workflow.

## Mission Result Size

A Mission result is the JSON completion report a Minion sends to Mission Control, including per-target/per-patch outcomes and error details. Its UTF-8 JSON `result` object is limited to 256 KiB. If the Minion's detailed report exceeds this limit, it submits a compact `MISSION_COMPLETE_FAILED` result explaining that details were omitted. Mission Control independently rejects oversized results.

The initial API routes are:

```text
POST /internal/v1/minions/{minion_id}/check-in
POST /internal/v1/minions/{minion_id}/missions/claim
POST /internal/v1/minions/{minion_id}/missions/{mission_id}/heartbeat
POST /internal/v1/minions/{minion_id}/missions/{mission_id}/status
POST /internal/v1/minions/{minion_id}/missions/{mission_id}/result
```
