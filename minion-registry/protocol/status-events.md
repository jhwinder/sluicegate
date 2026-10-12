# Mission Status Events

Minions authenticate to Minion Central Command with a per-Minon API key and submit status events after state changes. Idle claim polling is configurable (initial candidate: one hour). Status updates are event-driven and shall not wait for the next idle poll.

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

Status updates identify the mission, event name, occurrence time, and bounded structured detail. The service validates Minion identity, Mission assignment, signature, and allowed state transition before persistence. Duplicate submissions are idempotent. Mission status detail is operator-facing; the originating Agent receives only aggregate request status.

The initial API routes are:

```text
POST /internal/v1/minions/{minion_id}/check-in
POST /internal/v1/minions/{minion_id}/missions/claim
POST /internal/v1/minions/{minion_id}/missions/{mission_id}/status
POST /internal/v1/minions/{minion_id}/missions/{mission_id}/result
```
