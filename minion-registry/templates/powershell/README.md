# SluiceGate PowerShell Minion Template

This directory contains the reusable PowerShell Minion template and core library as specified in Section 3.4 of the SluiceGate Minion Architecture Requirements.

## Components

- **`SluiceGate.Minion.Core.psm1`**: Reusable PowerShell module providing:
  - Canonical JSON serialization (`ConvertTo-CanonicalJson`).
  - Ed25519 cryptographic signature verification and signing (`Test-MinionSignature`, `New-MinionSignature`).
  - Task Envelope validation against SluiceGate's public key, protocol version, expiration, and Minion identity (`Test-MissionEnvelope`).
  - Nonce replay tracking and persistent storage (`Test-MinionNonce`, `Add-MinionNonce`).
  - Minion Mission Control communication (`Invoke-MinionCheckIn`, `Get-MinionMissionClaim`, `Send-MinionStatus`, `Send-MinionResult`).
- **`MinionWorkerTemplate.ps1`**: The main execution loop template that handles the complete mission lifecycle:
  1. Authenticates to Mission Control.
  2. Claims queued missions for its assigned `minion_id`.
  3. Verifies envelope validity and cryptographic signature.
  4. Records nonce to prevent replay.
  5. Emits `MISSION_ACKNOWLEDGED` and `MISSION_IN_PROGRESS`.
  6. Dispatches to the capability handler.
  7. Signs the structured result envelope with the Minion's private key.
  8. Emits terminal status (`MISSION_COMPLETE_SUCCEEDED`, `MISSION_COMPLETE_FAILED`, etc.).

## Instantiating a Minion

To create a new functional Minion:
1. Define a configuration JSON specifying Minion ID, API key, SluiceGate public key, and supported capabilities.
2. Implement capability handler functions for authorized operations (e.g., `windows.patch.reconcile`).
3. Pass the capability scriptblock into `MinionWorkerTemplate.ps1`.
