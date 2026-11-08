# SluiceGate Service (`sg-service`) Operator Guide

`sg-service` is the authoritative control-plane and orchestration service for SluiceGate. It exposes:
- **Inbound Agent APIs**: Policy-governed action submission (`/api/v1/actions` and `/api/v1/patch-requests`) and low-information request polling (`/api/v1/requests/{id}`).
- **Minion Mission Control**: Private authenticated check-in, leased Mission claim, heartbeat, and signed status/result exchange (`/internal/v1/minions/...`).
- **Administrative API & Console**: Self-contained Web UI and REST endpoints (`/admin` and `/admin/v1/...`) for human approval, agent/minion management, policy reloads, and audit inspection.

For a first-time, split Linux-service and Windows-patching-Minion setup, follow the [SluiceGate Installation Guide](../docs/Installation_Guide.md). This operator guide remains the reference for individual service functions.

---

## 1. Quick Start with Docker

### Prerequisites
- Docker Engine / Docker Desktop
- OpenSSL (to generate the Ed25519 signing key)

### Step 1: Generate SluiceGate Signing Key
`sg-service` signs all outgoing Mission Envelopes using an Ed25519 private key:

```sh
mkdir -p secrets
openssl genpkey -algorithm ED25519 -out secrets/sg-signing-key.pem
```

### Step 2: Build the Container Image
From the repository root:

```sh
docker build -f sg-service/Dockerfile -t sluicegate/sg-service:local .
```

### Step 3: Run the Container
Run the container, binding the service to `127.0.0.1:8443` (host loopback recommended for security):

```sh
docker run -d \
  --name sg-service \
  -p 127.0.0.1:8443:8443 \
  -v sg-service-data:/data \
  -v "$PWD/secrets/sg-signing-key.pem:/run/secrets/sg-signing-key.pem:ro" \
  -v "$PWD/sg-service/policies:/config:rw" \
  -e SG_BOOTSTRAP_ADMIN_KEY="admin-secret-key-123" \
  -e SG_SIGNING_KEY_PATH="/run/secrets/sg-signing-key.pem" \
  -e SG_POLICY_PATH="/config/demo-policy.yml" \
  sluicegate/sg-service:local
```

### Step 4: Verify Service Health
```sh
curl -fsS http://127.0.0.1:8443/health
# Response: {"status":"ok"}
```

---

## 2. Environment Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SG_DATABASE_PATH` | `/data/sg-service.sqlite3` | Path to persistent SQLite database file. |
| `SG_SIGNING_KEY_PATH` | `/run/secrets/sg-signing-key.pem` | Path to Ed25519 private key PEM file for signing Missions. |
| `SG_POLICY_PATH` | `/config/policy.yml` | Path to active YAML policy file evaluated by `sg_core`. |
| `SG_BOOTSTRAP_ADMIN_KEY` | *(None)* | Initial one-time administrator bearer token. Once you create permanent keys, remove this. |
| `SG_PATCH_MINION_ID` | `PATCH-01` | Minion ID used only when `SG_ALLOW_FALLBACK_MINION=true` and no registered Minion is eligible. |
| `SG_ALLOW_FALLBACK_MINION` | `false` | Development only. Routes to `SG_PATCH_MINION_ID` when no eligible Minion exists; the routing record and a warning log mark it as a fallback. |
| `SG_MINION_STALE_SECONDS` | `300` | A Minion with no check-in or claim within this window (or never) is not routable. `0` disables the check. |
| `SG_DEV_BOOTSTRAP` | `false` | When `true`, automatically registers development agent & minion keys (the development Minion's scope is `*`). |
| `SG_MINION_MAX_ATTEMPTS` | `3` | Maximum signed execution attempts per Mission. |
| `SG_MINION_RETRY_INTERVAL_SECONDS` | `30` | Signed delay before an eligible retry. |
| `SG_MINION_ATTEMPT_TIMEOUT_SECONDS` | `300` | Signed per-attempt execution deadline. |
| `SG_MINION_OVERALL_TIMEOUT_SECONDS` | `900` | Signed overall execution deadline. |
| `SG_MINION_HEARTBEAT_INTERVAL_SECONDS` | `30` | Minion lease-renewal cadence. |
| `SG_MINION_CLAIM_LEASE_SECONDS` | `120` | Claim lease length; must exceed the heartbeat interval. |
| `SG_TLS_CERT_FILE` / `SG_TLS_KEY_FILE` | *(None)* | PEM certificate and private key. When both are set the service itself serves HTTPS on its port; set only one and it refuses to start. With neither it serves plain HTTP and logs a warning, which is acceptable only on loopback behind a TLS proxy or for local development. |
| `SG_BIND_HOST` / `SG_BIND_PORT` | `0.0.0.0` / `8443` | Address the service listens on inside its container. |
| `SG_PUBLIC_URL` | *(request host)* | External base URL used in notification and verification emails, such as `https://sluice.example.gov`. Set this behind a proxy. |
| `RESEND_API_KEY` / `RESEND_API_KEY_FILE` | *(None)* | Resend API key, or a file containing it. |
| `SG_SMTP_USERNAME` / `SG_SMTP_PASSWORD` (plus `_FILE`) | *(None)* | SMTP credentials for adapters that use `login` authentication. |
| `SG_NOTIFY_MAX_ATTEMPTS` | `4` | Delivery attempts before a notification is marked `FAILED`. |
| `SG_NOTIFY_RETRY_BASE_SECONDS` | `30` | First retry delay; each later retry is four times longer. |

---

## 3. Using the Administrative Console (Web UI)

The service includes a self-contained web console served directly at:

👉 **`http://localhost:8443/admin`** (or `http://localhost:8443/admin/ui`)

### Initial Login / Setting Your Admin Token
1. Open `http://localhost:8443/admin` in your browser.
2. In the top-right header under **Admin Bearer Token**, paste your admin secret key (e.g., the value of `SG_BOOTSTRAP_ADMIN_KEY`, or an admin key issued via `/admin/v1/credentials/admin/{name}`).
3. Click **Save**. The token is stored in your browser's `localStorage` and sent in the `Authorization: Bearer <token>` header for all API queries.

---

### UI Tabs & Functions

#### Policies
- **Create New** opens a guided patching-policy builder seeded with a default BLOCK decision. Add exact, ordered target-server lists and patching constraints, then generate a draft; a policy with no rules blocks all requests. Approval outside a maintenance window permits immediate execution.
- **Edit Policy** opens a wizard-generated policy from the YAML editor for visual editing. Policies with other rules, comments, or formatting cannot be represented without loss and must be edited as YAML; they remain unchanged.
- **Load YAML / Download YAML** exchange drafts with local files.
- **Validate / Save and Activate** validate and explicitly activate the draft. Reload from Service replaces the editor with the saved policy; unsaved drafts are protected by a confirmation. Saves back up the previous file and reject concurrent changes.

#### 1. Missions & Audit Tab
- **View Transactions**: Shows the current Mission summary. The Audit Events table shows correlated request receipt, policy decision, routing, signed Mission envelope, claim/recovery, status/result, signature-verification, approval and administrative-mutation events.
- **Filter and inspect**: Search by request/transaction ID, Mission, Agent, Minion, status, event type, and occurred-at time. Inspect an event to view its structured evidence, including the signed payload where relevant.
- **Clear and reload**: Clear removes events from the current display after confirmation; it never deletes audit records. Reload or refreshing the page retrieves events again using the current filters. Reset filters removes the search criteria.
- **API**: `GET /admin/v1/audit-events` accepts `request_id` (or `transaction_id`), `mission_id`, `agent_id`, `minion_id`, `status_filter`, `event_type`, `since`, `until`, `limit` (1-500), and `before_id`. It requires an Admin bearer token.
- **Storage limits**: Audit rows are retained without automatic expiry. SQLite triggers prevent ordinary application updates/deletes but do not make the database tamper-proof against a host or database administrator. Back up the WSL database and signing-key environment securely; use an independent immutable log store when stronger tamper evidence is required.

#### 2. Pending Approvals Tab
- **Human-in-the-Loop Gate**: Shows all actions currently held in `WAITING_FOR_APPROVAL` (`PAUSE` policy decision).
- **Approve**: Prompts for an optional comment. Upon approval:
  - SluiceGate re-evaluates the request against the *current active policy* with approval evidence bound to context.
  - If allowed, transitions to `QUEUED` and cryptographically signs a Mission Envelope.
  - The assigned Minion can now claim and execute it.
- **Reject**: Prompts for a reason, marks the mission `CLOSED`, and prevents any Minion execution.

#### 3. Agent Registry Tab
- **Register New Agent**: Click **+ Register New Agent**, enter the agent name, team, environment (`prod`/`stage`/`dev`), and rate limits (e.g. 60 submits/min, 120 polls/min).
- **Copy API Key**: SluiceGate generates an API key and displays it once. Provide this key to your autonomous agent.
- **Disable / Enable**: Instantly pause or resume an agent's ability to submit requests or query status.
- **Rotate Key**: Revokes the previous key and issues a new token on demand.

#### 4. Minion Registry Tab
- **Registered Minions**: Import an approved local JSON release manifest using **Register from File**. The official online catalog is not available yet. Inspect a type's immutable release metadata and deployment count, enable or disable it, or delete it after confirmation. A type cannot be disabled or deleted while it has deployed instances.
- **Deployed Minions**: Add an instance by selecting an enabled registered type, choosing its active capabilities, and providing its ID, environment, target scope when required, and Ed25519 public key. Type metadata is read-only. Edit, disable, enable, or delete instances from this table; deletion revokes credentials and is blocked while missions are unfinished. Registration records an instance; it does not install software on a host.
- **Copy Minion Key**: Copy the issued Minion Mission Control API key once, then store it in the Minion's ACL-protected key file with `Set-MinionApiKey.ps1`. Generated JSON contains `ApiKeyPath`, never the key itself.
- **Generate Configuration**: Use **Config** to download a runtime-shaped `minion.config.json` with the registered Minion ID, editable Mission Control URL and deployment paths, certificate trust, polling interval, and safe `DryRun: true` default.
- **Release manifest**: The Windows bundle builder creates `minion-release.json`. For other Minions, create a JSON object with `schema_version` (1), unique `type_id`, `name`, `version`, `runtime_type`, `artifact`, `package_sha256` (64 hex characters), `capabilities` (nonempty string array), and `requires_target_scope` (boolean). Optionally add `instance_fields`, an array of `{ "id": "owner", "label": "Owner team", "required": true }` objects for non-secret text metadata collected for each instance. This metadata is stored for inspection; it is not automatically provisioned to a worker. Do not put credentials or private keys in these fields. A type ID identifies one release; use a new ID for a different version. Independently verify the manifest and the named artifact before importing. The service records the supplied hash but does not check the artifact or verify the deployed software.
- **Hash scope**: The generated Windows manifest hashes `Minion/SluiceGate.Minion.Service.exe`, not the complete bundle or the PowerShell worker scripts. Use the bundle's `SHA256SUMS.txt` and your release controls to verify the remaining files separately.
- **Health & Heartbeat**: Displays `Last Contact`, computed health/staleness, active Mission count, and recent Mission details.
- **Key Lifecycle**: Inspect key fingerprints and active/disabled/revoked states; rotate or revoke keys without exposing stored credential material.

#### 5. Notification Profiles Tab
- **Create Notification Profile**: Route lifecycle events (such as `PAUSE_CREATED`, `REQUEST_APPROVED`, `REQUEST_REJECTED`, `MISSION_COMPLETE_FAILED`) to a chosen adapter and recipient list. Email profiles require valid recipient addresses.
- **Delivery Audit Log**: Inspect each delivery's status (`PENDING`, `RETRYING`, `DELIVERED`, `FAILED`), attempt count, and the last error. Delivery runs in the background with bounded retries and exponential backoff; a duplicate event creates no duplicate delivery.

#### 6. Notification Adapters Tab
- **Providers**: Each adapter selects one provider: `resend`, `smtp` (on-premises Microsoft Exchange), `webhook`, or `mock`. A profile always names one adapter; there is no fallback between providers.
- **Secrets**: Credentials are never stored in adapters or shown in the console. Resend reads `RESEND_API_KEY`; SMTP with username/password authentication reads `SG_SMTP_USERNAME` and `SG_SMTP_PASSWORD`. Each may instead be supplied as a file path in `<NAME>_FILE` (for example a Docker secret). The page shows only whether each secret is configured.
- **SMTP/Exchange**: Set host, port, TLS mode (`starttls`, `tls`, or `none` for an approved relay), and authentication (`login` or `none`). Server certificates are always validated; use the optional CA bundle path for an internal CA. `login` requires TLS. NTLM/Kerberos authentication is not supported.
- **Verification**: Email adapters send nothing until verified. **Send test email** mails a single-use link (valid 15 minutes) to an address you choose; opening it shows a confirmation page, and pressing **Confirm** marks the adapter verified. Changing the provider, sender, host, port, TLS/authentication mode, or the secret values requires verifying again. Nothing is sent or checked at service startup.
- **Approval emails**: `PAUSE_CREATED` emails link to `SG_PUBLIC_URL/admin/ui#approvals`. Approving or rejecting always requires the authenticated Admin Console; opening a link or receiving an email never changes approval state.

#### Header Action: Reload Policy
- Click **Reload Policy** in the top navigation bar to reload the YAML policy file from disk on demand without restarting the container. SluiceGate will report the new policy provenance hash immediately.
- **Policies Tab**: Load, validate, and save-and-activate the configured policy with backup and policy-hash confirmation.

---

## 4. Running via Docker Compose

You can also run `sg-service` as part of the integrated demo stack:

```sh
# Generate keys if not already done:
./deployment/compose/Generate-DemoKeys.ps1

# Start the full stack (sg-service, demo-minion, backend BFF, frontend):
docker compose --env-file sluice-demo/.env -f sluice-demo/docker-compose.yml up -d --build
```

Access points:
- **Admin Console**: `http://localhost:8443/admin`
- **Interactive API Swagger Docs**: `http://localhost:8443/docs`
- **Legacy Demo UI**: `http://localhost:8080`
