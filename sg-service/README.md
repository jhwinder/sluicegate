# SluiceGate Service (`sg-service`) Operator Guide

`sg-service` is the authoritative control-plane and orchestration service for SluiceGate. It exposes:
- **Inbound Agent APIs**: Policy-governed action submission (`/api/v1/actions` and `/api/v1/patch-requests`) and low-information request polling (`/api/v1/requests/{id}`).
- **Minion Mission Control**: Private authenticated check-in, mission claim, and signed status/result exchange (`/internal/v1/minions/...`).
- **Administrative API & Console**: Self-contained Web UI and REST endpoints (`/admin` and `/admin/v1/...`) for human approval, agent/minion management, policy reloads, and audit inspection.

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
  -v "$PWD/sg-service/policies/demo-policy.yml:/config/policy.yml:ro" \
  -e SG_BOOTSTRAP_ADMIN_KEY="admin-secret-key-123" \
  -e SG_SIGNING_KEY_PATH="/run/secrets/sg-signing-key.pem" \
  -e SG_POLICY_PATH="/config/policy.yml" \
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
| `SG_PATCH_MINION_ID` | `PATCH-01` | Default fallback Minion ID if dynamic routing is bypassed. |
| `SG_DEV_BOOTSTRAP` | `false` | When `true`, automatically registers development agent & minion keys. |

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

#### 1. Missions & Audit Tab
- **View All Transactions**: Displays an append-only ledger of every request submitted to SluiceGate.
- **Inspect Detailed Trace**: Click **Inspect** on any row to view the full cryptographic trace:
  - Original Request ID and Mission ID
  - Selected Minion
  - SluiceGate Policy Decision (`ALLOW`, `PAUSE`, `BLOCK`) and policy provenance hash
  - Status updates and timestamps

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
- **Register New Minion**: Click **+ Register New Minion**, specify the Minion ID (e.g., `PATCH-01`), friendly name, supported capabilities (e.g., `windows.patch.reconcile`), and paste the Minion's Ed25519 public key PEM.
- **Copy Minion Key**: Copy the issued Minion Mission Control API key and configure it in `minion.config.json`.
- **Health & Heartbeat**: Displays `Last Contact` timestamp updated whenever the Minion checks in.

#### 5. Notification Profiles Tab
- **Register Notification Adapter**: Configure delivery sinks (e.g., `mock` audit sink, `webhook` HTTP POST, or email).
- **Create Notification Profile**: Route specific lifecycle events (such as `PAUSE_CREATED`, `REQUEST_APPROVED`, `REQUEST_REJECTED`, `MISSION_COMPLETE_FAILED`) to chosen adapters and recipient lists.
- **Delivery Audit Log**: Inspect the delivery history and status of every emitted notification.

#### Header Action: Reload Policy
- Click **Reload Policy** in the top navigation bar to reload the YAML policy file from disk on demand without restarting the container. SluiceGate will report the new policy provenance hash immediately.

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
