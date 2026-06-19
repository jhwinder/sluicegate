# SluiceGate Policy Editor

This folder contains a small single-user policy authoring web app: a FastAPI backend that reuses the existing `sg_poledit` validation, and a React (Vite) form-based frontend.

Purpose
- Edit and validate policy files for the SluiceGate project with a simple form UI.
- Policies are saved to the canonical repository policies folder so other components can pick them up.

Quick start (Docker Compose)

```bash
cd open-core/src/sg_poledit/editor
docker compose up -d --build
```

Open http://localhost:8080 in your browser.

Important behavior
- Single-user: no authentication, the app is intended for local/hosted single-user use.
- Canonical policy path: the app reads and writes the file `policy.yml` located in the mounted `open-core/policies` folder inside the container.
- Backup on save: when you save, if `policy.yml` already exists it will be renamed to `policy_YYYYMMDD.yml` (UTC date) and the new content will be written to `policy.yml`.
- No autosave: changes are only saved when the user explicitly clicks Save.
- Validation: on save the backend runs `validate_policy_dict()` (the repo's validator) and rejects invalid policies with a structured `ValidationResult`.

API Endpoints (backend)
- `GET /api/policy` — returns the current `policy.yml` as JSON.
- `POST /api/validate` — validates a policy JSON payload and returns validation results.
- `POST /api/policy` — validate-and-save a policy JSON payload; performs the backup rename before writing.
- `POST /api/upload` — upload a YAML file (defaults to policies folder) and returns validation status.

Frontend notes
- The browser UI is at `/` and the page title is "SluiceGate Policy Editor".
- The form normalizes operator-keyed condition objects (e.g. `{path:..., eq:...}`) into form inputs and denormalizes back when saving so operator keys are preserved.
- The YAML preview uses `js-yaml` for rendering.

Development notes
- If you change the frontend, rebuild via Docker Compose (the Dockerfile builds the Vite frontend during image build).
- `requirements.txt` (backend) includes FastAPI and `python-multipart` for uploads.

Where policies live
- Host path: `open-core/policies` (this is mounted into the container and is the canonical repo location).
- Canonical filename: `policy.yml`. Backups use `policy_YYYYMMDD.yml`.

Troubleshooting
- If you change Node or plugin versions, ensure `@vitejs/plugin-react`'s major version matches Vite's major version.
- If uploads fail, confirm `python-multipart` is installed in the backend environment.

Questions or next steps
- If you'd like improved validation UI (field-level error highlighting) or a backups browser UI to preview/restore backups, I can add those next.

File: [open-core/src/sg_poledit/editor/README.md](open-core/src/sg_poledit/editor/README.md)
