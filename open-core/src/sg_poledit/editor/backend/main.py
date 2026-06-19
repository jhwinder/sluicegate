from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path
import shutil
import yaml

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

# Ensure local package imports work when running from container
# In the container the repository is copied to /app, so add the src folder to sys.path
ROOT = Path("/app/open-core/src")
sys.path.insert(0, str(ROOT))

from sg_poledit.validate import validate_policy_dict
from sg_poledit.errors import ValidationResult

POLICIES_DIR = Path(os.environ.get("POLICIES_DIR", "/policies"))
POLICY_FILENAME = "policy.yml"

app = FastAPI(title="Sluice Policy Editor API")


def ensure_policies_dir() -> None:
    POLICIES_DIR.mkdir(parents=True, exist_ok=True)


def policy_path() -> Path:
    return POLICIES_DIR / POLICY_FILENAME


def backup_existing(path: Path) -> None:
    if not path.exists():
        return
    date = datetime.utcnow().strftime("%Y%m%d")
    backup_name = f"policy_{date}.yml"
    backup_path = path.with_name(backup_name)
    shutil.copy2(path, backup_path)


def read_policy() -> dict | None:
    p = policy_path()
    if not p.exists():
        return None
    with p.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def write_policy(data: dict) -> None:
    ensure_policies_dir()
    p = policy_path()
    backup_existing(p)
    with p.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False)


@app.get("/api/policy")
def get_policy():
    data = read_policy()
    if data is None:
        raise HTTPException(status_code=404, detail="policy.yml not found")
    return JSONResponse(content={"policy": data})


@app.post("/api/validate")
def validate_policy(payload: dict):
    result: ValidationResult = validate_policy_dict(payload)
    return {"is_valid": result.is_valid, "issues": [issue.__dict__ for issue in result.issues], "render": result.render()}


@app.post("/api/policy")
def save_policy(payload: dict):
    result: ValidationResult = validate_policy_dict(payload)
    if not result.is_valid:
        return JSONResponse(status_code=400, content={"is_valid": False, "issues": [issue.__dict__ for issue in result.issues], "render": result.render()})
    try:
        write_policy(payload)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"is_valid": True, "message": "Saved", "render": result.render()}


@app.post("/api/upload")
async def upload_policy(file: UploadFile = File(...)):
    if file.content_type not in ("application/x-yaml", "text/yaml", "text/plain", "application/octet-stream"):
        # allow common types; we'll try to parse anyway
        pass
    contents = await file.read()
    try:
        data = yaml.safe_load(contents)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")
    result: ValidationResult = validate_policy_dict(data)
    if not result.is_valid:
        return JSONResponse(status_code=400, content={"is_valid": False, "issues": [issue.__dict__ for issue in result.issues], "render": result.render()})
    try:
        write_policy(data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"is_valid": True, "message": "Uploaded and saved.", "render": result.render()}


# Serve built frontend if present
FRONTEND_DIST = Path("/app/open-core/src/sg_poledit/editor/frontend/dist")
if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")


@app.get("/")
def serve_index():
    index = FRONTEND_DIST / "index.html"
    if index.exists():
        return FileResponse(index)
    raise HTTPException(status_code=404, detail="Not Found")


if __name__ == "__main__":
    import uvicorn

    ensure_policies_dir()
    uvicorn.run(app, host="0.0.0.0", port=8080)
