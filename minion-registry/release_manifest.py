#!/usr/bin/env python3
"""Generate or verify reproducible Minion release manifests."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELEASES = {
    "patching": {
        "directory": "minion-registry/minions/patching",
        "type_id": "windows-patching-1.0.4",
        "family": "windows-patching",
        "name": "Windows Patching Minion",
        "version": "1.0.4",
        "runtime_type": "powershell",
        "artifact": "Minion/SluiceGate.Minion.Service.exe",
        "capabilities": ["windows.patch.reconcile", "windows.patch.discover", "windows.patch.status"],
        "requires_target_scope": True,
        "files": {
            "SluiceGate.Minion.Service.exe": "deployment/windows/Minion/SluiceGate.Minion.Service.exe",
            "runtime/PatchingMinion.ps1": "minion-registry/minions/patching/PatchingMinion.ps1",
            "runtime/PatchingCatalog.psm1": "minion-registry/minions/patching/PatchingCatalog.psm1",
            "runtime/PatchingEngine.psm1": "minion-registry/minions/patching/PatchingEngine.psm1",
            "runtime/SluiceGate.Minion.Core.psm1": "minion-registry/templates/powershell/SluiceGate.Minion.Core.psm1",
            "runtime/protocol/mission-envelope.schema.json": "minion-registry/protocol/mission-envelope.schema.json",
        },
    },
    "demo_stub": {
        "directory": "minion-registry/minions/demo_stub",
        "type_id": "DEMO-STUB-1.0.0",
        "family": "demo-stub",
        "name": "Demo Stub Minion",
        "version": "1.0.0",
        "runtime_type": "python",
        "artifact": "worker.py",
        "capabilities": ["windows.patch.reconcile", "demo.action", "stripe.refund", "stripe.charge"],
        "requires_target_scope": True,
        "files": {
            "worker.py": "minion-registry/minions/demo_stub/worker.py",
            "requirements.txt": "minion-registry/minions/demo_stub/requirements.txt",
        },
    },
}


def create_manifest(spec: dict) -> dict:
    files = sorted(spec["files"])
    lines = []
    for path in files:
        digest = hashlib.sha256((ROOT / spec["files"][path]).read_bytes()).hexdigest()
        lines.append(f"{path}\0{digest}\n")
    fingerprint = hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()
    return {
        "schema_version": 2,
        **{key: spec[key] for key in ("type_id", "family", "name", "version", "runtime_type", "artifact", "capabilities", "requires_target_scope")},
        "package_sha256": fingerprint,
        "release_files": files,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Update manifests after changing a release")
    args = parser.parse_args()
    for spec in RELEASES.values():
        path = ROOT / spec["directory"] / "minion-release.json"
        manifest = create_manifest(spec)
        content = json.dumps(manifest, indent=2, ensure_ascii=True) + "\n"
        if args.write:
            if path.exists():
                previous = json.loads(path.read_text(encoding="utf-8"))
                if previous != manifest and (previous["type_id"] == manifest["type_id"] or previous["version"] == manifest["version"]):
                    raise SystemExit(f"Release changed: bump both type_id and version before writing {path.relative_to(ROOT)}")
            path.write_text(content, encoding="utf-8")
            print(f"Wrote {path.relative_to(ROOT)}")
        elif not path.exists() or path.read_text(encoding="utf-8") != content:
            raise SystemExit(f"Release manifest is out of sync: {path.relative_to(ROOT)}")
        else:
            print(f"Verified {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
