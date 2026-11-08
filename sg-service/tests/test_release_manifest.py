from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def test_release_generator_requires_new_identity_for_changed_files(tmp_path, monkeypatch):
    source = Path(__file__).resolve().parents[2] / "minion-registry" / "release_manifest.py"
    module_spec = importlib.util.spec_from_file_location("release_manifest", source)
    assert module_spec and module_spec.loader
    generator = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(generator)
    monkeypatch.setattr(generator, "ROOT", tmp_path)
    release_dir = tmp_path / "release"
    release_dir.mkdir()
    worker = release_dir / "worker.py"
    worker.write_text("first\n", encoding="utf-8")
    release = {
        "directory": "release", "type_id": "test-1", "family": "test",
        "name": "Test", "version": "1", "runtime_type": "python", "artifact": "worker.py",
        "capabilities": ["test.action"], "requires_target_scope": False,
        "files": {"worker.py": "release/worker.py"},
    }
    monkeypatch.setattr(generator, "RELEASES", {"test": release})
    monkeypatch.setattr(sys, "argv", ["release_manifest.py", "--write"])
    generator.main()
    worker.write_text("changed\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="bump both type_id and version"):
        generator.main()
    release["type_id"] = "test-2"
    with pytest.raises(SystemExit, match="bump both type_id and version"):
        generator.main()
    release["version"] = "2"
    generator.main()
    monkeypatch.setattr(sys, "argv", ["release_manifest.py"])
    generator.main()
    worker.unlink()
    with pytest.raises(FileNotFoundError):
        generator.main()
