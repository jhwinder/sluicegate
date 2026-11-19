"""Run on stdin inside the deliverable service image; never install this script."""
import importlib.metadata
import importlib.util
import json
from pathlib import Path

distribution = importlib.metadata.distribution("sg-service")
files = [str(path) for path in distribution.files or []]
assert "sg_service/policy_templates/catalog.json" in files
assert not any("/tests/" in path or "test_stub" in path or "test-policy.yml" in path for path in files)
for dependency in ("pytest", "requests", "playwright"):
    assert importlib.util.find_spec(dependency) is None, dependency
for root in (Path("/app"), Path("/opt/sluicegate")):
    assert not any(path.name in {"test_stub", "test-policy.yml", "test-minion-release.json"} for path in root.rglob("*"))
catalog = json.loads(Path(distribution.locate_file("sg_service/policy_templates/catalog.json")).read_text())
assert [entry["id"] for entry in catalog] == ["patching"]
print("RUNTIME: policy catalog packaged; TEST collateral and test dependencies absent")
