"""Run on stdin inside the deliverable service image; never install this script."""
import importlib.metadata
import importlib.util
import json
from pathlib import Path

distribution = importlib.metadata.distribution("sg-service")
files = [str(path) for path in distribution.files or []]
assert "sg_service/policy_templates/catalog.json" in files
assert "sg_service/static/assets/mission-control.css" in files
assert "sg_service/static/assets/sluicegate-logo.png" in files
assert not any("/tests/" in path or "test_stub" in path or "test-policy.yml" in path for path in files)
for dependency in ("pytest", "requests", "playwright"):
    assert importlib.util.find_spec(dependency) is None, dependency
for root in (Path("/app"), Path("/opt/sluicegate")):
    assert not any(path.name in {"test_stub", "test-policy.yml", "test-minion-release.json"} for path in root.rglob("*"))
catalog = json.loads(Path(distribution.locate_file("sg_service/policy_templates/catalog.json")).read_text())
assert [entry["id"] for entry in catalog] == ["patching"]
print("RUNTIME: policy catalog packaged; TEST collateral and test dependencies absent")

# The assets must also be reachable through the installed app's HTTP routes.
from urllib.request import urlopen
import time

for attempt in range(30):
    try:
        with urlopen("http://127.0.0.1:8443/admin/assets/mission-control.css", timeout=2) as response:
            assert response.status == 200 and response.headers.get_content_type() == "text/css"
        with urlopen("http://127.0.0.1:8443/admin/assets/sluicegate-logo.png", timeout=2) as response:
            assert response.status == 200 and response.headers.get_content_type() == "image/png"
            assert response.read(8) == b"\x89PNG\r\n\x1a\n"
        break
    except OSError:
        if attempt == 29:
            raise
        time.sleep(0.2)
print("BRANDING: installed CSS and logo served with correct content types")
