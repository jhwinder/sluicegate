import pytest


@pytest.fixture(autouse=True)
def isolate_development_bootstrap(monkeypatch):
    """Tests explicitly provision what they need, independent of the user's shell."""
    monkeypatch.setenv("SG_DEV_BOOTSTRAP", "false")
