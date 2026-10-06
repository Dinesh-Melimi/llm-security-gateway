import pytest
from fastapi.testclient import TestClient

from gateway.config import load_settings
from gateway.main import create_app

ALPHA = {"Authorization": "Bearer demo-key-alpha"}
BETA = {"Authorization": "Bearer demo-key-beta"}


@pytest.fixture
def settings(tmp_path):
    s = load_settings()
    s.audit_log_path = str(tmp_path / "audit.jsonl")
    return s


@pytest.fixture
def client(settings):
    return TestClient(create_app(settings))


def chat(text, model="gpt-4o-mini", **kw):
    return {"model": model, "messages": [{"role": "user", "content": text}], **kw}
