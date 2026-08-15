"""Naive-variant behaviour: denylist rejection, resolved-address blindness, and the bypass."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from credjack.app.constants import GENERIC_REJECTION_JSON
from credjack.app.factory import create_app
from credjack.app.fetch import RejectError, naive_fetch, naive_guard, secure_guard
from credjack.config import SEED_USERS
from credjack.fixtures import data

pytestmark = pytest.mark.topology

AVERY = {"Authorization": f"Bearer {SEED_USERS[0]['token']}"}
DIRECT_IP = "http://169.254.169.254/latest/meta-data/iam/security-credentials/beacon-worker"
KNOWN_NAME = "http://metadata.google.internal/latest/meta-data/iam/security-credentials/"
RESOLVING_NAME = (
    "http://cdn-edge.partner.test/latest/meta-data/iam/security-credentials/beacon-worker"
)
CONTROL_BUCKET = f"http://{data.CONTROL_NAME}/buckets/{data.BUCKET_NAME}"


def _token(snippet: str) -> str:
    return str(json.loads(snippet)["Token"])


def test_naive_denylist_rejects_direct_ip_and_known_name() -> None:
    for url in (DIRECT_IP, KNOWN_NAME):
        with pytest.raises(RejectError) as info:
            naive_guard(url)
        assert info.value.rejection_class == "denylist"


def test_naive_does_not_inspect_resolved_address(monkeypatch: pytest.MonkeyPatch) -> None:
    # A non-denylisted name that resolves to the link-local metadata address:
    # naive returns it (never inspected), while secure rejects it.
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(None, None, None, "", ("169.254.169.254", 0))],
    )
    assert naive_guard("http://cdn-edge.partner.test/x") == "169.254.169.254"
    with pytest.raises(RejectError):
        secure_guard("http://cdn-edge.partner.test/x")


def test_naive_fetch_resolving_name_steals_credentials() -> None:
    outcome = naive_fetch(RESOLVING_NAME)
    assert outcome.http_status == 200
    assert data.FICTIONAL_SESSION_TOKEN in outcome.body_snippet
    token = _token(outcome.body_snippet)
    replay = httpx.get(CONTROL_BUCKET, headers={"X-Nimbus-Session-Token": token}, timeout=5)
    assert replay.status_code == 200
    assert replay.content == data.BUCKET_JSON.encode()


def test_naive_app_http_bypass_and_rejection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CREDJACK_DB_URL", f"sqlite+pysqlite:///{tmp_path}/n.db")
    monkeypatch.setenv("ALLOW_VULNERABLE_DEMO", "true")
    app = create_app(naive_fetch, title="test-naive", require_ack=True)
    with TestClient(app) as client:
        # Direct IP rejected with the same generic body the secure app uses.
        rejected = client.post("/checks", headers=AVERY, json={"url": DIRECT_IP})
        assert rejected.status_code == 400
        assert rejected.content == GENERIC_REJECTION_JSON.encode()
        # The resolving name bypasses the text denylist and steals the credentials.
        stolen = client.post("/checks", headers=AVERY, json={"url": RESOLVING_NAME})
        assert stolen.status_code == 201
        assert data.FICTIONAL_SESSION_TOKEN in stolen.json()["body_snippet"]
