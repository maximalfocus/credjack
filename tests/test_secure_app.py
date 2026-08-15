"""Integration tests for the secure application through its HTTP boundary.

These run inside the `verify` service and reach the secure application (a default Compose
service) by its service name on the shared fixture networks.
"""

from __future__ import annotations

import httpx
import pytest

from credjack.app.constants import GENERIC_REJECTION_JSON, GENERIC_UNAUTHORIZED_JSON
from credjack.config import SEED_USERS
from credjack.fixtures import data

pytestmark = pytest.mark.topology

BASE = "http://secure:8000"
AVERY = {"Authorization": f"Bearer {SEED_USERS[0]['token']}"}
BLAIR = {"Authorization": f"Bearer {SEED_USERS[1]['token']}"}

BENIGN = "http://status.partner.test/health"
DIRECT_IP = "http://169.254.169.254/latest/meta-data/iam/security-credentials/beacon-worker"
RESOLVING_NAME = (
    "http://cdn-edge.partner.test/latest/meta-data/iam/security-credentials/beacon-worker"
)
REDIRECT_TO_META = (
    "http://status.partner.test/r?to="
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/beacon-worker"
)


def _history(headers: dict[str, str]) -> list[dict[str, object]]:
    response = httpx.get(f"{BASE}/checks", headers=headers, timeout=5)
    assert response.status_code == 200
    return response.json()


def _count(headers: dict[str, str]) -> int:
    return len(_history(headers))


def _post(headers: dict[str, str], url: str) -> httpx.Response:
    return httpx.post(f"{BASE}/checks", headers=headers, json={"url": url}, timeout=10)


def test_legitimate_check_appends_exactly_one_record() -> None:
    before = _count(AVERY)
    response = _post(AVERY, BENIGN)
    assert response.status_code == 201
    body = response.json()
    assert body["resolved_status"] == "completed"
    assert body["http_status"] == 200
    assert body["body_snippet"] == data.BENIGN_HEALTH_JSON
    assert isinstance(body["latency_ms"], int)
    assert _count(AVERY) == before + 1

    # Submitting the same benign target again appends another independent record.
    assert _post(AVERY, BENIGN).status_code == 201
    assert _count(AVERY) == before + 2


def test_secure_rejects_metadata_paths_byte_identically() -> None:
    before = _count(AVERY)
    bodies = []
    for url in (DIRECT_IP, RESOLVING_NAME, REDIRECT_TO_META):
        response = _post(AVERY, url)
        assert response.status_code == 400
        bodies.append(response.content)
    assert bodies[0] == bodies[1] == bodies[2] == GENERIC_REJECTION_JSON.encode()
    # No record was created for any rejected submission.
    assert _count(AVERY) == before


def test_rejected_snippet_carries_no_credentials() -> None:
    _post(AVERY, DIRECT_IP)
    # None of the caller's records contain the fictional credential token.
    for record in _history(AVERY):
        snippet = str(record.get("body_snippet") or "")
        assert data.FICTIONAL_SESSION_TOKEN not in snippet


def test_generic_401_for_missing_malformed_and_unknown_credentials() -> None:
    missing = httpx.get(f"{BASE}/checks", timeout=5)
    malformed = httpx.get(f"{BASE}/checks", headers={"Authorization": "Basic x"}, timeout=5)
    unknown = httpx.get(f"{BASE}/checks", headers={"Authorization": "Bearer nope"}, timeout=5)
    for response in (missing, malformed, unknown):
        assert response.status_code == 401
        assert response.headers.get("www-authenticate") == "Bearer"
    assert (
        missing.content
        == malformed.content
        == unknown.content
        == GENERIC_UNAUTHORIZED_JSON.encode()
    )


def test_history_is_user_scoped() -> None:
    blair_before = _count(BLAIR)
    assert _post(BLAIR, BENIGN).status_code == 201
    blair_after = _count(BLAIR)
    assert blair_after == blair_before + 1
    # An avery submission does not change blair's history.
    assert _post(AVERY, BENIGN).status_code == 201
    assert _count(BLAIR) == blair_after
