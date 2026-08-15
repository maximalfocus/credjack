"""The consolidated FR-014 security regression matrix.

Runs the scenario engine across the live secure service and in-process vulnerable/naive apps
and asserts the full matrix: theft on the non-secure apps (with control-plane replay), the
secure app's byte-identical rejections and unchanged state, and identical benign bodies.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from credjack.app.constants import GENERIC_REJECTION_JSON, GENERIC_UNAUTHORIZED_JSON
from credjack.app.factory import create_app
from credjack.app.fetch import naive_fetch, vulnerable_fetch
from credjack.cli.scenario import (
    DEFAULT_HEADERS,
    DIRECT_IP_URL,
    REDIRECT_URL,
    RESOLVING_NAME_URL,
    ScenarioOutcome,
    expected_matrix_holds,
    make_control_replay,
    run_comparison,
)
from credjack.fixtures import data

pytestmark = pytest.mark.topology

SECURE_URL = "http://secure:8000"


def _benign_snippet(outcomes: list[ScenarioOutcome]) -> str | None:
    return next(o.snippet for o in outcomes if o.scenario.key == "benign")


def test_full_regression_matrix(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ALLOW_VULNERABLE_DEMO", "true")
    monkeypatch.setenv("CREDJACK_DB_URL", f"sqlite+pysqlite:///{tmp_path}/vuln.db")
    vulnerable_app = create_app(vulnerable_fetch, title="reg-vuln", require_ack=True)
    monkeypatch.setenv("CREDJACK_DB_URL", f"sqlite+pysqlite:///{tmp_path}/naive.db")
    naive_app = create_app(naive_fetch, title="reg-naive", require_ack=True)

    replay = make_control_replay(f"http://{data.CONTROL_NAME}")
    with (
        httpx.Client(base_url=SECURE_URL, timeout=10) as secure,
        TestClient(vulnerable_app) as vulnerable,
        TestClient(naive_app) as naive,
    ):
        apps: dict[str, httpx.Client] = {
            "secure": secure,
            "vulnerable": vulnerable,
            "naive": naive,
        }
        result = run_comparison(apps, replay=replay)

    assert expected_matrix_holds(result)
    by = result.by_name()

    # Secure: every metadata attempt blocked; control-plane replay obtains nothing.
    for outcome in by["secure"].outcomes:
        if outcome.scenario.key != "benign":
            assert outcome.status_code == 400 and not outcome.allowed
        assert outcome.replay_succeeded is None

    # Vulnerable: both the direct IP and the resolving name steal credentials and replay.
    vuln = by["vulnerable"].by_key()
    assert vuln["direct_ip"].credentials_obtained and vuln["direct_ip"].replay_succeeded
    assert vuln["resolving_name"].credentials_obtained and vuln["resolving_name"].replay_succeeded

    # Naive: direct IP blocked by the denylist, defeated by the resolving name.
    naive_by = by["naive"].by_key()
    assert not naive_by["direct_ip"].allowed
    assert naive_by["resolving_name"].credentials_obtained
    assert naive_by["resolving_name"].replay_succeeded

    # Secure and vulnerable return identical bodies for the same benign input.
    assert _benign_snippet(by["secure"].outcomes) == data.BENIGN_HEALTH_JSON
    assert _benign_snippet(by["vulnerable"].outcomes) == data.BENIGN_HEALTH_JSON


def test_secure_rejections_are_byte_identical() -> None:
    with httpx.Client(base_url=SECURE_URL, timeout=10) as secure:
        before = len(secure.get("/checks", headers=DEFAULT_HEADERS).json())
        bodies = []
        for url in (DIRECT_IP_URL, RESOLVING_NAME_URL, REDIRECT_URL):
            response = secure.post("/checks", headers=DEFAULT_HEADERS, json={"url": url})
            assert response.status_code == 400
            bodies.append(response.content)
        after = len(secure.get("/checks", headers=DEFAULT_HEADERS).json())
    assert bodies[0] == bodies[1] == bodies[2] == GENERIC_REJECTION_JSON.encode()
    assert after == before  # rejected paths leave check history byte-for-byte unchanged


def test_secure_generic_401() -> None:
    with httpx.Client(base_url=SECURE_URL, timeout=10) as secure:
        missing = secure.get("/checks")
        bad = secure.get("/checks", headers={"Authorization": "Bearer nope"})
    assert missing.status_code == bad.status_code == 401
    assert missing.content == bad.content == GENERIC_UNAUTHORIZED_JSON.encode()
