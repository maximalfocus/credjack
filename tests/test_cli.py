from __future__ import annotations

import httpx
import pytest

from credjack.cli.render import render_default, render_verbose
from credjack.cli.scenario import (
    SCENARIOS,
    AppReport,
    ComparisonResult,
    Scenario,
    ScenarioOutcome,
    _token_from_snippet,
    expected_matrix_holds,
    make_control_replay,
)
from credjack.fixtures import data


def _scenario(key: str) -> Scenario:
    return next(s for s in SCENARIOS if s.key == key)


def _outcome(key: str, *, allowed: bool, creds: bool, replay: bool | None) -> ScenarioOutcome:
    token = data.FICTIONAL_SESSION_TOKEN if creds else None
    return ScenarioOutcome(
        scenario=_scenario(key),
        status_code=201 if allowed else 400,
        allowed=allowed,
        snippet="{...}" if allowed else None,
        credentials_obtained=creds,
        session_token=token,
        replay_succeeded=replay,
    )


def _secure_report(new_records: int = 1) -> AppReport:
    return AppReport(
        "secure",
        0,
        new_records,
        [
            _outcome("direct_ip", allowed=False, creds=False, replay=None),
            _outcome("resolving_name", allowed=False, creds=False, replay=None),
            _outcome("redirect", allowed=False, creds=False, replay=None),
            _outcome("benign", allowed=True, creds=False, replay=None),
        ],
    )


def _compromised_report(name: str) -> AppReport:
    vuln = name == "vulnerable"
    return AppReport(
        name,
        0,
        4 if vuln else 2,
        [
            _outcome("direct_ip", allowed=vuln, creds=vuln, replay=True if vuln else None),
            _outcome("resolving_name", allowed=True, creds=True, replay=True),
            _outcome("redirect", allowed=vuln, creds=vuln, replay=True if vuln else None),
            _outcome("benign", allowed=True, creds=False, replay=None),
        ],
    )


def _good_result() -> ComparisonResult:
    return ComparisonResult(
        [_secure_report(), _compromised_report("vulnerable"), _compromised_report("naive")]
    )


def test_expected_matrix_holds() -> None:
    assert expected_matrix_holds(_good_result())


def test_matrix_false_if_secure_leaks() -> None:
    secure = _secure_report()
    secure.outcomes[0] = _outcome("direct_ip", allowed=True, creds=True, replay=True)
    result = ComparisonResult(
        [secure, _compromised_report("vulnerable"), _compromised_report("naive")]
    )
    assert not expected_matrix_holds(result)


def test_matrix_false_if_secure_history_grows_too_much() -> None:
    result = ComparisonResult(
        [
            _secure_report(new_records=3),
            _compromised_report("vulnerable"),
            _compromised_report("naive"),
        ]
    )
    assert not expected_matrix_holds(result)


def test_matrix_false_if_missing_app() -> None:
    assert not expected_matrix_holds(ComparisonResult([_secure_report()]))


def test_token_from_snippet() -> None:
    assert _token_from_snippet(data.CREDENTIAL_JSON) == data.FICTIONAL_SESSION_TOKEN
    assert _token_from_snippet(data.BENIGN_HEALTH_JSON) is None
    assert _token_from_snippet(None) is None
    assert _token_from_snippet("not json at all") is None


def test_render_default_reports_verdicts_and_theft() -> None:
    text = "\n".join(render_default(_good_result()))
    assert "SAFE" in text
    assert "COMPROMISED" in text
    assert "STOLEN" in text
    assert "replay SUCCEEDED" in text


def test_render_verbose_includes_resolution() -> None:
    text = "\n".join(render_verbose(_good_result(), lambda _host: "203.0.113.5"))
    assert "resolved to 203.0.113.5" in text


def test_make_control_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    import credjack.cli.scenario as scenario

    def fake_get(url: str, *, headers: dict[str, str], timeout: float) -> httpx.Response:
        ok = headers.get("X-Nimbus-Session-Token") == "good-token"
        return httpx.Response(200 if ok else 403)

    monkeypatch.setattr(scenario.httpx, "get", fake_get)
    replay = make_control_replay("http://control.nimbus.internal")
    assert replay("good-token") is True
    assert replay("bad-token") is False
