from __future__ import annotations

import json

import pytest

from credjack.app.audit import emit_rejection
from credjack.app.auth import parse_bearer
from credjack.fixtures import data


def test_rejection_event_fields_and_determinism(capsys: pytest.CaptureFixture[str]) -> None:
    event = emit_rejection(
        username="avery", target_url="http://169.254.169.254/x", rejection_class="blocked_address"
    )
    printed = json.loads(capsys.readouterr().out.strip())
    assert printed == event
    assert event["event"] == "check.rejected"
    assert event["user"] == "avery"
    assert event["action"] == "check"
    assert event["rejection_class"] == "blocked_address"
    assert event["outcome"] == "rejected"
    # Deterministic correlation id for identical rejected submissions.
    again = emit_rejection(
        username="avery", target_url="http://169.254.169.254/x", rejection_class="blocked_address"
    )
    capsys.readouterr()
    assert again["request_id"] == event["request_id"]


def test_rejection_event_never_leaks_secrets(capsys: pytest.CaptureFixture[str]) -> None:
    emit_rejection(
        username="avery",
        target_url="http://cdn-edge.partner.test/creds",
        rejection_class="blocked_address",
    )
    out = capsys.readouterr().out.lower()
    for secret in (
        data.FICTIONAL_SESSION_TOKEN.lower(),
        "authorization",
        "bearer",
        "secretaccesskey",
        data.BUCKET_NAME.lower(),
    ):
        assert secret not in out


def test_rejection_event_caps_and_escapes_url(capsys: pytest.CaptureFixture[str]) -> None:
    nasty = "http://x/" + ("A" * 500) + "\n\tinjected"
    emit_rejection(username="avery", target_url=nasty, rejection_class="scheme")
    raw = capsys.readouterr().out
    # Control characters are escaped by json.dumps (no literal newline/tab in the line).
    assert "\n\t" not in raw.rstrip("\n")
    event = json.loads(raw)
    assert len(event["target_url"]) <= 256


def test_parse_bearer() -> None:
    assert parse_bearer("Bearer abc") == "abc"
    assert parse_bearer("Bearer   spaced  ") == "spaced"
    assert parse_bearer(None) is None
    assert parse_bearer("") is None
    assert parse_bearer("Basic abc") is None
    assert parse_bearer("bearer abc") is None  # case-sensitive scheme
    assert parse_bearer("Bearer ") is None
