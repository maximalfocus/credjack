from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from credjack.checks import append_check, deterministic_id, list_checks, snippet
from credjack.config import SEED_USERS, SNIPPET_MAX_BYTES
from tests.helpers import fresh_session, get_user


def test_append_returns_uuid_and_retains_fields(session: Session) -> None:
    user = get_user(session, 0)
    record = append_check(
        session,
        user=user,
        target_url="http://status.partner.test/health",
        resolved_status="completed",
        http_status=200,
        latency_ms=12,
        body="hello",
    )
    uuid.UUID(record.id)  # parses as a valid UUID
    assert record.target_url == "http://status.partner.test/health"
    assert record.resolved_status == "completed"
    assert record.http_status == 200
    assert record.latency_ms == 12
    assert record.body_snippet == "hello"
    assert record.user_id == user.id


def test_ids_are_deterministic_across_fresh_state() -> None:
    runs: list[tuple[str, str]] = []
    for _ in range(2):
        s = fresh_session()
        user = get_user(s, 0)
        r1 = append_check(s, user=user, target_url="a", resolved_status="completed")
        r2 = append_check(s, user=user, target_url="b", resolved_status="completed")
        runs.append((r1.id, r2.id))
        s.close()
    assert runs[0] == runs[1]
    assert runs[0][0] != runs[0][1]
    assert runs[0][0] == deterministic_id(SEED_USERS[0]["id"], 0)


def test_ordering_and_isolation_between_users() -> None:
    s = fresh_session()
    avery = get_user(s, 0)
    blair = get_user(s, 1)
    append_check(s, user=avery, target_url="a1", resolved_status="completed")
    append_check(s, user=blair, target_url="b1", resolved_status="rejected")
    append_check(s, user=avery, target_url="a2", resolved_status="completed")

    assert [c.target_url for c in list_checks(s, avery)] == ["a1", "a2"]
    assert [c.target_url for c in list_checks(s, blair)] == ["b1"]
    s.close()


def test_snippet_caps_bytes() -> None:
    big = "x" * (SNIPPET_MAX_BYTES + 100)
    capped = snippet(big)
    assert len(capped.encode("utf-8")) == SNIPPET_MAX_BYTES
    assert snippet("short") == "short"


def test_no_mutation_or_delete_api() -> None:
    import credjack.checks as checks

    for forbidden in ("delete_check", "update_check", "remove_check", "clear_checks"):
        assert not hasattr(checks, forbidden)
