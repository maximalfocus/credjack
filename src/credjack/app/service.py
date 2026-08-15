"""Check orchestration shared by every application entry point."""

from __future__ import annotations

# A fetcher takes a submitted URL and returns an outcome, or raises RejectError.
from collections.abc import Callable

from sqlalchemy.orm import Session

from credjack.app.fetch import FetchOutcome
from credjack.checks import append_check
from credjack.models import CheckRecord, User

Fetcher = Callable[[str], FetchOutcome]


def perform_check(
    session: Session, *, user: User, target_url: str, fetcher: Fetcher
) -> CheckRecord:
    """Fetch ``target_url`` and append exactly one check record for ``user``.

    Raises :class:`credjack.app.fetch.RejectError` if the fetcher refuses the target, in
    which case no record is created.
    """
    outcome = fetcher(target_url)
    record = append_check(
        session,
        user=user,
        target_url=target_url,
        resolved_status="completed",
        http_status=outcome.http_status,
        latency_ms=outcome.latency_ms,
        body=outcome.body_snippet,
    )
    session.commit()
    return record
