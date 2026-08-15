"""Append-only check-record service.

Record identifiers are deterministic UUID strings derived from the owning user and the
per-user insertion index, so a fresh run against fresh state produces identical output.
This module deliberately exposes no update or delete operation: records are append-only.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from credjack.config import SNIPPET_MAX_BYTES
from credjack.models import CheckRecord, User

# Fixed namespace so record identifiers are reproducible across fresh runs.
_CHECK_NAMESPACE = uuid.UUID("c0ffee00-0000-4000-8000-000000000000")


def snippet(body: str) -> str:
    """Length-cap a fetched body to ``SNIPPET_MAX_BYTES`` bytes without splitting UTF-8."""
    encoded = body.encode("utf-8")[:SNIPPET_MAX_BYTES]
    return encoded.decode("utf-8", errors="ignore")


def deterministic_id(user_id: str, index: int) -> str:
    """The reproducible UUID identifier for the ``index``-th check of ``user_id``."""
    return str(uuid.uuid5(_CHECK_NAMESPACE, f"{user_id}:{index}"))


def _next_index(session: Session, user_id: str) -> int:
    count = session.scalar(
        select(func.count()).select_from(CheckRecord).where(CheckRecord.user_id == user_id)
    )
    return count or 0


def append_check(
    session: Session,
    *,
    user: User,
    target_url: str,
    resolved_status: str,
    http_status: int | None = None,
    latency_ms: int | None = None,
    body: str | None = None,
) -> CheckRecord:
    """Append one check record for ``user`` and return it."""
    index = _next_index(session, user.id)
    record = CheckRecord(
        id=deterministic_id(user.id, index),
        user_id=user.id,
        target_url=target_url,
        resolved_status=resolved_status,
        http_status=http_status,
        latency_ms=latency_ms,
        body_snippet=snippet(body) if body is not None else None,
    )
    session.add(record)
    session.flush()
    return record


def list_checks(session: Session, user: User) -> list[CheckRecord]:
    """Return ``user``'s check records in stable insertion order."""
    return list(
        session.scalars(
            select(CheckRecord).where(CheckRecord.user_id == user.id).order_by(CheckRecord.seq)
        )
    )
