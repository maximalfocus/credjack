"""Request and response schemas shared by every application entry point."""

from __future__ import annotations

from pydantic import BaseModel

from credjack.models import CheckRecord


class CheckCreate(BaseModel):
    url: str


class CheckRead(BaseModel):
    id: str
    target_url: str
    resolved_status: str
    http_status: int | None
    latency_ms: int | None
    body_snippet: str | None

    @classmethod
    def from_record(cls, record: CheckRecord) -> CheckRead:
        return cls(
            id=record.id,
            target_url=record.target_url,
            resolved_status=record.resolved_status,
            http_status=record.http_status,
            latency_ms=record.latency_ms,
            body_snippet=record.body_snippet,
        )
