"""Deterministic, wholly fictional configuration for the Beacon monitor domain."""

from __future__ import annotations

from typing import Final, TypedDict


class SeedUser(TypedDict):
    id: str
    username: str
    token: str


# Fixed fictional users. Tokens are conspicuously demo-only; they are never real secrets
# and their unpredictability is never relied on as a security control.
SEED_USERS: Final[tuple[SeedUser, ...]] = (
    {
        "id": "00000000-0000-0000-0000-000000000001",
        "username": "avery",
        "token": "demo-token-avery-FICTIONAL",
    },
    {
        "id": "00000000-0000-0000-0000-000000000002",
        "username": "blair",
        "token": "demo-token-blair-FICTIONAL",
    },
)

# Stored fetched-body snippets are capped to this many bytes.
SNIPPET_MAX_BYTES: Final = 512
