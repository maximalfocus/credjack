"""Structured rejection audit event.

Emitted once per rejected submission to stdout. It supports request correlation and records
the authenticated user, the attempted action, the rejection class, and the outcome. It never
includes fetched content, credential material, bucket contents, bearer tokens, or
Authorization headers, and the submitted URL appears only as a length-capped, control-
character-escaped rendering (``json.dumps`` escapes control characters).
"""

from __future__ import annotations

import json
import uuid
from typing import Final

# Fixed namespace so a correlation id is reproducible for identical rejected submissions.
_AUDIT_NAMESPACE = uuid.UUID("a0d17000-0000-4000-8000-000000000000")

_URL_CAP: Final = 256


def _capped(url: str) -> str:
    return url[:_URL_CAP]


def emit_rejection(*, username: str, target_url: str, rejection_class: str) -> dict[str, str]:
    """Emit and return the rejection event (returned for testability)."""
    request_id = str(uuid.uuid5(_AUDIT_NAMESPACE, f"{username}:{target_url}:{rejection_class}"))
    event = {
        "event": "check.rejected",
        "request_id": request_id,
        "user": username,
        "action": "check",
        "rejection_class": rejection_class,
        "outcome": "rejected",
        "target_url": _capped(target_url),
    }
    print(json.dumps(event), flush=True)
    return event
