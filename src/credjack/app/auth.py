"""Demo bearer authentication.

Static, unmistakably demo-only tokens. Missing, malformed, and unknown credentials all
raise :class:`Unauthorized`, which the application renders as one generic ``401`` with the
standard bearer challenge and an identical body. Tokens are never logged or stored.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, Request
from sqlalchemy import select

from credjack.models import User


class Unauthorized(Exception):
    """Raised for any authentication failure; rendered as a generic 401."""


def parse_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        return None
    token = authorization[len(prefix) :].strip()
    return token or None


def get_current_user(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> User:
    token = parse_bearer(authorization)
    if token is None:
        raise Unauthorized()
    with request.app.state.sessionmaker() as session:
        user = session.scalar(select(User).where(User.token == token))
        if user is None:
            raise Unauthorized()
        # Return a detached identity so callers need no live session for the user's fields.
        return User(id=user.id, username=user.username, token=user.token)


CurrentUser = Annotated[User, Depends(get_current_user)]
