from __future__ import annotations

from sqlalchemy.orm import Session

from credjack.config import SEED_USERS
from credjack.db import make_engine, make_sessionmaker, seed_users
from credjack.models import User


def fresh_session() -> Session:
    """A session over a brand-new in-memory database seeded with the fixed users."""
    engine = make_engine()
    session = make_sessionmaker(engine)()
    seed_users(session)
    session.commit()
    return session


def get_user(session: Session, index: int) -> User:
    user = session.get(User, SEED_USERS[index]["id"])
    assert user is not None
    return user
