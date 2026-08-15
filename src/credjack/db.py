"""Engine, session, and deterministic user seeding."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from credjack.config import SEED_USERS
from credjack.models import Base, User


def make_engine(url: str = "sqlite+pysqlite:///:memory:") -> Engine:
    # Sync FastAPI endpoints run in a threadpool, so a file-backed SQLite connection may be
    # used across threads; disable SQLite's same-thread guard for that case.
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, future=True, connect_args=connect_args)
    Base.metadata.create_all(engine)
    return engine


def make_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, future=True, expire_on_commit=False)


def seed_users(session: Session) -> None:
    """Insert the fixed fictional users if they are not already present (idempotent)."""
    for user in SEED_USERS:
        if session.get(User, user["id"]) is None:
            session.add(User(id=user["id"], username=user["username"], token=user["token"]))
    session.flush()
