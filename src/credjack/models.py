"""SQLAlchemy 2.0 models for the fictional Beacon monitor."""

from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    token: Mapped[str] = mapped_column(String(128), unique=True)

    checks: Mapped[list[CheckRecord]] = relationship(
        back_populates="user", order_by="CheckRecord.seq"
    )


class CheckRecord(Base):
    """An append-only record of one check submission and its fetched result."""

    __tablename__ = "check_records"

    # Internal monotonic ordering key (stable insertion order); not the public identity.
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Public identifier: a deterministic UUID string (see checks.append_check).
    id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    target_url: Mapped[str] = mapped_column(Text)
    resolved_status: Mapped[str] = mapped_column(String(32))
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    body_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)

    user: Mapped[User] = relationship(back_populates="checks")
