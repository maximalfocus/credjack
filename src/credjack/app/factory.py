"""Application factory shared by the secure, vulnerable, and naive entry points.

Each entry point supplies its own fetcher; everything else — authentication, the check
lifecycle, history inspection, generic rejection/unauthorized rendering, and the rejection
audit event — is identical, so the three applications share one method, path, auth contract,
and success shape.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, Response

from credjack.app.audit import emit_rejection
from credjack.app.auth import CurrentUser, Unauthorized
from credjack.app.constants import GENERIC_REJECTION_JSON, GENERIC_UNAUTHORIZED_JSON
from credjack.app.deps import SessionDep
from credjack.app.fetch import RejectError
from credjack.app.gating import check_vulnerable_ack
from credjack.app.schemas import CheckCreate, CheckRead
from credjack.app.service import Fetcher, perform_check
from credjack.checks import list_checks
from credjack.db import make_engine, make_sessionmaker, seed_users

DEFAULT_DB_URL = "sqlite+pysqlite:////tmp/credjack.db"


def create_app(fetcher: Fetcher, *, title: str, require_ack: bool = False) -> FastAPI:
    db_url = os.environ.get("CREDJACK_DB_URL", DEFAULT_DB_URL)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Non-secure applications refuse to start without the explicit acknowledgement.
        if require_ack:
            check_vulnerable_ack(os.environ)
        engine = make_engine(db_url)
        sessionmaker = make_sessionmaker(engine)
        with sessionmaker() as session:
            seed_users(session)
            session.commit()
        app.state.sessionmaker = sessionmaker
        yield

    app = FastAPI(title=title, redirect_slashes=False, lifespan=lifespan)

    @app.exception_handler(Unauthorized)
    async def _on_unauthorized(request: Request, exc: Exception) -> Response:
        return Response(
            content=GENERIC_UNAUTHORIZED_JSON,
            status_code=401,
            media_type="application/json",
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz() -> str:
        return "ok"

    @app.post("/checks", status_code=201, response_model=CheckRead)
    def create_check(
        payload: CheckCreate, user: CurrentUser, session: SessionDep
    ) -> CheckRead | Response:
        try:
            record = perform_check(session, user=user, target_url=payload.url, fetcher=fetcher)
        except RejectError as exc:
            emit_rejection(
                username=user.username,
                target_url=payload.url,
                rejection_class=exc.rejection_class,
            )
            return Response(
                content=GENERIC_REJECTION_JSON,
                status_code=400,
                media_type="application/json",
            )
        return CheckRead.from_record(record)

    @app.get("/checks", response_model=list[CheckRead])
    def list_user_checks(user: CurrentUser, session: SessionDep) -> list[CheckRead]:
        return [CheckRead.from_record(record) for record in list_checks(session, user)]

    return app
