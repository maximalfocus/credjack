"""Fake Nimbus cloud control plane on a private-range host.

Authenticates the fictional session token minted by the metadata fixture and, for the
beacon-worker role, returns the fictional private bucket. Every other case receives one
generic denial that reveals nothing about which part of a credential was wrong.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import FastAPI, Header
from fastapi.responses import PlainTextResponse, Response

from credjack.fixtures import data

app = FastAPI(title="credjack fake Nimbus control plane", redirect_slashes=False)


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


def _deny() -> Response:
    return Response(content=data.CONTROL_DENY_JSON, media_type="application/json", status_code=403)


@app.get("/buckets/{bucket}")
def get_bucket(
    bucket: str,
    x_nimbus_session_token: Annotated[str | None, Header()] = None,
) -> Response:
    if x_nimbus_session_token != data.FICTIONAL_SESSION_TOKEN or bucket != data.BUCKET_NAME:
        return _deny()
    return Response(content=data.BUCKET_JSON, media_type="application/json")
