"""Benign upstream fixture on a documentation-range address (outside every blocked range).

This is the one normal external target the monitor is meant to use. It serves deterministic
content at /health and a redirect endpoint at /r?to=... that issues a 302 to an arbitrary
caller-specified location.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, Response

from credjack.fixtures import data

app = FastAPI(title="credjack benign upstream fixture", redirect_slashes=False)


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.get("/health")
def health() -> Response:
    return Response(content=data.BENIGN_HEALTH_JSON, media_type="application/json")


@app.get("/r")
def redirect(to: str) -> Response:
    return Response(status_code=302, headers={"Location": to})
