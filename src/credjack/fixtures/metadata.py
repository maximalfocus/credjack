"""Fake instance metadata service, bound to the link-local address 169.254.169.254.

Serves IMDSv1-style paths. Wholly fictional: the credential document it returns is invented
and declares so in its own body.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, Response

from credjack.fixtures import data

app = FastAPI(title="credjack fake instance metadata service", redirect_slashes=False)

_ROLE_PREFIX = "/latest/meta-data/iam/security-credentials/"


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.get(_ROLE_PREFIX, response_class=PlainTextResponse)
def role_list() -> str:
    return data.INSTANCE_ROLE + "\n"


@app.get(_ROLE_PREFIX + "{role}")
def credentials(role: str) -> Response:
    if role != data.INSTANCE_ROLE:
        return PlainTextResponse("Not Found\n", status_code=404)
    return Response(content=data.CREDENTIAL_JSON, media_type="application/json")
