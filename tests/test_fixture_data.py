from __future__ import annotations

import json

from credjack.fixtures import data


def test_credential_doc_is_fictional_and_linked_to_token() -> None:
    doc = json.loads(data.CREDENTIAL_JSON)
    assert doc["Token"] == data.FICTIONAL_SESSION_TOKEN
    assert doc["Expiration"].startswith("2099")  # far-future fixed expiration
    assert "FICTIONAL" in doc["_warning"]
    assert "FICTIONAL" in data.CREDENTIAL_JSON


def test_bucket_doc_declares_fictional() -> None:
    doc = json.loads(data.BUCKET_JSON)
    assert doc["bucket"] == data.BUCKET_NAME
    assert doc["role"] == data.INSTANCE_ROLE
    assert "FICTIONAL" in doc["_warning"]


def test_control_denial_is_generic() -> None:
    text = data.CONTROL_DENY_JSON.lower()
    for leak in ("token", "secret", "accesskey", "bucket", data.BUCKET_NAME.lower()):
        assert leak not in text


def test_serialized_constants_are_stable_strings() -> None:
    for value in (
        data.CREDENTIAL_JSON,
        data.BUCKET_JSON,
        data.CONTROL_DENY_JSON,
        data.BENIGN_HEALTH_JSON,
    ):
        assert isinstance(value, str)
        assert value.endswith("\n")
