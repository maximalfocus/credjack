"""Shared, wholly fictional constants for the in-network fixtures.

Nothing here is a real credential, host, or account, and none of it grants access to any
real system. The credential and bucket documents declare their fictional nature in their
own contents.
"""

from __future__ import annotations

import json
from typing import Final

# In-network fixture identities. docker-compose.yml binds these exact addresses/names.
METADATA_IP: Final = "169.254.169.254"
ATTACKER_NAME: Final = "cdn-edge.partner.test"
BENIGN_NAME: Final = "status.partner.test"
CONTROL_NAME: Final = "control.nimbus.internal"

INSTANCE_ROLE: Final = "beacon-worker"

FICTIONAL_NOTICE: Final = (
    "FICTIONAL DEMO FIXTURE - invented for the credjack SSRF teaching demo; "
    "grants no access to any real system."
)

# The fictional short-lived session token minted by the metadata fixture and accepted by
# the control-plane fixture. Conspicuously fake.
FICTIONAL_SESSION_TOKEN: Final = "FICTIONAL.credjack-demo.session-token.NOT-A-REAL-CREDENTIAL"

_CREDENTIAL_DOC: Final = {
    "Code": "Success",
    "LastUpdated": "2026-01-01T00:00:00Z",
    "Type": "Nimbus-Demo",
    "AccessKeyId": "AKIA-FICTIONAL-CREDJACK-DEMO",
    "SecretAccessKey": "FICTIONAL-secret-not-a-real-key-000000000000",
    "Token": FICTIONAL_SESSION_TOKEN,
    "Expiration": "2099-12-31T23:59:59Z",
    "_warning": FICTIONAL_NOTICE,
}
CREDENTIAL_JSON: Final = json.dumps(_CREDENTIAL_DOC, indent=2) + "\n"

BUCKET_NAME: Final = "nimbus-beacon-artifacts"
_BUCKET_DOC: Final = {
    "bucket": BUCKET_NAME,
    "role": INSTANCE_ROLE,
    "objects": [
        {
            "key": "onboarding/notes.txt",
            "content": "FICTIONAL private artifact contents for the credjack demo.",
        },
        {
            "key": "config/beacon.yaml",
            "content": "monitor: beacon\nregion: nimbus-demo\n# FICTIONAL demo data",
        },
    ],
    "_warning": FICTIONAL_NOTICE,
}
BUCKET_JSON: Final = json.dumps(_BUCKET_DOC, indent=2) + "\n"

# Generic control-plane denial: reveals nothing about which part of a credential was wrong,
# nor whether a given bucket exists.
CONTROL_DENY_JSON: Final = json.dumps({"error": "access denied"}, indent=2) + "\n"

# Deterministic benign upstream body (the one legitimate fetch target).
_BENIGN_HEALTH_DOC: Final = {
    "status": "ok",
    "service": BENIGN_NAME,
    "note": "FICTIONAL benign upstream fixture for the credjack demo.",
}
BENIGN_HEALTH_JSON: Final = json.dumps(_BENIGN_HEALTH_DOC, indent=2) + "\n"
