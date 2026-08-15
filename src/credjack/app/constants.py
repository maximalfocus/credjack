"""Fixed, generic response bodies shared by every application entry point.

The rejection and unauthorized bodies are byte-identical constants so the secure path
provides no oracle for the rejection class or the existence of a host or internal service.
"""

from __future__ import annotations

import json
from typing import Final

# Every rejection class (bad scheme, blocked resolved address, blocked redirect hop) returns
# exactly this body with a 400 status.
GENERIC_REJECTION_JSON: Final = json.dumps({"error": "request rejected"}, indent=2) + "\n"

# Missing, malformed, and unknown credentials return exactly this body with a 401 status.
GENERIC_UNAUTHORIZED_JSON: Final = json.dumps({"error": "unauthorized"}, indent=2) + "\n"
