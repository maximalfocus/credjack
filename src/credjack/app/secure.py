"""The secure application entry point (the default Compose service).

Scheme restriction plus resolved-address blocking enforced on every hop, connecting only to
the validated address. This is the taught fix.
"""

from __future__ import annotations

from credjack.app.factory import create_app
from credjack.app.fetch import secure_fetch

app = create_app(secure_fetch, title="credjack secure Beacon monitor")
