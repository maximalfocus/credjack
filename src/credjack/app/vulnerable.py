"""The vulnerable application entry point (non-secure; opt-in only).

Deliberately unsafe: no address validation, follows redirects, and connects to whatever the
target resolves to — so an SSRF reaches the link-local metadata address and returns the
fictional instance credentials. It refuses to start without the two-action opt-in gate and
is never part of the default Compose path.
"""

from __future__ import annotations

from credjack.app.factory import create_app
from credjack.app.fetch import vulnerable_fetch

app = create_app(
    vulnerable_fetch,
    title="credjack VULNERABLE Beacon monitor (educational demo only)",
    require_ack=True,
)
