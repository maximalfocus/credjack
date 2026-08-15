"""The naive application entry point (non-secure; opt-in only).

The insufficient control: it rejects submissions whose host or URL text matches a denylist,
so the obvious direct-IP and known-name submissions are refused exactly as the secure app
refuses them — but it then fetches any name that passes the text check without inspecting the
resolved address, so a name that resolves to the metadata address is fetched anyway. It
refuses to start without the two-action opt-in gate and is never part of the default path.
"""

from __future__ import annotations

from credjack.app.factory import create_app
from credjack.app.fetch import naive_fetch

app = create_app(
    naive_fetch,
    title="credjack NAIVE Beacon monitor (educational demo only)",
    require_ack=True,
)
