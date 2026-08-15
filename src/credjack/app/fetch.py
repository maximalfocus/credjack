"""The shared server-side fetch engine and the secure fetch policy.

The engine drives one request, optionally following redirects, and — critically — connects
only to the specific IP address a *guard* validated for each hop. The three applications
differ only in their guard:

* secure  — resolve, reject any blocked resolved address, connect only to the validated IP,
            re-resolve and re-validate every redirect hop (this slice);
* vulnerable / naive — added in later slices.

A guard raises :class:`RejectError` to refuse a hop; the engine never issues an outbound
request for a refused hop, so no request is ever made to a blocked resolved address.
"""

from __future__ import annotations

import hashlib
import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urljoin, urlparse

import httpx

from credjack.checks import snippet
from credjack.netblocks import is_blocked

ALLOWED_SCHEMES = ("http", "https")
MAX_REDIRECT_HOPS = 5


class RejectError(Exception):
    """Raised by a guard (or the engine) to refuse a submission before connecting."""

    def __init__(self, rejection_class: str) -> None:
        super().__init__(rejection_class)
        self.rejection_class = rejection_class


@dataclass
class HopResult:
    status_code: int
    headers: dict[str, str]
    text: str


class Requester(Protocol):
    def __call__(
        self, *, scheme: str, host: str, ip: str, port: int, path_qs: str
    ) -> HopResult: ...


@dataclass
class FetchOutcome:
    http_status: int
    body_snippet: str
    latency_ms: int
    final_url: str
    connected_ip: str
    redirect_chain: list[str]


# A guard maps a hop URL to the validated IP to connect to, or raises RejectError.
Guard = Callable[[str], str]


def modeled_latency_ms(url: str) -> int:
    """A deterministic, reproducible modeled latency (NFR-003 forbids clock-based output).

    It is a stable function of the target, so identical inputs yield identical bodies across
    applications and across repeated runs.
    """
    digest = hashlib.sha256(url.encode("utf-8")).digest()
    return 5 + digest[0] % 45


def _split(url: str) -> tuple[str, str, int, str]:
    parsed = urlparse(url)
    scheme = parsed.scheme
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    path_qs = parsed.path or "/"
    if parsed.query:
        path_qs += "?" + parsed.query
    return scheme, host, port, path_qs


def _default_requester(*, scheme: str, host: str, ip: str, port: int, path_qs: str) -> HopResult:
    # Connect to the validated IP while preserving the original Host header, so the address
    # checked is exactly the address used.
    url = f"{scheme}://{ip}:{port}{path_qs}"
    response = httpx.get(url, headers={"Host": host}, follow_redirects=False, timeout=5.0)
    headers = {key.lower(): value for key, value in response.headers.items()}
    return HopResult(status_code=response.status_code, headers=headers, text=response.text)


def fetch(
    url: str,
    *,
    guard: Guard,
    requester: Requester = _default_requester,
    allow_redirects: bool = True,
    max_hops: int = MAX_REDIRECT_HOPS,
) -> FetchOutcome:
    current = url
    chain: list[str] = []
    for hop in range(max_hops + 1):
        try:
            pinned_ip = guard(current)
        except RejectError as exc:
            # A refusal on any redirect hop is reported as a redirect-hop rejection.
            raise RejectError(exc.rejection_class if hop == 0 else "redirect_hop") from exc

        scheme, host, port, path_qs = _split(current)
        result = requester(scheme=scheme, host=host, ip=pinned_ip, port=port, path_qs=path_qs)
        chain.append(f"{current} -> {pinned_ip}")

        location = result.headers.get("location")
        if 300 <= result.status_code < 400 and location:
            # A redirect: refuse it outright, or follow it only if budget remains.
            if not allow_redirects or hop >= max_hops:
                raise RejectError("redirect_hop")
            current = urljoin(current, location)
            continue

        return FetchOutcome(
            http_status=result.status_code,
            body_snippet=snippet(result.text),
            latency_ms=modeled_latency_ms(url),
            final_url=current,
            connected_ip=pinned_ip,
            redirect_chain=chain,
        )

    # Unreachable: the loop always returns or raises within the hop budget.
    raise RejectError("redirect_hop")


def _resolve(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]) for info in infos]


def secure_guard(url: str) -> str:
    """Scheme restriction + resolved-address blocking, returning the validated IP to pin."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise RejectError("scheme")
    host = parsed.hostname
    if not host:
        raise RejectError("scheme")
    try:
        ips = _resolve(host)
    except socket.gaierror as exc:
        raise RejectError("blocked_address") from exc
    if not ips or any(is_blocked(ip) for ip in ips):
        raise RejectError("blocked_address")
    return ips[0]


def secure_fetch(url: str) -> FetchOutcome:
    return fetch(url, guard=secure_guard)


def vulnerable_guard(url: str) -> str:
    """No address validation: resolve and connect to whatever the host resolves to.

    This is the deliberately unsafe construction that lets an SSRF reach the link-local
    metadata address. It still only reaches in-network fixtures (the networks are internal).
    """
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise RejectError("scheme")
    try:
        ips = _resolve(host)
    except socket.gaierror as exc:
        raise RejectError("blocked_address") from exc
    if not ips:
        raise RejectError("blocked_address")
    return ips[0]


def vulnerable_fetch(url: str) -> FetchOutcome:
    return fetch(url, guard=vulnerable_guard)


# The naive denylist checks the submitted name/text, never the resolved address. It blocks the
# obvious literals and known metadata names, but not an innocuous-looking name that resolves to
# the metadata address (the whole point of the bypass).
NAIVE_DENYLIST_HOSTS = frozenset(
    {
        "169.254.169.254",
        "localhost",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
    }
)
NAIVE_DENYLIST_MARKERS = ("169.254.169.254",)


def naive_guard(url: str) -> str:
    """Hostname/string denylist on the submitted URL, then connect without address checks."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        raise RejectError("scheme")
    lowered = url.lower()
    if host in NAIVE_DENYLIST_HOSTS or any(marker in lowered for marker in NAIVE_DENYLIST_MARKERS):
        raise RejectError("denylist")
    # Passed the text check: resolve and connect to whatever it resolves to, WITHOUT inspecting
    # the resolved address — so a name that resolves to the metadata address is fetched anyway.
    try:
        ips = _resolve(host)
    except socket.gaierror as exc:
        raise RejectError("blocked_address") from exc
    if not ips:
        raise RejectError("blocked_address")
    return ips[0]


def naive_fetch(url: str) -> FetchOutcome:
    return fetch(url, guard=naive_guard)
