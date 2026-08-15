from __future__ import annotations

import socket

import pytest

from credjack.app import fetch as fetchmod
from credjack.app.fetch import (
    HopResult,
    RejectError,
    fetch,
    modeled_latency_ms,
    secure_guard,
)


class RecordingRequester:
    """A fake requester that records every hop it is asked to connect to."""

    def __init__(self, script: list[HopResult]) -> None:
        self.script = script
        self.calls: list[tuple[str, str, int, str]] = []

    def __call__(self, *, scheme: str, host: str, ip: str, port: int, path_qs: str) -> HopResult:
        self.calls.append((host, ip, port, path_qs))
        return self.script[len(self.calls) - 1]


def test_modeled_latency_is_deterministic_and_bounded() -> None:
    a = modeled_latency_ms("http://status.partner.test/health")
    b = modeled_latency_ms("http://status.partner.test/health")
    assert a == b
    assert 5 <= a < 50


def test_engine_pins_to_validated_ip_and_preserves_host() -> None:
    req = RecordingRequester([HopResult(200, {}, "body")])
    outcome = fetch(
        "http://status.partner.test/health", guard=lambda _u: "192.0.2.10", requester=req
    )
    assert outcome.http_status == 200
    assert outcome.connected_ip == "192.0.2.10"
    assert req.calls == [("status.partner.test", "192.0.2.10", 80, "/health")]


def test_engine_makes_no_request_when_guard_rejects_first_hop() -> None:
    req = RecordingRequester([])

    def guard(_url: str) -> str:
        raise RejectError("blocked_address")

    with pytest.raises(RejectError) as info:
        fetch("http://169.254.169.254/x", guard=guard, requester=req)
    assert info.value.rejection_class == "blocked_address"
    assert req.calls == []  # never connected


def test_engine_relabels_blocked_redirect_hop() -> None:
    # First hop allowed and returns a 302; the redirect target is rejected by the guard.
    req = RecordingRequester([HopResult(302, {"location": "http://169.254.169.254/creds"}, "")])
    hops: list[str] = []

    def guard(url: str) -> str:
        hops.append(url)
        if "169.254.169.254" in url:
            raise RejectError("blocked_address")
        return "192.0.2.10"

    with pytest.raises(RejectError) as info:
        fetch("http://status.partner.test/r", guard=guard, requester=req)
    assert info.value.rejection_class == "redirect_hop"
    assert len(req.calls) == 1  # only the first hop connected


def test_engine_follows_allowed_redirect_to_terminal() -> None:
    req = RecordingRequester(
        [
            HopResult(302, {"location": "http://status.partner.test/health"}, ""),
            HopResult(200, {}, "final"),
        ]
    )
    outcome = fetch("http://status.partner.test/r", guard=lambda _u: "192.0.2.10", requester=req)
    assert outcome.http_status == 200
    assert outcome.body_snippet == "final"
    assert len(req.calls) == 2


def test_engine_rejects_when_exceeding_hop_budget() -> None:
    loop = HopResult(302, {"location": "http://status.partner.test/r"}, "")
    req = RecordingRequester([loop] * 10)
    with pytest.raises(RejectError) as info:
        fetch(
            "http://status.partner.test/r",
            guard=lambda _u: "192.0.2.10",
            requester=req,
            max_hops=2,
        )
    assert info.value.rejection_class == "redirect_hop"


def test_secure_guard_rejects_non_http_scheme() -> None:
    with pytest.raises(RejectError) as info:
        secure_guard("file:///etc/passwd")
    assert info.value.rejection_class == "scheme"


def test_secure_guard_blocks_and_returns_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, *_a: object, **_k: object) -> list[tuple[object, ...]]:
        table = {
            "blocked.example": "169.254.169.254",
            "ok.example": "192.0.2.55",
        }
        return [(None, None, None, "", (table[host], 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(RejectError) as info:
        secure_guard("http://blocked.example/x")
    assert info.value.rejection_class == "blocked_address"
    assert secure_guard("http://ok.example/x") == "192.0.2.55"


def test_secure_guard_uses_socket_module(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ensure the guard resolves via the standard resolver (patchable at the module boundary).
    monkeypatch.setattr(
        fetchmod.socket,
        "getaddrinfo",
        lambda *a, **k: [(None, None, None, "", ("192.0.2.7", 0))],
    )
    assert secure_guard("https://ok.example/") == "192.0.2.7"
