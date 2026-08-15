"""Integration tests over the in-network fixture topology.

These run inside the `verify` compose service, which is attached to all three fixture
networks. They assert where each fixture resolves, that the fixtures answer with
byte-identical fictional content, that the control plane gates the fictional bucket on the
fictional token, and that no path can reach the public internet.
"""

from __future__ import annotations

import ipaddress
import socket

import httpx
import pytest

from credjack.fixtures import data
from credjack.netblocks import is_blocked

pytestmark = pytest.mark.topology

_ROLE_PATH = "/latest/meta-data/iam/security-credentials/"
_CRED_PATH = _ROLE_PATH + data.INSTANCE_ROLE


def _resolve(name: str) -> str:
    return socket.gethostbyname(name)


def test_attacker_name_resolves_to_link_local() -> None:
    assert _resolve(data.ATTACKER_NAME) == data.METADATA_IP
    assert is_blocked(data.METADATA_IP)


def test_benign_resolves_outside_every_blocked_range() -> None:
    ip = _resolve(data.BENIGN_NAME)
    assert not is_blocked(ip)
    assert ipaddress.ip_address(ip) in ipaddress.ip_network("192.0.2.0/24")


def test_control_plane_resolves_inside_a_private_range() -> None:
    ip = _resolve(data.CONTROL_NAME)
    assert is_blocked(ip)
    assert ipaddress.ip_address(ip).is_private


def test_metadata_direct_ip_returns_role_and_fictional_credentials() -> None:
    base = f"http://{data.METADATA_IP}"
    role = httpx.get(base + _ROLE_PATH, timeout=5)
    assert role.status_code == 200
    assert role.content == (data.INSTANCE_ROLE + "\n").encode()

    creds = httpx.get(base + _CRED_PATH, timeout=5)
    assert creds.status_code == 200
    assert creds.content == data.CREDENTIAL_JSON.encode()
    assert "FICTIONAL" in creds.text


def test_metadata_via_attacker_name_matches_direct_ip() -> None:
    via_name = httpx.get(f"http://{data.ATTACKER_NAME}{_CRED_PATH}", timeout=5)
    via_ip = httpx.get(f"http://{data.METADATA_IP}{_CRED_PATH}", timeout=5)
    assert via_name.status_code == 200
    assert via_name.content == via_ip.content


def test_metadata_is_byte_identical_across_requests() -> None:
    url = f"http://{data.METADATA_IP}{_CRED_PATH}"
    first = httpx.get(url, timeout=5).content
    second = httpx.get(url, timeout=5).content
    assert first == second == data.CREDENTIAL_JSON.encode()


def test_control_plane_gates_bucket_on_token() -> None:
    url = f"http://{data.CONTROL_NAME}/buckets/{data.BUCKET_NAME}"
    ok = httpx.get(url, headers={"X-Nimbus-Session-Token": data.FICTIONAL_SESSION_TOKEN}, timeout=5)
    assert ok.status_code == 200
    assert ok.content == data.BUCKET_JSON.encode()

    missing = httpx.get(url, timeout=5)
    wrong = httpx.get(url, headers={"X-Nimbus-Session-Token": "nope"}, timeout=5)
    assert missing.status_code == 403
    assert wrong.status_code == 403
    # Generic and identical denial regardless of which part failed.
    assert missing.content == wrong.content == data.CONTROL_DENY_JSON.encode()


def test_control_plane_denies_unknown_bucket_generically() -> None:
    url = f"http://{data.CONTROL_NAME}/buckets/some-other-bucket"
    r = httpx.get(url, headers={"X-Nimbus-Session-Token": data.FICTIONAL_SESSION_TOKEN}, timeout=5)
    assert r.status_code == 403
    assert r.content == data.CONTROL_DENY_JSON.encode()


def test_benign_health_and_redirect() -> None:
    health = httpx.get(f"http://{data.BENIGN_NAME}/health", timeout=5)
    assert health.status_code == 200
    assert health.content == data.BENIGN_HEALTH_JSON.encode()

    redirect = httpx.get(
        f"http://{data.BENIGN_NAME}/r",
        params={"to": "http://169.254.169.254/x"},
        timeout=5,
        follow_redirects=False,
    )
    assert redirect.status_code == 302
    assert redirect.headers["location"] == "http://169.254.169.254/x"


def test_no_public_egress() -> None:
    # The fixture networks are `internal: true`, so there is no route off-network.
    with pytest.raises((httpx.ConnectError, httpx.ConnectTimeout)):
        httpx.get("http://8.8.8.8/", timeout=2)
