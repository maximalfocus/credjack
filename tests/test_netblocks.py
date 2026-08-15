from __future__ import annotations

from credjack.fixtures import data
from credjack.netblocks import is_blocked


def test_metadata_ip_is_link_local_blocked() -> None:
    assert is_blocked(data.METADATA_IP)


def test_documentation_range_not_blocked() -> None:
    # The benign upstream fixture lives in a documentation range, outside every block.
    assert not is_blocked("192.0.2.10")
    assert not is_blocked("203.0.113.5")


def test_private_loopback_cgnat_and_unspecified_blocked() -> None:
    for ip in ("10.13.37.10", "127.0.0.1", "192.168.1.1", "172.16.0.1", "100.64.0.1", "0.0.0.0"):
        assert is_blocked(ip)


def test_public_addresses_not_blocked() -> None:
    for ip in ("8.8.8.8", "93.184.216.34"):
        assert not is_blocked(ip)


def test_ipv6_ranges() -> None:
    assert is_blocked("::1")
    assert is_blocked("fe80::1")
    assert is_blocked("fc00::1")
    assert not is_blocked("2606:4700:4700::1111")
