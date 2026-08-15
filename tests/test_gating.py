from __future__ import annotations

import pytest

from credjack.app.gating import ACK_ENV, VulnerableNotAcknowledged, check_vulnerable_ack


def test_ack_required_and_explained() -> None:
    with pytest.raises(VulnerableNotAcknowledged) as info:
        check_vulnerable_ack({})
    message = str(info.value)
    assert ACK_ENV in message
    assert "profile" in message.lower()
    assert "vulnerable" in message.lower()


def test_ack_must_be_exactly_true() -> None:
    for bad in ("", "True", "1", "yes", "false", "TRUE"):
        with pytest.raises(VulnerableNotAcknowledged):
            check_vulnerable_ack({ACK_ENV: bad})


def test_ack_accepts_true() -> None:
    check_vulnerable_ack({ACK_ENV: "true"})  # does not raise
