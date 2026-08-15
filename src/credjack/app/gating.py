"""Opt-in gate for the non-secure demo applications.

A non-secure application requires two deliberate actions to start: enabling the ``vulnerable``
Docker Compose profile (enforced by Compose) and supplying ``ALLOW_VULNERABLE_DEMO=true``
(enforced here, at application startup). Absent the acknowledgement, startup is refused with
an explanation.
"""

from __future__ import annotations

from collections.abc import Mapping

ACK_ENV = "ALLOW_VULNERABLE_DEMO"


class VulnerableNotAcknowledged(RuntimeError):
    """Raised when a non-secure application starts without the required acknowledgement."""


def check_vulnerable_ack(environ: Mapping[str, str]) -> None:
    """Refuse startup unless ``ALLOW_VULNERABLE_DEMO=true`` is set."""
    if environ.get(ACK_ENV) != "true":
        raise VulnerableNotAcknowledged(
            "Refusing to start a non-secure Beacon demo application. This is intentionally "
            "vulnerable educational code and must never be deployed. To run it you must take "
            f"two deliberate actions: set {ACK_ENV}=true and enable the 'vulnerable' Docker "
            "Compose profile. Neither is enabled by default; the secure application is the "
            "default service."
        )
