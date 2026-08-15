"""Documentation-completeness checks for the walkthrough and README (FR-015 / NFR-005).

Also enforces the SLICE-007 publication boundary: the MIT license is present and consistent, the
README is public-facing, SECURITY.md / CONTRIBUTING.md exist, and no public document references
the private companion repository (FR-016 / FR-017 / FR-018 / NFR-007).
"""

from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_WALKTHROUGH = _ROOT / "docs" / "WALKTHROUGH.md"
_README = _ROOT / "README.md"
_LICENSE = _ROOT / "LICENSE"
_SECURITY = _ROOT / "SECURITY.md"
_CONTRIBUTING = _ROOT / "CONTRIBUTING.md"
_PYPROJECT = _ROOT / "pyproject.toml"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_walkthrough_exists() -> None:
    assert _WALKTHROUGH.is_file()


def test_walkthrough_covers_required_topics() -> None:
    text = _text(_WALKTHROUGH)
    required = [
        "169.254.169.254",  # the metadata endpoint
        "highest-value",  # highest-value SSRF target
        "trust boundary",  # crosses a trust boundary the user's client cannot
        "CWE-918",
        "A10:2021",
        "API7:2023",
        "resolved-address blocking",  # the stronger control
        "denylist",  # the weaker control
        "address pinning",  # connect only to the validated address
        "redirect hop",  # re-checked on every hop
        "IMDSv2",  # defence-in-depth
        "PUT",  # IMDSv2 token handshake
        "hop limit",  # low response hop limit
        "least-privilege",  # defence-in-depth
        "DNS rebinding",  # out of scope by design
        "fetchjack",  # basic scheme/host-allowlist lesson, out of scope
        "scripts/demo.sh",  # the one-shot command
        "scripts/verify.sh",  # test command
        "/docs",  # local OpenAPI exploration
        "must never be deployed",  # conspicuous warning
    ]
    missing = [marker for marker in required if marker not in text]
    assert not missing, f"walkthrough missing required content: {missing}"


def test_walkthrough_states_section_four_outcomes() -> None:
    text = _text(_WALKTHROUGH)
    markers = (
        "cdn-edge.partner.test",
        "control.nimbus.internal",
        "status.partner.test",
        "201",
        "400",
    )
    for marker in markers:
        assert marker in text


def test_readme_points_to_walkthrough_and_warns() -> None:
    text = _text(_README)
    assert "docs/WALKTHROUGH.md" in text
    assert "scripts/demo.sh" in text
    assert "must never be deployed" in text


def test_readme_is_public_facing() -> None:
    """The public-facing rewrite (FR-018): no private-development language, and it
    surfaces the license, security policy, and contribution guidance."""
    text = _text(_README)
    lowered = text.lower()
    assert "private development" not in lowered
    assert "no license is granted" not in lowered
    assert "in-development repository" not in lowered
    assert "no hosted service" in lowered  # no production/hosting claim
    assert "LICENSE" in text
    assert "SECURITY.md" in text
    assert "CONTRIBUTING.md" in text


def test_license_present_and_mit() -> None:
    """FR-017: canonical MIT text in a root LICENSE with accurate attribution."""
    assert _LICENSE.is_file()
    text = _text(_LICENSE)
    assert "MIT License" in text
    assert "Copyright (c) 2026 maximalfocus" in text
    # canonical OSI text markers
    assert "Permission is hereby granted, free of charge" in text
    assert 'THE SOFTWARE IS PROVIDED "AS IS"' in text


def test_pyproject_declares_mit() -> None:
    """FR-017: consistent MIT SPDX metadata."""
    text = _text(_PYPROJECT)
    assert 'license = "MIT"' in text


def test_security_and_contributing_present() -> None:
    """FR-018: security policy that separates the intended flaw from unintended issues
    with a private reporting path, plus contribution guidance."""
    assert _SECURITY.is_file()
    assert _CONTRIBUTING.is_file()
    security = _text(_SECURITY)
    assert "intentionally vulnerable" in security.lower()
    assert "Report a vulnerability" in security  # private advisory path
    contributing = _text(_CONTRIBUTING)
    assert "SECURITY.md" in contributing


def test_no_public_reference_to_private_companion() -> None:
    """FR-016 / NFR-007: no public document references the private companion
    requirements repository or carries private-development language. The companion
    name is constructed from the project name so the forbidden literal never appears
    in published source (it would otherwise survive in retained pull-request refs)."""
    project_name = tomllib.loads(_text(_PYPROJECT))["project"]["name"]
    companion = f"{project_name}-prd"
    private_language = (
        "private development",
        "in-development repository",
        "no license is granted",
    )
    for path in (_README, _WALKTHROUGH, _SECURITY, _CONTRIBUTING, _PYPROJECT):
        lowered = _text(path).lower()
        assert companion not in lowered, f"{path.name} names the private companion repository"
        for phrase in private_language:
            assert phrase not in lowered, f"{path.name} carries private-development language"


def test_docs_declare_fictional() -> None:
    for path in (_WALKTHROUGH, _README):
        assert "fictional" in _text(path).lower()
