"""Documentation-completeness checks for the walkthrough and README (FR-015 / NFR-005).

Also enforces the SLICE-006 boundary: no license or public-release claim is present yet.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_WALKTHROUGH = _ROOT / "docs" / "WALKTHROUGH.md"
_README = _ROOT / "README.md"


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
    assert "private development" in text  # public-facing rewrite is a later slice


def test_no_license_or_public_release_claim_yet() -> None:
    assert not (_ROOT / "LICENSE").exists()
    assert not (_ROOT / "LICENSE.md").exists()
    assert not (_ROOT / "LICENSE.txt").exists()
    for path in (_WALKTHROUGH, _README, _ROOT / "pyproject.toml"):
        text = _text(path)
        assert "MIT" not in text
        assert "SPDX-License-Identifier" not in text


def test_docs_declare_fictional() -> None:
    for path in (_WALKTHROUGH, _README):
        assert "fictional" in _text(path).lower()
