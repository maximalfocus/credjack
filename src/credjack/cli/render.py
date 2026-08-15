"""Rendering for the scripted comparison (default narrative and verbose detail)."""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlparse

from credjack.cli.scenario import ComparisonResult, ScenarioOutcome

Resolver = Callable[[str], str]

_HEADER = "credjack — SSRF to cloud instance metadata: secure vs. vulnerable vs. naive"


def _decision(outcome: ScenarioOutcome) -> str:
    if outcome.credentials_obtained:
        return "FETCHED — instance credentials STOLEN"
    if outcome.allowed:
        return "fetched — benign result"
    return "blocked"


def _replay(outcome: ScenarioOutcome) -> str:
    if outcome.replay_succeeded is None:
        return ""
    return "; control-plane replay " + ("SUCCEEDED" if outcome.replay_succeeded else "failed")


def render_default(result: ComparisonResult) -> list[str]:
    lines = [_HEADER, ""]
    for report in result.reports:
        lines.append(f"[{report.name.upper()}]  verdict: {report.verdict}")
        lines.append(
            f"    check history: {report.history_before} record(s) before "
            f"-> {report.history_after} after"
        )
        for outcome in report.outcomes:
            lines.append(
                f"    - {outcome.scenario.label}: HTTP {outcome.status_code} "
                f"[{_decision(outcome)}]{_replay(outcome)}"
            )
        lines.append("")
    lines.append(
        "Summary: the secure application blocks every metadata attempt on the resolved "
        "address; the vulnerable and naive applications leak the fictional credentials, which "
        "unlock the fictional control-plane bucket."
    )
    return lines


def render_verbose(result: ComparisonResult, resolve: Resolver) -> list[str]:
    lines = render_default(result)
    lines += ["", "Verbose per-scenario detail:"]
    for report in result.reports:
        lines.append(f"[{report.name.upper()}]")
        for outcome in report.outcomes:
            host = urlparse(outcome.scenario.url).hostname or ""
            try:
                resolved = resolve(host)
            except OSError:
                resolved = "unresolved"
            redirect = ""
            if outcome.scenario.key == "redirect":
                redirect = " ; redirects toward the metadata address (169.254.169.254)"
            snippet_note = "no body" if outcome.snippet is None else f"{len(outcome.snippet)} bytes"
            lines.append(f"    - {outcome.scenario.key}: submitted {outcome.scenario.url}")
            lines.append(
                f"        host {host} resolved to {resolved}{redirect}; "
                f"decision {_decision(outcome)}; HTTP {outcome.status_code}; "
                f"snippet {snippet_note}; "
                f"credentials_obtained={outcome.credentials_obtained}; "
                f"replay_succeeded={outcome.replay_succeeded}"
            )
    return lines
