"""The scenario engine: exercise the three applications and the credential replay.

This module is deliberately free of terminal I/O so it can be tested directly. It talks to
each application over an ``httpx.Client`` (a real client to a running service, or a
``TestClient`` running the app in-process), submits the scenario URLs, and replays any stolen
token against the control plane.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

import httpx

from credjack.config import SEED_USERS
from credjack.fixtures import data

DIRECT_IP_URL = (
    f"http://{data.METADATA_IP}/latest/meta-data/iam/security-credentials/{data.INSTANCE_ROLE}"
)
RESOLVING_NAME_URL = (
    f"http://{data.ATTACKER_NAME}/latest/meta-data/iam/security-credentials/{data.INSTANCE_ROLE}"
)
REDIRECT_URL = f"http://{data.BENIGN_NAME}/r?to={DIRECT_IP_URL}"
BENIGN_URL = f"http://{data.BENIGN_NAME}/health"

CONTROL_BUCKET_PATH = f"/buckets/{data.BUCKET_NAME}"
DEFAULT_HEADERS = {"Authorization": f"Bearer {SEED_USERS[0]['token']}"}


@dataclass(frozen=True)
class Scenario:
    key: str
    label: str
    url: str


SCENARIOS: tuple[Scenario, ...] = (
    Scenario("direct_ip", "Direct IP to the metadata service", DIRECT_IP_URL),
    Scenario(
        "resolving_name", "Attacker name resolving to the metadata address", RESOLVING_NAME_URL
    ),
    Scenario("redirect", "Allowlisted-host redirect to the metadata address", REDIRECT_URL),
    Scenario("benign", "Legitimate benign target", BENIGN_URL),
)


@dataclass
class ScenarioOutcome:
    scenario: Scenario
    status_code: int
    allowed: bool
    snippet: str | None
    credentials_obtained: bool
    session_token: str | None
    replay_succeeded: bool | None


@dataclass
class AppReport:
    name: str
    history_before: int
    history_after: int
    outcomes: list[ScenarioOutcome]

    @property
    def compromised(self) -> bool:
        return any(o.credentials_obtained and o.replay_succeeded for o in self.outcomes)

    @property
    def verdict(self) -> str:
        return "COMPROMISED" if self.compromised else "SAFE"

    def by_key(self) -> dict[str, ScenarioOutcome]:
        return {o.scenario.key: o for o in self.outcomes}


@dataclass
class ComparisonResult:
    reports: list[AppReport]

    def by_name(self) -> dict[str, AppReport]:
        return {r.name: r for r in self.reports}


# A replay function returns True if the stolen token unlocks the control-plane bucket.
ReplayFn = Callable[[str], bool]


def make_control_replay(control_base_url: str) -> ReplayFn:
    def replay(token: str) -> bool:
        response = httpx.get(
            control_base_url.rstrip("/") + CONTROL_BUCKET_PATH,
            headers={"X-Nimbus-Session-Token": token},
            timeout=10,
        )
        return response.status_code == 200

    return replay


def _token_from_snippet(snippet: str | None) -> str | None:
    if not snippet:
        return None
    try:
        document = json.loads(snippet)
    except json.JSONDecodeError:
        return None
    token = document.get("Token")
    if isinstance(token, str) and token == data.FICTIONAL_SESSION_TOKEN:
        return token
    return None


def _history_count(client: httpx.Client, headers: Mapping[str, str]) -> int:
    response = client.get("/checks", headers=dict(headers))
    if response.status_code != 200:
        return 0
    return len(response.json())


def run_app(
    name: str,
    client: httpx.Client,
    *,
    headers: Mapping[str, str] = DEFAULT_HEADERS,
    replay: ReplayFn,
    scenarios: Sequence[Scenario] = SCENARIOS,
) -> AppReport:
    before = _history_count(client, headers)
    outcomes: list[ScenarioOutcome] = []
    for scenario in scenarios:
        response = client.post("/checks", headers=dict(headers), json={"url": scenario.url})
        allowed = response.status_code == 201
        snippet = response.json().get("body_snippet") if allowed else None
        token = _token_from_snippet(snippet)
        credentials = token is not None
        replay_ok = replay(token) if token is not None else None
        outcomes.append(
            ScenarioOutcome(
                scenario=scenario,
                status_code=response.status_code,
                allowed=allowed,
                snippet=snippet,
                credentials_obtained=credentials,
                session_token=token,
                replay_succeeded=replay_ok,
            )
        )
    after = _history_count(client, headers)
    return AppReport(name=name, history_before=before, history_after=after, outcomes=outcomes)


def run_comparison(
    apps: Mapping[str, httpx.Client],
    *,
    headers: Mapping[str, str] = DEFAULT_HEADERS,
    replay: ReplayFn,
) -> ComparisonResult:
    reports = [
        run_app(name, client, headers=headers, replay=replay) for name, client in apps.items()
    ]
    return ComparisonResult(reports=reports)


def expected_matrix_holds(result: ComparisonResult) -> bool:
    """True if the comparison matches the expected secure/vulnerable/naive security matrix."""
    by_name = result.by_name()
    if {"secure", "vulnerable", "naive"} - by_name.keys():
        return False
    secure, vulnerable, naive = by_name["secure"], by_name["vulnerable"], by_name["naive"]

    # Secure: safe; every metadata attempt blocked, benign allowed, exactly one new record.
    if secure.verdict != "SAFE":
        return False
    for outcome in secure.outcomes:
        if outcome.scenario.key == "benign":
            if not outcome.allowed:
                return False
        elif outcome.allowed or outcome.credentials_obtained:
            return False
    if secure.history_after != secure.history_before + 1:
        return False

    # Vulnerable and naive are both compromised (credentials stolen and replayed).
    if vulnerable.verdict != "COMPROMISED" or naive.verdict != "COMPROMISED":
        return False

    # Naive rejects the direct IP (denylist) but is defeated by the resolving name.
    naive_by = naive.by_key()
    if naive_by["direct_ip"].allowed:
        return False
    if not naive_by["resolving_name"].credentials_obtained:
        return False
    return True
