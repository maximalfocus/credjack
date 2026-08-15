"""Command-line entry point for the scripted comparison demo.

Scripted mode (the default) runs the deterministic comparison across all three applications
and the credential replay, prints the report, and exits non-zero if the expected security
matrix does not hold. Interactive mode offers a small menu over the same scenario engine.
"""

from __future__ import annotations

import argparse
import socket
import sys
from collections.abc import Mapping, Sequence

import httpx

from credjack.cli.render import render_default, render_verbose
from credjack.cli.scenario import (
    SCENARIOS,
    ComparisonResult,
    ReplayFn,
    expected_matrix_holds,
    make_control_replay,
    run_app,
    run_comparison,
)
from credjack.fixtures import data


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="credjack-demo", description=__doc__)
    parser.add_argument("--interactive", action="store_true", help="run the interactive menu")
    parser.add_argument("--verbose", action="store_true", help="show per-scenario detail")
    parser.add_argument("--secure-url", default="http://secure:8000")
    parser.add_argument("--vulnerable-url", default="http://vulnerable:8001")
    parser.add_argument("--naive-url", default="http://naive:8002")
    parser.add_argument("--control-url", default=f"http://{data.CONTROL_NAME}")
    return parser


def _build_clients(args: argparse.Namespace) -> dict[str, httpx.Client]:
    return {
        "secure": httpx.Client(base_url=args.secure_url, timeout=10),
        "vulnerable": httpx.Client(base_url=args.vulnerable_url, timeout=10),
        "naive": httpx.Client(base_url=args.naive_url, timeout=10),
    }


def _run_scripted(clients: Mapping[str, httpx.Client], replay: ReplayFn, *, verbose: bool) -> int:
    result = run_comparison(clients, replay=replay)
    lines = render_verbose(result, socket.gethostbyname) if verbose else render_default(result)
    print("\n".join(lines))
    if not expected_matrix_holds(result):
        print(
            "\nUNEXPECTED: the comparison did not match the expected security matrix.",
            file=sys.stderr,
        )
        return 1
    return 0


def _run_interactive(clients: Mapping[str, httpx.Client], replay: ReplayFn) -> int:
    print("credjack interactive demo. Applications: secure, vulnerable, naive.")
    for index, scenario in enumerate(SCENARIOS):
        print(f"  {index}) {scenario.label}")
    while True:
        try:
            raw = input("Pick 'app index' (e.g. 'secure 0'), or 'quit': ").strip()
        except EOFError:
            break
        if raw in {"quit", "q", "exit"}:
            break
        parts = raw.split()
        if len(parts) != 2 or parts[0] not in clients or not parts[1].isdigit():
            print("  ? try, for example: vulnerable 0")
            continue
        index = int(parts[1])
        if not 0 <= index < len(SCENARIOS):
            print("  ? no such scenario")
            continue
        report = run_app(parts[0], clients[parts[0]], replay=replay, scenarios=[SCENARIOS[index]])
        print("\n".join(render_default(ComparisonResult([report]))))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    clients = _build_clients(args)
    replay = make_control_replay(args.control_url)
    try:
        if args.interactive:
            return _run_interactive(clients, replay)
        return _run_scripted(clients, replay, verbose=args.verbose)
    finally:
        for client in clients.values():
            client.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
