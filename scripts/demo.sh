#!/usr/bin/env bash
# One-shot scripted comparison (FR-012 / FR-013): fresh state, all three applications and the
# fixture topology up, real HTTP requests, a reported result, then teardown. The host needs
# only Docker + Docker Compose. Enabling the non-secure applications is a deliberate action.
set -euo pipefail

cd "$(dirname "$0")/.."

export ALLOW_VULNERABLE_DEMO=true

docker compose --profile vulnerable build

set +e
docker compose --profile vulnerable run --rm demo python -m credjack.cli "$@"
rc=$?
set -e

docker compose --profile vulnerable down --volumes --remove-orphans

exit "$rc"
