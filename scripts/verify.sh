#!/usr/bin/env bash
# The single documented host workflow: build the image, bring up the in-network fixture
# topology, run the full ruff + mypy + pytest gate inside a container, then tear it down.
# The host needs only Docker + Docker Compose.
set -euo pipefail

cd "$(dirname "$0")/.."

docker compose build

set +e
docker compose run --rm verify
rc=$?
set -e

docker compose down --volumes --remove-orphans

exit "$rc"
