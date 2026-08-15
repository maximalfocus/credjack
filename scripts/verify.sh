#!/usr/bin/env bash
# The single documented host workflow: build the image, bring up the in-network fixture
# topology, run the full ruff + mypy + pytest gate inside a container, then tear it down.
# The host needs only Docker + Docker Compose.
set -euo pipefail

cd "$(dirname "$0")/.."

docker compose build

# Gating proof (FR-011 / NFR-001): the default Compose path must NOT start any non-secure
# application, and each non-secure application must be available only under the `vulnerable`
# profile, published loopback-only.
default_services="$(docker compose config --services)"
for svc in vulnerable naive; do
  if grep -qx "$svc" <<<"$default_services"; then
    echo "GATING FAILURE: '$svc' is started by the default Compose path" >&2
    exit 1
  fi
done
if ! grep -qx secure <<<"$default_services"; then
  echo "GATING FAILURE: the secure application is not a default service" >&2
  exit 1
fi
profile_config="$(docker compose --profile vulnerable config)"
grep -qx "vulnerable" <<<"$(docker compose --profile vulnerable config --services)" || {
  echo "GATING FAILURE: 'vulnerable' is not available under the vulnerable profile" >&2
  exit 1
}
# Each non-secure application is published on its port, bound to loopback.
grep -qx "naive" <<<"$(docker compose --profile vulnerable config --services)" || {
  echo "GATING FAILURE: 'naive' is not available under the vulnerable profile" >&2
  exit 1
}
for port in 8001 8002; do
  grep -B3 "published: \"$port\"" <<<"$profile_config" | grep -q 'host_ip: 127.0.0.1' || {
    echo "GATING FAILURE: a non-secure application is not published loopback-only on $port" >&2
    exit 1
  }
done
# No published port anywhere may bind a non-loopback interface.
if grep -qE 'host_ip: (0\.0\.0\.0|::)' <<<"$profile_config"; then
  echo "GATING FAILURE: a published port is not loopback-only" >&2
  exit 1
fi
echo "== gating checks passed (default excludes non-secure apps; vulnerable is opt-in, loopback:8001) =="

set +e
docker compose run --rm verify
rc=$?
set -e

docker compose down --volumes --remove-orphans

exit "$rc"
