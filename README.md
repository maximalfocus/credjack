# credjack

> **Private, in-development repository.** A container-only educational demo of
> **Server-Side Request Forgery to cloud instance metadata** (OWASP A10:2021 /
> API7:2023 / CWE-918). Everything is fully simulated and runs **only inside the demo's
> own container network** — no real host, cloud provider, or metadata service is ever
> contacted.

**Status:** private development. No license is granted during private development.

## Verify (Docker Compose only)

The host needs only Docker + Docker Compose. Python, dependencies, tests, Ruff, and mypy
all run inside containers.

```
bash scripts/verify.sh
```

This builds the image, starts the in-network fixture topology, runs the full containerized
**Ruff + mypy + pytest** gate against the live fixtures, and then tears everything down.
GitHub Actions runs the same command.

## What exists so far (SLICE-001)

- The fictional **Beacon** monitor domain model — append-only, UUID-identified check
  records over synchronous SQLAlchemy + SQLite.
- The **in-network fixture topology**, reachable only inside the container network:
  - a fake instance metadata service on the link-local address `169.254.169.254`;
  - a fake **Nimbus** cloud control plane on a private-range host
    (`control.nimbus.internal`), gating a fictional private bucket on a fictional token;
  - a benign upstream fixture on a documentation-range address
    (`status.partner.test`), with content and redirect endpoints;
  - an attacker-controlled name (`cdn-edge.partner.test`) that resolves to the
    link-local metadata address.
- The **containerized verification boundary** and its GitHub Actions workflow.

The fixture networks are `internal: true`, so nothing in the demo can reach the public
internet. Every fixture is wholly fictional; the credential and bucket fixtures declare so
in their own contents.

The secure, vulnerable, and naive applications; the comparison CLI; the walkthrough; and
any licensing/publication all arrive in later slices.
