# credjack

> **Private, in-development repository.** A container-only educational demo of **Server-Side
> Request Forgery to a cloud instance's metadata service** (OWASP **A10:2021** /
> **API7:2023** / **CWE-918**), carried through to a demonstrated **credential replay** that
> proves instance-role takeover — and the app-side control that stops it. Everything is fully
> simulated and runs **only inside the demo's own container network**; no real host, cloud
> provider, or metadata service is ever contacted.

**Status:** private development. **No license is granted during private development.**

## What it shows

The fictional **Beacon** uptime monitor fetches a user-submitted URL server-side. Three variants
differ only in how they validate the fetch target:

- **secure** (default, `127.0.0.1:8000`) — resolves the target, **rejects any blocked resolved
  address**, connects only to the validated address, and re-checks every redirect hop. It blocks
  every metadata attempt.
- **vulnerable** (opt-in, `127.0.0.1:8001`) — no validation; an SSRF reaches
  `169.254.169.254` and steals the fictional instance credentials, which unlock a fictional
  cloud-control-plane bucket.
- **naive** (opt-in, `127.0.0.1:8002`) — a hostname/string **denylist** that blocks the obvious
  literals but is **defeated by an attacker name that resolves to the metadata address**.

The lesson: a hostname/string denylist checks the *name*, not the *resolved address*; only
**resolved-address blocking** (on every hop, connecting only to the validated address) closes
the gap.

## Run it (Docker Compose only)

The host needs only Docker + Docker Compose. Python, dependencies, tests, Ruff, and mypy all run
inside containers.

```
bash scripts/demo.sh            # one-shot scripted comparison across all three apps + replay
bash scripts/demo.sh --verbose  # adds resolved address, per-hop decision, redirect chain, replay
bash scripts/verify.sh          # Ruff + mypy + the full pytest regression matrix
```

Local OpenAPI docs (secure app): `docker compose up -d secure`, then browse
`http://127.0.0.1:8000/docs`, then `docker compose down -v`.

## Read it

See **[docs/WALKTHROUGH.md](docs/WALKTHROUGH.md)** for the full walkthrough: why the instance
metadata service is the highest-value SSRF target, the terminology and standards mapping, why the
denylist is the weaker control and resolved-address blocking the stronger one, the real-world
defence-in-depth notes (IMDSv2 and least-privilege instance roles), expected outcomes, and the
deferred-scope items (DNS rebinding and the basic scheme/host-allowlist lesson are separate
demos).

## Safety

The **vulnerable** and **naive** applications are intentionally vulnerable local educational code
and **must never be deployed**. Each requires two deliberate actions to start (the `vulnerable`
Compose profile plus `ALLOW_VULNERABLE_DEMO=true`); the secure application is the default and the
default Compose path never starts them. All published ports are loopback-only, the fixture
networks are `internal` (no public-internet access on any path), and every fixture is wholly
fictional.
