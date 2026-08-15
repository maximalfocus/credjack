# credjack — walkthrough

A container-only, fully-simulated teaching demo of **Server-Side Request Forgery (SSRF) to a
cloud instance's metadata service**, carried through to a demonstrated **credential replay**
that proves instance-role takeover — and the app-side control that stops it.

Everything here is fictional and runs only inside the demo's own container network. No real
host, cloud provider, or metadata service is ever contacted, and nothing here is usable
against a real system.

---

## 1. The scenario

**Beacon** is an invented cloud-hosted uptime monitor. Its "check" feature accepts a URL and
**fetches it server-side**, storing a small result (target, HTTP status, latency, and a capped
body snippet). Beacon runs on a fictional **Nimbus** cloud instance whose instance role is
`beacon-worker`.

The demo ships the same monitor in three variants that differ **only** in how they validate the
fetch target:

| App | Port (loopback) | Fetch behaviour |
|---|---|---|
| **secure** | `127.0.0.1:8000` (default) | resolves the target, **rejects any blocked resolved address**, connects only to the validated address, re-checks every redirect hop |
| **vulnerable** | `127.0.0.1:8001` (opt-in) | no validation; fetches whatever the target resolves to |
| **naive** | `127.0.0.1:8002` (opt-in) | a **hostname/string denylist** on the submitted URL, then fetches without checking the resolved address |

The in-network fixtures, reachable only inside the container network:

- a **fake instance metadata service** on the link-local address `169.254.169.254`, serving
  IMDSv1-style paths and returning a **conspicuously fictional** credential document;
- a **fake Nimbus control plane** on the private-range host `control.nimbus.internal`, which
  returns the fictional private bucket `nimbus-beacon-artifacts` **only** for the fictional
  session token;
- a **benign upstream** on `status.partner.test` (a documentation-range address, outside every
  blocked range), the one legitimate target, with a `/health` endpoint and a `/r?to=` redirect;
- an **attacker-controlled name** `cdn-edge.partner.test` whose static DNS record resolves to
  the link-local metadata address `169.254.169.254`.

---

## 2. Why the metadata endpoint is the highest-value SSRF target

A cloud instance can read its own short-lived role credentials from a **link-local metadata
endpoint** at `169.254.169.254` using nothing more than an ordinary HTTP GET. That address is
**non-routable**: no client on the internet can reach it, and the user's own browser certainly
cannot. It is reachable only *from inside the instance*.

SSRF turns the server into that "inside": when the application fetches a user-supplied URL, the
request originates **from the instance, inside its trust boundary**. Point that fetch at
`169.254.169.254` and the response is the machine's cloud credentials — a request the user
could never send directly is instead sent by the server and returns the keys to the instance's
role. That is why the metadata endpoint is the single highest-value SSRF target on a cloud
instance: one unvalidated fetch converts "read a URL" into "become the instance."

The impact is not hypothetical hand-waving here — the demo **replays** the stolen token against
the fake Nimbus control plane and reads a bucket only the `beacon-worker` role may read.

---

## 3. Terminology and mapping

- **Server-Side Request Forgery (SSRF)** — an attacker induces the server to make a request of
  the attacker's choosing, from the server's own network position.
- This demo's specific case: **SSRF to cloud instance metadata**.
- Standards mapping:
  - **CWE-918** — Server-Side Request Forgery (SSRF)
  - **OWASP API Security Top 10 — API7:2023** — Server Side Request Forgery
  - **OWASP Top 10 — A10:2021** — Server-Side Request Forgery

---

## 4. Run it

The host needs only **Docker + Docker Compose**. Python, dependencies, tests, Ruff, and mypy all
run inside containers.

### One-shot scripted comparison (the main demo)

```
bash scripts/demo.sh            # scripted comparison across all three apps + credential replay
bash scripts/demo.sh --verbose  # adds resolved address, per-hop decision, redirect chain, replay
```

This brings up the fixtures and all three applications against fresh state, submits the four
scenarios to each, replays any stolen token against the control plane, prints a per-application
verdict, and tears everything down. It completes in well under five minutes and exits non-zero
if the expected security matrix does not hold.

### Full verification gate

```
bash scripts/verify.sh          # Ruff + mypy + the full pytest regression matrix
```

### Local OpenAPI exploration

The secure application publishes its generated OpenAPI docs on loopback:

```
docker compose up -d secure
# open http://127.0.0.1:8000/docs   (and http://127.0.0.1:8000/openapi.json)
docker compose down -v
```

The non-secure applications require the two-action opt-in gate (see §7) and then expose their
docs on `127.0.0.1:8001/docs` (vulnerable) and `127.0.0.1:8002/docs` (naive):

```
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable up -d
# secure http://127.0.0.1:8000/docs · vulnerable :8001/docs · naive :8002/docs
docker compose --profile vulnerable down -v
```

All applications authenticate with unmistakably demo-only bearer tokens (for example
`Authorization: Bearer demo-token-avery-FICTIONAL`).

---

## 5. Expected outcomes

Submit a URL to `POST /checks`; read history with `GET /checks`. Against fresh state:

1. **Vulnerable metadata theft (direct IP).** Submit
   `http://169.254.169.254/latest/meta-data/iam/security-credentials/beacon-worker` to the
   **vulnerable** app → `201 Created`, and the stored snippet contains the fictional instance
   credentials.
2. **Vulnerable instance-role takeover (impact).** Replay that fictional session token against
   `http://control.nimbus.internal/buckets/nimbus-beacon-artifacts` → `200 OK` with the
   fictional private-bucket contents.
3. **Naive denylist bypass.** The **naive** app rejects the direct-IP submission (its denylist
   contains the literal `169.254.169.254`) exactly as the secure app does — but given
   `http://cdn-edge.partner.test/latest/meta-data/iam/security-credentials/beacon-worker`, whose
   name is not on the denylist, it resolves that name to `169.254.169.254` and fetches it,
   returning `201` with the credentials, which again unlock the bucket.
4. **Secure rejection.** The **secure** app receives the direct-IP submission, the resolving-name
   submission, and an allowlisted-host **redirect** to the metadata address
   (`http://status.partner.test/r?to=http://169.254.169.254/...`) — and each gets the **same
   byte-identical generic `400 Bad Request`**, emits a structured rejection event, creates no
   record, obtains no credentials, and leaves check history byte-for-byte unchanged. A later
   control-plane replay therefore returns nothing.
5. **Secure legitimate check.** Submit `http://status.partner.test/health` to the secure app →
   `201` with the expected deterministic snippet and exactly one new record — identical to the
   vulnerable app's result for the same benign input.

The scripted comparison prints exactly this: `SECURE → SAFE`, `VULNERABLE → COMPROMISED`,
`NAIVE → COMPROMISED`.

---

## 6. The controls: why the denylist is weaker

A **hostname or string denylist** checks the *name or text the user submitted* — not the
*address the request actually reaches*. The naive app proves the gap: it blocks the literal
`169.254.169.254` and known metadata names, so the obvious submissions are refused. But
`cdn-edge.partner.test` is an innocuous-looking name that is not on any denylist, and it
*resolves* to the metadata address. The text check passes; the fetch still lands on
`169.254.169.254`. Checking the name is **necessary but not sufficient**.

The **stronger control**, and the one this demo teaches, is **resolved-address blocking**:

1. restrict the scheme to `http`/`https` (baseline hygiene, credited to the `fetchjack` demo);
2. **resolve** the target host to its IP address(es);
3. **reject** the request if any resolved address is in a blocked range — link-local
   (`169.254.0.0/16`, `fe80::/10`), loopback, private, carrier-grade NAT, and
   unspecified/reserved;
4. **connect only to the specific address just validated** (address pinning — the address
   checked is the address used); and
5. re-apply the same check to **every redirect hop**, or refuse redirects, under a fixed hop cap.

Because the check is on the *resolved address*, `cdn-edge.partner.test` fails at step 3 just as
the literal IP does, and the allowlisted-host redirect fails at step 5. Every rejection returns
the **same generic `400`** with no reason disclosed, so there is no oracle for the rejection
class or the existence of an internal host.

---

## 7. Safety: the opt-in gate

The **secure** application is the default long-running service. Each **non-secure** application
requires **two deliberate actions** to start:

1. enable the `vulnerable` Docker Compose profile, **and**
2. set `ALLOW_VULNERABLE_DEMO=true`.

Absent either, the application refuses to start and explains why. All published ports are
loopback-only. **The vulnerable and naive applications are intentionally vulnerable local
educational code and must never be deployed.**

---

## 8. Real-world defence-in-depth (documented, not taught here as the fix)

The taught, exercised fix in this demo is **app-side resolved-address blocking**. In production
you would also deploy defence-in-depth that this demo *documents but does not itself teach*:

- **IMDSv2 — session-oriented metadata access.** The metadata service requires a session token
  obtained by an HTTP **`PUT`**, and responses are returned with a low IP **response hop limit**.
  A simple GET-based SSRF cannot perform the `PUT` handshake, and the low hop limit stops tokens
  from being proxied off-host — so IMDSv2 defeats the exact GET-based primitive shown here.
- **Least-privilege instance roles.** This is least-privilege access: if the instance role can
  read almost nothing, stolen credentials are worth almost nothing. Scope the role to the
  minimum the workload needs.

These are complementary layers, not substitutes for validating the fetch.

---

## 9. Out of scope (by design)

These are deliberately **separate demos**, not omissions:

- **DNS rebinding / TOCTOU on hostname resolution.** credjack uses only **static** resolution
  and connects to the address it validated, so the address checked is the address used. The
  case where resolution changes *between* the check and the connect is a separate demo.
- **The basic SSRF scheme-and-host-allowlist lesson** (and non-HTTP scheme abuse such as
  `file://`). That is the **`fetchjack`** demo. credjack assumes the SSRF primitive and teaches
  the cloud-metadata escalation and resolved-address blocking.
- **IMDSv2 as a toggleable, demonstrated control.** It is documented above as real-world
  defence-in-depth only; the exercised fix here is app-side resolved-address blocking.

---

## 10. A note on fixtures

Every fixture is wholly fictional. The credential document and the private-bucket contents
declare their fictional nature in their own bodies. The fixture networks are `internal`, so no
component can reach the public internet on any path; the link-local address `169.254.169.254` is
a well-known public constant used here only as an in-network fixture. Fixtures are deterministic
(no clock or randomness), so identical requests produce identical bytes across runs.
