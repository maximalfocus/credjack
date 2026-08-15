# Contributing to credjack

Thanks for your interest. `credjack` is a small, local, educational demonstration of Server-Side
Request Forgery to a cloud instance metadata service and the app-side control that stops it.
Contributions are welcome within that purpose.

## Ground rules

- **The vulnerability stays.** The `vulnerable` and `naive` applications are intentionally
  insecure and are the whole point. Please do not "fix" them or remove their demonstrated
  behaviour; improvements to the *demonstration* — clarity, tests, documentation — are what help
  here. The `secure` application already shows the correct control.
- **Everything stays fictional and local.** All hosts, addresses, credentials, buckets, and
  "secrets" are invented. Do not add real data, real credentials, or anything that reaches a real
  system. No component may contact the public internet.
- **Keep the containment.** The secure application stays the default; each non-secure application
  keeps its two deliberate opt-in actions; all published ports stay loopback-only and the fixture
  networks stay `internal`.
- **No deployment or hosting.** This project is run locally with Docker Compose only. Do not add
  cloud deployment, hosting, or published-image configuration.

## Developing

Everything runs in containers; the host needs only Docker with Compose.

```sh
bash scripts/verify.sh   # Ruff, mypy, and the full pytest regression matrix
bash scripts/demo.sh     # the one-shot secure-vs-vulnerable-vs-naive comparison + replay
```

Please make sure `bash scripts/verify.sh` is green before opening a pull request, keep changes
focused, and add or update tests at the behaviour boundary you are changing. The same Docker
Compose boundary runs in GitHub Actions.

## Reporting problems

For an *unintended* security issue, follow [`SECURITY.md`](SECURITY.md) and report it privately.
For everything else — a bug in the demonstration, a documentation gap, an idea — open a normal
issue.
