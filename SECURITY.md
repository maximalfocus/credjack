# Security policy

`credjack` is an **intentionally vulnerable** educational project. Please read this before
reporting anything.

## The vulnerability that is supposed to be here

The **vulnerable** application performs a server-side fetch with **no target validation**, and it
demonstrates — on purpose — Server-Side Request Forgery reaching a cloud instance metadata service
(`169.254.169.254`), the theft of the fictional instance credentials, and a credential replay that
unlocks a fictional cloud-control-plane bucket. The **naive** application adds a hostname/string
**denylist** and demonstrates — also on purpose — how that weaker control is defeated by a name
that resolves to the metadata address. **These are the subject of the project, not bugs.** Please
do not report them, and please do not open "fixes" that remove the vulnerable or naive
applications or their demonstrated behaviour; the paired **secure** application already shows the
correct control (resolved-address blocking, re-applied on every redirect hop, connecting only to
the validated address).

Everything is wholly fictional and runs only on your own machine, inside the demo's own
`internal` container networks. No real host, cloud provider, or metadata service is ever
contacted, and no component reaches the public internet. The non-secure applications each require
two deliberate opt-in actions to start; the secure application is the default.

## Reporting an *unintended* problem

If you find a genuine, unintended security problem — something outside the deliberately
demonstrated SSRF-to-metadata flaw, for example an issue in the **secure** application, the
container setup, or the tooling — please report it **privately**:

1. Go to the repository's **Security** tab.
2. Choose **Report a vulnerability** to open a private security advisory.

Please do not open a public issue for an unintended vulnerability until it has been addressed.

## Scope and expectations

This is a local, educational project with no hosted service. It makes no service-level, support,
or production-readiness commitment, and provides no guaranteed response time. Reports are reviewed
on a best-effort basis.
