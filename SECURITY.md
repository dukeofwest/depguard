# Security Policy

## Reporting a vulnerability

Please report security issues through
[GitHub Security Advisories](https://github.com/dukeofwest/depguard/security/advisories/new),
which keeps the report private until a fix is available.

If you cannot use that, open a regular issue describing the problem without exploit
details, and a private channel can be arranged.

Please include what you were doing, what happened, and which browser you used.

## Scope

DepGuard is a static browser application with no backend and no stored user data. The
realistic attack surface is its rendering of third-party content — repository metadata,
package names and advisory text are all attacker-controllable.

In scope:

- Cross-site scripting or markup injection through repository, package or advisory data
- A crafted repository URL causing a request to an unintended host
- A response that can exhaust browser memory or hang the page
- Any way to make DepGuard report a false clean result for a vulnerable repository

Out of scope:

- Vulnerabilities in GitHub or OSV.dev themselves
- The absence of authentication, which is a documented v1.0 decision
- Rate limiting by GitHub, which is their limit and not a defect here
- Reports from automated scanners without a demonstrated impact

## What DepGuard does not claim

DepGuard reports observable repository signals. It is not a code security audit, does not
read or execute source code, and its score is a heuristic assessment rather than a
certification. A repository with no detected vulnerabilities is not guaranteed to be safe.

## What we do about a report

- **Acknowledged within 72 hours**, even if only to say it is being looked at.
- **Worked in a private advisory** until a fix is deployed. Not secrecy for its own sake: a
  public issue against a browser-only application is an exploit notice for every visitor.
- **90 days** to a fix and disclosure, faster for anything critical.
- **Credit to the reporter** unless they would rather not be named.
- **A reasoned answer if it is not a vulnerability.** The scope above is written down in
  advance so that conversation is about facts rather than preferences.

The full process, including how the site is taken down or reverted if needed, is in
[docs/INCIDENT-RESPONSE.md](docs/INCIDENT-RESPONSE.md).

## Further reading

| Document                                               | Contents                                                                |
| ------------------------------------------------------ | ----------------------------------------------------------------------- |
| [docs/SECURITY.md](docs/SECURITY.md)                   | Controls, CSP, resource limits, dependency triage, repository hardening |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)           | Assets, trust boundaries, attackers, attack scenarios, residual risks   |
| [docs/SECURITY-TESTING.md](docs/SECURITY-TESTING.md)   | How each control is tested, how to run it, and what is **not** covered  |
| [docs/INCIDENT-RESPONSE.md](docs/INCIDENT-RESPONSE.md) | Severity levels, containment, fixing, disclosure                        |

DepGuard is **not** claimed to be secure or immune to attack. What is claimed is narrower
and checkable: the controls described in those documents exist, they are tested, and the
tests run in CI on every change. The limits of that assessment are stated in
[docs/SECURITY-TESTING.md](docs/SECURITY-TESTING.md) — in particular, there has been no
independent audit or penetration test, and the browser-driven checks run Chrome only.
