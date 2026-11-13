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

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and accepted risks.
