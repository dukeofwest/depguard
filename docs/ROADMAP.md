# Roadmap

What exists today, what is deliberately out of scope, and what would come next. Nothing
here is a commitment.

## Shipped in v1.0

- Public repository analysis with no account or token
- Five categories: dependency security, dependency health, security configuration,
  maintenance and activity, engineering quality
- Vulnerability matching via OSV, with CVE-level deduplication
- Explainable scoring with coverage, weight redistribution and traceable deductions
- Evidence-linked recommendations
- Searchable, filterable dependency inventory distinguishing _checked and clean_ from
  _never checked_
- Versioned JSON export
- Rate-limit budget visible before a scan starts

## Open questions

These are genuine product decisions, not oversights.

### Should an unassessable security category cap the overall band?

A repository whose dependencies cannot be checked can still score highly on documentation,
licensing and activity. `psf/requests` scores 92 ("Excellent") with Dependency Security
reporting insufficient data.

The report states this three times — coverage, the explanation, and a "Needs attention
first" entry — but the headline number alone does not convey it. Capping the band (for
example, no higher than "Fair") when a security category is unassessable would be
defensible. The current behaviour follows the specification's model and has not been
changed unilaterally. See [SCORING.md](SCORING.md).

### Should unverified ecosystems be queried at all?

Maven, Go, crates.io, NuGet, RubyGems and Packagist are mapped from documentation but not
demonstrated against live data. They are currently queried with a disclosure in the
report. The alternative — excluding them until verified — would be more conservative but
less useful.

## Deferred, with reasons

| Feature                                | Why it is not here                                                                      |
| -------------------------------------- | --------------------------------------------------------------------------------------- |
| Version freshness / outdated detection | No reliable free registry source; DepGuard will not invent a "latest version"           |
| Deprecated package detection           | Same — requires per-ecosystem registry integration                                      |
| PDF export                             | JSON serves the machine-readable need; PDF is presentation work with no new information |
| Historical score tracking              | Requires storage, which requires a backend                                              |
| Multiple repository monitoring         | Same                                                                                    |
| Scheduled scans                        | Same                                                                                    |

## Requires authentication

Out of scope for v1.0 by deliberate decision: asking people to hand credentials to a new
application is a significant trust request, and public analysis is enough to establish
whether the product is useful.

- Private repository analysis
- Dependabot alert status (whether it is actually enabled, not merely configured)
- CodeQL scan results and whether workflows pass
- A higher rate limit than 60 requests per hour

The natural next step is a GitHub App or an optional user-supplied token. The architecture
does not preclude it: authentication would add a header to the existing API client and
change nothing in the engine.

## Likely next

In rough order of value per unit of work.

1. **Firefox and Safari verification.** The browser-driven checks currently run Chrome
   only. Nothing relies on Chrome-specific behaviour, but that is an assumption until
   tested.
2. **More verified ecosystems.** Each needs a real repository with a committed lockfile in
   that ecosystem, run end to end against OSV.
3. **Shareable reports.** A report encoded in the URL, or stored, so a link can be sent to
   a colleague. The first approach needs no backend and would introduce routing.
4. **Optional token input.** Would lift the rate limit and enable Dependabot and code
   scanning status — a large increase in what the product can honestly say. Needs careful
   handling: a token must never be persisted or exported.
5. **Deeper engineering signals.** Workflow run results, release cadence, issue response
   times — all authenticated or heavier API use.

## Explicitly not planned

- Executing repository code or package scripts, under any circumstances
- Sending repository data to any third party beyond GitHub and OSV
- Storing user data, analytics or telemetry
- Presenting DepGuard's score as a security certification
